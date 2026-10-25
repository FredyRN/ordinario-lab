-- =============================================================================
-- 01_init_schema.sql
-- Core DDL for White-Label Multi-Tenant AI Agent Platform
-- Architecture: B2B2C (Agencies -> Tenants -> Agents / RAG / MCP / Channels)
-- Engine: PostgreSQL 16+
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- 1. EXTENSIONS & UTILITY FUNCTIONS
-- -----------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "citext";

-- Trigger function to automatically maintain updated_at timestamps
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- -----------------------------------------------------------------------------
-- 2. CUSTOM ENUM TYPES
-- -----------------------------------------------------------------------------
CREATE TYPE user_role_type AS ENUM (
    'agency_owner',
    'agency_admin',
    'tenant_admin',
    'human_operator'
);

CREATE TYPE conversation_control_mode AS ENUM (
    'ai_active',       -- AI Agent automatically processes and replies
    'human_takeover'   -- AI Agent is paused; human operator handles the chat
);

CREATE TYPE message_sender_type AS ENUM (
    'contact',         -- End-user on WhatsApp / Telegram
    'ai_agent',        -- Automated LLM response
    'human_operator',  -- Human agent via HTMX live inbox
    'system_event'     -- Internal handoff or tool execution trace
);

CREATE TYPE message_delivery_status AS ENUM (
    'received',
    'queued',
    'sent',
    'delivered',
    'read',
    'failed'
);

CREATE TYPE rag_document_status AS ENUM (
    'pending',
    'chunking',
    'indexed',
    'failed'
);

CREATE TYPE mcp_transport_type AS ENUM (
    'sse',
    'streamable_http'
);

-- -----------------------------------------------------------------------------
-- 3. WHITE-LABEL AGENCIES & TENANTS (B2B2C HIERARCHY)
-- -----------------------------------------------------------------------------

-- Top-level entity: Marketing/AI Agencies selling white-label agents
CREATE TABLE agencies (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                VARCHAR(120) NOT NULL,
    slug                CITEXT NOT NULL UNIQUE,
    custom_domain       CITEXT NOT NULL UNIQUE, -- e.g. panel.myagency.com
    logo_url            TEXT,
    favicon_url         TEXT,
    primary_color       VARCHAR(7) NOT NULL DEFAULT '#4F46E5',
    secondary_color     VARCHAR(7) NOT NULL DEFAULT '#0F172A',
    support_email       CITEXT,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    settings            JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER trg_agencies_updated_at
    BEFORE UPDATE ON agencies
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- End-clients belonging to an Agency (RLS Isolation Boundary)
CREATE TABLE tenants (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agency_id           UUID NOT NULL REFERENCES agencies(id) ON DELETE RESTRICT,
    name                VARCHAR(120) NOT NULL,
    slug                CITEXT NOT NULL,
    timezone            VARCHAR(64) NOT NULL DEFAULT 'UTC',
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    quota_max_agents    INT NOT NULL DEFAULT 5,
    quota_max_kbs       INT NOT NULL DEFAULT 10,
    metadata            JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (agency_id, slug),
    UNIQUE (id, agency_id)
);

CREATE INDEX idx_tenants_agency_id ON tenants(agency_id);

-- Validate that tenants.timezone is an IANA name accepted by PostgreSQL.
-- A plain CHECK cannot reference pg_timezone_names (subqueries not allowed in
-- CHECK), so a lightweight trigger is the only engine-level enforcement.
CREATE OR REPLACE FUNCTION validate_tenant_timezone()
RETURNS TRIGGER
SECURITY DEFINER
SET search_path = public
LANGUAGE plpgsql
AS $$
BEGIN
    -- Only validate on INSERT or when the column actually changes on UPDATE
    IF TG_OP = 'INSERT'
       OR (TG_OP = 'UPDATE' AND NEW.timezone IS DISTINCT FROM OLD.timezone)
    THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_timezone_names WHERE name = NEW.timezone
        ) THEN
            RAISE EXCEPTION 'Invalid IANA timezone: %', NEW.timezone
                USING ERRCODE = '22023'; -- invalid_parameter_value
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_tenants_validate_timezone
    BEFORE INSERT OR UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION validate_tenant_timezone();

CREATE TRIGGER trg_tenants_updated_at
    BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Users (Agency administrators, Tenant admins, and Human chat operators)
CREATE TABLE users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agency_id           UUID NOT NULL,
    tenant_id           UUID, -- NULL for agency-level staff
    email               CITEXT NOT NULL,
    password_hash       TEXT NOT NULL, -- Argon2id hash
    full_name           VARCHAR(120) NOT NULL,
    role                user_role_type NOT NULL DEFAULT 'human_operator',
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at       TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Email is unique per agency so white-label domains remain completely independent
    UNIQUE (agency_id, email),
    UNIQUE (id, tenant_id),
    CONSTRAINT chk_tenant_role_assignment CHECK (
        (role IN ('agency_owner', 'agency_admin') AND tenant_id IS NULL) OR
        (role IN ('tenant_admin', 'human_operator') AND tenant_id IS NOT NULL)
    ),
    -- Agency-level foreign key: user always belongs to one agency
    FOREIGN KEY (agency_id) REFERENCES agencies(id) ON DELETE CASCADE,
    -- Composite foreign key: when tenant_id is set, it MUST belong to users.agency_id.
    -- MATCH SIMPLE (default) means the FK is only enforced when BOTH columns are
    -- non-NULL, which is exactly what we want: agency-level staff (tenant_id NULL)
    -- skip the check, tenant-level staff are forced into a same-agency tenant.
    FOREIGN KEY (tenant_id, agency_id) REFERENCES tenants(id, agency_id) ON DELETE CASCADE
);

CREATE INDEX idx_users_tenant_id ON users(tenant_id) WHERE tenant_id IS NOT NULL;
CREATE INDEX idx_users_agency_email ON users(agency_id, email);

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- -----------------------------------------------------------------------------
-- 4. AI AGENTS & OMNICHANNEL CONNECTIONS
-- -----------------------------------------------------------------------------

CREATE TABLE agents (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                    VARCHAR(120) NOT NULL,
    description             TEXT,
    system_prompt           TEXT NOT NULL,
    llm_provider            VARCHAR(40) NOT NULL DEFAULT 'openai',
    llm_model               VARCHAR(80) NOT NULL DEFAULT 'gpt-4o-mini',
    encrypted_llm_api_key   BYTEA, -- AES-256-GCM encrypted optional custom tenant key
    temperature             NUMERIC(3,2) NOT NULL DEFAULT 0.30 CHECK (temperature >= 0.0 AND temperature <= 2.0),
    max_tokens              INT NOT NULL DEFAULT 1024,
    debounce_window_ms      INT NOT NULL DEFAULT 3000 CHECK (debounce_window_ms >= 0 AND debounce_window_ms <= 30000),
    auto_handoff_enabled    BOOLEAN NOT NULL DEFAULT TRUE, -- Allows AI to invoke a built-in tool to request human help
    is_active               BOOLEAN NOT NULL DEFAULT TRUE,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Composite unique key required for strict same-tenant foreign keys in child tables
    UNIQUE (id, tenant_id)
);

CREATE INDEX idx_agents_tenant_id ON agents(tenant_id);

CREATE TRIGGER trg_agents_updated_at
    BEFORE UPDATE ON agents
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Inbound/Outbound Messaging Channels (Meta WhatsApp Cloud API, Telegram, etc.)
CREATE TABLE channel_connections (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID NOT NULL,
    agent_id                UUID NOT NULL,
    -- TEXT + CHECK instead of ENUM: channel providers are expected to grow
    -- (Slack, Discord, SMS, email, LINE…) and may need renaming/deprecation
    -- (e.g. custom_webhook -> generic_webhook). ENUMs cannot be renamed or
    -- shrunk without recreating the type; CHECK constraints can be altered
    -- in place with ADD CONSTRAINT ... NOT VALID + VALIDATE.
    --
    -- To add a provider:
    --   ALTER TABLE channel_connections DROP CONSTRAINT chk_channels_provider_type;
    --   ALTER TABLE channel_connections ADD CONSTRAINT chk_channels_provider_type
    --       CHECK (channel_type IN (..., 'slack', 'discord', ...)) NOT VALID;
    --   ALTER TABLE channel_connections VALIDATE CONSTRAINT chk_channels_provider_type;
    channel_type            VARCHAR(30) NOT NULL,
    display_name            VARCHAR(120) NOT NULL, -- e.g. "+57 300 123 4567 - Sales" or "@MySupportBot"
    -- External routing key: Meta phone_number_id or Telegram bot_id / webhook token
    external_identifier     VARCHAR(128) NOT NULL,
    -- Secondary identifier: e.g. Meta WABA ID (WhatsApp Business Account ID)
    external_account_id     VARCHAR(128),
    -- AES-256-GCM encrypted JSON containing access_token, bot_token, or signing keys
    encrypted_credentials   BYTEA NOT NULL,
    -- Token used for webhook verification handshakes
    webhook_verify_token    VARCHAR(128) NOT NULL,
    is_active               BOOLEAN NOT NULL DEFAULT TRUE,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (id, tenant_id),
    UNIQUE (channel_type, external_identifier),
    CONSTRAINT chk_channels_provider_type CHECK (channel_type IN (
        'whatsapp_meta',
        'telegram',
        'instagram_meta',
        'webchat',
        'custom_webhook'
    )),
    FOREIGN KEY (agent_id, tenant_id) REFERENCES agents(id, tenant_id) ON DELETE RESTRICT
);

CREATE INDEX idx_channels_tenant_id ON channel_connections(tenant_id);

CREATE TRIGGER trg_channels_updated_at
    BEFORE UPDATE ON channel_connections
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- -----------------------------------------------------------------------------
-- 5. RAG KNOWLEDGE BASES (INDIVIDUAL OR SHARED ACROSS AGENTS)
-- -----------------------------------------------------------------------------

CREATE TABLE knowledge_bases (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                VARCHAR(120) NOT NULL,
    description         TEXT,
    qdrant_collection   VARCHAR(100) NOT NULL DEFAULT 'tenants_knowledge_vectors',
    embedding_provider  VARCHAR(40) NOT NULL DEFAULT 'openai',
    embedding_model     VARCHAR(80) NOT NULL DEFAULT 'text-embedding-3-small',
    chunk_size          INT NOT NULL DEFAULT 800 CHECK (chunk_size >= 100 AND chunk_size <= 4000),
    chunk_overlap       INT NOT NULL DEFAULT 150 CHECK (chunk_overlap >= 0 AND chunk_overlap < chunk_size),
    top_k               INT NOT NULL DEFAULT 5 CHECK (top_k >= 1 AND top_k <= 20),
    score_threshold     NUMERIC(3,2) NOT NULL DEFAULT 0.72,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (id, tenant_id)
);

CREATE INDEX idx_kbs_tenant_id ON knowledge_bases(tenant_id);

CREATE TRIGGER trg_kbs_updated_at
    BEFORE UPDATE ON knowledge_bases
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Documents ingested into a Knowledge Base and indexed in Qdrant
CREATE TABLE rag_documents (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL,
    kb_id               UUID NOT NULL,
    title               VARCHAR(255) NOT NULL,
    source_type         VARCHAR(30) NOT NULL DEFAULT 'file', -- 'file', 'url', 'raw_text'
    mime_type           VARCHAR(100),
    content_sha256      CHAR(64) NOT NULL,
    chunk_count         INT NOT NULL DEFAULT 0,
    status              rag_document_status NOT NULL DEFAULT 'pending',
    error_message       TEXT,
    metadata            JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (id, tenant_id),
    -- Prevents re-ingesting the exact same file into the same KB
    UNIQUE (kb_id, content_sha256),
    FOREIGN KEY (kb_id, tenant_id) REFERENCES knowledge_bases(id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX idx_rag_docs_kb_id ON rag_documents(tenant_id, kb_id);

-- Ingestion worker queue: only non-indexed rows are "in flight" or retryable.
-- Keeping this partial keeps the index tiny even with millions of indexed docs.
CREATE INDEX idx_rag_docs_pending_queue
    ON rag_documents(tenant_id, status, created_at ASC)
    WHERE status IN ('pending', 'chunking', 'failed');

CREATE TRIGGER trg_rag_docs_updated_at
    BEFORE UPDATE ON rag_documents
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- N:M Pivot Table: Allows a Knowledge Base to be private to 1 Agent or shared across N Agents of the same Tenant
CREATE TABLE agent_knowledge_bases (
    agent_id            UUID NOT NULL,
    kb_id               UUID NOT NULL,
    tenant_id           UUID NOT NULL,
    priority            SMALLINT NOT NULL DEFAULT 1,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (agent_id, kb_id),
    -- Enforces that both Agent and Knowledge Base belong to the exact same Tenant
    FOREIGN KEY (agent_id, tenant_id) REFERENCES agents(id, tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (kb_id, tenant_id) REFERENCES knowledge_bases(id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX idx_agent_kbs_tenant_agent ON agent_knowledge_bases(tenant_id, agent_id);

-- -----------------------------------------------------------------------------
-- 6. MODEL CONTEXT PROTOCOL (MCP) SERVERS & AGENT BINDINGS
-- -----------------------------------------------------------------------------

CREATE TABLE mcp_servers (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                    VARCHAR(120) NOT NULL,
    description             TEXT,
    transport               mcp_transport_type NOT NULL DEFAULT 'sse',
    endpoint_url            TEXT NOT NULL,
    -- AES-256-GCM encrypted JSON map of custom HTTP headers (e.g. Authorization: Bearer ...)
    encrypted_auth_headers  BYTEA,
    -- Cached list of discovered MCP tools (name, description, inputSchema)
    cached_tools_schema     JSONB NOT NULL DEFAULT '[]'::jsonb,
    timeout_ms              INT NOT NULL DEFAULT 15000 CHECK (timeout_ms >= 1000 AND timeout_ms <= 60000),
    is_active               BOOLEAN NOT NULL DEFAULT TRUE,
    last_synced_at          TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (id, tenant_id)
);

CREATE INDEX idx_mcp_servers_tenant_id ON mcp_servers(tenant_id);

CREATE TRIGGER trg_mcp_servers_updated_at
    BEFORE UPDATE ON mcp_servers
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- N:M Pivot Table: Connects Agents to one or multiple MCP Servers
CREATE TABLE agent_mcp_servers (
    agent_id            UUID NOT NULL,
    mcp_server_id       UUID NOT NULL,
    tenant_id           UUID NOT NULL,
    -- Optional whitelist of tool names exposed to this specific agent (empty array = all tools)
    allowed_tools       TEXT[] NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (agent_id, mcp_server_id),
    FOREIGN KEY (agent_id, tenant_id) REFERENCES agents(id, tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (mcp_server_id, tenant_id) REFERENCES mcp_servers(id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX idx_agent_mcp_tenant_agent ON agent_mcp_servers(tenant_id, agent_id);

-- -----------------------------------------------------------------------------
-- 7. OUTBOUND WEBHOOKS & DELIVERY LOGS
-- -----------------------------------------------------------------------------

CREATE TABLE webhook_subscriptions (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Optional: NULL means the subscription listens to events from ALL agents of the tenant
    agent_id                UUID,
    name                    VARCHAR(120) NOT NULL,
    target_url              TEXT NOT NULL,
    -- AES-256-GCM encrypted secret used to compute X-Hub-Signature-256 (HMAC-SHA256)
    encrypted_secret        BYTEA NOT NULL,
    -- Subscribed event names, e.g.:
    -- {'message.received', 'message.sent', 'conversation.paused', 'conversation.resumed', 'mcp.tool_called'}
    subscribed_events       TEXT[] NOT NULL,
    custom_headers          JSONB NOT NULL DEFAULT '{}'::jsonb,
    max_retries             SMALLINT NOT NULL DEFAULT 3
        CONSTRAINT chk_webhook_subs_max_retries CHECK (max_retries BETWEEN 0 AND 10),
    is_active               BOOLEAN NOT NULL DEFAULT TRUE,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (id, tenant_id),
    FOREIGN KEY (agent_id, tenant_id) REFERENCES agents(id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX idx_webhook_subs_tenant_events ON webhook_subscriptions USING GIN (subscribed_events);
CREATE INDEX idx_webhook_subs_tenant_id ON webhook_subscriptions(tenant_id) WHERE is_active = TRUE;

CREATE TRIGGER trg_webhook_subs_updated_at
    BEFORE UPDATE ON webhook_subscriptions
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE webhook_deliveries (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID NOT NULL,
    subscription_id         UUID NOT NULL,
    event_name              VARCHAR(80) NOT NULL,
    payload                 JSONB NOT NULL,
    attempt_count           SMALLINT NOT NULL DEFAULT 1,
    response_status_code    SMALLINT,
    response_body           TEXT,
    succeeded               BOOLEAN NOT NULL DEFAULT FALSE,
    next_retry_at           TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (subscription_id, tenant_id) REFERENCES webhook_subscriptions(id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX idx_webhook_deliveries_retry ON webhook_deliveries(next_retry_at)
    WHERE succeeded = FALSE AND next_retry_at IS NOT NULL;
CREATE INDEX idx_webhook_deliveries_tenant_created ON webhook_deliveries(tenant_id, created_at DESC);

-- -----------------------------------------------------------------------------
-- 8. CONVERSATIONS, MESSAGES & HUMAN-IN-THE-LOOP (HITL) HANDOFF
-- -----------------------------------------------------------------------------

CREATE TABLE conversations (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID NOT NULL,
    agent_id                UUID NOT NULL,
    channel_connection_id   UUID NOT NULL,
    -- Contact identifier on the external platform (e.g. WhatsApp wa_id or Telegram chat_id)
    contact_external_id     VARCHAR(128) NOT NULL,
    contact_name            VARCHAR(160),
    contact_avatar_url      TEXT,
    contact_metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Core HITL state: 'ai_active' vs 'human_takeover'
    control_mode            conversation_control_mode NOT NULL DEFAULT 'ai_active',
    assigned_user_id        UUID,
    paused_at               TIMESTAMPTZ,
    paused_by_user_id       UUID,
    pause_reason            VARCHAR(255),
    unread_count            INT NOT NULL DEFAULT 0,
    last_message_preview    TEXT,
    last_message_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (id, tenant_id),
    -- Guarantees one active thread per contact on a given channel connection
    UNIQUE (channel_connection_id, contact_external_id),
    CONSTRAINT chk_conversations_takeover_requires_pause CHECK (
        control_mode = 'ai_active' OR paused_at IS NOT NULL
    ),
    FOREIGN KEY (agent_id, tenant_id) REFERENCES agents(id, tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (channel_connection_id, tenant_id) REFERENCES channel_connections(id, tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (assigned_user_id, tenant_id) REFERENCES users(id, tenant_id) ON DELETE SET NULL (assigned_user_id),
    FOREIGN KEY (paused_by_user_id, tenant_id) REFERENCES users(id, tenant_id) ON DELETE SET NULL (paused_by_user_id)
);

-- Optimized index for the HTMX live chat inbox ordered by most recent activity
CREATE INDEX idx_conversations_inbox ON conversations(tenant_id, control_mode, last_message_at DESC);
CREATE INDEX idx_conversations_channel_contact ON conversations(tenant_id, channel_connection_id, contact_external_id);

-- "My chats" filter for human operators (assigned_user_id IS NULL for unassigned/AI-only)
CREATE INDEX idx_conversations_assigned_user
    ON conversations(tenant_id, assigned_user_id, last_message_at DESC)
    WHERE assigned_user_id IS NOT NULL;

CREATE TRIGGER trg_conversations_updated_at
    BEFORE UPDATE ON conversations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Individual chat messages (Contact, AI Agent, Human Operator, or Tool Event)
CREATE TABLE messages (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID NOT NULL,
    conversation_id         UUID NOT NULL,
    -- External platform message ID (e.g. Meta wamid.xxx or Telegram message_id) for idempotency
    external_message_id     VARCHAR(160),
    sender_type             message_sender_type NOT NULL,
    -- Populated when sender_type = 'human_operator'
    sender_user_id          UUID,
    content_type            VARCHAR(30) NOT NULL DEFAULT 'text', -- 'text', 'image', 'audio', 'document', 'tool_call'
    content                 TEXT NOT NULL,
    media_url               TEXT,
    -- Stores RAG chunk citations, MCP tool call inputs/outputs, and LLM token metrics
    metadata                JSONB NOT NULL DEFAULT '{}'::jsonb,
    delivery_status         message_delivery_status NOT NULL DEFAULT 'sent',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_messages_human_operator_requires_user CHECK (
        sender_type <> 'human_operator' OR sender_user_id IS NOT NULL
    ),
    FOREIGN KEY (conversation_id, tenant_id) REFERENCES conversations(id, tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (sender_user_id, tenant_id) REFERENCES users(id, tenant_id) ON DELETE SET NULL (sender_user_id)
);

-- Unique partial index to prevent duplicate processing of retried Meta/Telegram webhooks
-- NOTE ON FUTURE PARTITIONING: this table is intentionally NOT partitioned by
-- created_at. PostgreSQL requires every unique constraint on a partitioned table
-- to include the partition key, which would force `created_at` into this index.
-- That would break idempotency: a retry arriving 1 second later with the same
-- external_message_id would land on a different `created_at` value and not
-- collide. If per-month pruning is ever needed, the correct pattern is to
-- extract dedupe into a separate unpartitioned table:
--
--   CREATE TABLE message_ids_seen (
--       tenant_id           UUID NOT NULL,
--       conversation_id     UUID NOT NULL,
--       external_message_id VARCHAR(160) NOT NULL,
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
--       PRIMARY KEY (tenant_id, conversation_id, external_message_id)
--   );
--
-- and have the ingest path do INSERT ... ON CONFLICT DO NOTHING into
-- message_ids_seen before writing to messages. That was intentionally not done
-- in this schema because it requires coordinated changes in the Go ingest path
-- and is out of scope for a DDL-only correction.
CREATE UNIQUE INDEX idx_messages_external_id_unique
    ON messages(tenant_id, conversation_id, external_message_id)
    WHERE external_message_id IS NOT NULL;

-- Optimized index for loading conversation history and LLM context window
CREATE INDEX idx_messages_conversation_history
    ON messages(tenant_id, conversation_id, created_at ASC);

-- Timeline global por tenant: usado por v_tenant_dashboard_stats (messages_last_24h)
-- y por cualquier consulta de métricas por rango de fechas sin filtrar por conversación
CREATE INDEX idx_messages_tenant_created
    ON messages(tenant_id, created_at DESC);

-- Audit log for every AI <-> Human control switch
CREATE TABLE handoff_events (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID NOT NULL,
    conversation_id         UUID NOT NULL,
    previous_mode           conversation_control_mode NOT NULL,
    new_mode                conversation_control_mode NOT NULL,
    triggered_by            VARCHAR(30) NOT NULL CHECK (triggered_by IN ('human_operator', 'ai_escalation', 'auto_timeout', 'api_webhook')),
    actor_user_id           UUID,
    reason                  TEXT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (conversation_id, tenant_id) REFERENCES conversations(id, tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (actor_user_id, tenant_id) REFERENCES users(id, tenant_id) ON DELETE SET NULL (actor_user_id)
);

CREATE INDEX idx_handoff_events_conv ON handoff_events(tenant_id, conversation_id, created_at DESC);

-- "What did operator X do?" — used by tenant_admin when reviewing human takeovers
CREATE INDEX idx_handoff_events_actor
    ON handoff_events(tenant_id, actor_user_id, created_at DESC)
    WHERE actor_user_id IS NOT NULL;

-- -----------------------------------------------------------------------------
-- 8.1 Denormalization Sync: keep conversations.* in lockstep with messages
-- -----------------------------------------------------------------------------
-- Rationale: last_message_at / last_message_preview / unread_count are derived
-- fields maintained at the DB layer so that every write path (Meta webhook,
-- Telegram webhook, HTMX operator reply, retry worker, batch import) keeps the
-- inbox consistent without depending on application-side correctness.

CREATE OR REPLACE FUNCTION sync_conversation_on_message()
RETURNS TRIGGER
SECURITY DEFINER
SET search_path = public
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE conversations
    SET last_message_at = NEW.created_at,
        last_message_preview = CASE NEW.content_type
            WHEN 'text'     THEN LEFT(NEW.content, 200)
            WHEN 'image'    THEN '[Image]'
            WHEN 'audio'    THEN '[Audio]'
            WHEN 'document' THEN '[Document]'
            WHEN 'tool_call' THEN '[Tool: ' || COALESCE(NEW.metadata->>'tool_name', 'unknown') || ']'
            ELSE LEFT(NEW.content, 200)
        END,
        unread_count = CASE
            WHEN NEW.sender_type = 'contact' THEN unread_count + 1
            ELSE unread_count
        END
    WHERE id = NEW.conversation_id
      AND tenant_id = NEW.tenant_id;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_update_conversation_on_message
    AFTER INSERT ON messages
    FOR EACH ROW EXECUTE FUNCTION sync_conversation_on_message();

COMMIT;