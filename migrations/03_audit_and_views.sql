-- =============================================================================
-- 03_audit_and_views.sql
-- Universal Transaction Auditing & High-Performance Security-Invoker Views
-- Engine: PostgreSQL 16+
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- 1. EXTENDED SESSION CONTEXT HELPERS FOR AUDITING
-- -----------------------------------------------------------------------------

-- Returns the UUID of the authenticated user executing the transaction
CREATE OR REPLACE FUNCTION app_current_user_id()
RETURNS UUID AS $$
    SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::UUID;
$$ LANGUAGE SQL STABLE;

-- Returns the actor category: 'human_user', 'ai_orchestrator', 'webhook_ingest', 'system_job'
CREATE OR REPLACE FUNCTION app_current_actor_type()
RETURNS VARCHAR(30) AS $$
    SELECT COALESCE(NULLIF(current_setting('app.current_actor_type', TRUE), ''), 'system');
$$ LANGUAGE SQL STABLE;

-- Returns the HTTP/Webhook correlation request ID set by the Go middleware
CREATE OR REPLACE FUNCTION app_current_request_id()
RETURNS VARCHAR(64) AS $$
    SELECT NULLIF(current_setting('app.request_id', TRUE), '');
$$ LANGUAGE SQL STABLE;

-- Returns the client IP address set by the Go HTTP adapter
CREATE OR REPLACE FUNCTION app_current_client_ip()
RETURNS INET AS $$
    SELECT NULLIF(current_setting('app.client_ip', TRUE), '')::INET;
$$ LANGUAGE SQL STABLE;

-- -----------------------------------------------------------------------------
-- 2. IMMUTABLE AUDIT LOG TABLE
-- -----------------------------------------------------------------------------

CREATE TABLE audit_logs (
    id                  UUID NOT NULL DEFAULT gen_random_uuid(),
    -- Native PostgreSQL transaction ID (groups multiple table mutations in one atomic tx)
    transaction_id      XID8 NOT NULL DEFAULT pg_current_xact_id(),
    agency_id           UUID,
    tenant_id           UUID,
    actor_user_id       UUID,
    actor_type          VARCHAR(30) NOT NULL DEFAULT 'system',
    request_id          VARCHAR(64),
    client_ip           INET,
    table_name          VARCHAR(64) NOT NULL,
    operation           VARCHAR(10) NOT NULL CHECK (operation IN ('INSERT', 'UPDATE', 'DELETE')),
    -- Primary UUID when present, plus text representation for composite primary keys
    record_id           UUID,
    record_pk           TEXT NOT NULL,
    changed_fields      TEXT[] NOT NULL DEFAULT '{}',
    old_data            JSONB,
    new_data            JSONB,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Partition key must be part of every unique constraint on a partitioned table
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

-- Pre-create monthly partitions for the next 12 months starting from the
-- month in which this schema is initialized. Monthly granularity is the right
-- trade-off for audit volume (millions of rows/month per busy tenant), keeps
-- pruning useful (DROP/CONVERT on ~30 partitions/year), and matches the
-- typical retention policy (compliance windows of 12–24 months).

DO $$
DECLARE
    v_start DATE := date_trunc('month', CURRENT_DATE)::DATE;
    v_i     INT;
BEGIN
    FOR v_i IN 0..11 LOOP
        EXECUTE format(
            'CREATE TABLE %I PARTITION OF audit_logs FOR VALUES FROM (%L) TO (%L)',
            'audit_logs_' || to_char(v_start + (v_i || ' months')::INTERVAL, 'YYYYMM'),
            v_start + (v_i || ' months')::INTERVAL,
            v_start + ((v_i + 1) || ' months')::INTERVAL
        );
    END LOOP;
END $$;

-- Safety net: any row whose created_at falls outside the pre-created range
-- lands here instead of failing the INSERT. Operations must monitor this
-- partition's row count and split it off once it grows.
CREATE TABLE audit_logs_default PARTITION OF audit_logs DEFAULT;

-- Indexes for fast compliance queries, tenant activity feeds, and entity history
CREATE INDEX idx_audit_logs_tenant_created ON audit_logs(tenant_id, created_at DESC)
    WHERE tenant_id IS NOT NULL;
CREATE INDEX idx_audit_logs_agency_created ON audit_logs(agency_id, created_at DESC)
    WHERE agency_id IS NOT NULL;
CREATE INDEX idx_audit_logs_record_lookup  ON audit_logs(tenant_id, table_name, record_id, created_at DESC);
CREATE INDEX idx_audit_logs_tx_id          ON audit_logs(transaction_id);

-- Enforce strict RLS on audit_logs (Tenants and Agencies can only read their own logs)
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_audit_logs_select ON audit_logs
    FOR SELECT
    USING (
        (tenant_id IS NOT NULL AND tenant_id = app_current_tenant_id())
        OR (agency_id IS NOT NULL AND agency_id = app_current_agency_id())
    );

CREATE POLICY rls_audit_logs_insert ON audit_logs
    FOR INSERT
    WITH CHECK (current_setting('app.audit_internal', TRUE) = 'on');

-- Prevent any modification or deletion of audit records (Append-Only Enforcement)
CREATE OR REPLACE FUNCTION prevent_audit_log_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit logs are strictly immutable and cannot be modified or deleted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_logs_immutable
    BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_mutation();

-- -----------------------------------------------------------------------------
-- 3. GENERIC TRANSACTION AUDIT TRIGGER FUNCTION
-- -----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION process_audit_log()
RETURNS TRIGGER
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_old_json       JSONB := NULL;
    v_new_json       JSONB := NULL;
    v_ref_json       JSONB;
    v_record_id      UUID := NULL;
    v_record_pk      TEXT := '';
    v_tenant_id      UUID := NULL;
    v_agency_id      UUID := NULL;
    v_changed_fields TEXT[] := '{}';
    v_sensitive_keys CONSTANT TEXT[] := ARRAY[
        'password_hash',
        'encrypted_llm_api_key',
        'encrypted_credentials',
        'encrypted_auth_headers',
        'encrypted_secret',
        'webhook_verify_token'
    ];
    v_key            TEXT;
BEGIN
    -- 1. Convert row states to JSONB and redact sensitive cryptographic fields
    IF TG_OP IN ('UPDATE', 'DELETE') THEN
        v_old_json := to_jsonb(OLD);
        FOREACH v_key IN ARRAY v_sensitive_keys LOOP
            IF v_old_json ? v_key AND v_old_json -> v_key IS NOT NULL AND v_old_json ->> v_key <> '' THEN
                v_old_json := jsonb_set(v_old_json, ARRAY[v_key], '"[REDACTED]"'::jsonb);
            END IF;
        END LOOP;
    END IF;

    IF TG_OP IN ('INSERT', 'UPDATE') THEN
        v_new_json := to_jsonb(NEW);
        FOREACH v_key IN ARRAY v_sensitive_keys LOOP
            IF v_new_json ? v_key AND v_new_json -> v_key IS NOT NULL AND v_new_json ->> v_key <> '' THEN
                v_new_json := jsonb_set(v_new_json, ARRAY[v_key], '"[REDACTED]"'::jsonb);
            END IF;
        END LOOP;
    END IF;

    -- 2. For UPDATE, compute the exact list of modified columns
    IF TG_OP = 'UPDATE' THEN
        SELECT COALESCE(array_agg(n.key), '{}')
        INTO v_changed_fields
        FROM jsonb_each(v_new_json) AS n(key, value)
        WHERE n.key <> 'updated_at'
          AND (NOT (v_old_json ? n.key) OR v_old_json -> n.key IS DISTINCT FROM n.value);

        -- Skip writing noise if an UPDATE statement did not change any business value
        IF array_length(v_changed_fields, 1) IS NULL THEN
            RETURN NEW;
        END IF;

        -- Skip denormalization-only updates on conversations (fired by
        -- trg_update_conversation_on_message when a new message is inserted).
        -- The message itself is already audited by trg_audit_messages, and
        -- logging the derived conversation state change would just double
        -- the audit volume without adding forensic value.
        IF TG_TABLE_NAME = 'conversations'
           AND v_changed_fields <@ ARRAY[
                'last_message_at',
                'last_message_preview',
                'unread_count'
           ]::TEXT[]
        THEN
            RETURN NEW;
        END IF;
    END IF;

    -- 3. Extract routing identifiers (tenant_id, agency_id, primary key)

    -- 3. Extract routing identifiers (tenant_id, agency_id, primary key)
    v_ref_json := COALESCE(v_new_json, v_old_json);

    IF v_ref_json ? 'id' THEN
        v_record_id := (v_ref_json ->> 'id')::UUID;
        v_record_pk := v_ref_json ->> 'id';
    ELSIF v_ref_json ? 'agent_id' AND v_ref_json ? 'kb_id' THEN
        v_record_id := (v_ref_json ->> 'agent_id')::UUID;
        v_record_pk := (v_ref_json ->> 'agent_id') || ':' || (v_ref_json ->> 'kb_id');
    ELSIF v_ref_json ? 'agent_id' AND v_ref_json ? 'mcp_server_id' THEN
        v_record_id := (v_ref_json ->> 'agent_id')::UUID;
        v_record_pk := (v_ref_json ->> 'agent_id') || ':' || (v_ref_json ->> 'mcp_server_id');
    END IF;

    IF v_ref_json ? 'tenant_id' AND v_ref_json ->> 'tenant_id' IS NOT NULL THEN
        v_tenant_id := (v_ref_json ->> 'tenant_id')::UUID;
    ELSE
        v_tenant_id := app_current_tenant_id();
    END IF;

    IF v_ref_json ? 'agency_id' AND v_ref_json ->> 'agency_id' IS NOT NULL THEN
        v_agency_id := (v_ref_json ->> 'agency_id')::UUID;
    ELSIF TG_TABLE_NAME = 'agencies' AND v_record_id IS NOT NULL THEN
        v_agency_id := v_record_id;
    ELSE
        v_agency_id := app_current_agency_id();
    END IF;

     -- 4. Marca la sesión como escritor interno de auditoría (solo válida en esta tx)
    PERFORM set_config('app.audit_internal', 'on', TRUE);

    -- 4.1. Insert immutable audit entry
    INSERT INTO audit_logs (
        transaction_id,
        agency_id,
        tenant_id,
        actor_user_id,
        actor_type,
        request_id,
        client_ip,
        table_name,
        operation,
        record_id,
        record_pk,
        changed_fields,
        old_data,
        new_data
    ) VALUES (
        pg_current_xact_id(),
        v_agency_id,
        v_tenant_id,
        app_current_user_id(),
        app_current_actor_type(),
        app_current_request_id(),
        app_current_client_ip(),
        TG_TABLE_NAME,
        TG_OP,
        v_record_id,
        v_record_pk,
        v_changed_fields,
        v_old_json,
        v_new_json
    );

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Attach transaction audit triggers across all domain tables
CREATE TRIGGER trg_audit_agencies
    AFTER INSERT OR UPDATE OR DELETE ON agencies
    FOR EACH ROW EXECUTE FUNCTION process_audit_log();

CREATE TRIGGER trg_audit_tenants
    AFTER INSERT OR UPDATE OR DELETE ON tenants
    FOR EACH ROW EXECUTE FUNCTION process_audit_log();

CREATE TRIGGER trg_audit_users
    AFTER INSERT OR UPDATE OR DELETE ON users
    FOR EACH ROW EXECUTE FUNCTION process_audit_log();

CREATE TRIGGER trg_audit_agents
    AFTER INSERT OR UPDATE OR DELETE ON agents
    FOR EACH ROW EXECUTE FUNCTION process_audit_log();

CREATE TRIGGER trg_audit_channel_connections
    AFTER INSERT OR UPDATE OR DELETE ON channel_connections
    FOR EACH ROW EXECUTE FUNCTION process_audit_log();

CREATE TRIGGER trg_audit_knowledge_bases
    AFTER INSERT OR UPDATE OR DELETE ON knowledge_bases
    FOR EACH ROW EXECUTE FUNCTION process_audit_log();

CREATE TRIGGER trg_audit_rag_documents
    AFTER INSERT OR UPDATE OR DELETE ON rag_documents
    FOR EACH ROW EXECUTE FUNCTION process_audit_log();

CREATE TRIGGER trg_audit_agent_knowledge_bases
    AFTER INSERT OR UPDATE OR DELETE ON agent_knowledge_bases
    FOR EACH ROW EXECUTE FUNCTION process_audit_log();

CREATE TRIGGER trg_audit_mcp_servers
    AFTER INSERT OR UPDATE OR DELETE ON mcp_servers
    FOR EACH ROW EXECUTE FUNCTION process_audit_log();

CREATE TRIGGER trg_audit_agent_mcp_servers
    AFTER INSERT OR UPDATE OR DELETE ON agent_mcp_servers
    FOR EACH ROW EXECUTE FUNCTION process_audit_log();

CREATE TRIGGER trg_audit_webhook_subscriptions
    AFTER INSERT OR UPDATE OR DELETE ON webhook_subscriptions
    FOR EACH ROW EXECUTE FUNCTION process_audit_log();

CREATE TRIGGER trg_audit_conversations
    AFTER INSERT OR UPDATE OR DELETE ON conversations
    FOR EACH ROW EXECUTE FUNCTION process_audit_log();

CREATE TRIGGER trg_audit_messages
    AFTER INSERT OR UPDATE OR DELETE ON messages
    FOR EACH ROW EXECUTE FUNCTION process_audit_log();

CREATE TRIGGER trg_audit_handoff_events
    AFTER INSERT OR UPDATE OR DELETE ON handoff_events
    FOR EACH ROW EXECUTE FUNCTION process_audit_log();

-- =============================================================================
-- 4. HIGH-PERFORMANCE VIEWS (WITH security_invoker = true)
-- =============================================================================
-- All views use PostgreSQL 15/16 `security_invoker = true` so that underlying
-- Row-Level Security (RLS) policies are strictly enforced for `app_tenant_user`.

-- -----------------------------------------------------------------------------
-- 4.1 View: v_agent_runtime_bundle
-- Purpose: Fetches an Agent's complete execution context (LLM config + bound RAG
-- Knowledge Bases + bound MCP Servers + active Webhook event names) in a SINGLE
-- database roundtrip for the AI Orchestrator.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_agent_runtime_bundle
WITH (security_invoker = true)
AS
SELECT
    a.id AS agent_id,
    a.tenant_id,
    a.name AS agent_name,
    a.system_prompt,
    a.llm_provider,
    a.llm_model,
    a.encrypted_llm_api_key,
    a.temperature,
    a.max_tokens,
    a.debounce_window_ms,
    a.auto_handoff_enabled,
    a.is_active,
    -- Pre-aggregated JSON array of attached Knowledge Bases ordered by priority
    COALESCE(
        (
            SELECT jsonb_agg(
                jsonb_build_object(
                    'kb_id', kb.id,
                    'name', kb.name,
                    'qdrant_collection', kb.qdrant_collection,
                    'embedding_provider', kb.embedding_provider,
                    'embedding_model', kb.embedding_model,
                    'top_k', kb.top_k,
                    'score_threshold', kb.score_threshold,
                    'priority', akb.priority
                ) ORDER BY akb.priority ASC
            )
            FROM agent_knowledge_bases akb
            INNER JOIN knowledge_bases kb
                ON kb.id = akb.kb_id AND kb.tenant_id = akb.tenant_id
            WHERE akb.agent_id = a.id
              AND akb.tenant_id = a.tenant_id
        ),
        '[]'::jsonb
    ) AS knowledge_bases,
    -- Pre-aggregated JSON array of active MCP Servers and tool whitelists
    COALESCE(
        (
            SELECT jsonb_agg(
                jsonb_build_object(
                    'mcp_server_id', ms.id,
                    'name', ms.name,
                    'transport', ms.transport,
                    'endpoint_url', ms.endpoint_url,
                    'timeout_ms', ms.timeout_ms,
                    'allowed_tools', ams.allowed_tools,
                    'cached_tools_schema', ms.cached_tools_schema
                )
            )
            FROM agent_mcp_servers ams
            INNER JOIN mcp_servers ms
                ON ms.id = ams.mcp_server_id AND ms.tenant_id = ams.tenant_id
            WHERE ams.agent_id = a.id
              AND ams.tenant_id = a.tenant_id
              AND ms.is_active = TRUE
        ),
        '[]'::jsonb
    ) AS mcp_servers,
    -- Distinct list of outbound webhook events active for this agent or tenant
    COALESCE(
        (
            SELECT array_agg(DISTINCT ev)
            FROM webhook_subscriptions ws
            CROSS JOIN LATERAL unnest(ws.subscribed_events) AS ev
            WHERE ws.tenant_id = a.tenant_id
              AND ws.is_active = TRUE
              AND (ws.agent_id IS NULL OR ws.agent_id = a.id)
        ),
        '{}'::TEXT[]
    ) AS active_webhook_events
FROM agents a;

-- -----------------------------------------------------------------------------
-- 4.2 View: v_htmx_live_inbox
-- Purpose: Powers the HTMX Live Chat Inbox and Human Takeover header without
-- executing N+1 queries for channel badges, agent names, or human operators.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_htmx_live_inbox
WITH (security_invoker = true)
AS
SELECT
    c.id AS conversation_id,
    c.tenant_id,
    c.contact_external_id,
    COALESCE(NULLIF(c.contact_name, ''), c.contact_external_id) AS contact_display_name,
    c.contact_avatar_url,
    c.control_mode,
    c.unread_count,
    c.last_message_preview,
    c.last_message_at,
    c.paused_at,
    c.pause_reason,
    -- Agent summary
    a.id AS agent_id,
    a.name AS agent_name,
    -- Channel summary
    cc.id AS channel_connection_id,
    cc.channel_type,
    cc.display_name AS channel_display_name,
    -- Assigned human operator (if any)
    u_assigned.id AS assigned_user_id,
    u_assigned.full_name AS assigned_user_name,
    u_assigned.email AS assigned_user_email,
    -- Operator who triggered the AI pause (if any)
    u_paused.id AS paused_by_user_id,
    u_paused.full_name AS paused_by_user_name
FROM conversations c
INNER JOIN agents a
    ON a.id = c.agent_id AND a.tenant_id = c.tenant_id
INNER JOIN channel_connections cc
    ON cc.id = c.channel_connection_id AND cc.tenant_id = c.tenant_id
LEFT JOIN users u_assigned
    ON u_assigned.id = c.assigned_user_id AND u_assigned.tenant_id = c.tenant_id
LEFT JOIN users u_paused
    ON u_paused.id = c.paused_by_user_id AND u_paused.tenant_id = c.tenant_id;

-- -----------------------------------------------------------------------------
-- 4.3 View: v_knowledge_base_summary
-- Purpose: Single-query view for the HTMX RAG management page showing document
-- ingestion counters, vector chunk totals, and whether the KB is shared or individual.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_knowledge_base_summary
WITH (security_invoker = true)
AS
SELECT
    kb.id AS kb_id,
    kb.tenant_id,
    kb.name,
    kb.description,
    kb.qdrant_collection,
    kb.embedding_provider,
    kb.embedding_model,
    kb.chunk_size,
    kb.chunk_overlap,
    kb.top_k,
    kb.score_threshold,
    kb.created_at,
    kb.updated_at,
    COUNT(DISTINCT rd.id) AS total_documents,
    COUNT(DISTINCT rd.id) FILTER (WHERE rd.status = 'indexed') AS indexed_documents,
    COUNT(DISTINCT rd.id) FILTER (WHERE rd.status IN ('pending', 'chunking')) AS processing_documents,
    COUNT(DISTINCT rd.id) FILTER (WHERE rd.status = 'failed') AS failed_documents,
    COALESCE(SUM(rd.chunk_count) FILTER (WHERE rd.status = 'indexed'), 0) AS total_indexed_chunks,
    COUNT(DISTINCT akb.agent_id) AS connected_agents_count,
    (COUNT(DISTINCT akb.agent_id) > 1) AS is_shared_across_agents,
    COALESCE(
        array_agg(DISTINCT a.name) FILTER (WHERE a.name IS NOT NULL),
        '{}'::VARCHAR[]
    ) AS connected_agent_names
FROM knowledge_bases kb
LEFT JOIN rag_documents rd
    ON rd.kb_id = kb.id AND rd.tenant_id = kb.tenant_id
LEFT JOIN agent_knowledge_bases akb
    ON akb.kb_id = kb.id AND akb.tenant_id = kb.tenant_id
LEFT JOIN agents a
    ON a.id = akb.agent_id AND a.tenant_id = kb.tenant_id
GROUP BY kb.id;

-- -----------------------------------------------------------------------------
-- 4.4 View: v_tenant_dashboard_stats
-- Purpose: Instant KPI counters for the Tenant HTMX home dashboard in 1 query.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_tenant_dashboard_stats
WITH (security_invoker = true)
AS
SELECT
    t.id AS tenant_id,
    t.name AS tenant_name,
    t.quota_max_agents,
    t.quota_max_kbs,
    (SELECT COUNT(*) FROM agents a WHERE a.tenant_id = t.id AND a.is_active = TRUE) AS active_agents_count,
    (SELECT COUNT(*) FROM channel_connections cc WHERE cc.tenant_id = t.id AND cc.is_active = TRUE) AS active_channels_count,
    (SELECT COUNT(*) FROM knowledge_bases kb WHERE kb.tenant_id = t.id) AS knowledge_bases_count,
    (SELECT COUNT(*) FROM mcp_servers ms WHERE ms.tenant_id = t.id AND ms.is_active = TRUE) AS active_mcp_servers_count,
    (SELECT COUNT(*) FROM conversations c WHERE c.tenant_id = t.id AND c.control_mode = 'ai_active') AS ai_active_conversations,
    (SELECT COUNT(*) FROM conversations c WHERE c.tenant_id = t.id AND c.control_mode = 'human_takeover') AS human_takeover_conversations,
    (SELECT COALESCE(SUM(c.unread_count), 0) FROM conversations c WHERE c.tenant_id = t.id) AS total_unread_messages,
    (
        SELECT COUNT(*)
        FROM messages m
        WHERE m.tenant_id = t.id
          AND m.created_at >= NOW() - INTERVAL '24 hours'
    ) AS messages_last_24h
FROM tenants t;

-- -----------------------------------------------------------------------------
-- 4.5 View: v_agency_tenants_overview
-- Purpose: B2B White-Label Agency console view to monitor all client tenants,
-- their quota utilization, and operational activity in a single query.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_agency_tenants_overview
WITH (security_invoker = true)
AS
SELECT
    t.id AS tenant_id,
    t.agency_id,
    t.name AS tenant_name,
    t.slug AS tenant_slug,
    t.is_active,
    t.quota_max_agents,
    t.quota_max_kbs,
    t.created_at,
    (SELECT COUNT(*) FROM users u WHERE u.tenant_id = t.id AND u.is_active = TRUE) AS active_users_count,
    (SELECT COUNT(*) FROM agents a WHERE a.tenant_id = t.id) AS agents_used,
    (SELECT COUNT(*) FROM knowledge_bases kb WHERE kb.tenant_id = t.id) AS kbs_used,
    (SELECT COUNT(*) FROM channel_connections cc WHERE cc.tenant_id = t.id AND cc.is_active = TRUE) AS active_channels_count,
    (SELECT COUNT(*) FROM conversations c WHERE c.tenant_id = t.id) AS total_conversations
FROM tenants t;

-- -----------------------------------------------------------------------------
-- 5. GRANTS FOR APPLICATION RLS ROLE (app_tenant_user)
-- -----------------------------------------------------------------------------

-- Audit logs: SELECT only. INSERT is performed exclusively by the
-- SECURITY DEFINER trigger process_audit_log(), which marks the session
-- with app.audit_internal = 'on' before writing.
GRANT SELECT ON audit_logs TO app_tenant_user;

-- Grant read access on all performance views
GRANT SELECT ON v_agent_runtime_bundle    TO app_tenant_user;
GRANT SELECT ON v_htmx_live_inbox         TO app_tenant_user;
GRANT SELECT ON v_knowledge_base_summary  TO app_tenant_user;
GRANT SELECT ON v_tenant_dashboard_stats  TO app_tenant_user;
GRANT SELECT ON v_agency_tenants_overview TO app_tenant_user;

-- Grant execution on audit session context functions
GRANT EXECUTE ON FUNCTION app_current_user_id()    TO app_tenant_user;
GRANT EXECUTE ON FUNCTION app_current_actor_type() TO app_tenant_user;
GRANT EXECUTE ON FUNCTION app_current_request_id() TO app_tenant_user;
GRANT EXECUTE ON FUNCTION app_current_client_ip()  TO app_tenant_user;

COMMIT;