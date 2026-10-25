-- =============================================================================
-- 02_rls_policies.sql
-- Row-Level Security (RLS) Policies & Entrypoint Lookup Functions
-- Enforces strict multi-tenant data isolation at the PostgreSQL engine layer.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- 1. SESSION CONTEXT HELPER FUNCTIONS
-- -----------------------------------------------------------------------------

-- Returns the UUID of the currently scoped Tenant set via:
-- SET LOCAL app.current_tenant_id = 'uuid';
CREATE OR REPLACE FUNCTION app_current_tenant_id()
RETURNS UUID AS $$
    SELECT NULLIF(current_setting('app.current_tenant_id', TRUE), '')::UUID;
$$ LANGUAGE SQL STABLE;

-- Returns the UUID of the currently scoped White-Label Agency set via:
-- SET LOCAL app.current_agency_id = 'uuid';
CREATE OR REPLACE FUNCTION app_current_agency_id()
RETURNS UUID AS $$
    SELECT NULLIF(current_setting('app.current_agency_id', TRUE), '')::UUID;
$$ LANGUAGE SQL STABLE;

-- -----------------------------------------------------------------------------
-- 2. ENABLE & FORCE ROW-LEVEL SECURITY ON ALL MULTI-TENANT TABLES
-- -----------------------------------------------------------------------------

ALTER TABLE agencies              ENABLE ROW LEVEL SECURITY;
ALTER TABLE agencies              FORCE ROW LEVEL SECURITY;

ALTER TABLE tenants               ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants               FORCE ROW LEVEL SECURITY;

ALTER TABLE users                 ENABLE ROW LEVEL SECURITY;
ALTER TABLE users                 FORCE ROW LEVEL SECURITY;

ALTER TABLE agents                ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents                FORCE ROW LEVEL SECURITY;

ALTER TABLE channel_connections   ENABLE ROW LEVEL SECURITY;
ALTER TABLE channel_connections   FORCE ROW LEVEL SECURITY;

ALTER TABLE knowledge_bases       ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge_bases       FORCE ROW LEVEL SECURITY;

ALTER TABLE rag_documents         ENABLE ROW LEVEL SECURITY;
ALTER TABLE rag_documents         FORCE ROW LEVEL SECURITY;

ALTER TABLE agent_knowledge_bases ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_knowledge_bases FORCE ROW LEVEL SECURITY;

ALTER TABLE mcp_servers           ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_servers           FORCE ROW LEVEL SECURITY;

ALTER TABLE agent_mcp_servers     ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_mcp_servers     FORCE ROW LEVEL SECURITY;

ALTER TABLE webhook_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_subscriptions FORCE ROW LEVEL SECURITY;

ALTER TABLE webhook_deliveries    ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_deliveries    FORCE ROW LEVEL SECURITY;

ALTER TABLE conversations         ENABLE ROW LEVEL SECURITY;
ALTER TABLE conversations         FORCE ROW LEVEL SECURITY;

ALTER TABLE messages              ENABLE ROW LEVEL SECURITY;
ALTER TABLE messages              FORCE ROW LEVEL SECURITY;

ALTER TABLE handoff_events        ENABLE ROW LEVEL SECURITY;
ALTER TABLE handoff_events        FORCE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- 3. AGENCY-SCOPED POLICIES (B2B Management Layer)
-- -----------------------------------------------------------------------------

CREATE POLICY rls_agencies_isolation ON agencies
    FOR ALL
    USING (id = app_current_agency_id())
    WITH CHECK (id = app_current_agency_id());

CREATE POLICY rls_tenants_isolation ON tenants
    FOR ALL
    USING (
        id = app_current_tenant_id()
        OR agency_id = app_current_agency_id()
    )
    WITH CHECK (
        id = app_current_tenant_id()
        OR agency_id = app_current_agency_id()
    );

CREATE POLICY rls_users_isolation ON users
    FOR ALL
    USING (
        (tenant_id IS NOT NULL AND tenant_id = app_current_tenant_id())
        OR agency_id = app_current_agency_id()
    )
    WITH CHECK (
        (tenant_id IS NOT NULL AND tenant_id = app_current_tenant_id())
        OR agency_id = app_current_agency_id()
    );

-- -----------------------------------------------------------------------------
-- 4. TENANT-SCOPED POLICIES (Strict Tenant Data Plane)
-- -----------------------------------------------------------------------------

CREATE POLICY rls_agents_tenant_isolation ON agents
    FOR ALL
    USING (tenant_id = app_current_tenant_id())
    WITH CHECK (tenant_id = app_current_tenant_id());

CREATE POLICY rls_channels_tenant_isolation ON channel_connections
    FOR ALL
    USING (tenant_id = app_current_tenant_id())
    WITH CHECK (tenant_id = app_current_tenant_id());

CREATE POLICY rls_kbs_tenant_isolation ON knowledge_bases
    FOR ALL
    USING (tenant_id = app_current_tenant_id())
    WITH CHECK (tenant_id = app_current_tenant_id());

CREATE POLICY rls_rag_docs_tenant_isolation ON rag_documents
    FOR ALL
    USING (tenant_id = app_current_tenant_id())
    WITH CHECK (tenant_id = app_current_tenant_id());

CREATE POLICY rls_agent_kbs_tenant_isolation ON agent_knowledge_bases
    FOR ALL
    USING (tenant_id = app_current_tenant_id())
    WITH CHECK (tenant_id = app_current_tenant_id());

CREATE POLICY rls_mcp_servers_tenant_isolation ON mcp_servers
    FOR ALL
    USING (tenant_id = app_current_tenant_id())
    WITH CHECK (tenant_id = app_current_tenant_id());

CREATE POLICY rls_agent_mcp_tenant_isolation ON agent_mcp_servers
    FOR ALL
    USING (tenant_id = app_current_tenant_id())
    WITH CHECK (tenant_id = app_current_tenant_id());

CREATE POLICY rls_webhook_subs_tenant_isolation ON webhook_subscriptions
    FOR ALL
    USING (tenant_id = app_current_tenant_id())
    WITH CHECK (tenant_id = app_current_tenant_id());

CREATE POLICY rls_webhook_deliveries_tenant_isolation ON webhook_deliveries
    FOR ALL
    USING (tenant_id = app_current_tenant_id())
    WITH CHECK (tenant_id = app_current_tenant_id());

CREATE POLICY rls_conversations_tenant_isolation ON conversations
    FOR ALL
    USING (tenant_id = app_current_tenant_id())
    WITH CHECK (tenant_id = app_current_tenant_id());

CREATE POLICY rls_messages_tenant_isolation ON messages
    FOR ALL
    USING (tenant_id = app_current_tenant_id())
    WITH CHECK (tenant_id = app_current_tenant_id());

CREATE POLICY rls_handoff_events_tenant_isolation ON handoff_events
    FOR ALL
    USING (tenant_id = app_current_tenant_id())
    WITH CHECK (tenant_id = app_current_tenant_id());

-- -----------------------------------------------------------------------------
-- 5. CONTROLLED PRE-RLS ENTRYPOINT FUNCTIONS (SECURITY DEFINER)
-- -----------------------------------------------------------------------------
-- Why these exist:
-- When an HTTP request arrives on a custom white-label domain OR when Meta/Telegram
-- delivers an inbound webhook, the Go backend does not know the tenant_id yet.
-- These tightly-scoped SECURITY DEFINER functions resolve ONLY the routing context
-- needed to initialize the RLS transaction safely.

-- 5.1 Resolve White-Label Agency branding by HTTP Host header
CREATE OR REPLACE FUNCTION resolve_agency_by_host(p_host TEXT)
RETURNS TABLE (
    agency_id       UUID,
    name            VARCHAR(120),
    slug            CITEXT,
    logo_url        TEXT,
    favicon_url     TEXT,
    primary_color   VARCHAR(7),
    secondary_color VARCHAR(7)
)
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    RETURN QUERY
    SELECT
        a.id,
        a.name,
        a.slug,
        a.logo_url,
        a.favicon_url,
        a.primary_color,
        a.secondary_color
    FROM agencies a
    WHERE a.custom_domain = p_host
      AND a.is_active = TRUE
    LIMIT 1;
END;
$$ LANGUAGE plpgsql STABLE;

-- 5.2 Resolve Tenant and Agent context from an inbound WhatsApp/Telegram Webhook
CREATE OR REPLACE FUNCTION resolve_inbound_channel_route(
    p_channel_type        TEXT,
    p_external_identifier VARCHAR(128)
)
RETURNS TABLE (
    channel_connection_id UUID,
    tenant_id             UUID,
    agent_id              UUID,
    encrypted_credentials BYTEA,
    webhook_verify_token  VARCHAR(128)
)
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    RETURN QUERY
    SELECT
        cc.id,
        cc.tenant_id,
        cc.agent_id,
        cc.encrypted_credentials,
        cc.webhook_verify_token
    FROM channel_connections cc
    INNER JOIN tenants t ON t.id = cc.tenant_id AND t.is_active = TRUE
    INNER JOIN agencies a ON a.id = t.agency_id AND a.is_active = TRUE
    WHERE cc.channel_type = p_channel_type
      AND cc.external_identifier = p_external_identifier
      AND cc.is_active = TRUE
    LIMIT 1;
END;
$$ LANGUAGE plpgsql STABLE;

-- 5.3 Resolve User credentials for Login on a specific White-Label Agency domain
CREATE OR REPLACE FUNCTION resolve_user_for_login(
    p_agency_id UUID,
    p_email     TEXT
)
RETURNS TABLE (
    user_id       UUID,
    agency_id     UUID,
    tenant_id     UUID,
    password_hash TEXT,
    full_name     VARCHAR(120),
    role          user_role_type,
    is_active     BOOLEAN
)
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    RETURN QUERY
    SELECT
        u.id,
        u.agency_id,
        u.tenant_id,
        u.password_hash,
        u.full_name,
        u.role,
        u.is_active
    FROM users u
    WHERE u.agency_id = p_agency_id
      AND u.email = p_email
    LIMIT 1;
END;
$$ LANGUAGE plpgsql STABLE;

-- -----------------------------------------------------------------------------
-- 6. GRANTS FOR APPLICATION RLS ROLE (app_tenant_user)
-- -----------------------------------------------------------------------------

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;

GRANT USAGE ON SCHEMA public TO app_tenant_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_tenant_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_tenant_user;

GRANT EXECUTE ON FUNCTION app_current_tenant_id() TO app_tenant_user;
GRANT EXECUTE ON FUNCTION app_current_agency_id() TO app_tenant_user;
GRANT EXECUTE ON FUNCTION set_updated_at() TO app_tenant_user;
GRANT EXECUTE ON FUNCTION resolve_agency_by_host(TEXT) TO app_tenant_user;
GRANT EXECUTE ON FUNCTION resolve_inbound_channel_route(TEXT, VARCHAR) TO app_tenant_user;
GRANT EXECUTE ON FUNCTION resolve_user_for_login(UUID, TEXT) TO app_tenant_user;

COMMIT;