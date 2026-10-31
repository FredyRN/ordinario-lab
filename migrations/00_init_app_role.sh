#!/usr/bin/env sh
# -----------------------------------------------------------------------------
# 00_init_app_role.sh
# Initializes the restricted PostgreSQL application role (app_tenant_user)
# using the Podman secret mounted at /run/secrets/pg_app_password.
# This role does NOT have BYPASSRLS or SUPERUSER privileges.
# -----------------------------------------------------------------------------
set -eu

APP_DB_USER="${DB_APP_USER:-app_tenant_user}"
SECRET_FILE="/run/secrets/pg_app_password"

if [ -f "$SECRET_FILE" ]; then
    APP_DB_PASS="$(cat "$SECRET_FILE")"
else
    echo "WARN: $SECRET_FILE not found. Falling back to development password."
    APP_DB_PASS="dev_only_rls_password_change_me"
fi

psql -v ON_ERROR_STOP=1 \
     -v app_user="$APP_DB_USER" \
     -v app_pass="$APP_DB_PASS" \
     --username "$POSTGRES_USER" \
     --dbname "$POSTGRES_DB" <<-'EOSQL'
    SELECT
        set_config('init.app_user', :'app_user', false),
        set_config('init.app_pass', :'app_pass', false);

    DO $$
    DECLARE
        v_user TEXT := current_setting('init.app_user');
        v_pass TEXT := current_setting('init.app_pass');
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = v_user) THEN
            EXECUTE format(
                'CREATE ROLE %I WITH LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD %L',
                v_user,
                v_pass
            );
        ELSE
            EXECUTE format(
                'ALTER ROLE %I WITH PASSWORD %L',
                v_user,
                v_pass
            );
        END IF;
    END
    $$;

    RESET init.app_user;
    RESET init.app_pass;
EOSQL

echo "✅ Application RLS role '${APP_DB_USER}' initialized."