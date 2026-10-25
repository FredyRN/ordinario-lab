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

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    DO \$\$
    BEGIN
        IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '${APP_DB_USER}') THEN
            CREATE ROLE ${APP_DB_USER} WITH
                LOGIN
                NOINHERIT
                NOSUPERUSER
                NOCREATEDB
                NOCREATEROLE
                NOBYPASSRLS
                PASSWORD '${APP_DB_PASS}';
        ELSE
            ALTER ROLE ${APP_DB_USER} WITH PASSWORD '${APP_DB_PASS}';
        END IF;
    END
    \$\$;
EOSQL

echo "✅ Application RLS role '${APP_DB_USER}' initialized."