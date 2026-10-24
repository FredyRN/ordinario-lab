#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# bootstrap.sh
# Creates shared resources (networks + secrets) exactly once, idempotently.
# Must run before up.sh. Safe to re-run.
# -----------------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")"

# Internal network: no NAT, no gateway → services cannot reach the Internet
# and cannot be reached from the host. Only containers attached to it can talk.
podman network exists nexus_coffee 2>/dev/null || \
  podman network create --internal nexus_coffee

# Public network: plain bridge with NAT.
# Required for publishing the app's port to the host.
podman network exists nexus_public 2>/dev/null || \
  podman network create nexus_public

# Secret: PostgreSQL superuser/app password
if ! podman secret exists pg_password >/dev/null 2>&1; then
  read -rs -p "DB password: " DB_PASSWORD; echo
  printf '%s' "$DB_PASSWORD" | podman secret create pg_password -
  unset DB_PASSWORD
fi

# Secret: Qdrant API Key
if ! podman secret exists qdrant_api_key >/dev/null 2>&1; then
  read -rs -p "Qdrant API Key: " QDRANT_API_KEY; echo
  printf '%s' "$QDRANT_API_KEY" | podman secret create qdrant_api_key -
  unset QDRANT_API_KEY
fi

# Secret: Redis password
if ! podman secret exists redis_password >/dev/null 2>&1; then
  read -rs -p "Redis password: " REDIS_PASSWORD; echo
  printf '%s' "$REDIS_PASSWORD" | podman secret create redis_password -
  unset REDIS_PASSWORD
fi

echo "✅ Networks and secrets are ready"