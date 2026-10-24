#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# up.sh
# Brings the full stack up in dependency order:
#   1) data services (postgres, qdrant)
#   2) app (after both are healthy)
# -----------------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")"

./bootstrap.sh

podman-compose -p nexus-postgres -f compose.postgres.yml up -d
podman-compose -p nexus-qdrant   -f compose.qdrant.yml   up -d
podman-compose -p nexus-redis    -f compose.redis.yml    up -d

until podman healthcheck run ord_postgres >/dev/null 2>&1; do sleep 1; done
until podman healthcheck run ord_qdrant   >/dev/null 2>&1; do sleep 1; done
until podman healthcheck run ord_redis    >/dev/null 2>&1; do sleep 1; done

podman-compose -p nexus-ordinario -f compose.ordinario.yml up -d

echo "✅ Full stack is up"