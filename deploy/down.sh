#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# down.sh
# Tears down in reverse dependency order: app → data services.
# Volumes are preserved. To wipe a service's data:
#   podman-compose -p nexus-postgres -f compose.postgres.yml down -v
# -----------------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")"

podman-compose -p nexus-ordinario -f compose.ordinario.yml down
podman-compose -p nexus-redis     -f compose.redis.yml     down
podman-compose -p nexus-qdrant    -f compose.qdrant.yml    down
podman-compose -p nexus-postgres  -f compose.postgres.yml  down