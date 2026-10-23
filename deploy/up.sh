#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# up.sh
# Brings the full stack up in dependency order:
#   1) data services (postgres, qdrant)
#   2) app (after both are healthy) — compose.ordinario.yml
#
# Each service uses its OWN project name (`-p`) so that `down` on one stack
# does not tear down the others. Without `-p`, podman-compose groups all
# containers under the directory name and cross-stack `down` becomes unsafe.
# -----------------------------------------------------------------------------
set -euo pipefail

./bootstrap.sh

podman-compose -p nexus-postgres -f compose.postgres.yml up -d
podman-compose -p nexus-qdrant   -f compose.qdrant.yml   up -d

# Block until data services pass their healthchecks.
# Note: podman-compose's `depends_on` cannot express "wait for healthy",
# so we enforce it here explicitly.
until podman healthcheck run wl_postgres >/dev/null 2>&1; do sleep 1; done
until podman healthcheck run wl_qdrant   >/dev/null 2>&1; do sleep 1; done

podman-compose -p nexus-app -f compose.ordinario.yml up -d

echo "✅ Full stack is up"