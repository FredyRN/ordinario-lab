#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# bootstrap.sh
# Creates shared resources (networks + secret) exactly once, idempotently.
# Must run before up.sh. Safe to re-run.
#
# Requires Podman >= 4.5 for `network exists` / `secret exists`.
# On older versions, replace with `podman network ls --format '{{.Name}}'`.
# -----------------------------------------------------------------------------
set -euo pipefail

# Internal network: no NAT, no gateway → services cannot reach the Internet
# and cannot be reached from the host. Only containers attached to it can talk.
podman network exists nexus_coffee 2>/dev/null || \
  podman network create --internal nexus_coffee

# Public network: plain bridge with NAT.
# Required for publishing the app's port to the host.
podman network exists nexus_public 2>/dev/null || \
  podman network create nexus_public

# Secret: read without echoing, never write it to shell history.
if ! podman secret exists pg_password >/dev/null 2>&1; then
  read -rs -p "DB password: " DB_PASSWORD; echo
  printf '%s' "$DB_PASSWORD" | podman secret create pg_password -
  unset DB_PASSWORD
fi

echo "✅ Networks and secret are ready"