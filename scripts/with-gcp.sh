#!/usr/bin/env bash
# Run a command with GOOGLE_APPLICATION_CREDENTIALS materialized from fnVault.
#
# GCP tooling wants a *path* to the service-account JSON, so we write it to a
# private temp file for the duration of the command and delete it afterwards.
#
# Usage:
#   ./scripts/with-gcp.sh gcp-sa-key -- gcloud storage ls
#   ./scripts/with-gcp.sh gcp-sa-key -- terraform apply
set -euo pipefail
NAME="${1:?usage: with-gcp.sh <vault-secret-name> -- <command...>}"; shift
[[ "${1:-}" == "--" ]] && shift
[[ $# -gt 0 ]] || { echo "no command given after --" >&2; exit 2; }

TMP="$(mktemp)"; chmod 600 "$TMP"
trap 'rm -f "$TMP"' EXIT
vault get "$NAME" > "$TMP"
GOOGLE_APPLICATION_CREDENTIALS="$TMP" "$@"
