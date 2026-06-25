#!/usr/bin/env bash
# kubectl exec credential plugin backed by fnVault.
#
# Add to your kubeconfig:
#   users:
#   - name: my-user
#     user:
#       exec:
#         apiVersion: client.authentication.k8s.io/v1
#         command: /absolute/path/to/k8s-credential.sh
#         args: ["my-k8s-token"]     # name of the secret stored in fnVault
#
# kubectl runs this on each call; fnVault stays unlocked for the session, so it
# only prompts Touch ID the first time.
set -euo pipefail
NAME="${1:?usage: k8s-credential.sh <vault-secret-name>}"
TOKEN="$(vault get "$NAME")"
printf '{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":"%s"}}\n' "$TOKEN"
