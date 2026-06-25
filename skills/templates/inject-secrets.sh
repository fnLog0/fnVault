#!/usr/bin/env bash
# Wrap a command with secrets injected from fnVault as environment variables.
# No plaintext is written to disk and nothing is echoed to the terminal.
#
# Usage:
#   ./inject-secrets.sh -- gh repo list
#   ./inject-secrets.sh GH_TOKEN=github-token OPENAI_API_KEY=openai-key -- ./deploy.sh
#
# Each VAR=secret-name pair before `--` is fetched with `vault get` and exported
# only into the wrapped command's environment.
set -euo pipefail

pairs=()
while [[ $# -gt 0 && "$1" != "--" ]]; do
  pairs+=("$1")
  shift
done
[[ "${1:-}" == "--" ]] && shift || { echo "usage: $0 VAR=secret ... -- command [args]" >&2; exit 1; }
[[ $# -gt 0 ]] || { echo "no command given after --" >&2; exit 1; }

# Default to a single pair if none supplied: GH_TOKEN=github-token
[[ ${#pairs[@]} -gt 0 ]] || pairs=("GH_TOKEN=github-token")

args=()
for pair in "${pairs[@]}"; do
  args+=(-e "$pair")
done

exec vault run "${args[@]}" -- "$@"
