#!/usr/bin/env bash
# Flag fnVault secrets whose `--expires` date has passed or is near.
# Reads `vault list` output (names, tags, "expires YYYY-MM-DD") — no unlock needed.
#
# Usage:
#   ./rotate-check.sh           # warn on anything expiring within 14 days
#   ./rotate-check.sh 30        # ... within 30 days
set -euo pipefail

window_days="${1:-14}"
now=$(date +%s)
soon=$(( now + window_days * 86400 ))
status=0

vault list | while IFS= read -r line; do
  # Lines look like: "name  [tag]  expires 2026-12-31"
  exp=$(printf '%s\n' "$line" | sed -n 's/.*expires \([0-9-]\{10\}\).*/\1/p')
  [[ -n "$exp" ]] || continue
  name=${line%% *}
  exp_secs=$(date -j -f "%Y-%m-%d" "$exp" +%s 2>/dev/null || date -d "$exp" +%s 2>/dev/null || echo 0)
  [[ "$exp_secs" != 0 ]] || continue
  if (( exp_secs < now )); then
    echo "EXPIRED  $name (was $exp)"
    status=1
  elif (( exp_secs < soon )); then
    echo "SOON     $name (expires $exp)"
    status=1
  fi
done

exit $status
