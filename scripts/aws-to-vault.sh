#!/usr/bin/env bash
# Migrate AWS credentials (in ~/.aws/credentials format) into fnVault.
#
# Each profile is stored as one secret named `aws-<profile>` holding the JSON
# that the AWS CLI's `credential_process` expects, so the CLI keeps working
# unchanged while the keys live behind Touch ID.
#
# Usage:
#   ./scripts/aws-to-vault.sh [--dry-run | --apply] [SOURCE_FILE]
#
#   --dry-run     parse and show the plan; do not call vault or write anything
#   --apply       store secrets AND edit ~/.aws/{config,credentials} for you,
#                 with a timestamped backup and automatic rollback if
#                 `aws sts get-caller-identity` fails afterwards
#   (default)     store secrets and PRINT the ~/.aws/config block to add by hand
#   SOURCE_FILE   credentials file to read (default: ~/.aws/credentials, or
#                 $AWS_SHARED_CREDENTIALS_FILE if set)
#
# Safe testing against temp files (no risk to real ~/.aws):
#   cp .fnaws /tmp/test-cred; rm -f /tmp/test-config
#   AWS_SHARED_CREDENTIALS_FILE=/tmp/test-cred AWS_CONFIG_FILE=/tmp/test-config \
#     ./scripts/aws-to-vault.sh --apply /tmp/test-cred
set -euo pipefail

MODE="print"   # print | dry | apply
CRED_FILE="${AWS_SHARED_CREDENTIALS_FILE:-$HOME/.aws/credentials}"
CONFIG_FILE="${AWS_CONFIG_FILE:-$HOME/.aws/config}"
SRC="$CRED_FILE"

for arg in "$@"; do
    case "$arg" in
        --dry-run) MODE="dry" ;;
        --apply)   MODE="apply" ;;
        -*) echo "unknown option: $arg" >&2; exit 2 ;;
        *) SRC="$arg" ;;
    esac
done

[[ -f "$SRC" ]] || { echo "source file not found: $SRC" >&2; exit 1; }

VAULT_BIN="$(command -v vault || true)"
if [[ -z "$VAULT_BIN" && "$MODE" != "dry" ]]; then
    echo "vault not found on PATH (build/install it, or use --dry-run)" >&2
    exit 1
fi

# Apply edits the file it read from; guard against stripping a different file.
if [[ "$MODE" == "apply" && "$SRC" != "$CRED_FILE" ]]; then
    echo "refusing --apply: SOURCE_FILE ($SRC) is not the credentials file being" >&2
    echo "edited ($CRED_FILE). Point them at the same file (or set" >&2
    echo "AWS_SHARED_CREDENTIALS_FILE) so we only strip what we read." >&2
    exit 2
fi

trim() { local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; s="${s%"${s##*[![:space:]]}"}"; printf '%s' "$s"; }
mask() { local s="$1"; local n=${#s}; if (( n <= 6 )); then printf '****'; else printf '%s…%s' "${s:0:4}" "${s: -2}"; fi; }

declare -a CONFIG_LINES=()
declare -a MIGRATED=()
section=""; akid=""; secret=""; token=""

flush() {
    [[ -z "$section" ]] && return 0
    if [[ -z "$akid" || -z "$secret" ]]; then
        echo "  ! skipping [$section]: missing access key id or secret" >&2
        section=""; akid=""; secret=""; token=""
        return 0
    fi
    local name="aws-$section" json
    if [[ -n "$token" ]]; then
        json=$(printf '{"Version":1,"AccessKeyId":"%s","SecretAccessKey":"%s","SessionToken":"%s"}' "$akid" "$secret" "$token")
    else
        json=$(printf '{"Version":1,"AccessKeyId":"%s","SecretAccessKey":"%s"}' "$akid" "$secret")
    fi

    if [[ "$MODE" == "dry" ]]; then
        printf '  would store %-16s AccessKeyId=%s SecretAccessKey=%s%s\n' \
            "$name" "$(mask "$akid")" "$(mask "$secret")" \
            "$([[ -n "$token" ]] && printf ' (+SessionToken)')"
    else
        printf '%s' "$json" | "$VAULT_BIN" set "$name" --tag aws --stdin
        echo "  stored $name"
    fi

    MIGRATED+=("$section")
    if [[ "$section" == "default" ]]; then
        CONFIG_LINES+=("[default]")
    else
        CONFIG_LINES+=("[profile $section]")
    fi
    CONFIG_LINES+=("credential_process = ${VAULT_BIN:-vault} get $name")
    CONFIG_LINES+=("")
    section=""; akid=""; secret=""; token=""
}

while IFS= read -r line || [[ -n "$line" ]]; do
    line="$(trim "$line")"
    [[ -z "$line" || "$line" == \#* || "$line" == \;* ]] && continue
    if [[ "$line" == \[*\] ]]; then
        flush
        section="$(trim "${line#\[}")"; section="$(trim "${section%\]}")"
        section="${section#profile }"
        continue
    fi
    key="$(trim "${line%%=*}")"
    val="$(trim "${line#*=}")"
    case "$key" in
        aws_access_key_id)     akid="$val" ;;
        aws_secret_access_key) secret="$val" ;;
        aws_session_token)     token="$val" ;;
    esac
done < "$SRC"
flush

if (( ${#MIGRATED[@]} == 0 )); then
    echo "no usable profiles found in $SRC" >&2
    exit 1
fi

# ---- print mode: just show the config to add by hand --------------------
if [[ "$MODE" != "apply" ]]; then
    echo
    echo "Add these to ~/.aws/config, and DELETE the matching [profile] sections"
    echo "from ~/.aws/credentials (static keys there override credential_process):"
    echo "--------------------------------------------------------------------"
    printf '%s\n' "${CONFIG_LINES[@]}"
    echo "--------------------------------------------------------------------"
    exit 0
fi

# ---- apply mode: edit files with backup + verify + rollback -------------
TS="$(date +%Y%m%d-%H%M%S)"
CRED_BAK="$CRED_FILE.fnvault-bak-$TS"
CONFIG_BAK="$CONFIG_FILE.fnvault-bak-$TS"
CONFIG_EXISTED=0; [[ -f "$CONFIG_FILE" ]] && CONFIG_EXISTED=1

echo
echo "Backing up:"
cp "$CRED_FILE" "$CRED_BAK"; echo "  $CRED_BAK"
if (( CONFIG_EXISTED )); then cp "$CONFIG_FILE" "$CONFIG_BAK"; echo "  $CONFIG_BAK"; fi

ROLLED_BACK=0
rollback() {
    (( ROLLED_BACK )) && return 0
    ROLLED_BACK=1
    echo "ROLLBACK: restoring AWS files" >&2
    cp "$CRED_BAK" "$CRED_FILE"
    if (( CONFIG_EXISTED )); then cp "$CONFIG_BAK" "$CONFIG_FILE"; else rm -f "$CONFIG_FILE"; fi
}
# Any unexpected failure after this point restores the original files.
trap rollback ERR

echo "Writing credential_process into $CONFIG_FILE"
for p in "${MIGRATED[@]}"; do
    if [[ "$p" == "default" ]]; then
        aws configure set credential_process "$VAULT_BIN get aws-default"
    else
        aws configure set credential_process "$VAULT_BIN get aws-$p" --profile "$p"
    fi
done

echo "Stripping static keys from $CRED_FILE"
migs=",$(IFS=,; printf '%s' "${MIGRATED[*]}"),"
awk -v migs="$migs" '
    /^[ \t]*\[/ { sec=$0; gsub(/[][ \t]/,"",sec); sub(/^profile/,"",sec);
                  inmig=(index(migs, ","sec",")>0); print; next }
    inmig && /^[ \t]*aws_access_key_id[ \t]*=/     { next }
    inmig && /^[ \t]*aws_secret_access_key[ \t]*=/ { next }
    inmig && /^[ \t]*aws_session_token[ \t]*=/     { next }
    { print }
' "$CRED_FILE" > "$CRED_FILE.tmp" && mv "$CRED_FILE.tmp" "$CRED_FILE"

# Verify with the default profile if present, else the first migrated one.
# (bash 3.2 + set -u needs the ${arr[@]+...} guard for empty arrays.)
verify_args=()
verify_desc="default profile"
if ! printf '%s\n' "${MIGRATED[@]}" | grep -qx default; then
    verify_args=(--profile "${MIGRATED[0]}")
    verify_desc="profile ${MIGRATED[0]}"
fi
echo "Verifying: aws sts get-caller-identity ($verify_desc)"
trap - ERR   # handle verification failure explicitly below, not via the trap
if aws sts get-caller-identity ${verify_args[@]+"${verify_args[@]}"} >/tmp/fnv_sts.out 2>&1; then
    echo "✅ verification passed:"
    cat /tmp/fnv_sts.out
    echo
    echo "Migration complete. Backups kept:"
    echo "  $CRED_BAK"
    (( CONFIG_EXISTED )) && echo "  $CONFIG_BAK"
    echo "Delete them once you are confident."
else
    echo "❌ verification failed:" >&2
    cat /tmp/fnv_sts.out >&2
    rollback
    echo "Rolled back ~/.aws to its previous state." >&2
    echo "Vault secrets were still created; remove with: ${MIGRATED[*]/#/vault rm aws-}" >&2
    exit 1
fi
