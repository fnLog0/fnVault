#!/usr/bin/env bash
# Optional: ad-hoc code-sign the fnVault binaries.
#
# fnVault works UNSIGNED — Touch ID goes through LocalAuthentication, which
# needs no entitlement. Ad-hoc signing just gives the binaries a stable code
# identity so the login Keychain's "Always Allow" decision sticks between runs.
#
# Do NOT add the keychain-access-groups entitlement here: it is a restricted
# entitlement and AMFI will SIGKILL an ad-hoc-signed binary that carries it.
set -euo pipefail

PROFILE="${1:-release}"
DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$DIR/target/$PROFILE"

for b in vaultd vault; do
    codesign --force --sign - "$BIN/$b"
    echo "signed $BIN/$b"
done
