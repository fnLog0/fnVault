# fnVault

A Touch ID-gated credential vault for macOS, as a Rust CLI + TUI.

Unlock once with your fingerprint and the vault stays open for the session — you
or an AI agent can then read secrets via plain commands with no further prompts,
until you lock it or the idle-timeout backstop fires.

```
  you / Claude
       │  vault get github-token
       ▼
   vault (CLI / TUI) ──unix socket──► vaultd (daemon, holds the session)
                                          │ master key cached in RAM, zeroized on lock
                                          ▼
                                   macOS login Keychain (encrypted secrets)
                                          ▲
                                   Touch ID  ── LocalAuthentication (once per session)
```

## Components

| Binary    | Role |
|-----------|------|
| `vaultd`  | Background daemon. Holds the unlocked master key for the session, enforces the idle timeout, serves a per-user Unix socket. Auto-spawned on demand. |
| `vault`   | CLI client and TUI dashboard. |

## Build

```sh
cargo build --release
# optional: stable code identity so the Keychain "Always Allow" sticks
./sign.sh release
```

Binaries land in `target/release/`. Put them on your `PATH` (keep `vault` and
`vaultd` in the same directory so the CLI can auto-spawn the daemon):

```sh
cp target/release/vault target/release/vaultd /usr/local/bin/
```

## Usage

```sh
vault init                 # one-time: create the master key
vault set github-token     # prompts (hidden) for the value
echo "$TOKEN" | vault set openai-key --tag api --stdin
vault get github-token     # Touch ID prompt (first time this session), prints the value
vault list                 # names + tags, no unlock needed
vault status               # session state + idle countdown
vault lock                 # relock now
vault                      # launch the TUI dashboard
```

For scripts / agents:

```sh
export OPENAI_API_KEY="$(vault get openai-key)"
```

Exit codes: `0` ok · `2` locked/auth-failed · `3` not found · `4` daemon unreachable.

### Idle-timeout backstop

After one unlock the vault stays open until it is idle for `FNVAULT_IDLE_SECS`
(default **900** = 15 min), then it relocks and zeroizes the key. Set to `0` to
disable (not recommended).

```sh
FNVAULT_IDLE_SECS=300 vaultd   # or set in your launch agent's environment
```

`vault status` shows the live countdown; so does the TUI header.

## TUI

Run `vault` (no args) or `vault ui`:

- left pane: searchable list of secret names + tags
- right pane: details; value masked until you reveal it
- header: lock state + idle relock countdown

Keys: `↑↓/jk` move · `/` search · `⏎`/`r` reveal · `c` copy · `a` add · `e` edit
· `d` delete · `L` lock · `?` help · `q` quit. When locked, `⏎` unlocks with
Touch ID.

## Using fnVault with other tools

The vault holds any text secret; you read it with `vault get <name>`. Tools
consume that in one of four ways.

### 1. Environment variable / inline — works with almost anything

```sh
export GITHUB_TOKEN="$(vault get github-token)"
export OPENAI_API_KEY="$(vault get openai-key)"
curl -H "Authorization: Bearer $(vault get stripe-live)" https://api.stripe.com/v1/...
PGPASSWORD="$(vault get pg-prod)" psql -h db.example.com -U app
```

A reusable helper — drop into `~/.zshrc`:

```sh
# vrun VAR secret-name -- cmd args...   (runs cmd with VAR set from the vault)
vrun() { local var="$1" name="$2"; shift 3; env "$var=$(vault get "$name")" "$@"; }
# e.g.  vrun GH_TOKEN github-token -- gh repo list
```

### 2. `credential_process` — AWS and anything built on the AWS SDK

AWS CLI/SDKs natively call an external command for credentials, so this is the
cleanest path. Use the included `aws-to-vault.sh`:

```sh
./aws-to-vault.sh --dry-run .fnaws   # validate against the sample file first
./aws-to-vault.sh --apply            # migrate real ~/.aws (backup + auto-rollback)
```

It stores each profile as `aws-<profile>` and writes this into `~/.aws/config`,
then removes the plaintext keys from `~/.aws/credentials`:

```ini
[default]
credential_process = /usr/local/bin/vault get aws-default
```

The stored secret is the JSON the CLI expects:
`{"Version":1,"AccessKeyId":"AKIA…","SecretAccessKey":"…"}` (add `"SessionToken"`
and `"Expiration"` for temporary creds). **Terraform, boto3, Pulumi, and every
AWS SDK pick this up automatically** — no per-tool config. One `terraform apply`
calls `vault get` once and caches it for that run; the AWS CLI calls it per
command (silent after the first unlock).

### 3. Tools that want a file *path* — Google Cloud, kubeconfig, etc.

Some tools accept only a path to a credentials file, not its contents. Store the
file in the vault and materialize it on demand.

**Google Cloud (service-account JSON):**

```sh
# store once, then delete the plaintext file
vault set gcp-sa-key --stdin < my-service-account.json
rm my-service-account.json

# single command — never touches disk (process substitution):
gcloud auth activate-service-account --key-file=<(vault get gcp-sa-key)

# for a whole session of gcloud/gsutil/terraform-google:
export GOOGLE_APPLICATION_CREDENTIALS="$(mktemp)"; chmod 600 "$GOOGLE_APPLICATION_CREDENTIALS"
vault get gcp-sa-key > "$GOOGLE_APPLICATION_CREDENTIALS"
# ... work ...
rm -f "$GOOGLE_APPLICATION_CREDENTIALS"   # clean up when done
```

The temp-file form briefly writes the key to a `0600` file on disk (the GCP
tooling's limitation, since it wants a path). Prefer the `<(...)` form for
one-shot commands, or keep the temp file on a RAM disk.

### 4. Other common CLIs

```sh
gh auth login --with-token < <(vault get github-token)     # GitHub CLI
vault get dockerhub-token | docker login -u USER --password-stdin
npm config set //registry.npmjs.org/:_authToken="$(vault get npm-token)"
```

`kubectl` supports an exec credential plugin in your kubeconfig — point it at a
small wrapper that runs `vault get` and prints the `ExecCredential` JSON, same
idea as AWS `credential_process`.

### CI / headless

All of the above need Touch ID, which requires an interactive GUI login. On
CI/servers there is no fingerprint — use the platform's native secrets there
(GitHub Actions secrets, cloud OIDC, IAM roles). fnVault is for your local
machine.

## Security model

- **Touch ID** is enforced via `LocalAuthentication` (`evaluatePolicy`,
  biometrics with device-passcode fallback). The daemon releases secrets only
  after a successful authentication in the current session.
- Secret **values** are encrypted with XChaCha20-Poly1305 under a random 32-byte
  master key and stored in the login Keychain. Secret **names/metadata** live in
  a plaintext index item so `list`/`status` work without unlocking.
- The master key is cached in memory wrapped in `zeroize` and wiped on relock.
- The Unix socket is `0600` in your per-user cache dir; the daemon also verifies
  the connecting peer's UID.
- Secret values never appear in `argv` (stdin / hidden prompt only).

**Accepted tradeoffs (by design):**

- *Session convenience:* while unlocked, any process running as your macOS user
  can read secrets through the daemon. The idle timeout bounds that window.
- *No hardware binding:* the strong path (a biometric `SecAccessControl` flag on
  the master key, so the OS itself enforces Touch ID on every read) needs the
  restricted `keychain-access-groups` entitlement. An ad-hoc signature carrying
  it is killed by AMFI, and a real one requires a **paid Apple Developer
  certificate**. fnVault therefore gates with `LocalAuthentication` and stores
  the key as a plain Keychain item, which means a process running as you could
  read the key from the Keychain directly, bypassing Touch ID. To upgrade,
  sign with a Developer cert and restore the `SecAccessControl` path in
  `crates/vaultcore/src/keychain_shim.m`.

## Layout

```
crates/
  vaultcore/   crypto, Keychain + Touch ID shim, session state, wire protocol
  vaultd/      daemon
  vault/       CLI client + TUI
```

Logs: `~/Library/Caches/fnvault/vaultd.log` (never contains secret values).

## Development

```sh
cargo test -p vaultcore     # crypto + session unit tests (no Keychain/Touch ID)
cargo clippy --all-targets
```

Touch ID and the Keychain require an interactive GUI login session; they can't
be exercised over SSH/headless.

### Keychain identity & rebuilds

A Keychain item is bound to the code identity that created it. Build once, run
`./sign.sh` once, install, and reads happen with no prompt. If you **rebuild and
re-sign** (ad-hoc signatures change every build), the new binary has a new
identity, so the first read of existing items shows a one-time "Always Allow"
Keychain prompt — click it once. To start clean instead:

```sh
security delete-generic-password -s fnvault.masterkey
security delete-generic-password -s fnvault.data   # repeat until "not found"
vault init
```

A stable Developer ID signature avoids this entirely.
