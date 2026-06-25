# fnVault

A small credential vault. Unlock once, then read your secrets straight from the
command line — so they stop living in plaintext dotfiles. It's a Rust CLI with a
TUI dashboard.

- **macOS**: secrets in the Keychain, unlock with **Touch ID**.
- **Linux**: secrets in the Secret Service (gnome-keyring / KWallet). Unlock with
  your **fingerprint** when fprintd has an enrolled finger, otherwise a **vault
  passphrase** (set on first unlock); the passphrase is always the fallback.
  Auto-locks on sleep and screen lock (logind / screensaver over D-Bus). Set
  `FNVAULT_NO_FPRINT=1` to skip the fingerprint and always use the passphrase.

Built so your tools (and an AI agent on your machine) can grab a secret with a
plain command, while the actual unlock still needs you.

## How it works

Three pieces:

- **`vaultd`** — a background daemon that holds your unlocked key in memory for
  the session.
- **`vault`** — the CLI you and your tools call.
- a **TUI dashboard** when you run `vault` with no arguments.

One unlock — Touch ID on macOS, vault passphrase on Linux — opens the session.
After that, reads are silent until you lock it or it goes idle (15 min by default,
`FNVAULT_IDLE_SECS` to change). Secrets are encrypted with XChaCha20-Poly1305 and
kept in the OS secret store; the key is wiped from memory the moment it locks.

## Install

### Homebrew (macOS & Linux)

The Homebrew formula lives in this repo (`Formula/fnvault.rb`), so tap it by URL:

```sh
brew tap fnLog0/fnvault https://github.com/fnLog0/fnVault
brew install fnvault
```

It builds from source, so the binaries are compiled locally — no Apple
notarization needed and nothing is quarantined by Gatekeeper. Both `vault` and
`vaultd` install into the same prefix, and shell completions are set up for you.

### From source

```sh
cargo build --release
./scripts/sign.sh release   # optional — gives a stable Keychain identity so it stops re-prompting
cp target/release/vault target/release/vaultd ~/.local/bin/
```

Keep `vault` and `vaultd` in the same directory — the CLI auto-starts the daemon.

## Usage

```sh
vault init                 # one-time setup
vault set github-token     # hidden prompt for the value
vault set aws-prod --tag prod --expires 2026-12-31   # tag + rotation reminder
vault get github-token     # Touch ID once, then prints it
vault list                 # names, tags, expiry
vault status               # session state + idle countdown
vault lock                 # lock now
vault                      # open the TUI
```

More commands:

```sh
vault otp my-2fa                      # current TOTP code from a stored base32 seed
vault run -e GH_TOKEN=github-token -- gh repo list   # inject secrets into a command
vault export vault-backup.fnv         # passphrase-encrypted backup of everything
vault import vault-backup.fnv         # restore on a new machine
vault audit -n 20                     # recent access events from the daemon log
vault completions zsh > ~/.zsh/_vault # shell completions
vault skills list                     # bundled agent skills (version-matched)
vault skills get fnvault --full       # full usage guide + references + templates
```

### Skills for AI agents

fnVault ships a bundled [agent skill](skills/SKILL.md) — a usage guide,
references, and copy-paste templates — embedded in the binary so it always
matches the installed version (the same pattern as `agent-browser skills`):

```sh
vault skills list                 # list available skills
vault skills get fnvault          # print the SKILL.md
vault skills get fnvault --full   # append references/ and templates/
vault skills path fnvault         # filesystem path (override with FNVAULT_SKILLS_DIR)
```

In scripts and agents:

```sh
export OPENAI_API_KEY="$(vault get openai-key)"
```

## Works with your other tools

- **AWS** (and Terraform, boto3, any AWS SDK): `./scripts/aws-to-vault.sh --apply`
  moves `~/.aws/credentials` behind Touch ID using the CLI's native
  `credential_process`. Try it on the sample first —
  `./scripts/aws-to-vault.sh --dry-run .fnaws`.
- **Google Cloud**: store the service-account JSON, then run tools with
  `./scripts/with-gcp.sh gcp-sa-key -- gcloud storage ls` (it materializes the key
  to a private temp file and cleans up), or
  `gcloud auth activate-service-account --key-file=<(vault get gcp-sa-key)`.
- **Kubernetes**: `scripts/k8s-credential.sh` is an exec credential plugin — point
  your kubeconfig's `user.exec.command` at it with the secret name as an arg.
- **Anything else**: `export TOKEN="$(vault get some-token)"`, pipe it in
  (`gh auth login --with-token < <(vault get github-token)`), or wrap a command
  with `vault run -e VAR=secret -- cmd`.

## Good to know

- It **auto-locks** on system sleep and screen lock, after the idle timeout, and
  (optionally) after an absolute cap — `FNVAULT_MAX_SESSION=28800` for 8h.
- **Tiered policy**: secrets tagged `prod`/`banking` ask for a fresh fingerprint
  on every read, even mid-session.
- Back up before you rely on it — Keychain items are device-only, so
  `vault export` is your recovery path if the Mac is lost or wiped.
- Touch ID and the Keychain need a real GUI login — this won't work over SSH or in
  CI. Use your platform's native secrets there.
- After one unlock, anything running as your user can read non-tiered secrets
  until it locks. The idle timeout and auto-lock bound that window.
- The OS-enforced biometric Keychain path needs a paid Apple Developer cert, so
  fnVault gates with `LocalAuthentication` and stores a plain Keychain item
  instead.

## License

MIT — see [LICENSE](LICENSE).
