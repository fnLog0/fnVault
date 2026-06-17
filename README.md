# fnVault

A small credential vault for macOS. Unlock once with Touch ID, then read your
secrets straight from the command line — so they stop living in plaintext
dotfiles. It's a Rust CLI with a TUI dashboard, backed by the macOS Keychain.

Built so your tools (and an AI agent on your machine) can grab a secret with a
plain command, while the actual unlock still needs your fingerprint.

## How it works

Three pieces:

- **`vaultd`** — a background daemon that holds your unlocked key in memory for
  the session.
- **`vault`** — the CLI you and your tools call.
- a **TUI dashboard** when you run `vault` with no arguments.

One fingerprint unlocks the session. After that, reads are silent until you lock
it or it goes idle (15 min by default, `FNVAULT_IDLE_SECS` to change). Secrets are
encrypted with XChaCha20-Poly1305 and kept in the Keychain; the key is wiped from
memory the moment it locks.

## Install

```sh
cargo build --release
./sign.sh release        # optional — gives a stable Keychain identity so it stops re-prompting
cp target/release/vault target/release/vaultd ~/.local/bin/
```

Keep `vault` and `vaultd` in the same directory — the CLI auto-starts the daemon.

## Usage

```sh
vault init                 # one-time setup
vault set github-token     # hidden prompt for the value
vault get github-token     # Touch ID once, then prints it
vault list                 # names + tags
vault status               # session state + idle countdown
vault lock                 # lock now
vault                      # open the TUI
```

In scripts and agents:

```sh
export OPENAI_API_KEY="$(vault get openai-key)"
```

## Works with your other tools

- **AWS** (and Terraform, boto3, any AWS SDK): `./aws-to-vault.sh --apply` moves
  `~/.aws/credentials` behind Touch ID using the CLI's native `credential_process`.
  Try it on the sample first — `./aws-to-vault.sh --dry-run .fnaws`.
- **Google Cloud**: store the service-account JSON, then
  `gcloud auth activate-service-account --key-file=<(vault get gcp-sa-key)`.
- **Anything else**: `export TOKEN="$(vault get some-token)"`, or pipe it in
  (`gh auth login --with-token < <(vault get github-token)`).

## Good to know

- Touch ID and the Keychain need a real GUI login — this won't work over SSH or in
  CI. Use your platform's native secrets there.
- After one unlock, anything running as your user can read secrets until it locks.
  The idle timeout bounds that window.
- The OS-enforced biometric Keychain path needs a paid Apple Developer cert, so
  fnVault gates with `LocalAuthentication` and stores a plain Keychain item
  instead. Full reasoning and tradeoffs are in [PLAN.md](PLAN.md).

## License

MIT — see [LICENSE](LICENSE).
