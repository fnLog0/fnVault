---
name: fnvault
description: Use the fnVault credential vault to store, read, and inject secrets from the command line. Covers the snapshot-and-unlock workflow, the `vault` CLI (init/set/get/list/status/lock), TOTP codes, injecting secrets into commands with `vault run`, passphrase-encrypted export/import backups, the TUI dashboard, AWS/GCP/Kubernetes integrations, and session/auto-lock/tiered-policy security behavior. Use whenever a task needs a secret (API key, token, credential) on this machine instead of a plaintext dotfile, or when setting up, backing up, or troubleshooting fnVault.
allowed-tools: Bash(vault:*), Bash(vaultd:*)
---

# fnVault

Fast local credential vault for AI agents and your own tools. Unlock once
(Touch ID on macOS, a vault passphrase or fingerprint on Linux), then read
secrets with plain commands. Secrets are encrypted with XChaCha20-Poly1305 and
held in the OS secret store; the key is wiped from memory the moment the vault
locks.

Two binaries must live in the same directory — `vault` auto-starts `vaultd`:

- **`vaultd`** — background daemon holding the unlocked key for the session.
- **`vault`** — the CLI you call. Run with no args to open the TUI dashboard.

## The core loop

```bash
vault status                # 1. Is the session unlocked? See the idle countdown.
vault list                  # 2. See what's stored (names, tags, expiry) — no unlock.
vault get github-token      # 3. Read a secret (unlocks once via Touch ID/passphrase).
vault lock                  # 4. Lock when done (also auto-locks on idle/sleep).
```

**Never print a secret into the chat or a log.** Inject it into the command that
needs it — see [references/injection.md](references/injection.md).

## Quickstart

```bash
vault init                  # one-time setup (generates the master key)
vault set github-token      # hidden prompt for the value (nothing echoed)
vault get github-token      # unlock once, then prints it
vault run -e GH_TOKEN=github-token -- gh repo list   # inject, don't capture
vault                       # open the TUI dashboard
```

## When to use this skill

- A task needs a secret on this machine (API key, token, AWS/GCP/k8s credential).
- The user wants to stop keeping secrets in plaintext dotfiles.
- Setting up, backing up, restoring, or troubleshooting fnVault.

## References

Load the file relevant to the task — each is self-contained:

- **[references/commands.md](references/commands.md)** — full CLI reference:
  set/get, tags & expiry, list/status/lock, TOTP, export/import, audit, completions.
- **[references/injection.md](references/injection.md)** — reading secrets safely
  in scripts and agents (`vault run`, process substitution, env export).
- **[references/integrations.md](references/integrations.md)** — AWS, Google Cloud,
  and Kubernetes integration scripts.
- **[references/security.md](references/security.md)** — session lifetime, auto-lock,
  tiered policy, platform limits, and troubleshooting.

## Templates

Copy-paste starting points in [templates/](templates/):

- **[templates/inject-secrets.sh](templates/inject-secrets.sh)** — wrap a command
  with vault-injected env vars, no plaintext on disk.
- **[templates/rotate-check.sh](templates/rotate-check.sh)** — list secrets and
  flag ones past their `--expires` date.
