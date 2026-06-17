# fnVault — Plan

A Rust CLI credential vault for macOS. One Touch ID unlock per session; afterward
you (or your AI agent) read secrets via CLI commands with no further prompts,
until the session ends or an idle-timeout backstop fires.

## Architecture

Three crates in one workspace:

- **vaultcore** — shared library: crypto, Keychain access (via an Objective-C
  shim), Touch ID gating, session state machine, wire protocol.
- **vaultd** — background daemon. Holds the unlocked master key in memory for the
  session, enforces the idle-timeout backstop, serves requests over a Unix socket.
- **vault** — thin CLI client *and* the TUI dashboard. Talks to the daemon.

```
  Claude / you
       |  vault get github-token
       v
   vault (CLI/TUI client) --unix socket--> vaultd (daemon, holds session)
                                              | master key in RAM (zeroized on lock)
                                              v
                                       macOS Keychain  <-- Touch ID once
                                       (biometric-gated master key + encrypted secrets)
```

## Key model

1. A random 32-byte **master key** encrypts every secret (XChaCha20-Poly1305).
2. The master key lives in the Keychain behind a biometric `SecAccessControl`
   flag, so the OS enforces Touch ID on read.
3. The daemon reads it **once** (one Touch ID prompt), caches it in memory for the
   session, and serves decrypted secrets without re-prompting.
4. On relock (idle timeout / manual `lock` / shutdown) the key is zeroized.

Secret *values* are stored encrypted in the Keychain. Secret *names/metadata*
live in a plaintext index item, so `list` and `status` never need an unlock.

## Session & idle-timeout backstop

- States: `Locked` (no key in RAM) / `Unlocked { last_activity }`.
- Each served request bumps `last_activity`.
- A watcher relocks (zeroizes the key) when `now - last_activity > idle_timeout`.
- Default idle timeout: **15 min** (`FNVAULT_IDLE_SECS` to override; 0 disables).
- `vault lock` relocks immediately; daemon shutdown relocks.

## Command surface

```
vault init                  generate master key + Touch ID enrollment item
vault set  <name> [--tag T] [--stdin]   add/update a secret (value via prompt or stdin)
vault get  <name> [--newline]           print secret to stdout (unlocks if needed)
vault list                  list secret names + tags (no unlock)
vault rm   <name>           delete a secret (requires unlock)
vault lock                  relock now (zeroize in-memory key)
vault unlock                trigger Touch ID without reading a secret
vault status                session state + idle countdown
vault ui                    launch the TUI dashboard (also the default with no args)
```

Exit codes: `0` ok, `2` locked/auth-failed, `3` not-found, `4` daemon-unreachable.

## Security notes

- Socket is `0600`, in the per-user cache dir; daemon verifies peer UID.
- Secret values never appear in argv (stdin / no-echo prompt only).
- Key material wrapped in `zeroize`; zeroized on relock.
- Accepted tradeoff (by design): while unlocked, any process running as your
  macOS user can read secrets. The idle timeout bounds the window.
- Touch ID + biometric Keychain items generally require the binaries to be
  code-signed. See README for `codesign` notes.

## Build milestones

1. Crypto + Keychain core (vaultcore)
2. Touch ID gate
3. Daemon + socket
4. Session state machine + idle timeout
5. CLI client polish (auto-spawn, exit codes, hidden input)
6. Hardening (logging, peer-UID check)
7. TUI dashboard
