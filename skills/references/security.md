# fnVault — session & security behavior

## Session lifetime and auto-lock

- After one unlock, reads are silent until the vault locks or goes idle
  (15 min default; set `FNVAULT_IDLE_SECS` to change).
- Auto-locks on system sleep, screen lock, idle timeout, and an optional absolute
  cap: `FNVAULT_MAX_SESSION=28800` for 8h.

## Tiered policy

Secrets tagged `prod` or `banking` require a fresh biometric check on **every**
read, even mid-session. Tag sensitive secrets accordingly when running
`vault set ... --tag prod`.

## Platform limits

- Touch ID / Keychain need a real GUI login — this does **not** work over SSH or
  in CI. Use the platform's native secret store there.
- Keychain items are device-only. `vault export` is the recovery path if the
  machine is lost or wiped — back up before relying on it.
- On Linux, set `FNVAULT_NO_FPRINT=1` to skip fingerprint and always use the
  vault passphrase.

## Troubleshooting

- `vault status` — shows whether the session is unlocked and the idle countdown.
- Re-prompting on every read on macOS — run `./scripts/sign.sh release` to give a
  stable Keychain identity so it stops re-prompting.
- Daemon won't start — `vault` and `vaultd` must be in the same directory, or the
  CLI can't auto-start the daemon.
