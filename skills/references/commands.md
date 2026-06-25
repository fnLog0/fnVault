# fnVault — command reference

## Core workflow

```sh
vault init                  # one-time setup
vault set github-token      # hidden prompt for the value (nothing echoed)
vault get github-token      # unlock once (Touch ID / passphrase), then prints it
vault list                  # names, tags, expiry
vault status                # session state + idle countdown
vault lock                  # lock now
vault                       # open the TUI dashboard
```

## Tags and rotation reminders

Tag a secret and set an expiry when storing it:

```sh
vault set aws-prod --tag prod --expires 2026-12-31
```

Tags drive the tiered policy — see [security.md](security.md).

## Other commands

```sh
vault otp my-2fa                       # current TOTP code from a stored base32 seed
vault export vault-backup.fnv          # passphrase-encrypted backup of everything
vault import vault-backup.fnv          # restore on a new machine
vault audit -n 20                      # recent access events from the daemon log
vault completions zsh > ~/.zsh/_vault  # shell completions (zsh/bash/fish)
```

For reading secrets into other commands, see [injection.md](injection.md).
