# fnVault — reading secrets in scripts and agents

Prefer injection over capturing the plaintext. Never echo a secret into the chat
or a log.

## Inject into one command's environment

No env var is left behind in your shell:

```sh
vault run -e GH_TOKEN=github-token -- gh repo list
```

## Process substitution

Feed a secret to a flag or stdin without it touching disk or the environment:

```sh
gh auth login --with-token < <(vault get github-token)
gcloud auth activate-service-account --key-file=<(vault get gcp-sa-key)
```

## Export into the current shell (last resort)

```sh
export OPENAI_API_KEY="$(vault get openai-key)"
```

This leaves the value in the shell environment until it exits — use the narrower
forms above when you can.
