# fnVault — tool integrations

Helper scripts live in the repo's `scripts/` directory.

## AWS / Terraform / boto3 / any AWS SDK

`scripts/aws-to-vault.sh` moves `~/.aws/credentials` behind Touch ID using the
AWS CLI's native `credential_process`:

```sh
./scripts/aws-to-vault.sh --dry-run .fnaws   # preview against the sample first
./scripts/aws-to-vault.sh --apply            # migrate for real
```

## Google Cloud

Materialize the stored service-account JSON to a private temp file, run, clean up:

```sh
./scripts/with-gcp.sh gcp-sa-key -- gcloud storage ls
```

Or feed it directly via process substitution:

```sh
gcloud auth activate-service-account --key-file=<(vault get gcp-sa-key)
```

## Kubernetes

`scripts/k8s-credential.sh` is an exec credential plugin. Point the kubeconfig's
`user.exec.command` at it with the secret name as an argument.
