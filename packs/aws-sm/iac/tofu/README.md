# AWS Secrets Manager setup

This template provisions:
- An IAM policy for Greentic Secrets Manager access (scoped to a prefix)
- An optional KMS key + alias (when `create_kms_key = true`)

It does not create any Secrets Manager secrets; the provider runtime manages secret values.

## Required variables
- `region`
- `name_prefix`

## Optional variables
- `create_kms_key` (default `false`)
- `kms_key_arn` (default `""`, used when `create_kms_key = false`)
- `tags` (default `{}`)
- `iam_principal_arns` (default `[]`, informational only)

## Apply with OpenTofu
1. `tofu init`
2. `tofu plan`
3. `tofu apply`

## Security notes
Do not commit any tfvars files that contain secrets. Prefer environment variables or external secret injection.
