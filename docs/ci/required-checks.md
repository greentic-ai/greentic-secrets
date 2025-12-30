# Required status checks for PRs

Recommended required checks before merge:

- Unit/lint (workspace CI)
- `k8s_kind`
- `vault_dev`
- `aws_localstack`

Real cloud jobs (`aws_real`, `azure_real`, `gcp_real`) run on schedule/manual and are not required for PRs.
