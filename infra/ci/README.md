# CI cloud identities (AWS/Azure/GCP)

Terraform modules to provision least-privilege identities for nightly/manual “real cloud” provider tests using GitHub OIDC/WIF. Each cloud is independent—apply only what you need.

## Layout
- `terraform/aws`: IAM role with GitHub OIDC trust + Secrets Manager scoped policy
- `terraform/azure`: App/SP + federated credential + Key Vault with RBAC/policy
- `terraform/gcp`: Workload Identity Pool/Provider + service account + Secret Manager role
- `scripts/bootstrap.sh`: helper to init/plan/apply a cloud module
- `scripts/print_github_vars.sh`: lists GitHub variables consumed by workflows

## Common inputs
- GitHub owner/repo and ref pattern (defaults to `refs/heads/main`)
- Test prefix defaults to `ci/greentic-secrets/<owner>/<repo>/...`

## Outputs → GitHub Actions variables
- AWS: `AWS_ROLE_TO_ASSUME`, `AWS_REGION`
- Azure: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `AZURE_KEYVAULT_NAME`
- GCP: `GCP_PROJECT_ID`, `GCP_SERVICE_ACCOUNT`, `GCP_WIF_PROVIDER`

Use GitHub Repository Variables for these; secrets are not required for these identities.

## Deploy
```bash
cd infra/ci
./scripts/bootstrap.sh aws   # or azure / gcp
```
Terraform must be installed. Review and override variables as needed (e.g., regions, resource group).

## Workflows
`.github/workflows/secrets-providers.yml` consumes the variables above for real cloud jobs. PR jobs (kind/vault/localstack) do not need cloud credentials.

