# Azure Key Vault secrets pack

## What it does
This pack provides Greentic secrets flows for Azure Key Vault.

## Required inputs
Config:
- tenant_id
- environment
- vault_url
- auth_mode
- namespace_prefix
- audit
- timeouts
- retry_policy
- redaction_policy

Secrets:
- audit_sink_credentials

Optional secrets:
- azure_client_secret

## Safety guarantees
- Setup plans always redact secrets (no values in logs or reports).
- Dry-run mode does not make network calls.
