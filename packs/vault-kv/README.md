# HashiCorp Vault KV secrets pack

## What it does
This pack provides Greentic secrets flows for HashiCorp Vault KV.

## Required inputs
Config:
- tenant_id
- environment
- vault_addr
- mount_path
- auth_mode
- namespace_prefix
- audit
- timeouts
- retry_policy
- redaction_policy

Secrets:
- audit_sink_credentials

Optional secrets:
- vault_token
- vault_role_id
- vault_secret_id
- k8s_jwt
- k8s_role

## Safety guarantees
- Setup plans always redact secrets (no values in logs or reports).
- Dry-run mode does not make network calls.
