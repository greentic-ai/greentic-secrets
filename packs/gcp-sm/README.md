# GCP Secret Manager secrets pack

## What it does
This pack provides Greentic secrets flows for GCP Secret Manager.

## Required inputs
Config:
- tenant_id
- environment
- project_id
- auth_mode
- namespace_prefix
- audit
- timeouts
- retry_policy
- redaction_policy

Secrets:
- audit_sink_credentials

Optional secrets:
- gcp_service_account_json

## Safety guarantees
- Setup plans always redact secrets (no values in logs or reports).
- Dry-run mode does not make network calls.
