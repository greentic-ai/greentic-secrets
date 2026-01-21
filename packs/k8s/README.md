# Kubernetes Secrets secrets pack

## What it does
This pack provides Greentic secrets flows for Kubernetes Secrets.

## Required inputs
Config:
- tenant_id
- environment
- namespace
- auth_mode
- namespace_prefix
- audit
- timeouts
- retry_policy
- redaction_policy

Secrets:
- audit_sink_credentials

Optional secrets:
- k8s_bearer_token
- kubeconfig_b64

## Safety guarantees
- Setup plans always redact secrets (no values in logs or reports).
- Dry-run mode does not make network calls.
