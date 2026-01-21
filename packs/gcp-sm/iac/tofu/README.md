# GCP Secret Manager setup

This template provisions:
- Optional placeholder secret (disabled by default)
- Optional IAM bindings for a service account

It does not create actual secrets by default.

## Authentication
The `google` provider uses Application Default Credentials (ADC) or a configured service account. Ensure your identity can manage Secret Manager IAM bindings.

## Required APIs
Enable the Secret Manager API: `secretmanager.googleapis.com`.

## Apply with OpenTofu
1. `tofu init`
2. `tofu plan`
3. `tofu apply`
