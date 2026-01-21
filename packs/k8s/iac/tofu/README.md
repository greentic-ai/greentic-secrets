# Kubernetes secrets setup

This template provisions:
- Optional namespace (when `create_namespace = true`)
- Service account for Greentic secrets
- Optional RBAC role + binding for secrets read/write in the namespace

It does not create any Secret objects.

## Authentication
Configure the Kubernetes provider with a kubeconfig or in-cluster credentials that can create namespaces, service accounts, and RBAC resources.

## Apply with OpenTofu
1. `tofu init`
2. `tofu plan`
3. `tofu apply`
