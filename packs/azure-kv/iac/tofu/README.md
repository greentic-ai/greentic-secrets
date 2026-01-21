# Azure Key Vault setup

This template provisions:
- An Azure Resource Group
- An Azure Key Vault
- Optional access configuration via RBAC or access policies

## AzureRM provider authentication
The `azurerm` provider must be configured to authenticate (service principal, managed identity, or Azure CLI). Make sure the identity has permission to create resource groups, key vaults, and role assignments/access policies.

## RBAC vs access policies
- `use_rbac = true` enables Azure RBAC and assigns the **Key Vault Administrator** role to any `admin_object_ids`.
- `use_rbac = false` creates key vault access policies granting secret management permissions to `admin_object_ids`.

## Apply with OpenTofu
1. `tofu init`
2. `tofu plan`
3. `tofu apply`
