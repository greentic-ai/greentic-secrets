output "azure_client_id" {
  value       = azuread_application.app.client_id
  description = "Client ID for CI login."
}

output "azure_tenant_id" {
  value       = var.tenant_id
  description = "Tenant ID."
}

output "azure_subscription_id" {
  value       = var.subscription_id
  description = "Subscription ID."
}

output "azure_keyvault_name" {
  value       = azurerm_key_vault.kv.name
  description = "Key Vault name."
}

