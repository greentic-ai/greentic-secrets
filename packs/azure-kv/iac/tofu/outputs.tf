output "key_vault_id" {
  value       = azurerm_key_vault.greentic.id
  description = "Key Vault resource id."
}

output "key_vault_uri" {
  value       = azurerm_key_vault.greentic.vault_uri
  description = "Key Vault URI."
}

output "key_vault_name" {
  value       = azurerm_key_vault.greentic.name
  description = "Key Vault name."
}

output "resource_group_name" {
  value       = azurerm_resource_group.greentic.name
  description = "Resource group name."
}

output "tenant_id" {
  value       = var.tenant_id
  description = "Azure tenant id."
}
