provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "greentic" {
  name     = var.resource_group_name
  location = var.location
}

resource "azurerm_key_vault" "greentic" {
  name                       = var.key_vault_name
  location                   = azurerm_resource_group.greentic.location
  resource_group_name        = azurerm_resource_group.greentic.name
  tenant_id                  = var.tenant_id
  sku_name                   = var.sku_name
  enable_rbac_authorization  = var.use_rbac
  soft_delete_retention_days = 7
  purge_protection_enabled   = false
}

data "azurerm_role_definition" "key_vault_admin" {
  name  = "Key Vault Administrator"
  scope = azurerm_key_vault.greentic.id
}

resource "azurerm_role_assignment" "admin" {
  count              = var.use_rbac ? length(var.admin_object_ids) : 0
  scope              = azurerm_key_vault.greentic.id
  role_definition_id = data.azurerm_role_definition.key_vault_admin.id
  principal_id       = var.admin_object_ids[count.index]
}

resource "azurerm_key_vault_access_policy" "admin" {
  count        = var.use_rbac ? 0 : length(var.admin_object_ids)
  key_vault_id = azurerm_key_vault.greentic.id
  tenant_id    = var.tenant_id
  object_id    = var.admin_object_ids[count.index]

  secret_permissions = [
    "Get",
    "List",
    "Set",
    "Delete",
    "Recover",
    "Purge",
  ]
}
