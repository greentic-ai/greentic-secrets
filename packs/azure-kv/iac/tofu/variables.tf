variable "location" {
  type        = string
  description = "Azure region (e.g. eastus)."
}

variable "resource_group_name" {
  type        = string
  description = "Resource group to create or manage."
}

variable "key_vault_name" {
  type        = string
  description = "Key Vault name."
}

variable "tenant_id" {
  type        = string
  description = "Azure tenant id."
}

variable "sku_name" {
  type        = string
  description = "Key Vault SKU name (standard or premium)."
  default     = "standard"
}

variable "use_rbac" {
  type        = bool
  description = "Whether to use RBAC for Key Vault access."
  default     = true
}

variable "admin_object_ids" {
  type        = list(string)
  description = "Principal object ids to grant admin access."
  default     = []
}
