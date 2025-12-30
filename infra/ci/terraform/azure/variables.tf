variable "tenant_id" {
  type        = string
  description = "Azure AD tenant ID."
}

variable "subscription_id" {
  type        = string
  description = "Azure subscription ID."
}

variable "resource_group_name" {
  type        = string
  description = "Resource group for Key Vault."
}

variable "location" {
  type        = string
  description = "Azure region for resources."
  default     = "eastus"
}

variable "github_owner" {
  type        = string
  description = "GitHub repository owner."
}

variable "github_repo" {
  type        = string
  description = "GitHub repository name."
}

variable "github_environment" {
  type        = string
  description = "GitHub environment to bind (optional)."
  default     = ""
}

variable "key_vault_name" {
  type        = string
  description = "Key Vault name to create/use."
}

variable "use_rbac" {
  type        = bool
  description = "Whether to use RBAC for Key Vault."
  default     = true
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to resources."
  default     = {}
}

