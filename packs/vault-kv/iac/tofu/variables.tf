variable "tenant_id" {
  type        = string
  description = "Greentic tenant identifier."
}

variable "environment" {
  type        = string
  description = "Deployment environment (dev/stage/prod)."
}

variable "vault_addr" {
  type        = string
  description = "Vault address (https://...)."
}

variable "mount_path" {
  type        = string
  description = "Vault mount path for KV secrets."
}

variable "auth_mode" {
  type        = string
  description = "Auth mode (token/approle/kubernetes)."
}

variable "namespace_prefix" {
  type        = string
  description = "Prefix for secret names."
}
