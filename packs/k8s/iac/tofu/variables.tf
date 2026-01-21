variable "namespace" {
  type        = string
  description = "Kubernetes namespace for secrets."
}

variable "service_account_name" {
  type        = string
  description = "Service account name for Greentic secrets."
  default     = "greentic-secrets"
}

variable "name_prefix" {
  type        = string
  description = "Prefix used for Kubernetes RBAC resources."
  default     = "greentic-"
}

variable "create_namespace" {
  type        = bool
  description = "Whether to create the namespace."
  default     = false
}

variable "create_rbac" {
  type        = bool
  description = "Whether to create RBAC role and binding."
  default     = true
}
