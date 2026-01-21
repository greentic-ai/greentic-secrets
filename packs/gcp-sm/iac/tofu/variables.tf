variable "project_id" {
  type        = string
  description = "GCP project id."
}

variable "name_prefix" {
  type        = string
  description = "Prefix for secret names."
}

variable "locations" {
  type        = list(string)
  description = "Replication locations for secrets."
  default     = ["us"]
}

variable "grant_sa_email" {
  type        = string
  description = "Optional service account email to grant access."
  default     = ""
}

variable "create_placeholder_secret" {
  type        = bool
  description = "Whether to create a placeholder secret."
  default     = false
}
