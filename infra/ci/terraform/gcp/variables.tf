variable "project_id" {
  type        = string
  description = "GCP project for CI secrets."
}

variable "region" {
  type        = string
  description = "GCP region (optional)."
  default     = "us-central1"
}

variable "github_owner" {
  type        = string
  description = "GitHub repository owner."
}

variable "github_repo" {
  type        = string
  description = "GitHub repository name."
}

variable "github_ref_pattern" {
  type        = string
  description = "GitHub ref condition (e.g. refs/heads/main)."
  default     = "refs/heads/main"
}

variable "pool_id" {
  type        = string
  description = "Workload Identity Pool ID."
  default     = "gh-pool"
}

variable "provider_id" {
  type        = string
  description = "Workload Identity Provider ID."
  default     = "gh-provider"
}

variable "service_account_id" {
  type        = string
  description = "Service account ID (name)."
  default     = "greentic-secrets-ci"
}

variable "labels" {
  type        = map(string)
  description = "Labels applied to resources."
  default     = {}
}

