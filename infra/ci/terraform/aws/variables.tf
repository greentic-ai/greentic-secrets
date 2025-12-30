variable "aws_region" {
  description = "AWS region for CI Secrets Manager resources."
  type        = string
}

variable "github_owner" {
  description = "GitHub repository owner."
  type        = string
}

variable "github_repo" {
  description = "GitHub repository name."
  type        = string
}

variable "github_ref_pattern" {
  description = "Git ref pattern to allow (e.g. refs/heads/main)."
  type        = string
  default     = "refs/heads/main"
}

variable "role_name" {
  description = "IAM role name for CI."
  type        = string
  default     = "greentic-secrets-ci"
}

variable "secrets_prefix" {
  description = "Secrets Manager name prefix enforced by policy."
  type        = string
  default     = "ci/greentic-secrets"
}

variable "thumbprint_list" {
  description = "OIDC provider thumbprints. Default covers GitHub Actions."
  type        = list(string)
  default     = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

variable "client_id_list" {
  description = "OIDC client IDs allowed."
  type        = list(string)
  default     = ["sts.amazonaws.com"]
}

variable "tags" {
  description = "Tags applied to IAM role."
  type        = map(string)
  default     = {}
}

