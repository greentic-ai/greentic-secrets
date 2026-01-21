variable "region" {
  type        = string
  description = "AWS region to target."
}

variable "name_prefix" {
  type        = string
  description = "Prefix for naming IAM policies and secrets."
}

variable "create_kms_key" {
  type        = bool
  description = "Whether to create a new KMS key for Secrets Manager."
  default     = false
}

variable "kms_key_arn" {
  type        = string
  description = "Existing KMS key ARN to use when create_kms_key is false."
  default     = ""
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to provisioned resources."
  default     = {}
}

variable "iam_principal_arns" {
  type        = list(string)
  description = "Optional IAM principal ARNs to grant access (not attached automatically)."
  default     = []
}
