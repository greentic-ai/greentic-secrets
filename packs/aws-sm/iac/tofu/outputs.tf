output "aws_region" {
  value       = var.region
  description = "AWS region used for provisioning."
}

output "kms_key_arn" {
  value       = local.kms_key_arn
  description = "KMS key ARN used for Secrets Manager."
}

output "policy_arn" {
  value       = aws_iam_policy.greentic_secrets.arn
  description = "IAM policy ARN for Secrets Manager access."
}

output "name_prefix" {
  value       = var.name_prefix
  description = "Name prefix used for resources."
}
