output "role_arn" {
  value       = aws_iam_role.ci.arn
  description = "IAM role to assume from GitHub OIDC."
}

output "aws_region" {
  value       = var.aws_region
  description = "AWS region for CI."
}

output "account_id" {
  value       = data.aws_caller_identity.current.account_id
  description = "AWS account ID."
}

