provider "aws" {
  region = var.region
}

locals {
  kms_key_arn = var.create_kms_key ? aws_kms_key.greentic[0].arn : var.kms_key_arn
}

resource "aws_kms_key" "greentic" {
  count                   = var.create_kms_key ? 1 : 0
  description             = "Greentic secrets KMS key"
  deletion_window_in_days = 7
  tags                    = var.tags
}

resource "aws_kms_alias" "greentic" {
  count         = var.create_kms_key ? 1 : 0
  name          = "alias/${var.name_prefix}-greentic-secrets"
  target_key_id = aws_kms_key.greentic[0].key_id
}

data "aws_caller_identity" "current" {}

resource "aws_iam_policy" "greentic_secrets" {
  name        = "${var.name_prefix}-greentic-secrets"
  description = "Policy for Greentic Secrets Manager access"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SecretsManagerAccess"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:ListSecrets",
        ]
        Resource = "arn:aws:secretsmanager:${var.region}:${data.aws_caller_identity.current.account_id}:secret:${var.name_prefix}*"
      }
    ]
  })
  tags = var.tags
}
