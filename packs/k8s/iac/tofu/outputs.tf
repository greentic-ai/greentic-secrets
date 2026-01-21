output "namespace" {
  value       = local.target_namespace
  description = "Namespace used for Greentic secrets."
}

output "service_account_name" {
  value       = kubernetes_service_account.greentic.metadata[0].name
  description = "Service account name for Greentic secrets."
}

output "name_prefix" {
  value       = var.name_prefix
  description = "Prefix used for RBAC resources."
}
