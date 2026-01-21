output "project_id" {
  value       = var.project_id
  description = "GCP project id."
}

output "name_prefix" {
  value       = var.name_prefix
  description = "Prefix for secrets."
}

output "grant_sa_email" {
  value       = var.grant_sa_email
  description = "Service account email granted access."
}
