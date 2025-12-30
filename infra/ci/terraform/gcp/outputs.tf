output "gcp_project_id" {
  value       = var.project_id
  description = "GCP project ID."
}

output "gcp_service_account_email" {
  value       = google_service_account.ci.email
  description = "Service account email for CI."
}

output "gcp_workload_identity_provider" {
  value       = google_iam_workload_identity_pool_provider.provider.name
  description = "Full resource name of WIF provider."
}

