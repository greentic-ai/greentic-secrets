provider "google" {
  project = var.project_id
}

resource "google_secret_manager_secret" "placeholder" {
  count     = var.create_placeholder_secret ? 1 : 0
  secret_id = "${var.name_prefix}-placeholder"
  replication {
    user_managed {
      dynamic "replicas" {
        for_each = toset(var.locations)
        content {
          location = replicas.value
        }
      }
    }
  }
}

resource "google_project_iam_member" "secret_accessor" {
  count  = var.grant_sa_email != "" ? 1 : 0
  role   = "roles/secretmanager.secretAccessor"
  member = "serviceAccount:${var.grant_sa_email}"
}

resource "google_project_iam_member" "secret_admin" {
  count  = var.grant_sa_email != "" ? 1 : 0
  role   = "roles/secretmanager.admin"
  member = "serviceAccount:${var.grant_sa_email}"
}
