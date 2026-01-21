provider "kubernetes" {}

locals {
  target_namespace = var.create_namespace ? kubernetes_namespace.greentic[0].metadata[0].name : var.namespace
}

resource "kubernetes_namespace" "greentic" {
  count = var.create_namespace ? 1 : 0
  metadata {
    name = var.namespace
    labels = {
      name_prefix = var.name_prefix
    }
  }
}

resource "kubernetes_service_account" "greentic" {
  metadata {
    name      = var.service_account_name
    namespace = local.target_namespace
    labels = {
      name_prefix = var.name_prefix
    }
  }
}

resource "kubernetes_role" "greentic" {
  count = var.create_rbac ? 1 : 0
  metadata {
    name      = "${var.name_prefix}secrets"
    namespace = local.target_namespace
  }
  rule {
    api_groups = [""]
    resources  = ["secrets"]
    verbs      = ["get", "list", "watch", "create", "update", "patch", "delete"]
  }
}

resource "kubernetes_role_binding" "greentic" {
  count = var.create_rbac ? 1 : 0
  metadata {
    name      = "${var.name_prefix}secrets"
    namespace = local.target_namespace
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = kubernetes_role.greentic[0].metadata[0].name
  }
  subject {
    kind      = "ServiceAccount"
    name      = kubernetes_service_account.greentic.metadata[0].name
    namespace = local.target_namespace
  }
}
