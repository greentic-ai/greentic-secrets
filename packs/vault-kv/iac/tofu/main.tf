terraform {
  required_version = ">= 1.5.0"
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = ">= 3.0"
    }
  }
}

provider "vault" {
  address = var.vault_addr
}

resource "vault_mount" "greentic" {
  path = var.mount_path
  type = "kv-v2"
}
