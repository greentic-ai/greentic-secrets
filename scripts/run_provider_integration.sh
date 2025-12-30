#!/usr/bin/env bash
set -euo pipefail

# One-shot local runner for provider integration tests.
# Requires Docker, kind, kubectl, awscli (for localstack via awslocal), and curl.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEEP="${KEEP:-0}"
PREFIX="local/$(date +%s)/$$"
GREENTIC_TEST_PREFIX="${GREENTIC_TEST_PREFIX:-$PREFIX}"
export GREENTIC_TEST_PREFIX GREENTIC_INTEGRATION=1

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1. $2" >&2
    exit 1
  fi
}

require_cmd docker "Install Docker and ensure the daemon is running."
require_cmd kind "Install kind: https://kind.sigs.k8s.io/"
require_cmd kubectl "Install kubectl: https://kubernetes.io/docs/tasks/tools/"
require_cmd curl "Install curl."

cleanup() {
  if [[ "${KEEP}" == "1" ]]; then
    echo "KEEP=1 set; skipping teardown"
    return
  fi
  echo "Stopping services..."
  docker rm -f greentic-vault >/dev/null 2>&1 || true
  docker rm -f greentic-localstack >/dev/null 2>&1 || true
  kind delete cluster --name greentic >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Using test prefix: ${GREENTIC_TEST_PREFIX}"

echo "Starting kind cluster..."
kind create cluster --name greentic --wait 60s >/dev/null

echo "Provisioning k8s serviceaccount..."
kubectl create serviceaccount greentic-sa -n default
kubectl create clusterrolebinding greentic-sa --clusterrole=cluster-admin --serviceaccount=default:greentic-sa
TOKEN=$(kubectl create token greentic-sa)
SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
CA_PATH="$(mktemp)"
kubectl config view --minify --raw --flatten -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > "${CA_PATH}"
export K8S_BEARER_TOKEN="${TOKEN}"
export K8S_API_SERVER="${SERVER}"
export K8S_CA_BUNDLE="${CA_PATH}"
export K8S_NAMESPACE_PREFIX="greentic"
export K8S_KEK_ALIAS="default"

echo "Starting Vault dev..."
docker run -d --rm --name greentic-vault -e VAULT_DEV_ROOT_TOKEN_ID=root -p 8200:8200 hashicorp/vault:1.17 >/dev/null
VAULT_ADDR="http://127.0.0.1:8200"
VAULT_TOKEN="root"
export VAULT_ADDR VAULT_TOKEN
echo "Waiting for Vault..."
for _ in {1..20}; do
  if curl -sf "${VAULT_ADDR}/v1/sys/health" >/dev/null; then break; fi
  sleep 2
done
echo "Configuring Vault transit..."
curl -sf -X POST -H "X-Vault-Token: ${VAULT_TOKEN}" -d '{"type":"transit"}' "${VAULT_ADDR}/v1/sys/mounts/transit" || true
curl -sf -X POST -H "X-Vault-Token: ${VAULT_TOKEN}" "${VAULT_ADDR}/v1/transit/keys/greentic" || true

echo "Starting LocalStack..."
docker run -d --rm --name greentic-localstack -p 4566:4566 -e SERVICES="secretsmanager,kms" localstack/localstack:3 >/dev/null
AWS_ENDPOINT_URL="http://127.0.0.1:4566"
export AWS_ACCESS_KEY_ID="test"
export AWS_SECRET_ACCESS_KEY="test"
export AWS_REGION="${AWS_REGION:-us-east-1}"
export AWS_ENDPOINT_URL
for _ in {1..30}; do
  if curl -sf "${AWS_ENDPOINT_URL}/health" >/dev/null; then break; fi
  sleep 2
done

echo "Running k8s provider tests..."
cargo test -p secrets-provider-k8s --features integration -- --ignored --nocapture

echo "Running Vault provider tests..."
cargo test -p secrets-provider-vault-kv --features integration -- --ignored --nocapture

echo "Running AWS (LocalStack) provider tests..."
cargo test -p secrets-provider-aws-sm --features integration -- --ignored --nocapture

echo "Integration suite complete."
