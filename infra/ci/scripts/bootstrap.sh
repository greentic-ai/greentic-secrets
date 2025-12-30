#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v terraform >/dev/null 2>&1; then
  echo "terraform not found; install Terraform first." >&2
  exit 1
fi

cloud="${1:-}"
if [[ -z "${cloud}" ]]; then
  echo "usage: $0 <aws|azure|gcp>" >&2
  exit 1
fi

case "${cloud}" in
  aws|azure|gcp) ;;
  *) echo "unknown cloud '${cloud}' (expected aws|azure|gcp)" >&2; exit 1 ;;
esac

cd "${ROOT}/terraform/${cloud}"
echo "Initializing terraform (${cloud})..."
terraform init -upgrade
echo "Planning..."
terraform plan
echo "Apply? (y/N)"
read -r answer
if [[ "${answer}" =~ ^[Yy]$ ]]; then
  terraform apply
else
  echo "Skipped apply."
fi
