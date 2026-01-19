#!/usr/bin/env bash
set -euo pipefail

PROVIDER="${1:-}"
if [[ -z "$PROVIDER" ]]; then
  echo "Usage: $0 <provider>"
  exit 1
fi

case "$PROVIDER" in
  dev)   cargo run -p greentic-secrets-conformance --features provider-dev ;;
  k8s)   cargo run -p greentic-secrets-conformance --features provider-k8s ;;
  vault) cargo run -p greentic-secrets-conformance --features provider-vault ;;
  *)
    echo "Unknown provider: $PROVIDER"
    exit 1
    ;;
esac
