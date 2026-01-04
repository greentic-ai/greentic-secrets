#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -lt 1 ]]; then
  echo "Usage: $0 <pack.gtpack> [pack2.gtpack ...]" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VALIDATOR_BIN="${VALIDATE_GTPACK_BIN:-}"

cd "${ROOT_DIR}"

if [[ -z "${VALIDATOR_BIN}" ]]; then
  VALIDATOR_BIN="${ROOT_DIR}/target/debug/validate_gtpack_extension"
  if [[ ! -x "${VALIDATOR_BIN}" ]]; then
    cargo build -q -p greentic-secrets-runner --bin validate_gtpack_extension
  fi
fi

"${VALIDATOR_BIN}" "$@"
