#!/usr/bin/env bash
set -euo pipefail

export PATH="${HOME}/.local/bin:${PATH}"

log() {
  printf '[seed][aws] %s\n' "$*"
}

require_python() {
  if ! command -v python3 >/dev/null 2>&1; then
    log "python3 is required for connectivity checks; please install python3"
    exit 1
  fi
}

extract_host_port() {
  python3 - <<'PY' "$1"
import sys, urllib.parse
parsed = urllib.parse.urlparse(sys.argv[1])
host = parsed.hostname or "127.0.0.1"
port = parsed.port or (443 if parsed.scheme == "https" else 80)
print(f"{host} {port}")
PY
}

wait_for_port() {
  python3 - <<'PY' "$1" "$2"
import socket, sys, time
host, port = sys.argv[1], int(sys.argv[2])
deadline = time.time() + 60
while time.time() < deadline:
    try:
        with socket.create_connection((host, port), timeout=2):
            sys.exit(0)
    except OSError:
        time.sleep(1)
print(f"timeout waiting for {host}:{port}", file=sys.stderr)
sys.exit(1)
PY
}

ensure_aws_cli() {
  if command -v aws >/dev/null 2>&1; then
    return
  fi

  log "aws CLI not found; attempting installation via pip"
  if ! command -v python3 >/dev/null 2>&1; then
    log "python3 is required to install awscli automatically"
    exit 1
  fi

  python3 -m ensurepip --upgrade >/dev/null 2>&1 || true
  python3 -m pip install --user --upgrade awscli >/dev/null

  if ! command -v aws >/dev/null 2>&1; then
    export PATH="${HOME}/.local/bin:${PATH}"
    if ! command -v aws >/dev/null 2>&1; then
      log "failed to install awscli via pip; please install it manually"
      exit 1
    fi
  fi
}

require_python
ensure_aws_cli

AWS_ENDPOINT_URL="${AWS_ENDPOINT_URL:-http://127.0.0.1:4566}"
AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
export AWS_DEFAULT_REGION="$AWS_REGION"
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_SESSION_TOKEN="${AWS_SESSION_TOKEN:-test}"
export AWS_PAGER=""

read -r AWS_HOST AWS_PORT < <(extract_host_port "$AWS_ENDPOINT_URL")
log "waiting for LocalStack at ${AWS_HOST}:${AWS_PORT}"
wait_for_port "$AWS_HOST" "$AWS_PORT"

SECRET_NAME="${AWS_SEED_SECRET_NAME:-greentic/test/basic}"
SECRET_PAYLOAD='{"api_key":"localstack-demo-key","region":"us-east-1-pr"}'
SECRET_STAGE="${AWS_SEED_VERSION_STAGE:-pr-latest}"

log "seeding secret ${SECRET_NAME} at ${AWS_ENDPOINT_URL}"

if ! aws --endpoint-url "$AWS_ENDPOINT_URL" secretsmanager describe-secret --secret-id "$SECRET_NAME" >/dev/null 2>&1; then
  log "secret missing; creating"
  aws --endpoint-url "$AWS_ENDPOINT_URL" secretsmanager create-secret \
    --name "$SECRET_NAME" \
    --secret-string "$SECRET_PAYLOAD" \
    --tags Key=seeded-by,Value=greentic-pr \
    >/dev/null
else
  log "secret already exists"
fi

current_payload="$(aws --endpoint-url "$AWS_ENDPOINT_URL" secretsmanager get-secret-value \
  --secret-id "$SECRET_NAME" \
  --query SecretString \
  --output text 2>/dev/null || true)"

if [[ "$current_payload" == "$SECRET_PAYLOAD" ]]; then
  log "secret value already matches desired payload"
  exit 0
fi

log "upserting secret value and stamping version stage ${SECRET_STAGE}"
aws --endpoint-url "$AWS_ENDPOINT_URL" secretsmanager put-secret-value \
  --secret-id "$SECRET_NAME" \
  --secret-string "$SECRET_PAYLOAD" \
  --version-stages "$SECRET_STAGE" \
  >/dev/null

log "secret seeded successfully"
