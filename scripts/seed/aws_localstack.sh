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

require_python

AWS_ENDPOINT_URL="${AWS_ENDPOINT_URL:-http://127.0.0.1:4566}"
AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
export AWS_DEFAULT_REGION="$AWS_REGION"
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_SESSION_TOKEN="${AWS_SESSION_TOKEN:-test}"
export AWS_PAGER=""

select_aws_client() {
  if command -v aws >/dev/null 2>&1; then
    local aws_path
    aws_path="$(command -v aws)"
    if [[ -n "$aws_path" && -x "$aws_path" ]]; then
      if "$aws_path" --version >/dev/null 2>&1; then
        AWS_CMD=("$aws_path")
        AWS_CMD_DESC="$aws_path"
        return
      fi
      log "aws CLI at ${aws_path} is present but failed to execute; falling back to awslocal"
    fi
    log "aws CLI resolved to ${aws_path:-unknown} but is not executable; falling back to awslocal"
  fi

  if ! command -v docker >/dev/null 2>&1; then
    log "aws CLI not found and docker unavailable to exec awslocal"
    exit 1
  fi

  if ! docker inspect greentic-localstack >/dev/null 2>&1; then
    log "aws CLI not found and greentic-localstack container missing; ensure make e2e-up ran"
    exit 1
  fi

  LOCALSTACK_CONTAINER="greentic-localstack"
  AWS_CMD=(
    docker exec
    -e AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID"
    -e AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY"
    -e AWS_SESSION_TOKEN="$AWS_SESSION_TOKEN"
    -e AWS_DEFAULT_REGION="$AWS_REGION"
    -e AWS_REGION="$AWS_REGION"
    "$LOCALSTACK_CONTAINER"
    awslocal
  )
  AWS_CMD_DESC="docker exec ${LOCALSTACK_CONTAINER} awslocal"
  log "aws CLI not found; using awslocal inside LocalStack container"
}

select_aws_client

read -r AWS_HOST AWS_PORT < <(extract_host_port "$AWS_ENDPOINT_URL")
log "waiting for LocalStack at ${AWS_HOST}:${AWS_PORT}"
if ! wait_for_port "$AWS_HOST" "$AWS_PORT"; then
  if [[ "${AWS_CMD[0]}" == "docker" && -n "${LOCALSTACK_CONTAINER:-}" ]]; then
    if ! docker inspect "$LOCALSTACK_CONTAINER" >/dev/null 2>&1; then
      log "LocalStack container ${LOCALSTACK_CONTAINER} not found; run 'make e2e-up' first."
    elif [[ "$(docker inspect -f '{{.State.Running}}' "$LOCALSTACK_CONTAINER")" != "true" ]]; then
      log "LocalStack container ${LOCALSTACK_CONTAINER} is not running; run 'make e2e-up' first."
    else
      log "LocalStack container ${LOCALSTACK_CONTAINER} is running but port ${AWS_PORT} is unreachable; check Docker port mapping."
    fi
  fi
  exit 1
fi

run_aws() {
  if [[ "${AWS_CMD[0]}" == "docker" ]]; then
    "${AWS_CMD[@]}" "$@"
  else
    "${AWS_CMD[@]}" --endpoint-url "$AWS_ENDPOINT_URL" "$@"
  fi
}

SECRET_NAME="${AWS_SEED_SECRET_NAME:-greentic/test/basic}"
SECRET_PAYLOAD='{"api_key":"localstack-demo-key","region":"us-east-1-pr"}'
SECRET_STAGE="${AWS_SEED_VERSION_STAGE:-pr-latest}"

if [[ -z "${AWS_CMD_DESC:-}" ]]; then
  AWS_CMD_DESC="${AWS_CMD[*]}"
fi

log "seeding secret ${SECRET_NAME} at ${AWS_ENDPOINT_URL} via ${AWS_CMD_DESC}"

if ! run_aws secretsmanager describe-secret --secret-id "$SECRET_NAME" >/dev/null 2>&1; then
  log "secret missing; creating"
  run_aws secretsmanager create-secret \
    --name "$SECRET_NAME" \
    --secret-string "$SECRET_PAYLOAD" \
    --tags Key=seeded-by,Value=greentic-pr \
    >/dev/null
else
  log "secret already exists"
fi

current_payload="$(run_aws secretsmanager get-secret-value \
  --secret-id "$SECRET_NAME" \
  --query SecretString \
  --output text 2>/dev/null || true)"

if [[ "$current_payload" == "$SECRET_PAYLOAD" ]]; then
  log "secret value already matches desired payload"
  exit 0
fi

log "upserting secret value and stamping version stage ${SECRET_STAGE}"
run_aws secretsmanager put-secret-value \
  --secret-id "$SECRET_NAME" \
  --secret-string "$SECRET_PAYLOAD" \
  --version-stages "$SECRET_STAGE" \
  >/dev/null

log "secret seeded successfully"
