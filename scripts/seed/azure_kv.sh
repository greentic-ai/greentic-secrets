#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '[seed][azure] %s\n' "$*"
}

require_python() {
  if ! command -v python3 >/dev/null 2>&1; then
    log "python3 is required for JSON encoding; please install python3"
    exit 1
  fi
}

require_python

BASE_URL="${AZURE_KEYVAULT_URI:-https://127.0.0.1:8080}"
API_VERSION="${AZURE_KEYVAULT_API_VERSION:-7.4}"

IS_HTTPS="$(AZURE_URL="$BASE_URL" python3 - <<'PY'
import os, urllib.parse
print('yes' if urllib.parse.urlparse(os.environ['AZURE_URL']).scheme == 'https' else 'no')
PY
)"

if [[ "$IS_HTTPS" == "yes" && "${AZURE_KEYVAULT_INSECURE_SKIP_VERIFY:-1}" != "0" ]]; then
  CURL_INSECURE="-k"
  log "TLS verification disabled for HTTPS requests (AZURE_KEYVAULT_INSECURE_SKIP_VERIFY)"
else
  CURL_INSECURE=""
fi

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

DEFAULT_BEARER_TOKEN="emulator"
AUTH_TOKEN="${AZURE_KEYVAULT_BEARER_TOKEN:-}"
AUTH_HEADER=()
if [[ -n "${AZURE_KEYVAULT_BEARER_TOKEN:-}" ]]; then
  log "using provided Azure bearer token"
fi

COMMON_HEADERS=(
  -H "Content-Type: application/json"
  -H "x-ms-keyvault-region: local"
  -H "x-ms-keyvault-service-version: 1.6.0.0"
)

http_request() {
  local method="$1"
  local url="$2"
  local data="${3:-}"
  local use_auth="${4:-yes}"
  local tmp
  tmp="$(mktemp)"

  local args=(curl)
  if [[ -n "$CURL_INSECURE" ]]; then
    args+=("$CURL_INSECURE")
  fi
  local headers=("${COMMON_HEADERS[@]}")
  if [[ "$use_auth" == "yes" ]]; then
    headers=("${AUTH_HEADER[@]}" "${headers[@]}")
  fi
  args+=(-sS -w '%{http_code}' -o "$tmp" -X "$method" "${headers[@]}" "$url")
  if [[ -n "$data" ]]; then
    args+=(-d "$data")
  fi

  local status
  status="$("${args[@]}")"
  HTTP_STATUS="$status"
  HTTP_BODY="$(cat "$tmp")"
  rm -f "$tmp"
}

fetch_stub_token() {
  local url="${BASE_URL%/}/token"
  HTTP_STATUS=""
  HTTP_BODY=""
  http_request GET "$url" "" "no"
  if [[ "$HTTP_STATUS" == "200" ]]; then
    printf '%s' "$HTTP_BODY"
    return 0
  fi
  log "failed to fetch stub token: HTTP ${HTTP_STATUS} ${HTTP_BODY}"
  return 1
}

ensure_secret() {
  local name="$1"
  local value="$2"
  local url="${BASE_URL%/}/secrets/${name}?api-version=${API_VERSION}"

  HTTP_STATUS=""
  HTTP_BODY=""
  http_request GET "$url"
  local status="$HTTP_STATUS"
  local body="$HTTP_BODY"

  if [[ "$status" == "200" ]]; then
    local existing
    existing="$(AZURE_EXISTING="$body" python3 - <<'PY'
import json, os, sys
payload = json.loads(os.environ["AZURE_EXISTING"])
print(payload.get("value", ""))
PY
)"
    if [[ "$existing" == "$value" ]]; then
      log "secret ${name} already up to date"
      return
    fi
    log "secret ${name} exists but value differs; updating via REST PUT"
  else
    log "secret ${name} missing (status ${status}); creating via REST PUT"
  fi

  local request_body
  request_body="$(AZURE_VALUE="$value" python3 - <<'PY'
import json, os
value = os.environ["AZURE_VALUE"]
print(json.dumps({
    "value": value,
    "attributes": {"enabled": True},
    "tags": {"seeded-by": "greentic-pr"}
}))
PY
)"

  HTTP_STATUS=""
  HTTP_BODY=""
  http_request PUT "$url" "$request_body"
  status="$HTTP_STATUS"
  body="$HTTP_BODY"
  if [[ "$status" != "200" ]]; then
    log "failed to seed ${name}: HTTP ${status} ${body}"
    exit 1
  fi
  log "secret ${name} seeded (HTTP ${status})"
}

log "seeding Azure Key Vault emulator at ${BASE_URL}"

read -r BASE_HOST BASE_PORT < <(extract_host_port "$BASE_URL")
log "waiting for emulator at ${BASE_HOST}:${BASE_PORT}"
wait_for_port "$BASE_HOST" "$BASE_PORT"

if [[ -z "$AUTH_TOKEN" ]]; then
  log "requesting stub token from emulator"
  if token="$(fetch_stub_token)"; then
    AUTH_TOKEN="$(printf '%s' "$token" | tr -d $'\r\n\"')"
    log "stub token acquired"
  else
    AUTH_TOKEN="$DEFAULT_BEARER_TOKEN"
    log "falling back to default bearer token (${DEFAULT_BEARER_TOKEN})"
  fi
fi

AUTH_HEADER=(-H "Authorization: Bearer ${AUTH_TOKEN}")

ensure_secret "kv-app-config" '{"db_user":"demo","db_pass":"demo-pass"}'
ensure_secret "kv-service-token" "service-token-local-pr"
ensure_secret "kv-feature-flag" '{"newUI":true,"rollout":42}'

log "Azure Key Vault emulator seeded successfully"
