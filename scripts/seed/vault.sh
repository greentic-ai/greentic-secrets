#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '[seed][vault] %s\n' "$*"
}

require_python() {
  if ! command -v python3 >/dev/null 2>&1; then
    log "python3 is required for JSON encoding; please install python3"
    exit 1
  fi
}

require_python

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-root}"
VAULT_NAMESPACE="${VAULT_NAMESPACE:-}"

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

AUTH_HEADERS=(-H "X-Vault-Token: ${VAULT_TOKEN}" -H "Content-Type: application/json")
if [[ -n "$VAULT_NAMESPACE" ]]; then
  AUTH_HEADERS+=(-H "X-Vault-Namespace: ${VAULT_NAMESPACE}")
fi

http_request() {
  local method="$1"
  local url="$2"
  local data="${3:-}"
  local tmp
  tmp="$(mktemp)"

  local args=(curl -sS -w '%{http_code}' -o "$tmp" -X "$method" "${AUTH_HEADERS[@]}" "$url")
  if [[ -n "$data" ]]; then
    args+=(-d "$data")
  fi

  local status
  status="$("${args[@]}")"
  HTTP_STATUS="$status"
  HTTP_BODY="$(cat "$tmp")"
  rm -f "$tmp"
}

ensure_kv_mount() {
  local mount_url="${VAULT_ADDR%/}/v1/sys/mounts/secret"
  HTTP_STATUS=""
  HTTP_BODY=""
  http_request GET "$mount_url"
  if [[ "$HTTP_STATUS" == "200" ]]; then
    local mount_type
    mount_type="$(VAULT_MOUNT_JSON="$HTTP_BODY" python3 - <<'PY'
import json, os
data = json.loads(os.environ["VAULT_MOUNT_JSON"])
config = data.get("data", {})
print(config.get("type", ""))
PY
)"
    if [[ "$mount_type" == "kv" ]]; then
      log "kv-v2 engine already mounted at secret/"
      return
    fi
    log "secret/ mount exists but is type ${mount_type}; refusing to mutate automatically"
    exit 1
  fi

  log "mounting kv-v2 at secret/"
  local body
  body='{"type":"kv","options":{"version":"2"}}'
  http_request POST "$mount_url" "$body"
  if [[ "$HTTP_STATUS" != "204" ]]; then
    log "failed to mount kv-v2: HTTP ${HTTP_STATUS} ${HTTP_BODY}"
    exit 1
  fi
  log "kv-v2 engine mounted successfully"
}

vault_put() {
  local path="$1"
  local data_json="$2"
  local cas="${3:-}"

  local payload
  if [[ -n "$cas" ]]; then
    payload="$(VAULT_DATA="$data_json" VAULT_CAS="$cas" python3 - <<'PY'
import json, os
data = json.loads(os.environ["VAULT_DATA"])
cas = os.environ["VAULT_CAS"]
body = {"data": data}
if cas:
    body["options"] = {"cas": int(cas)}
print(json.dumps(body))
PY
)"
  else
    payload="$(VAULT_DATA="$data_json" python3 - <<'PY'
import json, os
data = json.loads(os.environ["VAULT_DATA"])
print(json.dumps({"data": data}))
PY
)"
  fi

  local url="${VAULT_ADDR%/}/v1/secret/data/${path}"
  http_request POST "$url" "$payload"
  if [[ "$HTTP_STATUS" != "200" ]]; then
    log "failed to write ${path}: HTTP ${HTTP_STATUS} ${HTTP_BODY}"
    exit 1
  fi
}

fetch_metadata() {
  local path="$1"
  local url="${VAULT_ADDR%/}/v1/secret/metadata/${path}"
  http_request GET "$url"
}

fetch_data_version() {
  local path="$1"
  local version="$2"
  local url="${VAULT_ADDR%/}/v1/secret/data/${path}"
  if [[ -n "$version" ]]; then
    url+="?version=${version}"
  fi
  http_request GET "$url"
}

ensure_secret_versions() {
  local path="$1"
  local v1_data="$2"
  local v2_data="$3"

  fetch_metadata "$path"

  local current_version=0
  if [[ "$HTTP_STATUS" == "200" ]]; then
    current_version="$(VAULT_META_JSON="$HTTP_BODY" python3 - <<'PY'
import json, os
data = json.loads(os.environ["VAULT_META_JSON"])
print(data.get("data", {}).get("current_version", 0))
PY
)"
  fi

  if (( current_version == 0 )); then
    log "initialising ${path} with version 1"
    vault_put "$path" "$v1_data" ""
    current_version=1
  fi

  if (( current_version == 1 )); then
    log "creating version 2 for ${path}"
    vault_put "$path" "$v2_data" "1"
    current_version=2
  fi

  if (( current_version >= 2 )); then
    fetch_data_version "$path" ""
    if [[ "$HTTP_STATUS" != "200" ]]; then
      log "failed to read latest version for ${path}: HTTP ${HTTP_STATUS} ${HTTP_BODY}"
      exit 1
    fi
    local latest_data
    latest_data="$(VAULT_DATA_JSON="$HTTP_BODY" python3 - <<'PY'
import json, os
data = json.loads(os.environ["VAULT_DATA_JSON"])
print(json.dumps(data.get("data", {}).get("data", {}), sort_keys=True))
PY
)"

    local expected_latest
    expected_latest="$(EXPECTED_JSON="$v2_data" python3 - <<'PY'
import json, os
data = json.loads(os.environ["EXPECTED_JSON"])
print(json.dumps(data, sort_keys=True))
PY
)"

    if [[ "$latest_data" != "$expected_latest" ]]; then
      log "latest version for ${path} differs; writing reconciliation version (CAS ${current_version})"
      vault_put "$path" "$v2_data" "$current_version"
    else
      log "latest version for ${path} already matches desired payload"
    fi
  fi
}

log "seeding Vault dev server at ${VAULT_ADDR}"
read -r VAULT_HOST VAULT_PORT < <(extract_host_port "$VAULT_ADDR")
log "waiting for Vault at ${VAULT_HOST}:${VAULT_PORT}"
wait_for_port "$VAULT_HOST" "$VAULT_PORT"
ensure_kv_mount

ensure_secret_versions "greentic/app" \
  '{"api_key":"vault-app-0001","feature":"alpha","version":"v1"}' \
  '{"api_key":"vault-app-0002","feature":"beta","version":"v2"}'

ensure_secret_versions "greentic/analytics" \
  '{"token":"vault-analytics-0001","mode":"read-only"}' \
  '{"token":"vault-analytics-0002","mode":"read-write"}'

log "Vault secrets seeded successfully"
