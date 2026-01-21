#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACK_DIR="${ROOT_DIR}/packs"
PROVISION_BIN="${GREENTIC_PROVISION_CLI:-greentic-provision}"

error=false

for pack in "${PACK_DIR}"/*; do
  [[ -d "${pack}" ]] || continue
  slug=$(basename "${pack}")
  fixture_dir="${pack}/fixtures"
  pack_json="${pack}/pack.json"
  if [[ ! -d "${fixture_dir}" ]]; then
    echo "[ERROR] missing fixtures dir for ${slug}" >&2
    error=true
    continue
  fi
  for file in requirements.expected.json setup.input.json setup.expected.plan.json; do
    if [[ ! -f "${fixture_dir}/${file}" ]]; then
      echo "[ERROR] missing fixture ${fixture_dir}/${file}" >&2
      error=true
    fi
  done
  if [[ ! -f "${pack_json}" ]]; then
    echo "[ERROR] missing pack.json for ${slug}" >&2
    error=true
    continue
  fi

  pack_id=$(python3 - <<PY
import json
from pathlib import Path
pack = json.loads(Path("${pack_json}").read_text())
print(pack.get("id", ""))
PY
)
  if [[ -z "${pack_id}" ]]; then
    echo "[ERROR] missing pack id in ${pack_json}" >&2
    error=true
    continue
  fi

  output_json=$(mktemp)
  if ! "${PROVISION_BIN}" dry-run setup \
    --executor wasm \
    --pack "${pack}" \
    --provider-id "${pack_id}" \
    --install-id "${pack_id}-fixture" \
    --public-base-url "https://example.invalid" \
    --answers "${fixture_dir}/setup.input.json" \
    --json >"${output_json}"; then
    echo "[ERROR] provision dry-run failed for ${slug}" >&2
    error=true
    rm -f "${output_json}"
    continue
  fi

  python3 - <<PY || error=true
import json
from pathlib import Path

pack_dir = Path("${pack}")
fixture_dir = Path("${fixture_dir}")

output = json.loads(Path("${output_json}").read_text())
expected_plan = json.loads((fixture_dir / "setup.expected.plan.json").read_text())
plan = output.get("plan")
if plan != expected_plan:
    raise SystemExit(f"plan mismatch for {pack_dir.name}")

requirements = json.loads((fixture_dir / "requirements.expected.json").read_text())
answers = json.loads((fixture_dir / "setup.input.json").read_text())

required_config = set(requirements.get("config", {}).get("required", []))
required_secrets = set(requirements.get("secrets", {}).get("required", []))
enum_constraints = requirements.get("config", {}).get("constraints", {}).get("enum", {})
if not requirements.get("provider_id"):
    raise SystemExit(f"missing provider_id in requirements for {pack_dir.name}")
config_values = answers.get("config", {})
secrets_values = answers.get("secrets", {})
missing_config = [key for key in required_config if not config_values.get(key)]
missing_secrets = [key for key in required_secrets if not secrets_values.get(key)]
if missing_config or missing_secrets:
    raise SystemExit(f"missing required fields for {pack_dir.name}: config={missing_config}, secrets={missing_secrets}")
for key, allowed in enum_constraints.items():
    if key in config_values and config_values[key] not in allowed:
        raise SystemExit(f"invalid enum for {pack_dir.name}: {key}={config_values[key]}")

# Ensure secrets patch is redacted.
secrets_patch = (plan or {}).get("secrets_patch", {})
for key, value in (secrets_patch.get("set") or {}).items():
    if not value.get("redacted") or value.get("value") is not None:
        raise SystemExit(f"secret not redacted for {pack_dir.name}: {key}")

# Ensure no secret values appear in output.
setup_input = json.loads((fixture_dir / "setup.input.json").read_text())
secret_values = list((setup_input.get("secrets") or {}).values())
raw = json.dumps(output)
for secret in secret_values:
    if not secret:
        continue
    if secret in raw:
        raise SystemExit(f"secret leaked in output for {pack_dir.name}")
PY

  rm -f "${output_json}"
  echo "[OK] ${slug} provisioning fixtures"
done

if [[ "${error}" == "true" ]]; then
  echo "Provisioning fixture validation failed" >&2
  exit 1
fi
