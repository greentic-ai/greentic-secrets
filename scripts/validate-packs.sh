#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACK_DIR="${ROOT_DIR}/packs"
PROVIDER_EXTENSION_ID="greentic.provider-extension.v1"

required_flows=(
  provider_onboard.ygtc
  provider_validate.ygtc
  provider_read_secret.ygtc
  provider_write_secret.ygtc
  provider_rotate_secret.ygtc
  provider_export_audit.ygtc
  provider_breakglass.ygtc
)

error=false

for pack in "${PACK_DIR}"/*; do
  [[ -d "${pack}" ]] || continue
  name=$(basename "${pack}")
  manifest="${pack}/pack.yaml"
  meta="${pack}/metadata.json"
  cfg_schema="${pack}/schema/config.schema.json"
  sec_schema="${pack}/schema/secrets-required.schema.json"
  state_schema="${pack}/schema/state.schema.json"

  echo "Validating pack ${name}"

  if [[ ! -f "${manifest}" ]]; then
    echo "  [ERROR] missing manifest ${manifest}" >&2; error=true; continue
  fi
  if [[ ! -f "${meta}" ]]; then
    echo "  [ERROR] missing metadata ${meta}" >&2; error=true
  fi
  if [[ ! -f "${cfg_schema}" || ! -f "${sec_schema}" ]]; then
    echo "  [ERROR] missing schema files in ${pack}/schema" >&2; error=true
  fi
  if [[ ! -f "${state_schema}" ]]; then
    echo "  [WARN] missing state schema (optional) ${state_schema}" >&2
  fi
  for flow in "${required_flows[@]}"; do
    if [[ ! -f "${pack}/flows/${flow}" ]]; then
      echo "  [ERROR] missing flow ${flow}" >&2; error=true
    fi
  done

  # Basic manifest sanity with python (yaml required fields + provider ext).
  python3 - <<PY
import sys, yaml, pathlib
EXT_ID = "${PROVIDER_EXTENSION_ID}"
p = pathlib.Path("${manifest}")
data = yaml.safe_load(p.read_text())
required_entrypoints = ["onboard","validate","read_secret","write_secret","rotate_secret","export_audit","breakglass"]
flow_entrypoints = set()
for flow in data.get("flows") or []:
    for entry in flow.get("entrypoints") or []:
        flow_entrypoints.add(entry)
missing = [e for e in required_entrypoints if e not in flow_entrypoints]
if missing:
    print(f"[ERROR] {p}: missing entrypoints {missing}")
    sys.exit(1)
exts = (data.get("extensions") or {}).get(EXT_ID) or {}
if not exts:
    print(f"[ERROR] {p}: missing extensions.{EXT_ID}")
    sys.exit(1)
kind = exts.get("kind")
if kind != EXT_ID:
    print(f"[ERROR] {p}: provider extension kind must be {EXT_ID}, got {kind!r}")
    sys.exit(1)
version = exts.get("version")
if version != "1.0.0":
    print(f"[ERROR] {p}: provider extension version must be 1.0.0")
    sys.exit(1)
inline = exts.get("inline") or {}
providers = inline.get("providers") or []
if not providers:
    print(f"[ERROR] {p}: provider extension inline.providers missing")
    sys.exit(1)
runtime = (providers[0] or {}).get("runtime") or {}
if runtime.get("world") != "greentic:provider/schema-core@1.0.0":
    print(f"[ERROR] {p}: provider extension runtime.world must be greentic:provider/schema-core@1.0.0")
    sys.exit(1)
if not runtime.get("component_ref") or not runtime.get("export"):
    print(f"[ERROR] {p}: provider extension runtime must set component_ref and export")
    sys.exit(1)
config_ref = providers[0].get("config_schema_ref")
if config_ref != "assets/schema/config.schema.json":
    print(f"[ERROR] {p}: provider extension config_schema_ref must be assets/schema/config.schema.json")
    sys.exit(1)
PY
done

if [[ "${error}" == "true" ]]; then
  echo "Pack validation failed" >&2
  exit 1
fi

echo "All packs validated."
