#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACK_DIR="${ROOT_DIR}/packs"

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
  manifest="${pack}/gtpack.yaml"
  meta="${pack}/metadata.json"
  cfg_schema="${pack}/schema/config.schema.json"
  sec_schema="${pack}/schema/secrets-required.schema.json"
  state_schema="${pack}/schema/state.schema.json"
  lock_file="${pack}/pack.lock"

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
  if [[ ! -f "${lock_file}" ]]; then
    echo "  [ERROR] missing pack.lock ${lock_file}" >&2; error=true
  fi

  for flow in "${required_flows[@]}"; do
    if [[ ! -f "${pack}/flows/${flow}" ]]; then
      echo "  [ERROR] missing flow ${flow}" >&2; error=true
    fi
  done

  # Basic manifest sanity with python (yaml required fields + provider ext).
  python3 - <<PY
import sys, yaml, json, pathlib
p = pathlib.Path("${manifest}")
data = yaml.safe_load(p.read_text())
required_entrypoints = ["onboard","validate","read_secret","write_secret","rotate_secret","export_audit","breakglass"]
missing = [e for e in required_entrypoints if e not in (data.get("entrypoints") or {})]
if missing:
    print(f"[ERROR] {p}: missing entrypoints {missing}")
    sys.exit(1)
components = data.get("components") or []
for comp in components:
    if not comp.get("id") or not comp.get("version"):
        print(f"[ERROR] {p}: component missing id/version: {comp}")
        sys.exit(1)
exts = (data.get("extensions") or {}).get("greentic.ext.provider") or {}
provider = exts.get("provider") or {}
runtime = provider.get("runtime") or {}
if runtime.get("world") != "greentic:provider-schema-core/schema-core@1.0.0":
    print(f"[ERROR] {p}: provider extension runtime.world must be greentic:provider-schema-core/schema-core@1.0.0")
    sys.exit(1)
if not runtime.get("component_ref") or not runtime.get("export"):
    print(f"[ERROR] {p}: provider extension runtime must set component_ref and export")
    sys.exit(1)
PY
done

if [[ "${error}" == "true" ]]; then
  echo "Pack validation failed" >&2
  exit 1
fi

echo "All packs validated."
