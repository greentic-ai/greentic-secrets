#!/usr/bin/env bash
set -euo pipefail

# Build enterprise provider .gtpack bundles from ./packs/<provider>.
# Supports optional airgapped embedding via PACK_AIRGAPPED=1 (expects WASM artifacts present).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT_DIR/target/provider-packs"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
DIGESTS_JSON="$ROOT_DIR/target/components/digests.json"

VERSION="$(python3 - <<'PY'
import re
from pathlib import Path
text = Path("Cargo.toml").read_text()
match = re.search(r'\[workspace\.package\].*?^version\s*=\s*"([^"]+)"', text, re.M | re.S)
if not match:
    raise SystemExit("workspace.package.version not found")
print(match.group(1))
PY
)"

providers=(
  aws-sm
  azure-kv
  gcp-sm
  k8s
  vault-kv
)

bundle_staging="${OUT_DIR}/secrets-providers"
rm -rf "${bundle_staging}"
mkdir -p "${bundle_staging}"

echo "Building provider packs for version ${VERSION}"

for slug in "${providers[@]}"; do
  src="${ROOT_DIR}/packs/${slug}"
  if [[ ! -d "${src}" ]]; then
    echo "missing pack source: ${src}" >&2
    exit 1
  fi

  staging="${OUT_DIR}/secrets-${slug}"
  rm -rf "${staging}"
  mkdir -p "${staging}"

  rsync -a "${src}/" "${staging}/"

  # Inject version into manifest if placeholder present.
  if grep -q '__PACK_VERSION__' "${staging}/gtpack.yaml"; then
    sed -i.bak "s/__PACK_VERSION__/${VERSION}/g" "${staging}/gtpack.yaml"
    rm -f "${staging}/gtpack.yaml.bak"
  fi

  # If digests are available, rewrite component URIs to pin them.
  if [[ -f "${DIGESTS_JSON}" ]]; then
    tmp="${staging}/gtpack.tmp.yaml"
    python3 - "$DIGESTS_JSON" "$staging/gtpack.yaml" > "${tmp}" <<'PY'
import json, sys, yaml
digests = {d["id"]: d for d in json.load(open(sys.argv[1]))}
manifest = yaml.safe_load(open(sys.argv[2]))
for comp in manifest.get("components", []):
    did = comp.get("id")
    d = digests.get(did)
    if d:
        comp["uri"] = f"{d['ref']}@sha256:{d['digest']}"
yaml.safe_dump(manifest, sys.stdout, sort_keys=False)
PY
    mv "${tmp}" "${staging}/gtpack.yaml"
  fi

  # Handle airgapped embedding (expected to already include wasm under components/).
  if [[ "${PACK_AIRGAPPED:-0}" == "1" ]]; then
    if [[ -f "${staging}/components.manifest.json" ]]; then
      mv "${staging}/components.manifest.json" "${staging}/components/components.manifest.json"
    fi
  else
    rm -rf "${staging}/components"
  fi

  # Create pack.lock capturing component pins.
  if [[ -f "${DIGESTS_JSON}" ]]; then
    python3 - "$DIGESTS_JSON" "$staging/gtpack.yaml" > "${staging}/pack.lock" <<'PY'
import json, sys, yaml
digests = {d["id"]: d for d in json.load(open(sys.argv[1]))}
manifest = yaml.safe_load(open(sys.argv[2]))
print("components:")
for comp in manifest.get("components", []):
    did = comp.get("id")
    d = digests.get(did, {})
    uri = comp.get("uri", "")
    digest = d.get("digest")
    if digest and "@" not in uri:
        uri = f"{uri}@sha256:{digest}"
    print(f"  - id: {comp.get('id')}")
    print(f"    version: {comp.get('version')}")
    print(f"    source: {comp.get('source')}")
    if uri:
        print(f"    uri: {uri}")
    if digest:
        print(f"    digest: sha256:{digest}")
PY
  else
    python3 - "$staging/gtpack.yaml" > "${staging}/pack.lock" <<'PY'
import sys, yaml
manifest = yaml.safe_load(open(sys.argv[1]))
print("components:")
for comp in manifest.get("components", []):
    print(f"  - id: {comp.get('id')}")
    print(f"    version: {comp.get('version')}")
    print(f"    source: {comp.get('source')}")
    uri = comp.get("uri")
    if uri:
        print(f"    uri: {uri}")
PY
  fi

  (cd "${OUT_DIR}" && zip -qr "secrets-${slug}.gtpack" "secrets-${slug}")
  echo "::notice::built pack secrets-${slug}.gtpack"

  # Include in bundle deps.
  echo "  - id: greentic.secrets.${slug}" >> "${bundle_staging}/deps.tmp"
done

echo "${VERSION}" > "${OUT_DIR}/VERSION"

# Build bundle manifest (depends on per-provider packs)
cat >"${bundle_staging}/gtpack.yaml" <<EOF
schema_version: pack-v1
id: greentic.secrets.providers
version: "${VERSION}"
name: "Greentic secrets providers bundle"
description: "Aggregate pack that depends on all provider packs."
kind: bundle
dependencies:
$(sed 's/^/  /' "${bundle_staging}/deps.tmp")
EOF
rm -f "${bundle_staging}/deps.tmp"

(cd "${OUT_DIR}" && zip -qr "secrets-providers.gtpack" "secrets-providers")
echo "::notice::built bundle pack secrets-providers.gtpack"
