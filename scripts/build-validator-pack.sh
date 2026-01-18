#!/usr/bin/env bash
set -euo pipefail

# Build secrets validator .gtpack bundle from ./validators/secrets.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/dist"
rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

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

src="${ROOT_DIR}/validators/secrets"
if [[ ! -d "${src}" ]]; then
  echo "missing pack source: ${src}" >&2
  exit 1
fi

staging="${OUT_DIR}/validators-secrets"
rm -rf "${staging}"
mkdir -p "${staging}"
rsync -a "${src}/" "${staging}/"

if grep -q '__PACK_VERSION__' "${staging}/gtpack.yaml"; then
  sed -i.bak "s/__PACK_VERSION__/${VERSION}/g" "${staging}/gtpack.yaml"
  rm -f "${staging}/gtpack.yaml.bak"
fi

DIGESTS_JSON="${ROOT_DIR}/target/validators/digests.json"
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

(cd "${OUT_DIR}" && zip -qr "validators-secrets.gtpack" "validators-secrets")
echo "::notice::built pack validators-secrets.gtpack"
