#!/usr/bin/env bash
set -euo pipefail

# Build secrets validator .gtpack bundle from ./validators/secrets using packc.

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

for file in gtpack.yaml pack.yaml; do
  if [[ -f "${staging}/${file}" ]] && grep -q '__PACK_VERSION__' "${staging}/${file}"; then
    sed -i.bak "s/__PACK_VERSION__/${VERSION}/g" "${staging}/${file}"
    rm -f "${staging}/${file}.bak"
  fi
done

LOCK_FILE="${staging}/pack.lock.json"
greentic-pack resolve --in "${staging}" --lock "${LOCK_FILE}" --offline
greentic-pack build \
  --in "${staging}" \
  --lock "${LOCK_FILE}" \
  --gtpack-out "${OUT_DIR}/validators-secrets.gtpack" \
  --bundle none \
  --offline \
  --allow-oci-tags

greentic-pack doctor \
  --pack "${OUT_DIR}/validators-secrets.gtpack" \
  --offline \
  --allow-oci-tags

echo "::notice::built pack validators-secrets.gtpack"
