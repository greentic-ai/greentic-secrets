#!/usr/bin/env bash
set -euo pipefail

# -------- CONFIG --------
NEW_VERSION="${1:-}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -z "${NEW_VERSION}" ]]; then
  echo "Usage: scripts/release.sh X.Y.Z"
  exit 1
fi

echo "==> Releasing workspace version ${NEW_VERSION}"

# Tools we use (install if missing)
need() { command -v "$1" >/dev/null 2>&1 || (echo "Missing $1"; exit 2); }
need cargo
need git
need jq

# Optional helpers (we try to install if missing)
if ! command -v cargo-workspaces >/dev/null 2>&1; then
  echo "Installing cargo-workspaces..."
  cargo install cargo-workspaces --locked
fi
if ! command -v git-cliff >/dev/null 2>&1; then
  echo "Installing git-cliff..."
  cargo install git-cliff --locked
fi

# Verify clean tree
cd "${REPO_ROOT}"
if [[ -n "$(git status --porcelain)" ]]; then
  echo "Working tree is not clean. Commit or stash changes first."
  exit 3
fi

# -------- STEP 1: bump versions across all crates --------
echo "==> Bumping versions to ${NEW_VERSION} (updates inter-crate deps too)"
# This bumps all publishable packages AND updates dependent version fields.
cargo workspaces version custom "${NEW_VERSION}" \
  --force '*' \
  --no-git-commit \
  --exact \
  --yes

# -------- STEP 2: regenerate lock & build to sanity check --------
echo "==> Building workspace"
cargo update
cargo build --workspace --all-features

# Optional: ensure every publishable crate can be packaged
echo "==> Packaging dry-run"
fail=0
for PKG in $(cargo metadata --format-version 1 | jq -r '.packages[] | select(.publish != ["false"]) | .name'); do
  echo "  - $PKG"
  if ! cargo package -p "$PKG" --allow-dirty >/dev/null; then
    echo "Packaging failed for $PKG"
    fail=1
  fi
done
if [[ $fail -ne 0 ]]; then
  echo "One or more crates failed to package"; exit 4
fi

# -------- STEP 3: update CHANGELOG.md with git-cliff --------
# Use conventional commits; adjust cliff.toml if you have one.
if [[ -f cliff.toml ]]; then
  git cliff --tag "v${NEW_VERSION}" -o CHANGELOG.md
else
  cat > cliff.toml <<'EOF'
[git]
filter_unconventional = true

[changelog]
header = "# Changelog"
body   = """
{% for group, commits in commits | group_by(attribute="group") %}
### {{ group | upper_first }}
{% for commit in commits %}
- {{ commit.message | split(pat="\n") | first }} ({{ commit.id | truncate(length=7) }})
{% endfor %}
{% endfor %}
"""
footer = ""
trim = true
EOF
  git cliff --tag "v${NEW_VERSION}" -o CHANGELOG.md
fi

# -------- STEP 4: commit & tag --------
echo "==> Committing version bump and CHANGELOG"
git add -A
git commit -m "chore(release): v${NEW_VERSION}"
git tag "v${NEW_VERSION}"

# -------- STEP 5: push to trigger GitHub Action publish --------
echo "==> Pushing tag to trigger publish workflow"
git push origin HEAD
git push origin "v${NEW_VERSION}"

echo "==> Done. CI will publish in topological order."
echo "    Track progress under Actions → 'Publish crates (workspace)'."
