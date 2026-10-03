#!/usr/bin/env bash
set -euo pipefail

CORE_DIR="$1"
cd "$CORE_DIR"

VERSION="$(python3 -c 'import pathlib,re; t=pathlib.Path("scripts/patch_upstream.py").read_text(); m=re.search(r"^WAM_CLIENT_VERSION\s*=\s*\"([^\"]+)\"", t, re.M); print(m.group(1))')"
test -n "$VERSION"

ROOT_TMP="$RUNNER_TEMP"
OUT1="$ROOT_TMP/v5-release-one"
OUT2="$ROOT_TMP/v5-release-two"
WORK="$ROOT_TMP/v5-package-work"
X1="$ROOT_TMP/v5-extract-one"
X2="$ROOT_TMP/v5-extract-two"

rm -rf "$OUT1" "$OUT2" "$WORK" "$X1" "$X2"
mkdir -p "$OUT1" "$OUT2" "$X1" "$X2"

echo "Packaging current WAM release twice from the same built node tree"
echo "version: v$VERSION"

OUT="$OUT1" WORK="$WORK" bash scripts/package_release.sh --version "v$VERSION" >/tmp/v5-package-one.log
NODE1="$(find "$OUT1" -maxdepth 1 -name 'wam-coin-*.tar.gz' -type f | head -1)"
test -n "$NODE1"

sleep 2

OUT="$OUT2" WORK="$WORK" bash scripts/package_release.sh --version "v$VERSION" >/tmp/v5-package-two.log
NODE2="$(find "$OUT2" -maxdepth 1 -name 'wam-coin-*.tar.gz' -type f | head -1)"
test -n "$NODE2"

SHA1="$(sha256sum "$NODE1" | awk '{print $1}')"
SHA2="$(sha256sum "$NODE2" | awk '{print $1}')"

echo "first  node archive: $SHA1"
echo "second node archive: $SHA2"

if [ "$SHA1" = "$SHA2" ]; then
  echo "Current WAM release archive unexpectedly became byte-reproducible."
  echo "Review WS-SC-104 before changing the V5 baseline."
  exit 3
fi

tar -xzf "$NODE1" -C "$X1"
tar -xzf "$NODE2" -C "$X2"

(
  cd "$X1"
  find . -type f -print0 | sort -z | xargs -0 sha256sum
) > "$ROOT_TMP/v5-logical-one.sha256"

(
  cd "$X2"
  find . -type f -print0 | sort -z | xargs -0 sha256sum
) > "$ROOT_TMP/v5-logical-two.sha256"

if ! diff -u "$ROOT_TMP/v5-logical-one.sha256" "$ROOT_TMP/v5-logical-two.sha256"; then
  echo "The two package runs changed logical file bytes, not only archive metadata."
  echo "That is a stronger reproducibility regression and needs separate review."
  exit 4
fi

echo "V5 current WAM packaging probe: PASS"
echo "  logical payload bytes: identical"
echo "  release tar.gz bytes : different"
echo "  WS-SC-104 reproduced : yes"
