#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS_DIR="$ROOT/.v6-tools"
JAR="$TOOLS_DIR/tla2tools-1.7.4.jar"
URL="https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar"
EXPECTED_SHA1="bee4a54f3ee3d4afc347c3240ec2d9e93b075104"
EXPECTED_SHA256="936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"

mkdir -p "$TOOLS_DIR"

if [ ! -f "$JAR" ]; then
  curl -fsSL --retry 3 --retry-delay 2 "$URL" -o "$JAR"
fi

ACTUAL_SHA1="$(sha1sum "$JAR" | awk '{print $1}')"
if [ "$ACTUAL_SHA1" != "$EXPECTED_SHA1" ]; then
  echo "TLA+ tools digest mismatch: $ACTUAL_SHA1 != $EXPECTED_SHA1" >&2
  exit 2
fi

ACTUAL_SHA256="$(sha256sum "$JAR" | awk '{print $1}')"
if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
  echo "TLA+ tools SHA256 mismatch: $ACTUAL_SHA256 != $EXPECTED_SHA256" >&2
  exit 3
fi

echo "TLA+ tools v1.7.4 official SHA1 + observed locked SHA256: PASS"
echo "$ACTUAL_SHA256  $JAR"

(
  cd "$ROOT/formal"
  java -Xmx1g -cp "$JAR" tlc2.TLC -workers 1 -config PayoutSafety.cfg PayoutSafety.tla
  java -Xmx1g -cp "$JAR" tlc2.TLC -workers 1 -config ReleaseSafety.cfg ReleaseSafety.tla
)

echo "V6 TLA+/TLC model checking: PASS"
