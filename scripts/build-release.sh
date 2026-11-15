#!/usr/bin/env bash
#
# build-release.sh — build and package a ClawSec release for this platform.
#
# Usage: scripts/build-release.sh [VERSION]     (default: from src/version.h)
# Output: release-VERSION/clawsec-VERSION-<os>-<arch>.tar.gz (+ .sha256)
#
# The archive contains the binary, LICENSE, README.md, the man page and shell
# completions. Used by .github/workflows/release.yml, so local and CI release
# artifacts are built the same way. The binary is dynamically linked against
# OpenSSL 3, libargon2 and zlib (install them on the target system).
#
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
VERSION=${1:-$(sed -n 's/^#define CLAWSEC_VERSION "\(.*\)"/\1/p' "$ROOT/src/version.h")}
VERSION=${VERSION#v}

case "$(uname -s)" in
    Linux)  OS=linux;  TARGET=linux ;;
    Darwin) OS=macos;  TARGET=macos ;;
    *) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
    x86_64|amd64)  ARCH=x86_64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) ARCH=$(uname -m) ;;
esac

NAME="clawsec-$VERSION-$OS-$ARCH"
OUT="$ROOT/release-$VERSION"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

echo "Building ClawSec $VERSION for $OS/$ARCH"
make -C "$ROOT/src" clean >/dev/null
make -C "$ROOT/src" "$TARGET"

BUILT=$("$ROOT/src/clawsec" --version)
case "$BUILT" in
    "ClawSec $VERSION "*) ;;
    *) echo "version mismatch: binary reports '$BUILT', expected $VERSION" >&2; exit 1 ;;
esac

mkdir -p "$STAGE/$NAME/completions" "$OUT"
cp "$ROOT/src/clawsec" "$STAGE/$NAME/"
cp "$ROOT/LICENSE" "$ROOT/README.md" "$ROOT/docs/clawsec.1" "$STAGE/$NAME/"
cp "$ROOT"/completions/* "$STAGE/$NAME/completions/"

tar -C "$STAGE" -czf "$OUT/$NAME.tar.gz" "$NAME"
( cd "$OUT" && { command -v sha256sum >/dev/null && sha256sum "$NAME.tar.gz" || shasum -a 256 "$NAME.tar.gz"; } > "$NAME.tar.gz.sha256" )

echo "Created $OUT/$NAME.tar.gz"
cat "$OUT/$NAME.tar.gz.sha256"
