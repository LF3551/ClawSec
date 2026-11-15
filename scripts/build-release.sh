#!/usr/bin/env bash
#
# build-release.sh — build and package a ClawSec release for this platform.
#
# Usage: scripts/build-release.sh [VERSION] [--binary PATH]
#   VERSION         default: from src/version.h
#   --binary PATH   package an already built binary instead of building one
#                   (CI builds the static Linux binary in an Alpine container)
# Output: release-VERSION/clawsec-VERSION-<os>-<arch>.tar.gz (+ .sha256)
#
# The archive contains the binary, LICENSE, README.md, the man page and shell
# completions. Used by .github/workflows/release.yml, so local and CI release
# artifacts are packaged the same way.
#
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
VERSION=""
BINARY=""
while [ $# -gt 0 ]; do
    case "$1" in
        --binary) BINARY=$(cd "$(dirname "$2")" && pwd)/$(basename "$2"); shift 2 ;;
        *) VERSION=$1; shift ;;
    esac
done
[ -n "$VERSION" ] || VERSION=$(sed -n 's/^#define CLAWSEC_VERSION "\(.*\)"/\1/p' "$ROOT/src/version.h")
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

if [ -z "$BINARY" ]; then
    echo "Building ClawSec $VERSION for $OS/$ARCH"
    make -C "$ROOT/src" clean >/dev/null
    make -C "$ROOT/src" "$TARGET"
    BINARY="$ROOT/src/clawsec"
fi

BUILT=$("$BINARY" --version)
case "$BUILT" in
    "ClawSec $VERSION "*) ;;
    *) echo "version mismatch: binary reports '$BUILT', expected $VERSION" >&2; exit 1 ;;
esac

mkdir -p "$STAGE/$NAME/completions" "$OUT"
cp "$BINARY" "$STAGE/$NAME/clawsec"
cp "$ROOT/LICENSE" "$ROOT/README.md" "$ROOT/docs/clawsec.1" "$STAGE/$NAME/"
cp "$ROOT"/completions/* "$STAGE/$NAME/completions/"

tar -C "$STAGE" -czf "$OUT/$NAME.tar.gz" "$NAME"
( cd "$OUT" && { command -v sha256sum >/dev/null && sha256sum "$NAME.tar.gz" || shasum -a 256 "$NAME.tar.gz"; } > "$NAME.tar.gz.sha256" )

echo "Created $OUT/$NAME.tar.gz"
cat "$OUT/$NAME.tar.gz.sha256"
