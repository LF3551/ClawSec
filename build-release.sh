#!/bin/bash
# Build release binaries for multiple platforms

VERSION=${1:-"2.0.0"}
RELEASE_DIR="release-$VERSION"

echo "Building ClawSec v$VERSION"

mkdir -p "$RELEASE_DIR"

# Linux x86_64
echo "Building for Linux x86_64..."
cd unix
make clean
make linux
tar czf "../$RELEASE_DIR/clawsec-$VERSION-linux-x86_64.tar.gz" clawsec
cd ..

# macOS (if on macOS)
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "Building for macOS..."
    cd unix
    make clean
    make linux
    tar czf "../$RELEASE_DIR/clawsec-$VERSION-macos.tar.gz" clawsec
    cd ..
fi

# Create checksums
cd "$RELEASE_DIR"
shasum -a 256 * > SHA256SUMS
cd ..

echo ""
echo "Release built in: $RELEASE_DIR/"
echo "Files:"
ls -lh "$RELEASE_DIR/"
