#!/bin/bash
# Build script for ClawSec - cross-platform compilation

set -e

OPENSSL_MAC="/opt/homebrew/opt/openssl@3"
OPENSSL_LINUX="/usr"

echo "=== ClawSec Build Script ==="
echo ""

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    PLATFORM="macOS"
    OPENSSL_PATH="$OPENSSL_MAC"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    PLATFORM="Linux"
    OPENSSL_PATH="$OPENSSL_LINUX"
else
    echo "Unknown platform: $OSTYPE"
    exit 1
fi

echo "Platform: $PLATFORM"
echo "OpenSSL: $OPENSSL_PATH"
echo ""

# Clean
echo "[1/4] Cleaning old build..."
rm -f clawsec farm9crypt.o aesgcm.o

# Compile C++ modules
echo "[2/4] Compiling farm9crypt.cc..."
if [[ "$PLATFORM" == "macOS" ]]; then
    g++ -O -c farm9crypt.cc -I"$OPENSSL_PATH/include"
else
    g++ -O -c farm9crypt.cc
fi

echo "[3/4] Compiling aesgcm.cc..."
if [[ "$PLATFORM" == "macOS" ]]; then
    g++ -O -c aesgcm.cc -I"$OPENSSL_PATH/include"
else
    g++ -O -c aesgcm.cc
fi

# Link
echo "[4/4] Linking clawsec..."
if [[ "$PLATFORM" == "macOS" ]]; then
    cc -O -s -DGAPING_SECURITY_HOLE -I"$OPENSSL_PATH/include" \
       -o clawsec clawsec.c farm9crypt.o aesgcm.o \
       -L"$OPENSSL_PATH/lib" -lssl -lcrypto -lstdc++
else
    gcc -O -s -DGAPING_SECURITY_HOLE -DLINUX \
        -o clawsec clawsec.c farm9crypt.o aesgcm.o \
        -lssl -lcrypto -lstdc++
fi

echo ""
echo "✅ Build complete!"
echo ""
file clawsec
ls -lh clawsec
echo ""
echo "Test: ./clawsec --help"
