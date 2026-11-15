#!/bin/bash
# ClawSec Installation Script

set -e

echo "==================================="
echo "ClawSec Installer"
echo "==================================="

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ "$OSTYPE" == "freebsd"* ]]; then
    OS="freebsd"
else
    echo "Unsupported OS: $OSTYPE"
    exit 1
fi

echo "Detected OS: $OS"

# Build dependencies: OpenSSL 3 headers, libargon2, zlib, C/C++ compiler
echo "Installing build dependencies..."
if [[ "$OS" == "linux" ]]; then
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y libssl-dev libargon2-dev zlib1g-dev build-essential
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y openssl-devel libargon2-devel zlib-devel gcc gcc-c++ make
    elif command -v yum &> /dev/null; then
        sudo yum install -y openssl-devel libargon2-devel zlib-devel gcc gcc-c++ make
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --needed --noconfirm openssl argon2 zlib gcc make
    elif command -v apk &> /dev/null; then
        sudo apk add openssl-dev argon2-dev zlib-dev gcc g++ make musl-dev linux-headers
    else
        echo "Please install OpenSSL 3, libargon2 and zlib development packages manually"
        exit 1
    fi
elif [[ "$OS" == "macos" ]]; then
    if command -v brew &> /dev/null; then
        brew install openssl@3 argon2
    else
        echo "Please install Homebrew first: https://brew.sh"
        exit 1
    fi
elif [[ "$OS" == "freebsd" ]]; then
    sudo pkg install -y libargon2
fi

# Build ClawSec
echo "Building ClawSec..."
cd src

if [[ "$OS" == "linux" ]]; then
    make clean
    make linux
elif [[ "$OS" == "macos" ]]; then
    make clean
    make macos
elif [[ "$OS" == "freebsd" ]]; then
    make clean
    make freebsd
fi

# Check if binary was created
if [[ ! -f "clawsec" ]]; then
    echo "Build failed!"
    exit 1
fi

echo "Build successful!"

# Install to system (optional)
read -p "Install to /usr/local/bin? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    sudo cp clawsec /usr/local/bin/
    sudo chmod +x /usr/local/bin/clawsec
    echo "Installed to /usr/local/bin/clawsec"
fi

echo ""
echo "==================================="
echo "Installation complete!"
echo "==================================="
echo ""
echo "Usage:"
echo "  Server: ./clawsec -l -p 8888 -k 'YourPassword'"
echo "  Client: echo 'data' | ./clawsec -k 'YourPassword' server-ip 8888"
echo ""
echo "Documentation: ../README.md"
