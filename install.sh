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

# Check for OpenSSL
if ! command -v openssl &> /dev/null; then
    echo "OpenSSL not found. Installing..."
    if [[ "$OS" == "linux" ]]; then
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y libssl-dev build-essential
        elif command -v yum &> /dev/null; then
            sudo yum install -y openssl-devel gcc gcc-c++ make
        else
            echo "Please install OpenSSL manually"
            exit 1
        fi
    elif [[ "$OS" == "macos" ]]; then
        if command -v brew &> /dev/null; then
            brew install openssl@3
        else
            echo "Please install Homebrew first: https://brew.sh"
            exit 1
        fi
    fi
else
    echo "OpenSSL found: $(openssl version)"
fi

# Build ClawSec
echo "Building ClawSec..."
cd unix

if [[ "$OS" == "linux" ]]; then
    make clean
    make linux
elif [[ "$OS" == "macos" ]]; then
    make clean
    make linux
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
