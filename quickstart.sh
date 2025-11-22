#!/bin/bash
# Quick Start Demo for ClawSec

set -e

echo "================================"
echo "ClawSec Quick Start Demo"
echo "================================"
echo ""

# Check if clawsec exists
if [[ ! -f "unix/clawsec" ]]; then
    echo "Building ClawSec..."
    cd unix
    make clean
    make linux
    cd ..
    echo "Build complete!"
    echo ""
fi

echo "This demo will:"
echo "1. Start a ClawSec server on port 9999"
echo "2. Send an encrypted message to it"
echo "3. Show you the decrypted output"
echo ""
read -p "Press Enter to continue..."

# Start server in background
echo ""
echo "Starting server..."
(timeout 5 ./unix/clawsec -l -p 9999 -k "DemoPassword123" > /tmp/clawsec_demo.txt 2>&1) &
SERVER_PID=$!

sleep 1

# Send message
echo "Sending encrypted message..."
echo "Hello from ClawSec! AES-256-GCM works!" | ./unix/clawsec -k "DemoPassword123" localhost 9999

sleep 1

# Show result
echo ""
echo "================================"
echo "Server received (decrypted):"
echo "================================"
cat /tmp/clawsec_demo.txt 2>/dev/null || echo "No output"
echo ""

# Cleanup
kill $SERVER_PID 2>/dev/null || true
rm -f /tmp/clawsec_demo.txt

echo "================================"
echo "Demo complete!"
echo "================================"
echo ""
echo "Try it yourself:"
echo "  Terminal 1: ./unix/clawsec -l -p 8888 -k 'YourPassword'"
echo "  Terminal 2: echo 'message' | ./unix/clawsec -k 'YourPassword' localhost 8888"
echo ""
echo "Documentation: README.md"
