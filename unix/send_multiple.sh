#!/bin/bash
# Script for sending multiple messages through ClawSec

SERVER="localhost"
PORT="8888"
PASSWORD="TestPass123"

# Create named pipe (FIFO)
FIFO="/tmp/clawsec_fifo_$$"
mkfifo "$FIFO"

# Start client in background with pipe
./clawsec -k "$PASSWORD" "$SERVER" "$PORT" < "$FIFO" &
CLIENT_PID=$!

# Open pipe for writing
exec 3>"$FIFO"

echo "Channel open! Enter messages (Ctrl+D to exit):"
echo ""

# Read lines and send to pipe
while IFS= read -r line; do
    echo "$line" >&3
    echo "[Sent] $line"
done

# Close pipe
exec 3>&-
rm -f "$FIFO"
kill $CLIENT_PID 2>/dev/null

echo "Channel closed."
