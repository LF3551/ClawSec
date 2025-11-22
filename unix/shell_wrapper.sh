#!/bin/bash
# PTY wrapper for clawsec -e mode
# Makes shell interactive with proper echo

# Option 1: Using script command (works on Linux/macOS)
if command -v script &> /dev/null; then
    # macOS version
    if [[ "$OSTYPE" == "darwin"* ]]; then
        script -q /dev/null bash -i
    else
        # Linux version
        script -qc "bash -i" /dev/null
    fi
else
    # Option 2: Using Python pty module
    python3 -c 'import pty; pty.spawn("/bin/bash")'
fi
