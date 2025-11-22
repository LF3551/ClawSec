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

### Send a file
```bash
# Receiver
./clawsec -l -p 8080 -k "SecureFile2025" > received.tar.gz

# Sender  
./clawsec 192.168.1.100 8080 -k "SecureFile2025" < backup.tar.gz
```

## Interactive Chat

Both sides can type interactively:

```bash
# Server
./clawsec -l -p 4444 -k "ChatPassword"

# Client
./clawsec server.example.com 4444 -k "ChatPassword"
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
./clawsec -l -p 5555 -k "Pass" -w 30
```

### UDP mode
```bash
./clawsec -l -p 6666 -k "Pass" -u
```

### Verbose debugging
```bash
./clawsec -l -p 7777 -k "Pass" -vv
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
