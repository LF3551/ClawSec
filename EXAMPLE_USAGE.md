# ClawSec Usage Examples

## Quick Test

### Terminal 1 (Server):
```bash
cd unix
./cryptcat -l -p 9999 -k "TestPassword123!" -v
```

### Terminal 2 (Client):
```bash
cd unix
echo "Hello encrypted world!" | ./cryptcat localhost 9999 -k "TestPassword123!" -v
```

## File Transfer

### Send a file:
```bash
# Receiver
./cryptcat -l -p 8080 -k "SecureFile2025" > received.tar.gz

# Sender  
./cryptcat 192.168.1.100 8080 -k "SecureFile2025" < backup.tar.gz
```

## Chat Mode

Both sides can type interactively:

```bash
# Server
./cryptcat -l -p 4444 -k "ChatPassword"

# Client
./cryptcat server.example.com 4444 -k "ChatPassword"
```

## Common Mistakes

❌ **Wrong**: Missing -k option
```bash
./cryptcat -l -p 1234
# ERROR: Encryption password required!
```

❌ **Wrong**: Password mismatch
```bash
# Server
./cryptcat -l -p 1234 -k "Password1"

# Client  
./cryptcat localhost 1234 -k "Password2"
# ERROR: Decryption/authentication failed
```

✅ **Correct**: Same password on both sides
```bash
# Server
./cryptcat -l -p 1234 -k "SamePassword123!"

# Client
./cryptcat localhost 1234 -k "SamePassword123!"
```

## Advanced Options

### With timeout:
```bash
./cryptcat -l -p 5555 -k "Pass" -w 30  # 30 second timeout
```

### UDP mode:
```bash
./cryptcat -l -p 6666 -k "Pass" -u  # UDP instead of TCP
```

### Verbose debugging:
```bash
./cryptcat -l -p 7777 -k "Pass" -vv  # Double verbose
```

## Security Notes

1. **Never use default passwords** like "metallica"
2. **Always use strong passwords**: minimum 12 characters
3. **Share passwords securely** (Signal, encrypted email, etc.)
4. **Clear history** after use: `history -c`
5. **Use environment variables** for automation:
   ```bash
   export CLAW_PASS="YourSecurePassword"
   ./cryptcat -l -p 1234 -k "$CLAW_PASS"
   ```
