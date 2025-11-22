# ClawSec

**Modern, secure, and minimalist encrypted network tool** — evolved from Cryptcat with state-of-the-art cryptography.

## 🔐 Security Features

- **AES-256-GCM**: Authenticated encryption with integrity verification
- **PBKDF2**: Password-based key derivation (100,000 iterations)
- **Secure Random IV**: Cryptographically strong per-message randomization
- **Protocol Versioning**: Future-proof message format
- **Memory Safety**: Secure key wiping and resource cleanup

## 🚀 Quick Start

### Build

```bash
cd unix
make linux    # or: make freebsd, make netbsd, make solaris, etc.
```

### Basic Usage

```bash
# Listen mode (server)
./cryptcat -l -p 1234 -k "YourStrongPassword123!"

# Connect mode (client)
./cryptcat <server-ip> 1234 -k "YourStrongPassword123!"
```

### File Transfer

```bash
# Receiver
./cryptcat -l -p 9999 -k "SecureTransfer2025" > received_file.txt

# Sender
./cryptcat <receiver-ip> 9999 -k "SecureTransfer2025" < file_to_send.txt
```

## 📋 Requirements

- **OpenSSL 3.x**: For AES-GCM encryption
- **GCC/G++**: C++11 or later
- **POSIX System**: Linux, *BSD, macOS, Solaris, etc.

### Install OpenSSL on macOS

```bash
brew install openssl@3
```

### Install OpenSSL on Linux

```bash
# Debian/Ubuntu
sudo apt-get install libssl-dev

# RedHat/CentOS
sudo yum install openssl-devel
```

## 🔧 Usage Options

```
Usage: cryptcat [options] hostname port
       cryptcat -l -p port [options]

Required:
  -k password       Encryption password (REQUIRED, min 8 chars recommended)

Connection:
  -l                Listen mode for inbound connections
  -p port           Local port number
  -s addr           Local source address

Security:
  -v                Verbose mode (shows encryption details)
  -n                Numeric-only IP addresses (no DNS)

Advanced:
  -i secs           Delay interval for lines/ports
  -w secs           Timeout for connects and final reads
  -z                Zero-I/O mode (port scanning)
  -o file           Hex dump of traffic to file
  -u                UDP mode
  -e prog           Execute program (DANGEROUS - compile with -DGAPING_SECURITY_HOLE)

Examples:
  # Simple encrypted chat
  cryptcat -l -p 4444 -k "MyPassword"              # Server
  cryptcat 192.168.1.100 4444 -k "MyPassword"      # Client

  # Verbose mode with timeout
  cryptcat -l -p 8080 -k "Secret123" -v -w 30

  # File transfer
  cryptcat -l -p 9999 -k "FilePass" > backup.tar.gz
  cryptcat server.com 9999 -k "FilePass" < backup.tar.gz
```

## 🔒 Security Best Practices

### Password Requirements

✅ **Good Passwords:**
- Minimum 12 characters
- Mix of uppercase, lowercase, numbers, symbols
- Example: `MyS3cur3!Tr@nsf3r#2025`

❌ **Bad Passwords:**
- Default passwords (like "metallica")
- Dictionary words ("password123")
- Too short (< 8 characters)

### Operational Security

1. **Never hardcode passwords** in scripts
2. **Use environment variables** for automation:
   ```bash
   export CLAW_KEY="YourSecurePassword"
   cryptcat -l -p 1234 -k "$CLAW_KEY"
   ```
3. **Clear command history** after use:
   ```bash
   history -c
   ```
4. **Share passwords securely** (encrypted email, Signal, etc.)

## 🛡️ Cryptographic Details

| Component | Algorithm | Parameters |
|-----------|-----------|------------|
| Cipher | AES-256 | 256-bit key |
| Mode | GCM | AEAD with authentication |
| Key Derivation | PBKDF2-HMAC-SHA256 | 100,000 iterations |
| IV | Random | 96 bits (12 bytes) |
| Auth Tag | GMAC | 128 bits (16 bytes) |

### Protocol Format

```
[MAGIC:4][VERSION:2][FLAGS:2][LENGTH:4][IV:12][TAG:16][CIPHERTEXT]
```

- **Magic**: `0x434C4157` ("CLAW")
- **Version**: `0x0001` (protocol v1)
- **Automatic authentication** and integrity verification

See [SECURITY.md](SECURITY.md) for detailed security documentation.

## 📊 Comparison

| Feature | ClawSec | Original Cryptcat | Netcat |
|---------|---------|-------------------|--------|
| Encryption | AES-256-GCM ✅ | Twofish (deprecated) | None ❌ |
| Authentication | HMAC-based ✅ | None ❌ | None ❌ |
| Key Derivation | PBKDF2 ✅ | Direct key ❌ | N/A |
| Memory Safety | Secure wiping ✅ | No ⚠️ | N/A |
| Protocol Version | Yes ✅ | No ❌ | N/A |

## 🧪 Testing

```bash
# Compile test suite
cd unix
make test_aes

# Run encryption tests
./test_aes

# Test connection (two terminals)
# Terminal 1:
./cryptcat -l -p 12345 -k "TestPassword" -v

# Terminal 2:
echo "Hello, encrypted world!" | ./cryptcat localhost 12345 -k "TestPassword"
```

## 🐛 Troubleshooting

### "Encryption not initialized"
**Cause**: Missing `-k` password option  
**Solution**: Always provide `-k "YourPassword"`

### "Decryption/authentication failed"
**Cause**: Password mismatch or corrupted data  
**Solution**: Ensure both sides use identical password

### "Connection closed by peer"
**Cause**: Protocol version mismatch or network issue  
**Solution**: Update both endpoints to same ClawSec version

### OpenSSL errors
**Cause**: OpenSSL library not found  
**Solution**: 
```bash
# macOS
export CPPFLAGS="-I/opt/homebrew/opt/openssl@3/include"
export LDFLAGS="-L/opt/homebrew/opt/openssl@3/lib"
make clean && make linux
```

## 📝 Changelog

### Version 2.0 (November 2025)
- ✨ **NEW**: AES-256-GCM authenticated encryption
- ✨ **NEW**: PBKDF2 password-based key derivation
- ✨ **NEW**: Protocol versioning and magic number
- 🔒 **SECURITY**: Removed hardcoded default key
- 🔒 **SECURITY**: Secure random IV generation
- 🔒 **SECURITY**: Memory wiping for sensitive data
- 🐛 **FIX**: Improved error handling
- 📚 **DOCS**: Comprehensive security documentation

### Version 1.x (Legacy Cryptcat)
- Twofish encryption (deprecated)
- Direct key usage (insecure)

## 🤝 Contributing

Contributions welcome! Please:

1. Review [SECURITY.md](SECURITY.md) for security guidelines
2. Test thoroughly before submitting
3. Document all security-relevant changes
4. Follow existing code style

## ⚖️ License

Based on Netcat and Cryptcat. See [LICENSE](LICENSE) for details.

## ⚠️ Legal Notice

**This tool is for authorized testing and legitimate use only.**

- Ensure you have permission before testing networks
- Comply with all applicable laws and regulations
- Not responsible for misuse or unauthorized access
- Use at your own risk

## 🙏 Credits

- **Original Netcat**: Hobbit
- **Original Cryptcat**: Farm9 team
- **ClawSec Modernization**: 2025 security enhancements
- **OpenSSL Project**: Cryptographic library

## 📚 Further Reading

- [SECURITY.md](SECURITY.md) - Detailed security documentation
- [OpenSSL GCM Documentation](https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption)
- [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final) - GCM Specification
- [PBKDF2 RFC 8018](https://tools.ietf.org/html/rfc8018)

---

**⚡ Stay Secure. Stay Private. Stay ClawSec.**
