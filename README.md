# ClawSec

[![Build Status](https://github.com/LF3551/ClawSec/actions/workflows/build.yml/badge.svg)](https://github.com/LF3551/ClawSec/actions)
[![License](https://img.shields.io/badge/License-BSD-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20BSD-lightgrey.svg)](https://github.com/LF3551/ClawSec)
[![GitHub release](https://img.shields.io/github/v/release/LF3551/ClawSec)](https://github.com/LF3551/ClawSec/releases)
[![GitHub stars](https://img.shields.io/github/stars/LF3551/ClawSec?style=social)](https://github.com/LF3551/ClawSec)

Modern encrypted network tool evolved from Cryptcat with state-of-the-art cryptography.

## Why ClawSec?

| Feature | ClawSec | Cryptcat | Ncat (--ssl) | socat (openssl) |
|---------|---------|----------|--------------|-----------------|
| **Encryption** | AES-256-GCM | Twofish (deprecated) | TLS 1.3 | TLS 1.3 |
| **Authentication** | AEAD + PBKDF2 | None | Certificate | Certificate |
| **Setup** | Single password | Hardcoded key | Certificate required | Certificate required |
| **Lightweight** | ✅ 72KB | ✅ Small | ❌ Large | ❌ Large |
| **Drop-in Netcat** | ✅ Yes | ✅ Yes | ⚠️ Partial | ❌ No |

Perfect for: Secure file transfers, reverse shells, encrypted tunnels without certificate management.

## Security Features

- **AES-256-GCM**: Authenticated encryption with integrity verification
- **PBKDF2**: Password-based key derivation with 100,000 iterations
- **Secure Random IV**: Cryptographically strong per-message randomization
- **Protocol Versioning**: Future-proof binary message format
- **Memory Safety**: Secure key wiping and resource cleanup

## Quick Start

### Automatic Installation

```bash
# Clone repository
git clone https://github.com/LF3551/ClawSec.git
cd ClawSec

# Run installer
chmod +x install.sh
./install.sh
```

### Manual Build

```bash
cd unix
make linux    # or: make freebsd, make netbsd, make solaris
```

### Docker

```bash
# Build image
docker build -t clawsec .

# Run server
docker run -p 8888:8888 clawsec -l -p 8888 -k "YourPassword"

# Or use docker-compose
docker-compose up
```

### Basic Usage

```bash
# Listen mode (server)
./clawsec -l -p 1234 -k "YourStrongPassword123"

# Connect mode (client)
./clawsec <server-ip> 1234 -k "YourStrongPassword123"
```

### File Transfer

```bash
# Receiver
./clawsec -l -p 9999 -k "SecureTransfer2025" > received_file.txt

# Sender
./clawsec <receiver-ip> 9999 -k "SecureTransfer2025" < file_to_send.txt
```

## Requirements

- **OpenSSL 3.x**: For AES-GCM encryption
- **GCC/G++**: C++11 or later
- **POSIX System**: Linux, BSD, macOS, Solaris

### Install OpenSSL

```bash
# macOS
brew install openssl@3

# Debian/Ubuntu
sudo apt-get install libssl-dev

# RedHat/CentOS
sudo yum install openssl-devel
```

## Usage

```
Usage: clawsec [options] hostname port
       clawsec -l -p port [options]

Required:
  -k password       Encryption password (REQUIRED)

Connection:
  -l                Listen mode for inbound connections
  -p port           Local port number
  -s addr           Local source address

Options:
  -v                Verbose mode
  -w secs           Timeout for connects and reads
  -n                Numeric-only IP addresses (no DNS)
  -z                Zero-I/O mode (port scanning)
  -u                UDP mode
  -i secs           Delay interval for lines/ports
  -o file           Hex dump of traffic to file
  -e prog           Execute program after connect (requires DGAPING_SECURITY_HOLE)
```

## Examples

```bash
# Simple encrypted communication
clawsec -l -p 4444 -k "MyPassword"              # Server
clawsec 192.168.1.100 4444 -k "MyPassword"      # Client

# File transfer
clawsec -l -p 9999 -k "FilePass" > backup.tar.gz
clawsec server.com 9999 -k "FilePass" < backup.tar.gz

# Verbose mode with timeout
clawsec -l -p 8080 -k "Secret123" -v -w 30
```

## Security Guidelines

### Password Requirements

**Strong passwords:**
- Minimum 12 characters recommended
- Mix of uppercase, lowercase, numbers, symbols
- Example: `MyS3cur3Tr@nsf3r2025`

**Avoid:**
- Default passwords
- Dictionary words
- Short passwords (less than 8 characters)

### Operational Security

1. Never hardcode passwords in scripts
2. Use environment variables for automation
3. Clear command history after use
4. Share passwords through secure channels only

```bash
# Using environment variables
export CLAW_KEY="YourSecurePassword"
clawsec -l -p 1234 -k "$CLAW_KEY"
```

## Cryptographic Specifications

| Component | Algorithm | Parameters |
|-----------|-----------|------------|
| Cipher | AES-256 | 256-bit key |
| Mode | GCM | AEAD with authentication |
| Key Derivation | PBKDF2-HMAC-SHA256 | 100,000 iterations |
| IV | CSPRNG | 96 bits (12 bytes) |
| Auth Tag | GMAC | 128 bits (16 bytes) |

### Protocol Format

```
[MAGIC:4][VERSION:2][FLAGS:2][LENGTH:4][IV:12][TAG:16][CIPHERTEXT]
```

- Magic number: `0x434C4157` ("CLAW")
- Version: `0x0001` (protocol v1)
- Automatic authentication and integrity verification

See [SECURITY.md](SECURITY.md) for detailed cryptographic documentation.

## Comparison

| Feature | ClawSec | Original Cryptcat | Netcat |
|---------|---------|-------------------|--------|
| Encryption | AES-256-GCM | Twofish (deprecated) | None |
| Authentication | GCM Tag | None | None |
| Key Derivation | PBKDF2 | Direct key | N/A |
| Memory Safety | Secure wiping | No | N/A |
| Protocol Version | Yes | No | N/A |

## Testing

```bash
# Compile and run encryption tests
cd unix
make test_aes
./test_aes

# Test connection (two terminals)
# Terminal 1:
./clawsec -l -p 12345 -k "TestPassword" -v

# Terminal 2:
echo "Test message" | ./clawsec localhost 12345 -k "TestPassword"
```

## Troubleshooting

### "Encryption not initialized"
Missing `-k` password option. Always provide password parameter.

### "Decryption/authentication failed"
Password mismatch or corrupted data. Verify both endpoints use identical password.

### "Connection closed by peer"
Protocol version mismatch or network error. Update both endpoints to same version.

### OpenSSL library errors
```bash
# macOS: Set OpenSSL paths
export CPPFLAGS="-I/opt/homebrew/opt/openssl@3/include"
export LDFLAGS="-L/opt/homebrew/opt/openssl@3/lib"
make clean && make linux
```

## Changelog

### Version 2.0 (November 2025)
- Added AES-256-GCM authenticated encryption
- Added PBKDF2 password-based key derivation
- Added protocol versioning with magic number
- Removed hardcoded default password
- Implemented secure random IV generation
- Added memory wiping for sensitive data
- Improved error handling
- Comprehensive security documentation

### Version 1.x (Legacy Cryptcat)
- Twofish encryption (deprecated)
- Direct key usage (insecure)

## Contributing

Contributions are welcome. Please:

1. Review [SECURITY.md](SECURITY.md) before submitting security-related changes
2. Test thoroughly
3. Document all changes
4. Follow existing code style

## License

Based on Netcat and Cryptcat. See [LICENSE](LICENSE) for details.

## Legal Notice

This tool is for authorized testing and legitimate use only.

- Obtain permission before testing networks
- Comply with all applicable laws and regulations
- Authors not responsible for misuse or unauthorized access
- Use at your own risk

## Credits

- Original Netcat: Hobbit
- Original Cryptcat: Farm9 team
- ClawSec Modernization: 2025 security enhancements
- OpenSSL Project: Cryptographic library

## Documentation

- [SECURITY.md](SECURITY.md) - Detailed security documentation
- [EXAMPLE_USAGE.md](EXAMPLE_USAGE.md) - Usage examples
- [FAQ.md](FAQ.md) - Frequently asked questions
- [CHANGELOG.md](CHANGELOG.md) - Version history
- [CONTRIBUTING.md](CONTRIBUTING.md) - Development guide
- [OpenSSL GCM Documentation](https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption)
- [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final) - GCM Specification
- [PBKDF2 RFC 8018](https://tools.ietf.org/html/rfc8018)
