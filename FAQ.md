# Frequently Asked Questions (FAQ)

## General

### What is ClawSec?
ClawSec is a modern encrypted network tool that provides AES-256-GCM encryption for secure data transfer. It evolved from Cryptcat with completely rewritten cryptography using current best practices.

### Why ClawSec instead of SSH/SCP?
- No SSH keys or certificates needed
- Single static binary (72KB)
- Works on embedded systems
- Quick temporary file transfers
- Simpler for one-off connections

### Is ClawSec production-ready?
ClawSec uses industry-standard cryptography (AES-256-GCM, PBKDF2) but has not been independently audited. Use for:
- Development/testing environments
- Internal network transfers
- Non-critical data transfer

For production systems, consider professionally audited solutions like SSH/OpenSSH.

## Installation

### How do I install ClawSec?
```bash
git clone https://github.com/LF3551/ClawSec.git
cd ClawSec
./install.sh
```

### What are the dependencies?
- OpenSSL 3.x
- C/C++ compiler (GCC or Clang)
- POSIX-compatible system (Linux, BSD, macOS)

### Can I use it on Windows?
Not currently. ClawSec requires a POSIX system. Consider using WSL (Windows Subsystem for Linux).

## Usage

### How do I transfer a file?
```bash
# Receiver
./clawsec -l -p 9999 -k "Password" > file.txt

# Sender
./clawsec -k "Password" receiver-ip 9999 < file.txt
```

### Do both sides need the same password?
Yes. Both endpoints must use the exact same password for encryption/decryption.

### What happens if passwords don't match?
You'll see: `[AESGCM] Decrypt error: Authentication failed`

The GCM authentication tag prevents decryption with wrong passwords.

### Can I use it without a password?
No. The `-k` option is required for security. There is no default password.

### How do I run it as a service?
```bash
# Linux with systemd
sudo cp clawsec.service /etc/systemd/system/
sudo systemctl enable clawsec
sudo systemctl start clawsec
```

## Security

### Is ClawSec secure?
ClawSec uses:
- AES-256-GCM (NIST approved)
- PBKDF2 with 100k iterations
- Cryptographically secure random IVs
- GCM authentication tags

However, it lacks:
- Perfect forward secrecy
- Replay protection
- PKI/certificate infrastructure

### How strong should my password be?
Minimum 12 characters with mix of:
- Uppercase letters
- Lowercase letters
- Numbers
- Symbols

### Can someone intercept my data?
Without the password, intercepted data is encrypted and authenticated. An attacker would see random bytes and cannot decrypt or modify the data.

### Does ClawSec work over HTTPS?
No. ClawSec operates at the TCP/UDP level, not HTTP. It creates its own encrypted channel.

## Troubleshooting

### "Encryption not initialized"
Add the `-k` option with a password:
```bash
./clawsec -l -p 8888 -k "YourPassword"
```

### "Authentication failed"
Passwords don't match between client and server. Verify both use identical passwords.

### "Connection refused"
- Check server is running
- Verify correct port number
- Check firewall settings
- Ensure correct IP address

### OpenSSL errors on macOS
```bash
brew install openssl@3
export CPPFLAGS="-I/opt/homebrew/opt/openssl@3/include"
export LDFLAGS="-L/opt/homebrew/opt/openssl@3/lib"
cd unix && make clean && make linux
```

## Docker
### How do I run ClawSec in Docker?
```bash
docker build -t clawsec .
docker run -p 8888:8888 clawsec -l -p 8888 -k "Password"
```

### How do I use docker-compose?
```bash
docker-compose up
```

## Kubernetes

### How do I deploy to Kubernetes?
```bash
kubectl apply -f kubernetes.yaml
```

### How do I change the password?
Edit the Secret in `kubernetes.yaml`:
```yaml
stringData:
  password: "YourNewPassword"
```

## Compatibility

### Is ClawSec compatible with old Cryptcat?
No. ClawSec 2.0 uses a completely different protocol and encryption. It cannot communicate with legacy Cryptcat.

### What platforms are supported?
- Linux (x86_64, ARM)
- macOS (Intel, Apple Silicon)
- FreeBSD
- NetBSD
- OpenBSD
- Solaris

### Can I run it on Raspberry Pi?
Yes. ClawSec works on ARM platforms including Raspberry Pi.

## Contributing

### How can I contribute?
See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### I found a security issue
Email maintainers privately. Do not open public issues for security vulnerabilities.

## Support

### Where can I get help?
- GitHub Issues: https://github.com/LF3551/ClawSec/issues
- Documentation: README.md, SECURITY.md
- Examples: EXAMPLE_USAGE.md

### Is there a mailing list?
Not currently. Use GitHub Discussions or Issues.
