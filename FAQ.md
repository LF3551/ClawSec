# Frequently Asked Questions (FAQ)

## General


### What is ClawSec?
ClawSec is a modern encrypted network tool that provides AES-256-GCM encryption for secure data transfer. It evolved from Cryptcat with completely rewritten cryptography using current best practices.

### Why ClawSec instead of SSH/SCP?
- No SSH keys or certificates needed
- Single static binary (37KB)
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

### How do I use chat mode?
```bash
# Server
./clawsec -l -p 4444 -k "ChatPass" -c

# Client
./clawsec -k "ChatPass" -c server-ip 4444
```

Both sides will see timestamped messages with colored output.

### How do I get a reverse shell?
```bash
# Server (target machine)
./clawsec -l -p 8888 -k "ShellPass" -e /bin/bash

# Client (your machine)
./clawsec -k "ShellPass" server-ip 8888
```

Interactive programs (vim, nano, top) work with PTY support.

### How do I transfer a file?
```bash
# Receiver
./clawsec -v -l -p 9999 -k "Password" > file.txt

# Sender
./clawsec -v -k "Password" receiver-ip 9999 < file.txt
```

Use `-v` flag to see transfer statistics.

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
- X25519 ECDHE (Perfect Forward Secrecy)
- PBKDF2 with 100k iterations
- Cryptographically secure random IVs
- GCM authentication tags
- Replay protection (sequence counters)
- TLS 1.3 camouflage (`--obfs tls`)
- Packet padding and timing jitter (`--pad`, `--jitter`)

It lacks:
- PKI/certificate infrastructure (uses password-based auth)
- Independent security audit

### How strong should my password be?
Minimum 12 characters with mix of:
- Uppercase letters
- Lowercase letters
- Numbers
- Symbols

### Can someone intercept my data?
Without the password, intercepted data is encrypted and authenticated. An attacker would see random bytes and cannot decrypt or modify the data.

### Does ClawSec work over HTTPS?
No. ClawSec operates at the TCP/UDP level, not HTTP. It creates its own encrypted channel. However, `--obfs tls` wraps traffic in a real TLS 1.3 session, making it look like HTTPS to network observers.

## Troubleshooting

### "Encryption not initialized"
Add the `-k` option with a password:
```bash
./clawsec -l -p 8888 -k "YourPassword"
```

### "Authentication failed"
Passwords don't match between client and server. Verify both use identical passwords.

### Interactive programs (vim, nano) not working?
Use `-e` flag for reverse shell mode which provides PTY support:
```bash
./clawsec -l -p 8888 -k "Pass" -e /bin/bash
```

### Chat mode not showing colors?
Make sure both sides use `-c` flag:
```bash
# Server
./clawsec -l -p 4444 -k "Pass" -c

# Client  
./clawsec -k "Pass" -c server-ip 4444
```

## Anti-DPI / Stealth

### How do I hide ClawSec traffic from DPI?
Combine `--obfs tls` for TLS 1.3 camouflage with `--fingerprint chrome` to look like real browser traffic:
```bash
# Server
./clawsec -l -p 443 -k "Pass" --obfs tls

# Client (looks like Chrome to DPI)
./clawsec -k "Pass" --fingerprint chrome server 443
```

### What is TLS fingerprinting?
DPI systems identify tools by their TLS ClientHello pattern (JA3/JA4 hash). OpenSSL's default ClientHello stands out as a non-browser client. `--fingerprint chrome|firefox|safari` shapes ClawSec's ClientHello to match a real browser — cipher suites, curves, ALPN, extensions.

### Do I need `--fingerprint` on both sides?
No. `--fingerprint` is **client-side only** — it shapes the outgoing ClientHello. The server doesn't need it.

### What is `--fallback`?
REALITY-like active probing resistance. When a browser/DPI probe connects to your port, they see a real website. Only ClawSec clients that send the correct knock sequence get the encrypted tunnel:
```bash
# Server: DPI probes see real nginx
./clawsec -l -p 443 -k "Pass" --fallback 127.0.0.1:80

# Client: sends knock, gets tunnel
./clawsec -k "Pass" --fallback 127.0.0.1:80 server 443

# DPI probe: sees real nginx
curl https://server:443  # → nginx welcome page
```

### What is `--ech`?
Encrypted Client Hello — adds a GREASE ECH extension to the TLS ClientHello, hiding the SNI (server name) from DPI. Automatically enables TLS mode.

### What does `--mux` do?
Multiplexes up to 64 connections over a single encrypted tunnel. Think of it as encrypted port forwarding with connection pooling:
```bash
# Server: forward to internal web server
./clawsec -l -p 4430 -k "Pass" -L internal:80 --mux

# Client: 64 concurrent connections on localhost:8080
./clawsec -k "Pass" -p 8080 --mux server 4430
```

### Can I combine stealth features?
Yes. Maximum stealth configuration:
```bash
# Server
./clawsec -l -p 443 -k "Pass" --fallback 127.0.0.1:80 --ech --pad --jitter 100 --tofu

# Client (looks exactly like Chrome connecting to a real site, with MITM detection)
./clawsec -k "Pass" --fingerprint chrome --fallback 127.0.0.1:80 --ech --pad --jitter 100 --tofu server 443
```

### What is `--tofu`?
Trust On First Use — like SSH's `known_hosts`. The server generates a persistent Ed25519 identity key. On first connection, the client saves the server's fingerprint. On reconnection, it verifies the fingerprint hasn't changed. If it has — you get a big warning (possible MITM).

### Do I need `--tofu` on both sides?
Yes. The server signs its ephemeral key, the client verifies. Both must use `--tofu`.

### What's the difference between `--obfs tls` and `--fingerprint`?
- `--obfs tls` wraps traffic in a real TLS 1.3 session (required for all stealth features)
- `--fingerprint` additionally shapes the TLS ClientHello to look like a specific browser
- `--obfs tls` is needed on **both sides**, `--fingerprint` is **client-only**
- `--fingerprint` auto-enables `--obfs tls`

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

# For chat mode
docker run -p 8888:8888 clawsec -l -p 8888 -k "Password" -c

# For reverse shell
docker run -p 8888:8888 clawsec -l -p 8888 -k "Password" -e /bin/sh
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
