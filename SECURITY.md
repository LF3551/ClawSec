# ClawSec Security Documentation

## Overview

ClawSec implements modern authenticated encryption using **AES-256-GCM** (Galois/Counter Mode), providing both confidentiality and integrity protection for network communications.

## Cryptographic Features

### Encryption Algorithm
- **Cipher**: AES-256 (Advanced Encryption Standard, 256-bit key)
- **Mode**: GCM (Galois/Counter Mode) - AEAD (Authenticated Encryption with Associated Data)
- **Key Size**: 256 bits (32 bytes)
- **IV Size**: 96 bits (12 bytes) - optimal for GCM
- **Tag Size**: 128 bits (16 bytes) - authentication tag

### Key Derivation
- **Algorithm**: PBKDF2-HMAC-SHA256
- **Iterations**: 100,000 (OWASP recommended minimum)
- **Salt**: Fixed 16-byte salt (for session compatibility)
- **Output**: 256-bit derived key

### Protocol Format

```
[MAGIC:4][VERSION:2][FLAGS:2][LENGTH:4][IV:12][TAG:16][CIPHERTEXT:variable]

MAGIC    = 0x434C4157 ("CLAW")
VERSION  = 0x0001 (protocol version 1)
FLAGS    = 0x0000 (reserved for future use)
LENGTH   = ciphertext length in bytes (network byte order)
IV       = random initialization vector (unique per message)
TAG      = GCM authentication tag
```

## Security Properties

### ✅ Provided Protections

1. **Confidentiality**: AES-256 encryption protects data from eavesdropping
2. **Integrity**: GCM authentication tag detects tampering
3. **Authentication**: Both endpoints verify message authenticity
4. **IV Uniqueness**: Cryptographically secure random IV per message
5. **Forward Secrecy**: Different IV for each message (partial forward secrecy)

### ⚠️ Current Limitations

1. **No Key Exchange**: Both parties must share password out-of-band
2. **Replay Protection**: Not fully implemented (no sequence numbers)
3. **MITM Protection**: Requires pre-shared password (no PKI/certificates)
4. **Perfect Forward Secrecy**: Not provided (same derived key for session)

## Usage Guidelines

### Minimum Security Requirements

```bash
# REQUIRED: Always use -k option with a strong password
cryptcat -l -p 1234 -k "MyStr0ng!P@ssw0rd#2025"

# Connect with same password
cryptcat <host> 1234 -k "MyStr0ng!P@ssw0rd#2025"
```

### Password Recommendations

**Minimum Requirements:**
- At least 8 characters (12+ recommended)
- Mix of uppercase, lowercase, numbers, symbols
- Avoid dictionary words and common patterns

**Good Examples:**
```
MySecureP@ssw0rd2025!
7r@nsf3r_S3cur3_D@t@
Encryption#Strong$Key9
```

**Bad Examples (DO NOT USE):**
```
password123          # Too common
metallica            # Default key (NEVER use!)
12345678             # Sequential numbers
admin                # Too short and common
```

### Best Practices

1. **Password Distribution**
   - Share passwords securely (encrypted email, secure messaging)
   - Never send passwords over unencrypted channels
   - Use different passwords for different sessions

2. **Network Security**
   - Use over VPN or trusted networks when possible
   - Consider additional transport security (SSH tunnel)
   - Monitor for unusual connection patterns

3. **Operational Security**
   - Clear command history after use
   - Don't hardcode passwords in scripts
   - Use environment variables for automation:
     ```bash
     export CLAW_PASSWORD="YourStrongPassword"
     cryptcat -l -p 1234 -k "$CLAW_PASSWORD"
     ```

## Attack Scenarios & Mitigations

### 1. Man-in-the-Middle (MITM)
**Threat**: Attacker intercepts and relays traffic
**Mitigation**: Use pre-shared password; attacker without password cannot decrypt
**Limitation**: No authentication of endpoint identity

### 2. Replay Attacks
**Threat**: Attacker captures and resends encrypted messages
**Current Status**: Partial protection (unique IVs per message)
**Future**: Add sequence numbers and timestamps

### 3. Brute Force
**Threat**: Attacker tries to guess password
**Mitigation**: 
- Strong passwords (12+ chars)
- PBKDF2 with 100k iterations slows down attacks
- Monitor failed connection attempts

### 4. Side-Channel Attacks
**Threat**: Timing or power analysis reveals information
**Mitigation**: Use constant-time OpenSSL implementations
**Note**: Physical access attacks out of scope

## Comparison with Other Tools

| Feature | ClawSec | Standard Netcat | Cryptcat (Old) | OpenSSL s_client |
|---------|---------|-----------------|----------------|------------------|
| Encryption | AES-256-GCM | None | Twofish (deprecated) | TLS 1.3 |
| Authentication | HMAC (via GCM) | None | None | PKI Certificates |
| Key Derivation | PBKDF2 | N/A | Direct key | TLS handshake |
| Forward Secrecy | Partial | N/A | No | Full (ECDHE) |
| Ease of Use | High | High | High | Medium |

## Compliance & Standards

### Cryptographic Standards
- **AES**: FIPS 197, NIST approved
- **GCM**: NIST SP 800-38D
- **PBKDF2**: PKCS #5, RFC 8018
- **SHA-256**: FIPS 180-4

### Industry Guidelines
- **Key Length**: Meets NIST recommendations (256-bit)
- **Iterations**: Exceeds OWASP minimum (100k)
- **IV Length**: Optimal for GCM (96 bits)

## Known Vulnerabilities

### CVE Status
- No known CVEs for current implementation
- Based on industry-standard OpenSSL library
- Regular updates recommended

### Reported Issues
None at this time.

### Security Audits
- Initial implementation: November 2025
- Last review: November 2025
- Status: Not externally audited (community project)

## Responsible Disclosure

Found a security issue? Please report to:
- GitHub Issues (for non-critical bugs)
- Private email for critical vulnerabilities

**DO NOT** publicly disclose security vulnerabilities before coordinated disclosure.

## Future Enhancements

### Planned Security Features
1. **Key Exchange**: Implement ECDHE for perfect forward secrecy
2. **Replay Protection**: Add sequence numbers and timestamps
3. **Certificate Support**: Optional PKI for endpoint authentication
4. **Password Hashing**: Consider Argon2 instead of PBKDF2
5. **Rate Limiting**: Protect against brute force

### Under Consideration
- ChaCha20-Poly1305 as alternative cipher
- Post-quantum cryptography (future-proofing)
- Hardware security module (HSM) support

## License & Disclaimer

**THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.**

- Use at your own risk
- Not audited for production use
- Intended for educational and testing purposes
- No guarantee of security in all scenarios

For production environments, consider professionally audited solutions like:
- OpenSSH (for shell access)
- WireGuard/OpenVPN (for VPN)
- TLS/SSL (for web services)

---

**Last Updated**: November 22, 2025  
**Protocol Version**: 1  
**Maintainer**: ClawSec Project
