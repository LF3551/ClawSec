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
- **Algorithm**: X25519 ECDHE + PBKDF2-HMAC-SHA256
- **ECDHE**: Ephemeral X25519 keypair per session (Perfect Forward Secrecy)
- **PBKDF2 Iterations**: 100,000 (OWASP recommended minimum)
- **Key Binding**: final_key = SHA256(ECDH_shared_secret || PBKDF2(password, pubkey_hash))
- **Output**: 256-bit derived key
- **Property**: Both ECDH agreement AND password knowledge required for decryption

### Protocol Format

```
[MAGIC:4][VERSION:2][FLAGS:2][SEQ:4][LENGTH:4][IV:12][TAG:16][CIPHERTEXT:variable]

MAGIC    = 0x434C4157 ("CLAW")
VERSION  = 0x0001 (protocol version 1)
FLAGS    = 0x0000 (reserved for future use)
SEQ      = message sequence number (network byte order, replay protection)
LENGTH   = ciphertext length in bytes (network byte order)
IV       = random initialization vector (unique per message)
TAG      = GCM authentication tag
```

### Session Handshake

```
1. TCP connection established
2. Server sends X25519 ephemeral public key (32 bytes)
3. Client sends X25519 ephemeral public key (32 bytes)
4. Both compute: shared_secret = X25519(my_privkey, peer_pubkey)
5. Both compute: salt = SHA256(server_pubkey || client_pubkey)
6. Both compute: password_key = PBKDF2(password, salt[0:16], 100000)
7. Both compute: final_key = SHA256(shared_secret || password_key)
8. Encrypted communication begins (seq counters start at 0)
```

Perfect Forward Secrecy: ephemeral private keys are never stored. Even if
password is compromised later, recorded traffic cannot be decrypted.

## Security Properties

### ✅ Provided Protections

1. **Confidentiality**: AES-256 encryption protects data from eavesdropping
2. **Integrity**: GCM authentication tag detects tampering
3. **Authentication**: Both endpoints verify message authenticity via password-bound ECDHE
4. **IV Uniqueness**: Cryptographically secure random IV per message
5. **Replay Protection**: Monotonic sequence counters reject duplicated/reordered messages
6. **Session Isolation**: Ephemeral X25519 keys ensure unique session keys
7. **Perfect Forward Secrecy**: Compromised password cannot decrypt past sessions
8. **TOFU Identity Verification**: `--tofu` provides SSH-like server identity with Ed25519 signing and `known_hosts` — detects MITM on reconnection

### ⚠️ Current Limitations

1. **No PKI/certificate infrastructure**: Without `--tofu`, authentication relies solely on pre-shared password. With `--tofu`, MITM is detectable on reconnection but first contact requires out-of-band fingerprint verification
2. **No post-quantum cryptography**: X25519 and AES-256 are secure against classical computers but not against future quantum attacks (Harvest Now, Decrypt Later)
3. **PBKDF2 (not Argon2)**: PBKDF2 is resistant to CPU brute-force but not GPU/ASIC-optimized attacks. Argon2id would provide memory-hard protection
4. **No certificate pinning**: `--tofu` provides first-use trust, but not CA-signed certificate validation
5. **Single password per session**: No per-user authentication; all clients share the same password

## Usage Guidelines

### Minimum Security Requirements

```bash
# REQUIRED: Always use -k option with a strong password
clawsec -l -p 1234 -k "MyStr0ng!P@ssw0rd#2025"

# Connect with same password
clawsec <host> 1234 -k "MyStr0ng!P@ssw0rd#2025"
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
     clawsec -l -p 1234 -k "$CLAW_PASSWORD"
     ```

## Attack Scenarios & Mitigations

### 1. Man-in-the-Middle (MITM)
**Threat**: Attacker intercepts and relays traffic
**Mitigation**: Use pre-shared password; attacker without password cannot decrypt
**Limitation**: No authentication of endpoint identity

### 2. Replay Attacks
**Threat**: Attacker captures and resends encrypted messages
**Mitigation**: Monotonic sequence counter per session; receiver rejects any message with unexpected sequence number
**Status**: ✅ Implemented (v2.4.0)

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
| Forward Secrecy | Full (X25519 ECDHE) | N/A | No | Full (ECDHE) |
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
1. **Argon2id KDF**: Replace PBKDF2 with memory-hard key derivation (GPU/ASIC resistance)
2. **Post-quantum hybrid**: X25519 + ML-KEM (Kyber) hybrid key exchange for quantum resistance
3. **Per-user authentication**: Support multiple passwords/keys for multi-client deployments
4. **Key rotation**: Automatic session key renegotiation for long-lived connections

## Anti-Censorship / Anti-DPI

ClawSec includes multiple layers to resist Deep Packet Inspection and active probing:

| Layer | Flag | Protection |
|-------|------|-----------|
| TLS Camouflage | `--obfs tls` | Wraps connection in real TLS 1.3 session |
| Browser Mimicry | `--fingerprint chrome\|firefox\|safari` | ClientHello matches real browser JA3/JA4 |
| Encrypted Client Hello | `--ech` | Hides SNI from DPI with GREASE ECH extension |
| Active Probing Resistance | `--fallback host:port` | Non-ClawSec probes proxied to a real website |
| Packet Padding | `--pad` | Uniform 1400-byte packets defeat size analysis |
| Timing Jitter | `--jitter N` | Random 0-N ms delays defeat timing correlation |

**Maximum stealth** (all layers combined):
```bash
# Server
clawsec -l -p 443 -k "Pass" --fallback 127.0.0.1:80 --ech --pad --jitter 100

# Client
clawsec -k "Pass" --fingerprint chrome --fallback 127.0.0.1:80 --ech --pad --jitter 100 server 443
```

Note: `--fingerprint` is client-side only (shapes outgoing ClientHello).
The server does not need it.
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

**Last Updated**: May 3, 2026  
**Protocol Version**: 1  
**Maintainer**: ClawSec Project
