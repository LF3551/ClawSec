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
- **Algorithm**: X25519 ECDHE + Argon2id (libargon2; no fallback, so all builds derive identical keys)
- **ECDHE**: Ephemeral X25519 keypair per session (Perfect Forward Secrecy)
- **Argon2id parameters**: t=3, m=19 MiB, p=1 (OWASP minimum profile)
- **Session key**: session = SHA256(ECDH_shared_secret [|| ML-KEM secret] || KDF(password, SHA256(server_pub || client_pub)))
- **Traffic keys** (HKDF-SHA256, empty salt, info labels bound to the protocol version):
  - `ClawSec v3 tcp c2s` / `ClawSec v3 tcp s2c` — stream channel, one key per direction
  - `ClawSec v3 udp c2s` / `ClawSec v3 udp s2c` — `--tun-udp` data channel, one key per direction
  - `ClawSec v3 fingerprint` — session fingerprint shown in chat mode
  - `ClawSec v3 confirm c2s` / `ClawSec v3 confirm s2c` — key-confirmation MACs (wiped after use)
- **Property**: Both ECDH agreement AND password knowledge required for decryption; each
  direction and channel uses an independent key, so frames cannot be reflected or moved
  between channels

### Protocol Format

```
[MAGIC:4][VERSION:2][FLAGS:2][SEQ:4][LENGTH:4][IV:12][TAG:16][CIPHERTEXT:variable]

MAGIC    = 0x434C4157 ("CLAW")
VERSION  = 0x0003 (protocol version 3, ClawSec 3.x)
FLAGS    = 0x0000 (reserved, must be zero)
SEQ      = message sequence number (network byte order, replay protection)
LENGTH   = ciphertext length in bytes (network byte order, == plaintext length)
IV       = random initialization vector (unique per message)
TAG      = GCM authentication tag over AAD = the 16-byte header, and the ciphertext
```

Receiver rules (v3):
- the header is authenticated: any change to MAGIC, VERSION, FLAGS, SEQ or LENGTH fails the tag;
- SEQ must equal the next expected value; a direction never reuses a SEQ (the session
  refuses to continue after 2^32 messages instead of wrapping);
- plaintext is decrypted into an internal buffer and copied to the caller only after the
  tag verifies, and only if it fits the caller's buffer (otherwise `EMSGSIZE`).

Protocol v3 (ClawSec 3.0.0+) is not wire-compatible with protocol v1 (ClawSec ≤ 2.8.2);
a v1 peer is rejected with an explicit version error. The protocol number follows the
release major version, so there is no protocol v2.

### UDP VPN data channel (`--tun-udp`)

```
[MAGIC "CVPN":4][NONCE:12 = SEQ:4 || random:8][CIPHERTEXT][TAG:16]   AAD = "CVPN"
```

- Encrypted with the directional UDP keys (never the TCP keys).
- SEQ 0 is reserved for the negotiation probe/ACK; data starts at 1 and the
  256-entry sliding window rejects SEQ 0, duplicates and stale packets.
- The sender stops instead of wrapping SEQ.

### Session Handshake

```
1. TCP connection established
2. Server sends hello ("CS" + 16-bit protocol version) and its X25519 ephemeral
   public key (32 bytes) — before reading anything, so old clients never block
3. Client checks the hello (version mismatch → explicit error), then sends its
   own hello and X25519 public key; the server checks the client hello
4. Both compute: shared_secret = X25519(my_privkey, peer_pubkey)
5. Both compute: salt = SHA256(server_pubkey || client_pubkey)
6. Both compute: password_key = Argon2id(password, salt)
7. Both compute: session = SHA256(shared_secret || password_key)
8. Both derive directional traffic, UDP, fingerprint and confirmation keys
   with HKDF-SHA256 (see Key Derivation)
9. Key confirmation: each side sends HMAC-SHA256(confirm_key_own_direction,
   "ClawSec v3 key confirmation") and verifies the peer's in constant time;
   a mismatch (wrong password) aborts the session on both ends
10. Encrypted communication begins (seq counters start at 0 in each direction)
```

With `--tofu`, step 2 also carries the server identity key and its Ed25519
signature over the ephemeral key; with `--pq`, an ML-KEM-768 exchange follows
step 3 and its secret is mixed into step 7.

Perfect Forward Secrecy: ephemeral private keys are never stored. Even if
password is compromised later, recorded traffic cannot be decrypted.

## Security Properties

### ✅ Provided Protections

1. **Confidentiality**: AES-256 encryption protects data from eavesdropping
2. **Integrity**: GCM authentication tag detects tampering
3. **Authentication**: Both endpoints verify message authenticity via password-bound ECDHE
4. **IV Uniqueness**: Cryptographically secure random IV per message
5. **Replay Protection**: Authenticated, strictly consecutive sequence numbers reject duplicated, reordered and re-labelled messages
6. **Session Isolation**: Ephemeral X25519 keys ensure unique session keys
7. **Perfect Forward Secrecy**: Compromised password cannot decrypt past sessions
8. **TOFU Identity Verification**: `--tofu` provides SSH-like server identity with Ed25519 signing and `known_hosts` — detects MITM on reconnection
9. **Post-Quantum Resistance**: `--pq` adds ML-KEM-768 (CRYSTALS-Kyber) hybrid key exchange on top of X25519, protecting against quantum adversaries
10. **Reflection Resistance**: Separate keys per direction; a node never accepts its own frames
11. **Bounded Decryption**: Unauthenticated plaintext never reaches caller buffers; writes never exceed the buffer size
12. **Key Confirmation**: A wrong password or incompatible peer is detected during the handshake, on both ends
13. **Safe Defaults**: Local listeners (SOCKS proxy, `--mux`) bind to loopback; `-e` (program execution) is not built by default
14. **Password Handling**: `--key-file` / `CLAWSEC_PASSWORD` / no-echo prompt; `-k` is overwritten in argv; the environment variable is not inherited by child processes
15. **Resource Limits**: Session setup times out (`--handshake-timeout`, default 15 s); `-K` runs at most `--max-clients` handlers (default 16)
16. **SOCKS Destination Policy**: The SOCKS server refuses loopback, link-local/cloud-metadata, multicast and reserved destinations (checked on resolved addresses), or allows only `--socks-allow` ranges
17. **Safe File Reception**: `--recv` writes to a private `<name>.clawsec-part` (O_NOFOLLOW, single link, own uid) and renames it only after SHA-256 verification; chat `/file` never overwrites or follows links

### ⚠️ Current Limitations

1. **No PKI/certificate infrastructure**: Without `--tofu`, authentication relies solely on pre-shared password. With `--tofu`, MITM is detectable on reconnection but first contact requires out-of-band fingerprint verification
2. **No PAKE — offline password guessing by an active attacker**: the password is mixed into the
   session key after an unauthenticated X25519 exchange. An attacker who runs the handshake with a
   client or server (or sits in the middle) learns the X25519 secret and can test password guesses
   offline against captured frames. Use long random passwords (≥ 128 bits, e.g.
   `openssl rand -base64 24`). A PAKE (e.g. CPace) is planned
3. **Handshake transcript not signed**: `--tofu` signs only the server's ephemeral key, not the
   full transcript (client key, ML-KEM messages). Key confirmation is explicit (HMAC) and both keys
   enter the KDF salt, but the confirmation does not cover the hello/version bytes
4. **No certificate pinning**: `--tofu` provides first-use trust, but not CA-signed certificate validation
5. **Single password per session**: No per-user authentication; all clients share the same password
6. **Post-quantum requires OpenSSL >= 3.5**: `--pq` hybrid key exchange needs ML-KEM support (OpenSSL 3.5+)

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
   - Don't put passwords on command lines or in scripts: `-k` is visible to other
     local users (`ps`, `/proc`) until ClawSec overwrites it, and in shell history
   - Use a key file or the environment:
     ```bash
     clawsec -l -p 1234 --key-file /etc/clawsec/password      # mode 0600
     CLAWSEC_PASSWORD="$(cat /etc/clawsec/password)" clawsec server 1234
     ```
     `CLAWSEC_PASSWORD` is removed from the environment after reading, so
     programs run with `-e` and other child processes do not inherit it
   - Public servers: keep `--handshake-timeout` (default 15 s) and, with `-K`,
     `--max-clients` (default 16; each handshake uses ~19 MiB for Argon2id)
   - SOCKS server: restrict destinations with `--socks-allow` where possible

## Attack Scenarios & Mitigations

### 1. Man-in-the-Middle (MITM)
**Threat**: Attacker intercepts and relays traffic
**Mitigation**: Use pre-shared password; attacker without password cannot decrypt
**Limitation**: No authentication of endpoint identity without `--tofu`; an active attacker can
test password guesses offline (no PAKE yet) — use a long random password

### 2. Replay Attacks
**Threat**: Attacker captures and resends encrypted messages
**Mitigation**: Sequence counter per direction, authenticated as GCM AAD; receiver rejects any message with an unexpected sequence number, and editing the number invalidates the tag. Separate keys per direction prevent reflection.
**Status**: ✅ Implemented (v2.4.0); header authentication and directional keys added in protocol v3 / ClawSec 3.0.0 (v1 accepted replays with an edited sequence number and reflected frames)

### 3. Brute Force
**Threat**: Attacker tries to guess password
**Mitigation**: 
- Strong passwords (12+ chars)
- Argon2id (memory-hard) slows down guessing; note that guessing can be done offline by an active attacker (see Limitations)
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
| Key Derivation | Argon2id + HKDF | N/A | Direct key | TLS handshake |
| Forward Secrecy | Full (X25519 ECDHE) | N/A | No | Full (ECDHE) |
| Ease of Use | High | High | High | Medium |

## Compliance & Standards

### Cryptographic Standards
- **AES**: FIPS 197, NIST approved
- **GCM**: NIST SP 800-38D
- **Argon2id**: RFC 9106
- **HKDF**: RFC 5869
- **SHA-256**: FIPS 180-4

### Industry Guidelines
- **Key Length**: Meets NIST recommendations (256-bit)
- **Argon2id parameters**: OWASP minimum profile (t=3, m=19 MiB, p=1)
- **IV Length**: Optimal for GCM (96 bits)

## Known Vulnerabilities

### Fixed in 3.0.0 (affect ClawSec ≤ 2.8.2 — upgrade both endpoints)

| Issue | Impact |
|---|---|
| Receive path decrypted into the caller's buffer without a size check, before tag verification | Stack memory overwrite by an on-path attacker without the password |
| Frame header not authenticated | Replay of captured frames with an edited sequence number |
| One key for both directions | Reflection of a node's own frames |
| Stream data starting with `0x01` parsed as chat control messages | Silent data corruption; a peer could write files into the receiver's working directory |
| SOCKS proxy (unauthenticated) bound to all interfaces | Anyone on the LAN could use the proxy |
| `--tun` address passed unvalidated to shell commands run as root | Command injection via the `--tun` argument |
| `-e` built by default | Every binary could hand out a shell |

Details: [CHANGELOG.md](CHANGELOG.md) and
[releases/3.0.0/RELEASE_NOTES.md](releases/3.0.0/RELEASE_NOTES.md).
No CVE identifiers have been assigned.

### Open issues
See *Current Limitations* above (most importantly: no PAKE yet).

### Security Audits
- Initial implementation: November 2025
- Last review: November 2026 (internal review for 3.0.0)
- Status: Not externally audited (community project)

## Responsible Disclosure

Found a security issue? Please report it privately:
- GitHub private vulnerability report:
  https://github.com/LF3551/ClawSec/security/advisories/new
- Email: contact@alekseialeinikov.com

Use GitHub Issues only for non-security bugs.
**DO NOT** publicly disclose security vulnerabilities before coordinated disclosure.

## Future Enhancements

### Planned Security Features
1. **PAKE (e.g. CPace) + transcript-bound key confirmation**: remove offline password guessing by active attackers
2. **Per-user authentication**: Support multiple passwords/keys for multi-client deployments
3. **Key rotation**: Automatic session key renegotiation for long-lived connections

## Anti-Censorship / Anti-DPI

ClawSec can shape its traffic to look less like a custom protocol. These options do not
add secrecy and do not make ClawSec undetectable (see the README table for limits):

| Layer | Flag | Protection |
|-------|------|-----------|
| TLS Camouflage | `--obfs tls` | Runs the session inside TLS 1.3 (self-signed certificate) |
| Browser Mimicry | `--fingerprint chrome\|firefox\|safari` | ClientHello approximates a browser (not an exact JA3/JA4 match) |
| Encrypted Client Hello | `--ech` | Adds a GREASE ECH extension (the SNI stays visible) |
| Fallback | `--fallback host:port` | Clients without the knock are proxied to another service (they still see the self-signed certificate) |
| Packet Padding | `--pad` | Stream/chat/`-L` messages padded to 1400 bytes |
| Timing Jitter | `--jitter N` | Random 0-N ms delay before each message |

**All layers combined** (none of them makes ClawSec undetectable; see README):
```bash
# Server
clawsec -l -p 443 -k "Pass" --fallback 127.0.0.1:80 --ech --pad --jitter 100

# Client
clawsec -k "Pass" --fingerprint chrome --fallback 127.0.0.1:80 --ech --pad --jitter 100 server 443
```

Note: `--fingerprint` is client-side only (shapes outgoing ClientHello).
The server does not need it.
3. **Certificate Support**: Optional PKI for endpoint authentication
4. **Rate Limiting**: Protect against brute force

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

**Last Updated**: November 15, 2026  
**Release**: 3.0.0  
**Protocol Version**: 3  
**Maintainer**: ClawSec Project
