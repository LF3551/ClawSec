# ClawSec Security Documentation

## Overview

ClawSec implements modern authenticated encryption using **AES-256-GCM** (Galois/Counter Mode), providing both confidentiality and integrity protection for network communications.

## Cryptographic Features

### Record Encryption
- **Cipher**: AES-256 (Advanced Encryption Standard, 256-bit key)
- **Mode**: GCM (Galois/Counter Mode) - AEAD (Authenticated Encryption with Associated Data)
- **Key Size**: 256 bits (32 bytes)
- **IV Size**: 96 bits (12 bytes) - optimal for GCM
- **Tag Size**: 128 bits (16 bytes) - authentication tag

### Key Exchange and Key Derivation
- **Handshake**: SPAKE2 password-authenticated key exchange (RFC 9382, ciphersuite
  P256-SHA256-HKDF-HMAC), verified against all RFC 9382 test vectors
- **Password scalar**: w = Argon2id(password) reduced modulo the P-256 group order
  (libargon2, t=3, m=19 MiB, p=1 — OWASP minimum profile), computed once per process
- **Forward secrecy**: fresh random SPAKE2 scalars per session; nothing long-term besides
  the password (and the optional `--tofu` identity key) exists
- **Explicit mutual key confirmation**: HMAC-SHA256 confirmation messages (RFC 9382
  section 4) whose keys are bound to `AAD = SHA-256(message 1 || message 2)`, i.e. to the
  complete handshake transcript (versions, options, `--tofu` identity key, ML-KEM data)
- **Session key**: `HKDF-SHA256(Ke [|| ML-KEM-768 shared secret], info = "ClawSec v4 session" || AAD)`
- **Traffic keys** (HKDF-SHA256, empty salt, info labels bound to the protocol version):
  - `ClawSec v4 tcp c2s` / `ClawSec v4 tcp s2c` — stream channel, one key per direction
  - `ClawSec v4 udp c2s` / `ClawSec v4 udp s2c` — `--tun-udp` data channel, one key per direction
  - `ClawSec v4 fingerprint` — session fingerprint shown in chat mode
- **Property**: only someone who knows the password completes the handshake; an active
  attacker gets exactly one password guess per connection and nothing to test guesses
  against offline; each direction and channel uses an independent key, so frames cannot
  be reflected or moved between channels

### Protocol Format

```
[MAGIC:4][VERSION:2][FLAGS:2][SEQ:4][LENGTH:4][IV:12][TAG:16][CIPHERTEXT:variable]

MAGIC    = 0x434C4157 ("CLAW")
VERSION  = 0x0004 (protocol version 4, ClawSec 4.x)
FLAGS    = 0x0000 (reserved, must be zero)
SEQ      = message sequence number (network byte order, replay protection)
LENGTH   = ciphertext length in bytes (network byte order, == plaintext length)
IV       = random initialization vector (unique per message)
TAG      = GCM authentication tag over AAD = the 16-byte header, and the ciphertext
```

Receiver rules:
- the header is authenticated: any change to MAGIC, VERSION, FLAGS, SEQ or LENGTH fails the tag;
- SEQ must equal the next expected value; a direction never reuses a SEQ (the session
  refuses to continue after 2^32 messages instead of wrapping);
- plaintext is decrypted into an internal buffer and copied to the caller only after the
  tag verifies, and only if it fits the caller's buffer (otherwise `EMSGSIZE`).

Protocol v4 (ClawSec 4.x) is not wire-compatible with protocol v3 (ClawSec 3.x) or
v1 (ClawSec ≤ 2.8.2); older peers are rejected with an explicit version error on both
ends. The protocol number follows the release major version, so there is no protocol v2.
The record layer (frame format above) is unchanged from v3; only the handshake changed.

### UDP VPN data channel (`--tun-udp`)

```
[MAGIC "CVPN":4][NONCE:12 = SEQ:4 || random:8][CIPHERTEXT][TAG:16]   AAD = "CVPN"
```

- Encrypted with the directional UDP keys (never the TCP keys).
- SEQ 0 is reserved for the negotiation probe/ACK; data starts at 1 and the
  256-entry sliding window rejects SEQ 0, duplicates and stale packets.
- The sender stops instead of wrapping SEQ.

### Session Handshake (protocol v4)

```
hello = "CS" || u16 version (= 4) || u16 flags          flags: 1 = --tofu, 2 = --pq

1  S -> C  hello || pB (65) || [identity pubkey (32)] || [ML-KEM-768 pubkey (1184)]
2  C -> S  hello || pA (65) || [ML-KEM-768 ciphertext (1088)]
3  S -> C  cB (32) || [Ed25519 signature (64)]
4  C -> S  cA (32)

pA = x*P + w*M   (client = SPAKE2 party A, identity "ClawSec v4 client")
pB = y*P + w*N   (server = SPAKE2 party B, identity "ClawSec v4 server")
K, TT, Ke, Ka, KcA, KcB, cA, cB as in RFC 9382, with AAD = SHA-256(msg1 || msg2)
signature = Ed25519(identity key, "ClawSec v4 server signature" || SHA-256(TT) || AAD)
session   = HKDF-SHA256(Ke [|| ML-KEM secret], info = "ClawSec v4 session" || AAD)
```

- Each side checks the peer's hello first: another protocol version or different
  `--tofu`/`--pq` settings are reported explicitly instead of failing later.
- Received points are validated (on the curve, not the identity); K must not be the identity.
- The server proves the password first (cB); the client verifies it — and, with `--tofu`,
  the signature and `known_hosts` — before it sends cA. The server accepts the session only
  after a valid cA; anything else is counted as an authentication failure.
- Confirmation MACs and the signature cover the whole transcript, so changing any
  handshake byte (version, flags, identity key, ML-KEM data) aborts the session.
- In UDP mode (`-u`) the connecting side takes the server role, because a UDP listener
  only learns its peer's address from the first datagram.

Perfect Forward Secrecy: the SPAKE2 scalars (and the ML-KEM key pair) are ephemeral.
Learning the password later does not decrypt recorded sessions.

## Security Properties

### ✅ Provided Protections

1. **Confidentiality**: AES-256 encryption protects data from eavesdropping
2. **Integrity**: GCM authentication tag detects tampering
3. **Password Authentication without Offline Guessing**: SPAKE2 (RFC 9382) — an eavesdropper learns nothing about the password, and an active attacker (including a man-in-the-middle) can test only one guess per connection
4. **IV Uniqueness**: Cryptographically secure random IV per message
5. **Replay Protection**: Authenticated, strictly consecutive sequence numbers reject duplicated, reordered and re-labelled messages
6. **Session Isolation**: Ephemeral SPAKE2 scalars ensure unique session keys
7. **Perfect Forward Secrecy**: Compromised password cannot decrypt past sessions
8. **TOFU Identity Verification**: `--tofu` provides SSH-like server identity with Ed25519 signing and `known_hosts` — detects MITM on reconnection
9. **Post-Quantum Confidentiality**: `--pq` mixes an ML-KEM-768 shared secret into the session key, so recorded traffic stays confidential against a future quantum adversary (see Limitations for the password)
10. **Reflection Resistance**: Separate keys per direction; a node never accepts its own frames
11. **Bounded Decryption**: Unauthenticated plaintext never reaches caller buffers; writes never exceed the buffer size
12. **Transcript-Bound Key Confirmation**: A wrong password, an incompatible peer or any modification of the handshake is detected during the handshake, on both ends
13. **Safe Defaults**: Local listeners (SOCKS proxy, `--mux`) bind to loopback; `-e` (program execution) is not built by default
14. **Password Handling**: `--key-file` / `CLAWSEC_PASSWORD` / no-echo prompt; `-k` is overwritten in argv; the environment variable is not inherited by child processes
15. **Resource Limits**: Session setup times out (`--handshake-timeout`, default 15 s); `-K` runs at most `--max-clients` handlers (default 16) and `--max-per-ip` per address (default 8, IPv6 per /64); Argon2id runs once per process, not per connection
18. **Online Guessing Limits**: with `-K`, an address with `--auth-fail-limit` (default 5) wrong passwords within 10 minutes is refused for 10 minutes; a single-session server exits after one failed attempt
16. **SOCKS Destination Policy**: The SOCKS server refuses loopback, link-local/cloud-metadata, multicast and reserved destinations (checked on resolved addresses), or allows only `--socks-allow` ranges
17. **Safe File Reception**: `--recv` writes to a private `<name>.clawsec-part` (O_NOFOLLOW, single link, own uid) and renames it only after SHA-256 verification; chat `/file` never overwrites or follows links

### ⚠️ Current Limitations

1. **No PKI/certificate infrastructure**: Without `--tofu`, authentication relies solely on the shared password. With `--tofu`, a changed server key is detected on reconnection, but first contact requires out-of-band fingerprint verification (no CA-signed certificates)
2. **Online guessing remains possible**: as with any PAKE, every connection is one password
   guess. `--auth-fail-limit` slows this down per address, but an attacker with many
   addresses gets more guesses; use a random password (e.g. `openssl rand -base64 24`),
   not a short human one
3. **Not quantum-resistant for the password**: SPAKE2 relies on discrete logarithms in P-256.
   A quantum attacker recording a handshake could later run an offline guessing attack on
   the password (and, without `--pq`, decrypt the session). `--pq` keeps the *session*
   confidential; it does not make the password check post-quantum
4. **Single shared password**: No per-user authentication; all clients share the same password,
   and the server holds it (SPAKE2 is a balanced PAKE: a compromised server reveals it)
5. **Post-quantum requires OpenSSL >= 3.5**: `--pq` needs ML-KEM support (OpenSSL 3.5+)

## Usage Guidelines

### Minimum Security Requirements

```bash
# Generate a random password once and store it with mode 0600
openssl rand -base64 24 > ~/.clawsec-key && chmod 600 ~/.clawsec-key

# Server and client read it from the file (not from the command line)
clawsec -l -p 1234 --key-file ~/.clawsec-key
clawsec --key-file ~/.clawsec-key <host> 1234
```

### Password Recommendations

SPAKE2 removes offline guessing, but every connection attempt is still one online
guess. Prefer a random password of at least 128 bits (`openssl rand -base64 24`);
human-chosen passwords should be long passphrases, never dictionary words or
common patterns. Never reuse the default/example passwords from documentation.

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
     `--max-clients` (default 16), `--max-per-ip` (default 8) and
     `--auth-fail-limit` (default 5 failures per 10 minutes, then a 10-minute block)
   - SOCKS server: restrict destinations with `--socks-allow` where possible

## Attack Scenarios & Mitigations

### 1. Man-in-the-Middle (MITM)
**Threat**: Attacker intercepts, relays or modifies the handshake
**Mitigation**: SPAKE2 — without the password the attacker cannot complete either side of
the handshake, and a failed attempt reveals nothing that allows offline guessing; the
transcript-bound confirmation detects any modification. `--tofu` additionally pins the
server identity
**Limitation**: one online guess per connection (rate-limited with `--auth-fail-limit`)

### 2. Replay Attacks
**Threat**: Attacker captures and resends encrypted messages
**Mitigation**: Sequence counter per direction, authenticated as GCM AAD; receiver rejects any message with an unexpected sequence number, and editing the number invalidates the tag. Separate keys per direction prevent reflection.
**Status**: ✅ Implemented (v2.4.0); header authentication and directional keys added in protocol v3 / ClawSec 3.0.0 (v1 accepted replays with an edited sequence number and reflected frames)

### 3. Password Guessing
**Threat**: Attacker tries to guess the password
**Mitigation**:
- Offline guessing is not possible: neither a recorded handshake nor an interfered one
  gives the attacker anything to test guesses against (SPAKE2)
- Online guessing: one guess per connection; `-K` blocks an address after
  `--auth-fail-limit` failures and limits concurrent handlers per address
- Failures are logged on the server (`authentication failure from <address> (n/limit)`)
- Use random passwords (≥ 128 bits)

### 4. Side-Channel Attacks
**Threat**: Timing or power analysis reveals information
**Mitigation**: Use constant-time OpenSSL implementations
**Note**: Physical access attacks out of scope

## Comparison with Other Tools

| Feature | ClawSec | Standard Netcat | Cryptcat (Old) | OpenSSL s_client |
|---------|---------|-----------------|----------------|------------------|
| Encryption | AES-256-GCM | None | Twofish (deprecated) | TLS 1.3 |
| Authentication | Password (SPAKE2 PAKE) + optional TOFU | None | None | PKI Certificates |
| Key Exchange | SPAKE2 (+ ML-KEM-768) + HKDF | N/A | Direct key | TLS handshake |
| Forward Secrecy | Full | N/A | No | Full (ECDHE) |
| Ease of Use | High | High | High | Medium |

## Compliance & Standards

### Cryptographic Standards
- **AES**: FIPS 197, NIST approved
- **GCM**: NIST SP 800-38D
- **SPAKE2**: RFC 9382 (P256-SHA256-HKDF-HMAC)
- **Argon2id**: RFC 9106
- **ML-KEM-768**: FIPS 203 (`--pq`)
- **Ed25519**: RFC 8032 (`--tofu`)
- **HKDF**: RFC 5869
- **SHA-256**: FIPS 180-4

### Industry Guidelines
- **Key Length**: Meets NIST recommendations (256-bit)
- **Argon2id parameters**: OWASP minimum profile (t=3, m=19 MiB, p=1)
- **IV Length**: Optimal for GCM (96 bits)

## Known Vulnerabilities

### Fixed in 4.0.0 (affect ClawSec ≤ 3.1.0 — upgrade both endpoints)

| Issue | Impact |
|---|---|
| Password mixed into the key after an unauthenticated X25519 exchange (no PAKE) | An active attacker (or a malicious peer) could guess the password offline against one captured handshake |
| `--tofu` signed only the server's ephemeral key; confirmation did not cover hellos/options | Handshake fields outside the signed key were not bound to the session |
| No limit on password attempts per address with `-K`; Argon2id per connection | Unthrottled online guessing; CPU/memory cost per connection attempt |

### Fixed in 3.1.0 (affect ClawSec ≤ 3.0.0)

| Issue | Impact |
|---|---|
| `--recv` followed a symlink/hard link named like the incoming file | A link in the receive directory made the receiver append to its target, corrupting an unrelated file |
| SOCKS server connected to any destination | Password holders could reach the server's loopback services and cloud metadata (SSRF) |
| No handshake timeout; `-K` forked without limit | A silent client held a single-session server forever; many clients exhausted memory (~19 MiB Argon2id each) |
| `-u`: one forged datagram ended the session | Off-path denial of service for UDP sessions |
| Password only via `-k` | Visible to other local users in the process list and in shell history |

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

Details: [CHANGELOG.md](CHANGELOG.md),
[releases/4.0.0/RELEASE_NOTES.md](releases/4.0.0/RELEASE_NOTES.md),
[releases/3.1.0/RELEASE_NOTES.md](releases/3.1.0/RELEASE_NOTES.md) and
[releases/3.0.0/RELEASE_NOTES.md](releases/3.0.0/RELEASE_NOTES.md).
GitHub Security Advisories:
[GHSA-xhj4-6qx3-3784](https://github.com/LF3551/ClawSec/security/advisories/GHSA-xhj4-6qx3-3784) (offline password guessing, fixed in 4.0.0, high),
[GHSA-p24v-84fh-v7r2](https://github.com/LF3551/ClawSec/security/advisories/GHSA-p24v-84fh-v7r2) (record layer, high),
[GHSA-vx49-pc8w-vgrx](https://github.com/LF3551/ClawSec/security/advisories/GHSA-vx49-pc8w-vgrx) (receiver file writes),
[GHSA-f39q-c788-x6h5](https://github.com/LF3551/ClawSec/security/advisories/GHSA-f39q-c788-x6h5) (SOCKS exposure/SSRF),
[GHSA-jxhr-v32g-6pjx](https://github.com/LF3551/ClawSec/security/advisories/GHSA-jxhr-v32g-6pjx) (denial of service).
No CVE identifiers have been requested.

### Open issues
See *Current Limitations* above.

### Security Audits
- Initial implementation: November 2025
- Last review: November 2026 (internal reviews for 3.0.0, 3.1.0 and 4.0.0)
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
1. **Per-user authentication**: multiple passwords/keys for multi-client deployments
2. **Key rotation**: automatic session key renegotiation for long-lived connections
3. **Post-quantum password authentication**: a PAKE that stays secure against quantum
   adversaries once standardised designs mature

### Under Consideration
- ChaCha20-Poly1305 as alternative cipher
- Hardware security module (HSM) support

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
**Release**: 4.0.0  
**Protocol Version**: 4  
**Maintainer**: ClawSec Project
