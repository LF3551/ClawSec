# ClawSec v4.0.0 — Password-authenticated key exchange (SPAKE2)

**Wire protocol 4 — not compatible with 3.x. Upgrade both ends.**
An older peer is rejected immediately with a version error.

```bash
clawsec --version
# ClawSec 4.0.0 (wire protocol 4)
```

## Why a new major version

Up to 3.1.0 the password was mixed into the session key *after* an
unauthenticated X25519 exchange. Anyone who could run one handshake against
a client or server — a man-in-the-middle, or simply a client connecting to a
public server — could then guess the password **offline**, at the speed of
Argon2id on their own hardware. Short or human-chosen passwords were at risk.

4.0.0 replaces the handshake with **SPAKE2 (RFC 9382)**, a password-authenticated
key exchange:

| | ≤ 3.1.0 | 4.0.0 |
|---|---|---|
| Passive eavesdropper | learns nothing | learns nothing |
| Active attacker / malicious peer | **offline guessing** after one handshake | **one guess per connection**, nothing to test offline |
| Handshake integrity | `--tofu` signed only the server key; hellos not confirmed | confirmation MACs and `--tofu` signature cover the whole transcript |
| Guessing against a `-K` server | unlimited, 19 MiB Argon2id per attempt | `--auth-fail-limit` lockout, `--max-per-ip`, Argon2id once per process |
| Forward secrecy | yes | yes |

## 🔐 Security

- **SPAKE2** (P256-SHA256-HKDF-HMAC), implemented on OpenSSL's P-256 arithmetic
  and verified byte-for-byte against all RFC 9382 test vectors. Received points
  are validated; secret scalars use constant-time code paths.
- **Transcript binding.** `AAD = SHA-256(message 1 || message 2)` keys the
  confirmation MACs and the session key; `--tofu` signs `SHA-256(TT) || AAD`.
  Changing any handshake byte — version, `--tofu`/`--pq` flags, identity key,
  ML-KEM ciphertext — aborts the session on both ends (tested with a
  man-in-the-middle relay).
- **`-K` guessing limits.** `--auth-fail-limit 5` (default): an address with five
  wrong passwords within 10 minutes is refused for 10 minutes — even with the
  right password. `--max-per-ip 8` (default) stops one address from taking all
  `--max-clients` slots. IPv6 is counted per /64.
- **`--pq`** still mixes an ML-KEM-768 secret into the session key (recorded
  traffic stays confidential against a future quantum computer). Note that the
  password check itself — like any discrete-log PAKE — is not post-quantum.

## Handshake (protocol 4)

```
1  S->C  hello("CS", 4, flags) || pB [|| identity key] [|| ML-KEM public key]
2  C->S  hello("CS", 4, flags) || pA [|| ML-KEM ciphertext]
3  S->C  cB [|| Ed25519 signature]
4  C->S  cA
```

The record layer (AES-256-GCM frames, directional keys, sequence numbers) is
unchanged. Full description: [SECURITY.md](../../SECURITY.md#session-handshake-protocol-v4).

## ⬆️ Upgrading

- Upgrade **both** endpoints; 3.x and 4.x refuse each other with a clear message.
- Different `--tofu`/`--pq` settings now fail with `option mismatch` instead of a
  generic error.
- `-K` servers: if many legitimate clients share one address (NAT) and open more
  than 8 sessions at once (e.g. `-L` without `--mux`), raise `--max-per-ip`.
- `--tofu` identity keys and `known_hosts` entries stay valid.

## ✅ Testing

- 144 unit tests (RFC 9382 vectors, handshake failure modes, MITM tampering,
  per-address limits), 39 end-to-end tests, 4 VPN tests (namespaces), ASan/UBSan/
  LeakSanitizer, `-Werror`, libFuzzer (new SPAKE2 harness).
- Interoperability checked against the published 3.1.0 binaries (TCP and UDP,
  both directions): explicit version errors, no hangs except the documented UDP case.

## 📦 Install

```bash
brew install lf3551/clawsec/clawsec
docker pull ghcr.io/lf3551/clawsec:4.0.0
yay -S clawsec
# or a static binary from the assets below (verify with SHA256SUMS)
```
