# ClawSec v2.6.0 — Post-Quantum + Argon2id

Major cryptographic upgrade: post-quantum hybrid key exchange, memory-hard KDF, and codebase restructuring.

## New Features

### Post-Quantum Hybrid Key Exchange (`--pq`)
- **X25519 + ML-KEM-768** hybrid handshake — resistant to quantum computer attacks
- Compatible with `--tofu` for full PQ + identity verification stack
- Graceful fallback: plain ECDHE on OpenSSL < 3.5

### Argon2id Key Derivation
- Replaced PBKDF2-SHA256 with **Argon2id** (memory-hard, GPU/ASIC resistant)
- Parameters: t=3, m=19 MiB, p=1 (OWASP 2024 recommendations)
- Automatic PBKDF2 fallback on OpenSSL < 3.2

## Improvements

### Architecture
- **Repo reorganization**: `unix/` → `src/`, tests → `tests/`, docs → `docs/`, scripts → `scripts/`
- **ECDHE decomposition**: extracted handshake code into `ecdhe.cc/h` (farm9crypt.cc: 1046 → 497 lines)
- Deduplicated X25519 keygen, derive, key derivation helpers

### Security Fixes
- **TOCTOU race condition** in `/file` command (CWE-367) — `stat()` + `open()` → `open()` + `fstat()`

### Testing
- **72 tests** (was 58), all passing
- `TEST_SKIP` macro for graceful degradation on older OpenSSL
- 7 new Argon2id tests, 7 new ML-KEM-768 tests

## Cryptographic Stack

| Layer | Algorithm | Status |
|-------|-----------|--------|
| Key Exchange | X25519 ECDHE | ✅ Always |
| Post-Quantum | ML-KEM-768 hybrid | ✅ `--pq` (OpenSSL ≥ 3.5) |
| Server Identity | Ed25519 TOFU | ✅ `--tofu` |
| KDF | Argon2id (PBKDF2 fallback) | ✅ Always |
| Encryption | AES-256-GCM | ✅ Always |

## Download

- **macOS (arm64)**: `clawsec-2.6.0-macos.tar.gz`
- **Docker**: `docker pull ghcr.io/lf3551/clawsec:2.6.0`

## Verification

```
shasum -a 256 clawsec-2.6.0-*.tar.gz
```

See `SHA256SUMS` for expected values.
