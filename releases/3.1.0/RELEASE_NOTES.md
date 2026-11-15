# ClawSec v3.1.0 — Hardening, reliability and packaging

**Wire-compatible with 3.0.0** (protocol 3): 3.0.0 and 3.1.0 endpoints work
together. Upgrading is recommended for everyone on 3.0.0 or earlier.

```bash
clawsec --version
# ClawSec 3.1.0 (wire protocol 3)
```

## 🔐 Security fixes

| Issue in ≤ 3.0.0 | Impact | Fix in 3.1.0 |
|---|---|---|
| `--recv` followed a symlink/hard link named like the incoming file | The receiver appended data to the link target, corrupting an unrelated file | Data goes to a private `<name>.clawsec-part` (O_NOFOLLOW, single link, own uid) and is renamed into place only after SHA-256 matches |
| SOCKS server connected to any destination | Password holders reached the server's loopback services and cloud metadata (169.254.169.254) | Loopback, link-local/metadata, multicast and reserved destinations denied by default (checked on resolved addresses); `--socks-allow CIDR,...` |
| No handshake timeout; unlimited `-K` | A silent client held a single-session server forever; many clients exhausted memory | `--handshake-timeout` (default 15 s), `--max-clients` (default 16) |
| `-u`: one forged/lost/reordered datagram ended the session | Off-path denial of service, fragile UDP sessions | 64-entry anti-replay window; invalid datagrams dropped |
| Password only via `-k` | Visible in the process list and shell history | `--key-file`, `CLAWSEC_PASSWORD` (unset after reading), no-echo prompt; `-k` warns and is overwritten in argv |
| TUN/VPN commands ran through a shell | Defence in depth (input was already validated in 3.0.0) | `ip`/`iptables`/`nft`/`pfctl`/... run via `execvp`, never `/bin/sh` |

## 🛠 Fixed

- `--mux` reuses stream ids (a tunnel was limited to 63 connections in total)
- `--persistent` gives up on a wrong password instead of reconnecting forever
- SYN scan (`--scan` as root) found nothing: missing TCP checksum; fixed on Linux
- TLS camouflage sessions leaked on every reconnect
- `select()` replaced by `poll()` (no 1024-descriptor limit)
- macOS: build fix and Homebrew paths on Intel Macs

## 📦 Packaging

- **Linux binaries are fully static** (x86_64, arm64): no OpenSSL, libargon2 or zlib
  needed, any distribution
- **macOS binaries** for arm64 and x86_64
- **Homebrew:** `brew install lf3551/clawsec/clawsec`
- **Docker:** `ghcr.io/lf3551/clawsec:3.1.0` / `lf3551/clawsec:3.1.0` — multi-arch
  (amd64, arm64), 18 MB, non-root, no default password:
  `docker run -e CLAWSEC_PASSWORD="$(openssl rand -base64 24)" -p 8888:8888 ghcr.io/lf3551/clawsec:3.1.0`
- AUR: `clawsec` 3.1.0

## ⚠️ Behaviour changes

- The SOCKS server denies loopback/link-local destinations unless allowed, e.g.
  `--socks-allow 127.0.0.1/32` (an explicit list replaces the defaults).
- `-K` runs at most 16 concurrent handlers by default (`--max-clients`).
- Session setup times out after 15 s by default (`--handshake-timeout 0` disables).
- The Docker image has no default password; set `CLAWSEC_PASSWORD`.

## 🧪 Quality

130 unit tests (ASan, UBSan, LeakSanitizer), 37 end-to-end checks, VPN tests in
network namespaces and a macOS TUN test, libFuzzer harnesses for the record layer
and all parsers, zero `-Wall -Wextra` warnings with `-Werror` in CI, hardened
builds (FORTIFY, stack protector, PIE, full RELRO), GitHub Actions pinned by SHA.

Full list: [CHANGELOG.md](https://github.com/LF3551/ClawSec/blob/v3.1.0/CHANGELOG.md).
Known limitations (no PAKE yet — use a long random password):
[SECURITY.md](https://github.com/LF3551/ClawSec/blob/v3.1.0/SECURITY.md).
