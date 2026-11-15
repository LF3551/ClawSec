# Changelog

All notable changes to ClawSec will be documented in this file.

## [3.0.0] - 2026-11-15

Major release: security fixes that required a new, incompatible wire protocol.
**Upgrade both endpoints**: 3.x does not interoperate with 2.x (`clawsec --version`
shows the release and protocol version). The wire protocol number now follows the
release major version (protocol 1 → 3).

### Security
- **Wire protocol v3 (breaking: not compatible with ≤ 2.8.2).** The 16-byte frame
  header (magic, version, flags, sequence number, length) is now authenticated as
  AES-GCM associated data. In protocol v1 a captured frame could be replayed by editing its
  unauthenticated sequence number.
- **Directional keys.** HKDF-SHA256 derives independent client→server and
  server→client keys from the session key. In protocol v1 both directions shared one key,
  so a node accepted its own frames reflected back to it.
- **Receive-buffer overflow fixed.** `farm9crypt_read()` decrypted into the caller's
  buffer without honouring its size, before verifying the tag. A frame forged by an
  on-path attacker (no password needed) could overwrite up to ~8 KB of stack memory
  behind small buffers (e.g. SOCKS status, file-transfer offsets, reverse-tunnel
  signals). Plaintext is now decrypted internally and released only after tag
  verification, never beyond the caller's buffer (`EMSGSIZE` otherwise).
- Sequence numbers are never reused: a session stops after 2^32 messages per
  direction instead of wrapping (TCP and UDP channels).
- `--tun-udp`: the UDP data channel uses its own directional keys (separate from the
  TCP channel), and sequence number 0 — reserved for the negotiation probe/ACK — is
  no longer accepted as data, so captured probes cannot be replayed into the tunnel.
- Stream mode no longer interprets payload bytes as chat control messages. Data that
  happened to start with `0x01` was silently dropped (corrupting transfers), and data
  starting with `0x01 'F'` made the receiver write a file into its working directory.
  Control messages are now only processed in interactive chat mode (`-c`).
- **Handshake version check and key confirmation.** Each side sends a hello with
  its protocol version; a 2.x peer or a non-ClawSec service is reported immediately
  instead of failing silently. After the key exchange both sides prove knowledge of
  the session key (HMAC-SHA256), so a wrong password is reported on both ends.
- **SOCKS proxy bound to all interfaces.** The unauthenticated `--socks` client
  proxy listened on `0.0.0.0` (the log said 127.0.0.1), so anyone on the LAN could
  use it. `--socks [host:]port` and the `--mux` client port (`-p [host:]port`) now
  default to loopback; the `-R` server listens on the address given in its spec
  (previously the host part was ignored and it listened on all interfaces).
- **Command injection via `--tun` (root).** The address part of `--tun` went
  unvalidated into `ip`/`ifconfig`/`iptables` command lines. The CIDR is now parsed
  strictly, and gateway/interface values read back from `ip route`/`route` are
  validated before reuse.
- **`-e` is opt-in.** Remote program execution was compiled into every build; build
  with `make <target> DFLAGS=-DGAPING_SECURITY_HOLE` to get it.
- The TUN signal handler no longer calls `system()` (not async-signal-safe); it sets
  a flag and cleanup runs on the normal path.
- Key material is wiped with `OPENSSL_cleanse`.

### Fixed
- `--mux` did not work at all: every frame read failed with `EINVAL` (frame buffer
  4 bytes larger than the maximum message), and full 8 KB reads could not be sent.
  `MUX_MAX_PAYLOAD` is now `8192 - MUX_HDR_SIZE`.
- `--tun-udp` negotiation race: the client sent a single UDP probe that could arrive
  before the server had bound its socket, silently falling back to TCP on one side.
  The server now binds before announcing its token, the client retransmits the probe
  until it is acknowledged, and invalid datagrams are ignored instead of aborting.
- `-z` aborted on incompressible data and `--pad` aborted any read above 1398 bytes:
  input is now read in chunks whose compressed/padded size fits one message. `-z`
  also works with `-L` (the server side never compressed). Inline `/file` in chat is
  limited to what fits in one message (~8 KB) with a clear error instead of failing.
- `--obfs tls` ended every session with "read from network failed" (exit 1): the
  sender now sends TLS `close_notify` and a bare TCP EOF ends the stream like plain TCP.
- `--masquerade` left its NAT rule and `ip_forward=1` behind; both are undone on exit
  (iptables, or a dedicated `ip clawsec` nftables table). On macOS the NAT rule goes
  into the `com.apple/clawsec` pf anchor instead of replacing the whole pf ruleset,
  uses the default-route interface instead of `en0`, and the utun netmask follows
  the prefix (was always /24). *(macOS paths are not covered by CI.)*
- Failures now exit with status 1 (handshake, wrong password, TLS camouflage, file
  transfer, TUN setup); previously the process exited 0.
- `--persistent` stops instead of reconnecting after Ctrl-C in VPN mode.
- `ecdhe_recv()` accepted short reads in `--obfs tls`/`http` as complete messages.
- Test suite builds with GCC 14 (`usleep` replaced by a `nanosleep` helper).

### Changed
- `farm9crypt_init_password*()` take a role (`FARM9_ROLE_CLIENT` / `FARM9_ROLE_SERVER`).
  The deprecated `farm9crypt_init(char*)` (which read a raw key with `strlen`) was
  removed. `farm9crypt_export_key()` was replaced by `farm9crypt_export_udp_keys()`.
- Session fingerprint is derived with HKDF (still identical on both ends).
- **Breaking:** `-e` requires an opt-in build (see Security). `--socks` and the
  `--mux` client port listen on loopback unless an address is given.
- Host/port specs are validated at startup (port must be 1-65535).
- Docs: the duplicate root `EXAMPLE_USAGE.md` was merged into
  `docs/EXAMPLE_USAGE.md`; SECURITY.md lists the fixed issues and a private
  reporting channel.
- Packaging: AUR `pkgver`, Homebrew formula (also fixed its build directory:
  `src`, not `unix`) and `scripts/build-release.sh` default to 3.0.0.

### Added
- `--version`: prints the release and wire protocol version (also in shell completions
  and the man page).
- `tests/test_security.c`: regression tests for each issue above.
- `tests/e2e.sh` (`make e2e`): end-to-end tests of the real binary — stream modes,
  `--obfs http|tls`, `--tofu`, `--pq`, `--mux`, `--socks`, `-R`, `--send/--recv`,
  wrong password, control-byte payloads.
- `tests/e2e_vpn.sh` (`sudo make e2e-vpn`): `--tun` and `--tun-udp` across two
  network namespaces, plus `--default-route` + `--masquerade` set-up and cleanup on
  SIGINT/SIGTERM.
- e2e also covers `-z`, `--pad`, `-L`, exit statuses, listener addresses and the
  `-e` opt-in.
- `make test-asan`; CI runs the unit tests under ASan/UBSan and both e2e suites.

## [2.8.2] - 2026-05-11

### Fixed
- Add VPN options to shell completions (zsh, bash, fish): `--tun`, `--tun-udp`, `--masquerade`, `--default-route`, `--scan`, `-b`, `--socks`, `--send`, `--recv`, `-R`, `--persistent`

## [2.8.1] - 2026-05-10

### Fixed
- Fix flaky `fallback knock` TLS test race condition on macOS CI (usleep before accept)

### Changed
- CI: Docker images now published to both ghcr.io and Docker Hub (`lf3551/clawsec`)

## [2.8.0] - 2026-05-10

### Added — TUN VPN
- `--tun <ip/mask>` — Zero-config encrypted VPN via TUN interface. Creates
  virtual network interface with full L3 connectivity. Supports macOS (utun)
  and Linux (/dev/net/tun). Wire protocol: TVPN header + encrypted IP packets.
- `--tun-udp` — UDP data channel for VPN. After TCP handshake (ECDHE key
  exchange), VPN data is relayed over a dedicated UDP socket with per-packet
  AES-256-GCM encryption. Eliminates TCP-over-TCP meltdown, reduces latency.
  Wire format: `CVPN(4B) + nonce(12B) + ciphertext + GCM tag(16B)`.
  Includes replay protection (256-bit sliding window) and automatic TCP fallback.
- `--masquerade` — Enable NAT/masquerade on server side. Allows VPN clients
  to access the internet through the server as exit node. Uses iptables on
  Linux, pf on macOS.
- `--default-route` — Full tunnel mode: routes ALL client traffic through the
  VPN. Saves and restores original routes on disconnect. Server must have
  `--masquerade` enabled. Works like WireGuard `AllowedIPs = 0.0.0.0/0`.
- Keepalive heartbeats (THB) every 30s to maintain VPN tunnel.
- `farm9crypt_export_key()` — Export session key for external use (UDP VPN).
- 17 new unit tests (CIDR parsing, validation, wire format, constants,
  UDP encrypt/decrypt round-trip, tamper detection, wrong key, truncated/bad magic).

## [2.6.0] - 2026-05-04

### Added — Offensive / Pentest Tools
- `--scan <range>` — Stealth port scanner with randomized order, configurable
  timeout, and connect-based scanning. Range syntax: `1-1024`, `80`, `all`.
- `-b` — Banner grabbing: detect service versions on open ports during scan.
- `--socks <port>` — Full SOCKS5 proxy through encrypted tunnel. Client opens
  local SOCKS5 listener, server proxies outbound connections.
- `--send <file>` / `--recv <dir>` — Dedicated encrypted file transfer with:
  SHA-256 end-to-end verification, automatic resume on interrupted transfers,
  progress bar, path traversal protection (CWE-22).
- `-R <host:port>` — Reverse tunnel (like SSH `-R`): server listens on extra port,
  incoming connections are forwarded through encrypted tunnel to client's local
  target. Works behind NAT/firewalls.
- `--persistent` — Auto-reconnect with heartbeat + exponential backoff (1s→60s
  with ±25% jitter). Turns one-shot tunnel into persistent stable channel.
  Works with any mode: `-L`, `-R`, `--socks`, chat.

### Changed
- Password warning threshold: warn if < 8 characters
- `--recv` changed from optional to required argument (fixes getopt quirk)
- Test suite expanded: 65 → 92 tests

### Security
- File transfer receiver sanitizes filenames (strips `/`, `\`, leading `.`)
- Reverse tunnel uses authenticated signals through encrypted channel only

## [2.5.0] - 2026-05-03

### Added — Stealth Mode (Anti-DPI / Anti-Fingerprint)
- `--pq` — Post-quantum hybrid key exchange: X25519 + ML-KEM-768 (CRYSTALS-Kyber).
  Both classical ECDHE and quantum-resistant KEM shared secrets are combined,
  so the session key is secure against both classical and quantum adversaries.
  Requires OpenSSL >= 3.5. Combinable with `--tofu`.
- `--tofu` — Trust On First Use: SSH-like server identity verification with
  persistent Ed25519 keypair. Server signs ephemeral ECDHE keys; client verifies
  signature and checks `~/.clawsec/known_hosts`. Detects MITM on reconnection.
- `--fingerprint chrome|firefox|safari` — TLS ClientHello shaping: cipher suite
  order, supported groups, signature algorithms, ALPN, and Chrome-specific
  extensions (ALPS 0x4469) are set to match a real browser’s JA3/JA4
  fingerprint. DPI cannot distinguish ClawSec from normal browser traffic.
- `--fallback host:port` — REALITY-like active probing resistance: when DPI or a
  browser connects, traffic is proxied to a real website. Only ClawSec clients
  that send the correct knock sequence get the encrypted tunnel.
- `--ech` — Encrypted Client Hello: GREASE ECH extension in TLS ClientHello,
  hides SNI from DPI. Automatically enables TLS mode.
- `--mux` — Stream multiplexer: multiple logical connections over one encrypted
  tunnel. Server: `--mux -L host:port`, Client: `--mux -p local_port`.
  Up to 64 concurrent streams.
- `--obfs tls` — TLS 1.3 camouflage: wraps connection in a real TLS session
  with auto-generated EC P-256 certificate and randomized CDN-like SNI hostname.
  Traffic is indistinguishable from HTTPS to any DPI system.
- `--pad` — Uniform packet padding: all packets padded to 1400 bytes with
  cryptographically random data. Defeats traffic analysis based on packet sizes.
- `--jitter N` — Timing jitter: random 0-N ms delay between packets.
  Defeats timing correlation attacks.

### Added — Production Features
- `-K` keep-open mode: accept multiple clients (fork per connection)
- `-L host:port` port forwarding: encrypted tunnel without SSH
- `--obfs http` HTTP obfuscation: wrap packets as HTTP POST requests
- `-z` zlib compression before encryption
- `-P` transfer progress bar with speed display
- `-V` SHA-256 end-to-end file verification
- `-n name` custom chat nicknames
- Chat mode enhancements: session fingerprints (emoji + hex), read receipts,
  `/file`, `/ping`, `/clear`, `/whoami`, `/help` slash commands

### Added — Security
- X25519 ECDHE for Perfect Forward Secrecy
- Replay protection with sequence counters
- 65 integration tests covering crypto, protocol, obfuscation, stealth, ECH, mux, fallback, fingerprint, TOFU, post-quantum

## [2.3.0] - 2025-11-23

### Changed
- **Complete code rewrite**: Modernized from legacy K&R C to C99/POSIX standards
- Reduced codebase from 1714 to 439 lines (75% reduction)
- Binary size reduced from 72KB to 37KB (48% smaller)
- Removed obsolete `generic.h` compatibility layer (1996 legacy code)
- Improved code architecture with clean function separation
- Enhanced error handling on all system calls
- Thread-safe functions: `localtime_r`, `strerror_r`
- Proper resource cleanup and memory management

### Added
- Chat mode with timestamps and colored output (server-side only)
- File transfer mode with auto-close and statistics
- Robust `write_all()` with EINTR handling
- Non-blocking `connect_with_timeout()` with select
- Signal handling (SIGPIPE ignored)

### Fixed
- Chat mode formatting isolated to server in listen mode
- Reverse shell mode works cleanly without formatting artifacts
- File transfer completes gracefully with `shutdown(SHUT_WR)`

### Removed
- Legacy K&R C code and goto statements
- Global variables and setjmp/longjmp
- Platform-specific compatibility hacks for obsolete systems
- Unused files: `generic.h`, old documentation

## [2.0.0] - 2025-11-22

### Added
- AES-256-GCM authenticated encryption
- PBKDF2-HMAC-SHA256 key derivation (100,000 iterations)
- Protocol versioning with magic number validation
- Secure random IV generation using OpenSSL
- Memory wiping for sensitive data
- Comprehensive security documentation
- Docker support with Alpine Linux
- Kubernetes deployment manifests
- Systemd service file
- Automatic installation script
- CI/CD with GitHub Actions
- Multi-platform build support

### Changed
- Renamed binary from `cryptcat` to `clawsec`
- Updated all documentation to English
- Improved error messages and user feedback
- Enhanced Makefile with platform-specific targets

### Removed
- Deprecated Twofish encryption
- Hardcoded default password "metallica"
- Legacy Cryptcat documentation
- Obsolete netcat promotional files

### Security
- Fixed direct key usage vulnerability
- Removed weak random number generation
- Added GCM authentication tags
- Implemented secure password-based key derivation
- Added protocol version checking

## [1.x] - Legacy Cryptcat

### Features
- Twofish encryption (deprecated)
- Basic netcat functionality
- Direct key usage (insecure)

---

**Note:** Version 2.0.0 represents a complete cryptographic rewrite and is **not compatible** with legacy Cryptcat versions.
