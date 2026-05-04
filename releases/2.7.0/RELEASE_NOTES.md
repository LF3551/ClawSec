# ClawSec v2.7.0 — Reverse Tunnel + File Transfer + Persistent

## New Features

### 🔁 Reverse Tunnel (`-R host:port`)
SSH-like reverse port forwarding through encrypted tunnel.
Server listens on extra port; incoming connections are tunneled to client's local target.
Works behind NAT/firewalls — no port forwarding required on client side.

```bash
# Server: open public port 8080, tunnel to client
./clawsec -l -k "pass" -p 9999 -R 0.0.0.0:8080

# Client (behind NAT): forward to local web app
./clawsec -k "pass" -R 127.0.0.1:3000 server.com 9999
```

### 📁 Encrypted File Transfer (`--send` / `--recv`)
Dedicated file transfer mode with:
- AES-256-GCM encrypted stream
- SHA-256 end-to-end verification
- Automatic resume on interrupted transfers
- Progress bar with speed display
- Path traversal protection (CWE-22)

```bash
./clawsec -l -k "pass" -p 4444 --recv ./incoming
./clawsec -k "pass" --send backup.tar.gz server.com 4444
```

### 🔄 Persistent Auto-Reconnect (`--persistent`)
Turns any tunnel into a stable persistent channel:
- Exponential backoff: 1s → 60s with ±25% jitter
- Heartbeat detection for dead tunnel awareness
- Works with `-L`, `-R`, `--socks`, chat

```bash
./clawsec -k "pass" --persistent -R 127.0.0.1:22 server.com 9999
```

### 🌐 SOCKS5 Proxy (`--socks`)
Full SOCKS5 proxy through encrypted tunnel — route any app:
```bash
./clawsec -l -k "pass" -p 9999 --socks 0
./clawsec -k "pass" --socks 1080 server.com 9999
curl --proxy socks5://127.0.0.1:1080 https://ifconfig.me
```

### 🔍 Port Scanner (`--scan`) + Banner Grab (`-b`)
Stealth port scanning with randomized order and service detection:
```bash
./clawsec --scan 1-1024 -b target.com
```

## Changes
- `--recv` now requires directory argument (fixes getopt quirk with optional args)
- Password warning if < 8 characters

## Test Suite
- **95 tests** (up from 65 in v2.5.0)
- New test coverage: file transfer, reverse tunnel, persistent, SOCKS5, portscan

## Security Notes
- File receiver sanitizes filenames (strips `/`, `\`, leading `.`)
- Reverse tunnel signals travel only through authenticated encrypted channel
- Heartbeat packets are distinct from all control signals

---

**Full Changelog**: [CHANGELOG.md](CHANGELOG.md)

**Platforms**: Linux (x86_64, arm64), macOS (arm64), FreeBSD
