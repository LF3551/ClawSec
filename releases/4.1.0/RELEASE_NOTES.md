# ClawSec v4.1.0 — Concurrent SOCKS, flow control, half-close

**Wire-compatible with 4.0.0** (protocol 4). The improvements are negotiated
inside the encrypted channel and take effect when both ends run 4.1; mixed
4.0/4.1 setups keep working with 4.0 behaviour.

```bash
clawsec --version
# ClawSec 4.1.0 (wire protocol 4)
```

## 🐛 Fixed

| Problem in ≤ 4.0.0 | Fix in 4.1.0 |
|---|---|
| **SOCKS broke after the first connection** to a destination that keeps its socket open (HTTP keep-alive, TLS): the next CONNECT was relayed as data to the *previous* destination, which also saw the next host name | SOCKS runs over the stream multiplexer: every connection is its own stream with an explicit end |
| SOCKS handled one connection at a time | Up to 255 concurrent connections per tunnel |
| `-u`: one lost handshake datagram failed the connection | Retransmission with backoff, duplicate detection, last message sent three times |
| ~40 ms extra latency per small message (Nagle) | `TCP_NODELAY` on the tunnel; 300 SOCKS connections 13.4 s → 0.1 s |

## ✨ mux v2 (`--mux`, `--socks`)

- **Flow control** per stream (256 KiB window): a stalled reader holds up only
  its own stream; memory stays bounded.
- **Half-close**: send a request, close your write side, still get the whole
  response.
- **No head-of-line blocking** from slow destinations: connects and DNS run in
  helper threads, all socket writes are queued and non-blocking.

## ⬆️ Upgrading

- Upgrade both ends to get concurrent SOCKS and the mux v2 features; a 4.1
  client talking to a 4.0 server prints
  `Warning: the server runs ClawSec < 4.1: SOCKS connections are handled one at a time`.
- No option changes.

## ✅ Testing

147 unit tests, 47 end-to-end tests (new SOCKS suite: keep-alive, 40 parallel
connections, half-close, 8 MiB stalled stream next to a live one, 300
connections), 4 VPN tests, ASan/UBSan/LeakSanitizer, libFuzzer (SOCKS5 and mux
parsers). Interoperability with the 4.0.0 binaries checked for SOCKS and
`-L --mux` in both directions.

## 📦 Install

```bash
brew upgrade lf3551/clawsec/clawsec
docker pull ghcr.io/lf3551/clawsec:4.1.0
yay -S clawsec
# or a static binary from the assets below (verify with SHA256SUMS)
```
