# ClawSec v3.0.0 — Security release (wire protocol 3)

ClawSec 3.0.0 fixes vulnerabilities in the encrypted record layer and several
broken features. The fixes required a new wire protocol, so **3.x does not
interoperate with 2.x — upgrade both endpoints.**

```bash
clawsec --version
# ClawSec 3.0.0 (wire protocol 3)
```

## 🔐 Security fixes

| Issue in ≤ 2.8.2 | Impact | Fix in 3.0.0 |
|---|---|---|
| `farm9crypt_read()` decrypted into the caller's buffer without checking its size, before verifying the tag | An on-path attacker **without the password** could forge a frame and overwrite stack memory behind small buffers (SOCKS status, file-transfer offset, reverse-tunnel signals) | Decrypt into an internal buffer; release plaintext only after tag verification and only if it fits (`EMSGSIZE`) |
| Frame header (sequence number, length, version, flags) not authenticated | A captured frame was accepted again after editing its sequence number (replay) | Header authenticated as AES-GCM associated data |
| One key for both directions | A node accepted its own frames reflected back to it | HKDF-SHA256 directional keys (client→server, server→client) for TCP and UDP |
| `--tun-udp`: sequence 0 always accepted; same key as the TCP channel | Negotiation probes could be replayed into the tunnel | Separate directional UDP keys; seq 0 reserved for negotiation and rejected as data |
| Stream mode parsed data starting with `0x01` as chat control messages | Silent data corruption (~14% of random 300 KB transfers); data starting with `0x01 'F'` wrote a file into the receiver's working directory | Control messages only in interactive chat mode (`-c`) |
| Sequence numbers could wrap after 2^32 messages | Nonce/sequence reuse in very long sessions | Session stops instead of wrapping |
| SOCKS client proxy (no auth) listened on `0.0.0.0`; `-R` ignored its host | Anyone on the LAN could use your proxy / reach the reverse port | Loopback by default; `-R` listens on the given address |
| `--tun` address went unvalidated into root shell commands | Command injection as root via the argument | Strict IPv4/prefix parsing; all values validated before `system()` |
| `-e` compiled into every build | Every binary could hand out a shell to password holders | Opt-in: `make <target> DFLAGS=-DGAPING_SECURITY_HOLE` |
| No version check, no key confirmation | 3.0 client vs 2.8.2 server failed silently; wrong password looked like a dropped connection | Version hello + HMAC key confirmation; clear errors and exit status 1 on both ends |

## 🛠 Fixed

- **`--mux` works again**: it failed on the first frame in 2.x (frame buffer
  4 bytes larger than the maximum message).
- **`--tun-udp` negotiation race**: the client's single UDP probe could arrive
  before the server's socket was bound, leaving the two sides on different
  transports. The server now binds first and the client retransmits until ACKed.
- **`-z` and `--pad` work**: they aborted transfers of binary data / any read
  over 1398 bytes. `-z` now also works with `-L`.
- **`--obfs tls`** no longer ends every session with an error (exit 1).
- **`--masquerade` cleans up**: the NAT rule and `ip_forward` are restored on exit.
  On macOS the rule no longer replaces your whole pf ruleset *(not covered by CI)*.
- Failures exit with status 1 (they exited 0).
- Test suite builds with GCC 14.
- Homebrew formula built from a non-existent `unix/` directory.

## ✨ Added

- `--version` (also in bash/zsh/fish completions and the man page).
- `tests/test_security.c`: a regression test for every issue above (131 unit tests).
- `make e2e`: end-to-end tests of the real binary — stream modes, `--obfs http|tls`,
  `--tofu`, `--pq`, `-z`, `--pad`, `-L`, `--mux`, `--socks`, `-R`, `--send/--recv`,
  wrong password, exit statuses, listener addresses (22 checks).
- `sudo make e2e-vpn`: `--tun`, `--tun-udp`, `--default-route` + `--masquerade`
  with cleanup on SIGINT/SIGTERM, between two network namespaces.
- `make test-asan`: unit tests under AddressSanitizer + UndefinedBehaviorSanitizer.
- CI runs the sanitizer build and both end-to-end suites.

## ⚠️ Breaking changes

- Wire protocol 3: no interoperability with ClawSec ≤ 2.8.2 (protocol 1).
  A 2.x peer is rejected with `the server/client does not speak ClawSec protocol v3`.
- `-e` (program execution) is no longer built by default:
  `make <target> DFLAGS=-DGAPING_SECURITY_HOLE`.
- `--socks PORT` and the `--mux` client `-p PORT` listen on 127.0.0.1; pass
  `0.0.0.0:PORT` to expose them. The `-R` server listens on the address you give
  (use `-R 0.0.0.0:PORT` for a public port, as in the examples).
- C API: `farm9crypt_init_password*()` take a role (`FARM9_ROLE_CLIENT` /
  `FARM9_ROLE_SERVER`); `farm9crypt_init()` was removed;
  `farm9crypt_export_key()` was replaced by `farm9crypt_export_udp_keys()`.

## Known limitations

See [SECURITY.md](../../SECURITY.md). Most importantly, there is no PAKE yet:
an active attacker who completes a handshake can guess the password offline.
**Use a long random password**, e.g. `openssl rand -base64 24`.
