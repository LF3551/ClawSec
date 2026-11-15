# ClawSec v4.2.0 — Multi-client VPN, IPv6, per-user passwords

**Wire-compatible with 4.0 and 4.1** for every existing option. One change to
note: **`--pad` now needs 4.2 on both ends** (it moved to the record layer and
works in every mode).

```bash
clawsec --version
# ClawSec 4.2.0 (wire protocol 4)
```

## ✨ New

### Multi-client VPN hub
```bash
sudo clawsec -l -p 9000 -K --tun 10.8.0.1/24 --tun6 fd00:c1a5::1/64 --masquerade
sudo clawsec --tun auto --default-route vpn.example.com 9000      # 10.8.0.2 + fd00:c1a5::2
```
- One TUN device, one process per client, routing by destination.
- Every client may only send from its own addresses — spoofed packets are
  dropped and logged.
- `--tun auto` (address from the server) or a fixed address; conflicts are
  refused with a clear message. 4.1 clients keep working.

### IPv6 inside the tunnel
`--tun6` on the server; clients get a matching address. IPv6 NAT with
`--masquerade`, IPv6 full tunnel with `--default-route` (`::/1` + `8000::/1`).

### Per-user passwords
```bash
clawsec --users /etc/clawsec/users --add-user alice     # asks twice, file mode 0600
clawsec -l -p 9000 -K --users /etc/clawsec/users
clawsec --user alice server.example.com 9000
```
SPAKE2 with the user name bound into the transcript; unknown users fail
exactly like wrong passwords; users can be added or removed without a restart.

### Faster SYN scan, IPv6
Pipelined at `--scan-rate` probes/s (default 1000) with open/closed/filtered
results; 2000 ports with 200 firewalled ones take ~4 s instead of minutes.

### `--pad` everywhere
Every encrypted record is padded to 1400-byte units in every mode, including
`--mux`, `--socks`, `-R`, `-u`, `--tun` and `--tun-udp`. A one-sided `--pad`
is now an explicit option mismatch instead of corrupted data.

## ⚠️ Limits

- `--tun-udp` is not available with `-K` yet; hub clients use the TCP
  channel (4.2 clients fall back immediately).
- The users file holds SPAKE2 scalars, not passwords — but a stolen line lets
  its holder log in as that user (balanced PAKE): keep it private.

## ✅ Testing

157 unit, 62 end-to-end and 18 VPN tests (network namespaces: hub with three
clients, IPv4/IPv6, client-to-client, spoofing, address conflicts, IPv6 NAT,
pipelined SYN scan), ASan/UBSan/LeakSanitizer, `-Werror`, libFuzzer.
Interoperability with 4.1.0 checked for the handshake (incl. `--tofu --pq`)
and for a 4.1.0 VPN client on the 4.2 hub.

## 📦 Install

```bash
brew upgrade lf3551/clawsec/clawsec
docker pull ghcr.io/lf3551/clawsec:4.2.0
yay -S clawsec
# or a static binary from the assets below (verify with SHA256SUMS)
```
