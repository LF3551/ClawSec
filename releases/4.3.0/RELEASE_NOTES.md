# ClawSec v4.3.0 — Key updates, UDP for the VPN hub, server operations

**Wire-compatible with 4.0–4.2.** New features are opt-in and negotiated.
**macOS users of the multi-client VPN hub (`-K --tun`): please upgrade** — the
hub did not accept clients on macOS in 4.2.0.

```bash
clawsec --version
# ClawSec 4.3.0 (wire protocol 4)
```

## ✨ New

### Key updates — `--rekey`
```bash
clawsec -l -p 9000 --rekey 30m ...      # both ends
clawsec --rekey 30m server 9000
```
Each direction ratchets its stream key (HKDF, like TLS 1.3 KeyUpdate) and wipes
the old one: a key that leaks later does not decrypt earlier traffic, and long
sessions no longer have a record limit. (No fresh key exchange: reconnect for
post-compromise security.)

### UDP data channel for the multi-client VPN hub
`-K --tun --tun-udp` now works: the hub runs every client's UDP channel on the
server port, with its own replay window per client. No client change needed.

### Per-user options
```bash
clawsec --users /etc/clawsec/users --add-user carol --user-option ip=10.8.0.10
clawsec --users /etc/clawsec/users --set-user bob --user-option socks-allow=10.0.0.0/8
clawsec --users /etc/clawsec/users --set-user bob --user-option disabled
clawsec --users /etc/clawsec/users --del-user bob
```

### Server configuration file and status
```bash
sudo clawsec --config /etc/clawsec/server.conf      # key = value, see the man page
sudo clawsec --status /run/clawsec.sock             # with "control = /run/clawsec.sock"
```
The status lists sessions (PID, peer, user, age) and, for the VPN hub, each
client's IPv4/IPv6 address and traffic.

### Verifiable releases
This is the first release with **Sigstore-signed checksums**, **SLSA build
provenance** for every archive and **cosign-signed Docker images** with SBOM:

```bash
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/LF3551/ClawSec/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify clawsec-4.3.0-linux-x86_64.tar.gz -R LF3551/ClawSec
```

## 🐛 Fixed
- Multi-client VPN hub on macOS (AF_UNIX datagrams instead of `SOCK_SEQPACKET`,
  session end via SIGCHLD); new macOS CI test with IPv6, routes and pf NAT66.
- Status socket handling without a stat/unlink race (found by CodeQL).

## ✅ Testing
161 unit, 72 end-to-end, 23 VPN tests (namespaces: hub with UDP, `--pad`,
`--rekey`, users), macOS utun/pf checks, ASan/UBSan/LeakSanitizer, `-Werror`,
libFuzzer. Manual interoperability with 4.1.0 clients (TCP and UDP) on the hub.

## 📦 Install
```bash
brew upgrade lf3551/clawsec/clawsec
docker pull ghcr.io/lf3551/clawsec:4.3.0
yay -S clawsec
```
