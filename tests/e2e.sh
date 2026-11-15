#!/usr/bin/env bash
#
# e2e.sh — End-to-end smoke tests for the real clawsec binary (no root needed).
#
# Usage: tests/e2e.sh [path/to/clawsec]      (default: src/clawsec)
# Requires: Linux (/proc/net/tcp), python3, curl.
#
# Every scenario moves a 300 KB random payload through a real client/server
# pair on 127.0.0.1 and verifies it byte-for-byte.
#
set -u

# Everything here talks to 127.0.0.1. Proxy settings from the environment
# (e.g. NO_PROXY=localhost) would make curl bypass --socks5 and turn the
# SOCKS checks into no-ops, so drop them.
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy no_proxy NO_PROXY

TESTS_DIR=$(cd "$(dirname "$0")" && pwd)
BIN=$(realpath "${1:-src/clawsec}")
KEY='E2e-Passw0rd!'
WORK=$(mktemp -d)
export HOME="$WORK"          # isolate ~/.clawsec (TOFU identity, known_hosts)
PIDS=()
PASS=0
FAIL=0

cleanup() {
    for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
    wait 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

die() { echo "e2e: $*" >&2; exit 2; }
[ -x "$BIN" ] || die "binary not found: $BIN"
command -v python3 >/dev/null || die "python3 required"
command -v curl >/dev/null || die "curl required"

free_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'
}

# Wait until a socket is in LISTEN state on TCP port $1 (max ~5 s).
# Deliberately does not connect: a single-client server would accept the
# probe as its one session. Reads /proc/net/tcp{,6} (Linux).
wait_port() {
    local hex
    hex=$(printf ':%04X ' "$1")
    for _ in $(seq 50); do
        grep -q "$hex[0-9A-F:]* 0A " /proc/net/tcp /proc/net/tcp6 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

# Print the local IPv4 address (hex, as in /proc/net/tcp) of the LISTEN socket on port $1
listen_addr() {
    awk -v p="$(printf '%04X' "$1")" '$4 == "0A" { split($2, a, ":"); if (a[2] == p) print a[1] }' /proc/net/tcp
}

expect_loopback() {   # expect_loopback <name> <port>
    local addr
    addr=$(listen_addr "$2")
    if [ "$addr" = "0100007F" ]; then
        echo "  [E2E] $1 listens on 127.0.0.1 only ... PASS"; PASS=$((PASS + 1))
    else
        echo "  [E2E] $1 listens on 127.0.0.1 only ... FAIL (bound to '${addr:-?}')"; FAIL=$((FAIL + 1))
    fi
}

check() {   # check <name> <expected-file> <actual-file>
    if cmp -s "$2" "$3"; then
        echo "  [E2E] $1 ... PASS"; PASS=$((PASS + 1))
    else
        echo "  [E2E] $1 ... FAIL"; FAIL=$((FAIL + 1))
    fi
}

# Servers need a stdin that stays open but never delivers data (otherwise
# they half-close early). One FIFO with a single long-lived writer serves all
# of them; killing the writer at cleanup closes it. (`< <(sleep N)` left
# orphaned sleeps holding our stdout/stderr, so callers waited N more seconds.)
HOLD="$WORK/hold.fifo"
mkfifo "$HOLD"
sleep 3600 > "$HOLD" 2>/dev/null &
PIDS+=($!)

PAYLOAD="$WORK/payload.bin"
head -c 300000 /dev/urandom > "$PAYLOAD"

# Run everything from a scratch directory: nothing may land in the caller's cwd
mkdir -p "$WORK/cwd"
cd "$WORK/cwd" || die "cannot enter scratch directory"

# ── Stream mode: stdin -> encrypted tunnel -> stdout ──────────────────────
stream_test() {   # stream_test <label> [extra options...]
    local label=$1; shift
    local port out srv crc src
    port=$(free_port); out="$WORK/stream.out"; rm -f "$out"
    # Keep the server's stdin open (no early half-close) without a pipeline
    timeout 25 "$BIN" -l -p "$port" -k "$KEY" "$@" < "$HOLD" > "$out" 2>/dev/null &
    srv=$!
    wait_port "$port" || { echo "  [E2E] $label ... FAIL (server not listening)"; FAIL=$((FAIL + 1)); kill "$srv" 2>/dev/null; return; }
    timeout 20 "$BIN" -k "$KEY" "$@" 127.0.0.1 "$port" < "$PAYLOAD" > /dev/null 2>&1
    crc=$?
    wait "$srv"; src=$?
    if cmp -s "$PAYLOAD" "$out" && [ "$crc" -eq 0 ] && [ "$src" -eq 0 ]; then
        echo "  [E2E] $label ... PASS"; PASS=$((PASS + 1))
    else
        echo "  [E2E] $label ... FAIL (client exit $crc, server exit $src)"; FAIL=$((FAIL + 1))
    fi
}

echo
echo "=== ClawSec end-to-end tests ($BIN) ==="

# --version must report the release and the wire protocol
if "$BIN" --version | grep -Eq '^ClawSec [0-9]+\.[0-9]+\.[0-9]+ \(wire protocol [0-9]+\)$'; then
    echo "  [E2E] --version ... PASS"; PASS=$((PASS + 1))
else
    echo "  [E2E] --version ... FAIL"; FAIL=$((FAIL + 1))
fi
stream_test "stream (plain)"
stream_test "stream --obfs http" --obfs http
stream_test "stream --obfs tls"  --obfs tls
stream_test "stream --tofu"      --tofu
# --pq needs ML-KEM-768 (OpenSSL >= 3.5) in the libcrypto the binary loads
if command -v openssl >/dev/null && openssl list -kem-algorithms 2>/dev/null | grep -qi 'ml-kem-768'; then
    stream_test "stream --pq --tofu" --pq --tofu
else
    echo "  [E2E] stream --pq --tofu ... SKIP (OpenSSL without ML-KEM-768)"
fi
stream_test "stream -z (incompressible data)" -z
stream_test "stream --pad" --pad
stream_test "stream -z --pad" -z --pad
stream_test "stream --pad --obfs tls" --pad --obfs tls

# Stream data that looks like a chat control frame (SOH + 'F' = inline file)
# must be delivered verbatim and must never create files on the receiver.
CTRL_PAYLOAD="$WORK/ctrl.bin"
{ printf '\001F5:planted.txt\nAAAAA'; head -c 50000 /dev/urandom; } > "$CTRL_PAYLOAD"
SAVED_PAYLOAD=$PAYLOAD; PAYLOAD=$CTRL_PAYLOAD
stream_test "stream payload starting with SOH control byte"
PAYLOAD=$SAVED_PAYLOAD
if [ -e "$WORK/cwd/planted.txt" ]; then
    echo "  [E2E] no file planted by stream data ... FAIL"; FAIL=$((FAIL + 1))
else
    echo "  [E2E] no file planted by stream data ... PASS"; PASS=$((PASS + 1))
fi

# ── UDP mode (-u): datagrams, no TCP; small payload (loopback UDP can drop
#    under load and UDP has no retransmission, by design) ───────────────
P=$(free_port); rm -f "$WORK/udp.out"
head -c 20000 "$PAYLOAD" > "$WORK/udp.in"
timeout 15 "$BIN" -u -l -p "$P" -k "$KEY" < "$HOLD" > "$WORK/udp.out" 2>/dev/null &
SRV=$!
sleep 0.5
# UDP has no end-of-stream: the client runs until its timeout
{ cat "$WORK/udp.in"; sleep 1; } | timeout 3 "$BIN" -u -k "$KEY" 127.0.0.1 "$P" >/dev/null 2>&1
kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null
check "UDP mode (-u)" "$WORK/udp.in" "$WORK/udp.out"

P=$(free_port); rm -f "$WORK/udp-pad.out"
timeout 15 "$BIN" -u -l -p "$P" -k "$KEY" --pad < "$HOLD" > "$WORK/udp-pad.out" 2>/dev/null &
SRV=$!
sleep 0.5
{ cat "$WORK/udp.in"; sleep 1; } | timeout 3 "$BIN" -u -k "$KEY" --pad 127.0.0.1 "$P" >/dev/null 2>&1
kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null
check "UDP mode (-u) --pad" "$WORK/udp.in" "$WORK/udp-pad.out"

# ── --pad must be set on both ends: a clear error, not corrupted data ──
P=$(free_port)
timeout 10 "$BIN" -l -p "$P" -k "$KEY" --pad < "$HOLD" >/dev/null 2>&1 &
SRV=$!
wait_port "$P"
START=$SECONDS
timeout 10 "$BIN" -k "$KEY" 127.0.0.1 "$P" < "$PAYLOAD" >/dev/null 2>"$WORK/padmm.err"
PRC=$?
wait "$SRV" 2>/dev/null
if [ "$PRC" -eq 1 ] && [ $((SECONDS - START)) -le 3 ] && grep -q 'option mismatch' "$WORK/padmm.err"; then
    echo "  [E2E] --pad on one end only: option mismatch ... PASS"; PASS=$((PASS + 1))
else
    echo "  [E2E] --pad on one end only: option mismatch ... FAIL (exit $PRC)"; FAIL=$((FAIL + 1))
fi

# ── HTTP origin for the tunnel scenarios ────────────────────────────────
WEB=$(free_port)
(cd "$WORK" && exec python3 -m http.server "$WEB" --bind 127.0.0.1 >/dev/null 2>&1) &
PIDS+=($!)
wait_port "$WEB" || die "http origin did not start"
URL_PATH="/payload.bin"

# ── -L: single-connection port forwarding (target sends the payload) ────
forward_test() {   # forward_test <label> [extra options...]
    local label=$1; shift
    local tp p out
    tp=$(free_port); p=$(free_port); out="$WORK/fwd.out"; rm -f "$out"
    python3 - "$tp" "$PAYLOAD" <<'PY' &
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(1); s.settimeout(20)
c, _ = s.accept(); c.sendall(open(sys.argv[2], "rb").read()); c.close()
PY
    local tgt=$!
    wait_port "$tp"
    timeout 20 "$BIN" -l -p "$p" -k "$KEY" -L "127.0.0.1:$tp" "$@" >/dev/null 2>&1 &
    local srv=$!
    wait_port "$p"
    # stdin stays open (no early half-close) without making us wait for it
    timeout 20 "$BIN" -k "$KEY" "$@" 127.0.0.1 "$p" < "$HOLD" > "$out" 2>/dev/null
    kill "$srv" "$tgt" 2>/dev/null; wait "$srv" "$tgt" 2>/dev/null
    check "$label" "$PAYLOAD" "$out"
}
forward_test "-L port forwarding"
forward_test "-L port forwarding -z --pad" -z --pad

# ── --socks over mux v2: keep-alive, parallel, half-close, flow control ──
socks_suite() {   # socks_suite <label> [extra options for both ends...]
    local label=$1; shift
    local p sp sb out
    p=$(free_port); sp=$(free_port); sb=$(free_port)
    "$BIN" -l -p "$p" -k "$KEY" "$@" --socks 0 --socks-allow 127.0.0.0/8 >/dev/null 2>&1 & PIDS+=($!)
    wait_port "$p"
    "$BIN" -k "$KEY" "$@" --socks "$sp" 127.0.0.1 "$p" >/dev/null 2>&1 & PIDS+=($!)
    wait_port "$sp"
    out=$(timeout 120 python3 "$TESTS_DIR/e2e_socks.py" "$sp" "$sb" "$label" 2>&1)
    echo "$out" | grep '\[E2E\]'
    PASS=$((PASS + $(echo "$out" | grep -c '\.\.\. PASS')))
    FAIL=$((FAIL + $(echo "$out" | grep -c '\.\.\. FAIL')))
    [ "$(echo "$out" | grep -c '\.\.\. PASS')" -eq 7 ] || {
        echo "  [E2E] $label suite incomplete ... FAIL"; FAIL=$((FAIL + 1)); echo "$out" | tail -5; }
}
socks_suite "--socks"
socks_suite "--socks --pad" --pad

# ── --mux -L: multiplexed port forwarding (max-size frames) ─────────────
P=$(free_port); LP=$(free_port)
"$BIN" -l -p "$P" -k "$KEY" -L "127.0.0.1:$WEB" --mux >/dev/null 2>&1 & PIDS+=($!)
wait_port "$P"
"$BIN" -k "$KEY" -p "$LP" --mux 127.0.0.1 "$P" >/dev/null 2>&1 & PIDS+=($!)
wait_port "$LP"
timeout 15 curl -s -o "$WORK/mux.out" "http://127.0.0.1:$LP$URL_PATH"
check "--mux -L port forwarding" "$PAYLOAD" "$WORK/mux.out"
expect_loopback "--mux local port (default)" "$LP"

# 100 sequential connections through one tunnel: stream ids must be reused
# (3.0.0 ran out after 63)
MUX_OK=0
for _ in $(seq 100); do
    timeout 5 curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$LP/" | grep -q 200 && MUX_OK=$((MUX_OK + 1))
done
if [ "$MUX_OK" -eq 100 ]; then
    echo "  [E2E] --mux reuses stream ids (100 connections) ... PASS"; PASS=$((PASS + 1))
else
    echo "  [E2E] --mux reuses stream ids (100 connections) ... FAIL ($MUX_OK/100)"; FAIL=$((FAIL + 1))
fi

# 20 parallel downloads through the same tunnel (wait for these PIDs only:
# job numbers would also match the long-running servers started above)
PAR_PIDS=()
for i in $(seq 20); do
    timeout 20 curl -s -o "$WORK/mux-par-$i.out" "http://127.0.0.1:$LP$URL_PATH" &
    PAR_PIDS+=($!)
done
wait "${PAR_PIDS[@]}" 2>/dev/null
PAR_OK=1
for i in $(seq 20); do cmp -s "$PAYLOAD" "$WORK/mux-par-$i.out" || PAR_OK=0; done
if [ "$PAR_OK" -eq 1 ]; then
    echo "  [E2E] --mux 20 parallel downloads ... PASS"; PASS=$((PASS + 1))
else
    echo "  [E2E] --mux 20 parallel downloads ... FAIL"; FAIL=$((FAIL + 1))
fi

# --mux with --pad (records padded to 1400-byte units)
P=$(free_port); LP=$(free_port)
"$BIN" -l -p "$P" -k "$KEY" --pad -L "127.0.0.1:$WEB" --mux >/dev/null 2>&1 & PIDS+=($!)
wait_port "$P"
"$BIN" -k "$KEY" --pad -p "$LP" --mux 127.0.0.1 "$P" >/dev/null 2>&1 & PIDS+=($!)
wait_port "$LP"
timeout 15 curl -s -o "$WORK/mux-pad.out" "http://127.0.0.1:$LP$URL_PATH"
check "--mux -L --pad" "$PAYLOAD" "$WORK/mux-pad.out"

# ── --mux -L half-close: request, shutdown(SHUT_WR), full response ─────
RP=$(free_port); P=$(free_port); LP=$(free_port)
python3 -c '
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(4)
while True:
    c, _ = s.accept(); data = b""
    while (d := c.recv(65536)): data += d
    c.sendall(data[::-1]); c.close()' "$RP" & PIDS+=($!)
wait_port "$RP"
"$BIN" -l -p "$P" -k "$KEY" -L "127.0.0.1:$RP" --mux >/dev/null 2>&1 & PIDS+=($!)
wait_port "$P"
"$BIN" -k "$KEY" -p "$LP" --mux 127.0.0.1 "$P" >/dev/null 2>&1 & PIDS+=($!)
wait_port "$LP"
sleep 0.3                                     # let the mux v2 HELLO arrive
if timeout 15 python3 -c '
import os, socket, sys
c = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10)
p = os.urandom(500000); c.sendall(p); c.shutdown(socket.SHUT_WR)
got = b""
while (d := c.recv(65536)): got += d
sys.exit(0 if got == p[::-1] else 1)' "$LP"; then
    echo "  [E2E] --mux -L half-close (500 KB request, EOF, response) ... PASS"; PASS=$((PASS + 1))
else
    echo "  [E2E] --mux -L half-close ... FAIL"; FAIL=$((FAIL + 1))
fi

# ── --socks: SOCKS5 through the tunnel ─────────────────────────────────
P=$(free_port); SP=$(free_port)
# The origin is on 127.0.0.1, which the default SOCKS policy denies
"$BIN" -l -p "$P" -k "$KEY" --socks 0 --socks-allow 127.0.0.1/32 >/dev/null 2>&1 & PIDS+=($!)
wait_port "$P"
"$BIN" -k "$KEY" --socks "$SP" 127.0.0.1 "$P" >/dev/null 2>&1 & PIDS+=($!)
wait_port "$SP"
timeout 15 curl -s --socks5 "127.0.0.1:$SP" -o "$WORK/socks.out" "http://127.0.0.1:$WEB$URL_PATH"
check "--socks SOCKS5 proxy" "$PAYLOAD" "$WORK/socks.out"
expect_loopback "--socks proxy (default)" "$SP"

# ── -R: reverse tunnel ─────────────────────────────────────────────────
P=$(free_port); RP=$(free_port)
"$BIN" -l -p "$P" -k "$KEY" -R "127.0.0.1:$RP" >/dev/null 2>&1 & PIDS+=($!)
wait_port "$P"
"$BIN" -k "$KEY" -R "127.0.0.1:$WEB" 127.0.0.1 "$P" >/dev/null 2>&1 & PIDS+=($!)
wait_port "$RP"
timeout 15 curl -s -o "$WORK/rev.out" "http://127.0.0.1:$RP$URL_PATH"
check "-R reverse tunnel" "$PAYLOAD" "$WORK/rev.out"
expect_loopback "-R 127.0.0.1:port" "$RP"

P=$(free_port); RP=$(free_port)
"$BIN" -l -p "$P" -k "$KEY" --pad -R "127.0.0.1:$RP" >/dev/null 2>&1 & PIDS+=($!)
wait_port "$P"
"$BIN" -k "$KEY" --pad -R "127.0.0.1:$WEB" 127.0.0.1 "$P" >/dev/null 2>&1 & PIDS+=($!)
wait_port "$RP"
timeout 15 curl -s -o "$WORK/rev-pad.out" "http://127.0.0.1:$RP$URL_PATH"
check "-R reverse tunnel --pad" "$PAYLOAD" "$WORK/rev-pad.out"

# ── --send / --recv: file transfer with SHA-256 verification ────────────
P=$(free_port); mkdir -p "$WORK/inbox"
timeout 20 "$BIN" -l -p "$P" -k "$KEY" --recv "$WORK/inbox" >/dev/null 2>&1 &
RX=$!
wait_port "$P"
timeout 20 "$BIN" -k "$KEY" --send "$PAYLOAD" 127.0.0.1 "$P" >/dev/null 2>&1
wait "$RX" 2>/dev/null
check "--send/--recv file transfer" "$PAYLOAD" "$WORK/inbox/payload.bin"

# ── -e must be opt-in: a default build refuses it with guidance ─────────
if ! "$BIN" -h 2>&1 | grep -q -- '-e <program>'; then
    if "$BIN" -k "$KEY" -e /bin/sh 127.0.0.1 1 2>&1 | grep -q 'DFLAGS=-DGAPING_SECURITY_HOLE'; then
        echo "  [E2E] -e not built by default ... PASS"; PASS=$((PASS + 1))
    else
        echo "  [E2E] -e not built by default ... FAIL"; FAIL=$((FAIL + 1))
    fi
fi

# ── SOCKS default policy denies loopback destinations ─────────────────
P=$(free_port); SP=$(free_port)
"$BIN" -l -p "$P" -k "$KEY" -v --socks 0 >/dev/null 2>"$WORK/socks-deny.err" & PIDS+=($!)
wait_port "$P"
"$BIN" -k "$KEY" --socks "$SP" 127.0.0.1 "$P" >/dev/null 2>&1 & PIDS+=($!)
wait_port "$SP"
if ! timeout 10 curl -s --socks5 "127.0.0.1:$SP" -o /dev/null "http://127.0.0.1:$WEB$URL_PATH" &&
   grep -q 'denied by destination policy' "$WORK/socks-deny.err"; then
    echo "  [E2E] --socks server denies 127.0.0.1 by default ... PASS"; PASS=$((PASS + 1))
else
    echo "  [E2E] --socks server denies 127.0.0.1 by default ... FAIL"; FAIL=$((FAIL + 1))
fi

# ── --recv never writes through links; resume uses its own .clawsec-part ─
recv_send() {   # recv_send <inbox> <file> -> exit status of the sender
    local p rx rc
    p=$(free_port)
    timeout 20 "$BIN" -l -p "$p" -k "$KEY" --recv "$1" >/dev/null 2>&1 &
    rx=$!
    wait_port "$p"
    timeout 20 "$BIN" -k "$KEY" --send "$2" 127.0.0.1 "$p" >/dev/null 2>&1
    rc=$?
    wait "$rx" 2>/dev/null
    return "$rc"
}
mkdir -p "$WORK/rx-link" "$WORK/src"
cp "$PAYLOAD" "$WORK/src/data.bin"
printf 'victim-content' > "$WORK/victim.txt"
ln -s "$WORK/victim.txt" "$WORK/rx-link/data.bin"
recv_send "$WORK/rx-link" "$WORK/src/data.bin"
if [ "$(cat "$WORK/victim.txt")" = "victim-content" ] && [ ! -L "$WORK/rx-link/data.bin" ] &&
   cmp -s "$PAYLOAD" "$WORK/rx-link/data.bin"; then
    echo "  [E2E] --recv replaces a symlink, never writes through it ... PASS"; PASS=$((PASS + 1))
else
    echo "  [E2E] --recv replaces a symlink, never writes through it ... FAIL"; FAIL=$((FAIL + 1))
fi

mkdir -p "$WORK/rx-hard"
printf 'victim-content' > "$WORK/victim2.txt"
ln "$WORK/victim2.txt" "$WORK/rx-hard/data.bin.clawsec-part"
recv_send "$WORK/rx-hard" "$WORK/src/data.bin"
if [ "$(cat "$WORK/victim2.txt")" = "victim-content" ] && [ ! -e "$WORK/rx-hard/data.bin" ]; then
    echo "  [E2E] --recv refuses a hard-linked partial file ... PASS"; PASS=$((PASS + 1))
else
    echo "  [E2E] --recv refuses a hard-linked partial file ... FAIL"; FAIL=$((FAIL + 1))
fi

mkdir -p "$WORK/rx-resume"
head -c 100000 "$PAYLOAD" > "$WORK/rx-resume/data.bin.clawsec-part"
if recv_send "$WORK/rx-resume" "$WORK/src/data.bin" &&
   cmp -s "$PAYLOAD" "$WORK/rx-resume/data.bin" && [ ! -e "$WORK/rx-resume/data.bin.clawsec-part" ]; then
    echo "  [E2E] --recv resumes from its own partial file ... PASS"; PASS=$((PASS + 1))
else
    echo "  [E2E] --recv resumes from its own partial file ... FAIL"; FAIL=$((FAIL + 1))
fi

mkdir -p "$WORK/rx-bad"
head -c 100000 /dev/urandom > "$WORK/rx-bad/data.bin.clawsec-part"   # wrong prefix
if ! recv_send "$WORK/rx-bad" "$WORK/src/data.bin" &&
   [ ! -e "$WORK/rx-bad/data.bin" ] && [ ! -e "$WORK/rx-bad/data.bin.clawsec-part" ]; then
    echo "  [E2E] --recv discards a corrupt partial, writes nothing ... PASS"; PASS=$((PASS + 1))
else
    echo "  [E2E] --recv discards a corrupt partial, writes nothing ... FAIL"; FAIL=$((FAIL + 1))
fi

# ── Password sources: --key-file, CLAWSEC_PASSWORD; -k scrubbed from argv ─
printf '%s\n' "$KEY" > "$WORK/key"; chmod 600 "$WORK/key"
P=$(free_port); rm -f "$WORK/pw.out"
timeout 15 "$BIN" -l -p "$P" --key-file "$WORK/key" < "$HOLD" > "$WORK/pw.out" 2>/dev/null &
SRV=$!
wait_port "$P"
CLAWSEC_PASSWORD="$KEY" timeout 10 "$BIN" 127.0.0.1 "$P" < "$PAYLOAD" >/dev/null 2>&1
CRC=$?
wait "$SRV"; SRC=$?
if [ "$CRC" -eq 0 ] && [ "$SRC" -eq 0 ] && cmp -s "$PAYLOAD" "$WORK/pw.out"; then
    echo "  [E2E] --key-file (server) + CLAWSEC_PASSWORD (client) ... PASS"; PASS=$((PASS + 1))
else
    echo "  [E2E] --key-file (server) + CLAWSEC_PASSWORD (client) ... FAIL"; FAIL=$((FAIL + 1))
fi

P=$(free_port)
"$BIN" -l -p "$P" -k "$KEY" < "$HOLD" >/dev/null 2>&1 &
SRV=$!
wait_port "$P"
if ! tr '\0' ' ' < "/proc/$SRV/cmdline" | grep -qF -- "$KEY"; then
    echo "  [E2E] -k password scrubbed from /proc/<pid>/cmdline ... PASS"; PASS=$((PASS + 1))
else
    echo "  [E2E] -k password scrubbed from /proc/<pid>/cmdline ... FAIL"; FAIL=$((FAIL + 1))
fi
kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null

if CLAWSEC_PASSWORD= "$BIN" 127.0.0.1 1 < /dev/null 2>&1 | grep -q 'password required\|empty password'; then
    echo "  [E2E] no password source without a terminal: clear error ... PASS"; PASS=$((PASS + 1))
else
    echo "  [E2E] no password source without a terminal: clear error ... FAIL"; FAIL=$((FAIL + 1))
fi

# ── Handshake timeout: a silent client cannot hold the server ──────────
silent_client() {   # silent_client <port> <seconds>: connect and say nothing
    python3 -c 'import socket,sys,time; s=socket.create_connection(("127.0.0.1",int(sys.argv[1]))); time.sleep(float(sys.argv[2]))' "$1" "$2" &
}
P=$(free_port)
timeout 15 "$BIN" -l -p "$P" -k "$KEY" --handshake-timeout 2 < "$HOLD" >/dev/null 2>"$WORK/hs.err" &
SRV=$!
wait_port "$P"
silent_client "$P" 12; SIL=$!
START=$SECONDS
wait "$SRV"; SRC=$?
ELAPSED=$((SECONDS - START))
kill "$SIL" 2>/dev/null; wait "$SIL" 2>/dev/null
if [ "$SRC" -eq 1 ] && [ "$ELAPSED" -le 6 ] && grep -q 'timed out' "$WORK/hs.err"; then
    echo "  [E2E] --handshake-timeout ends a silent session (${ELAPSED}s) ... PASS"; PASS=$((PASS + 1))
else
    echo "  [E2E] --handshake-timeout ends a silent session ... FAIL (exit $SRC, ${ELAPSED}s)"; FAIL=$((FAIL + 1))
fi

# ── -K --max-clients: a silent client holds the only slot until timeout ─
P=$(free_port); mkdir -p "$WORK/rx-k"
"$BIN" -l -p "$P" -k "$KEY" -K --max-clients 1 --handshake-timeout 3 --recv "$WORK/rx-k" \
    >/dev/null 2>/dev/null & PIDS+=($!)
wait_port "$P"
silent_client "$P" 20; SIL=$!
sleep 0.5
START=$SECONDS
timeout 20 "$BIN" -k "$KEY" --send "$WORK/src/data.bin" 127.0.0.1 "$P" >/dev/null 2>&1
CRC=$?
ELAPSED=$((SECONDS - START))
kill "$SIL" 2>/dev/null; wait "$SIL" 2>/dev/null
if [ "$CRC" -eq 0 ] && [ "$ELAPSED" -ge 2 ] && cmp -s "$PAYLOAD" "$WORK/rx-k/data.bin"; then
    echo "  [E2E] -K --max-clients 1 queues the next client (${ELAPSED}s) ... PASS"; PASS=$((PASS + 1))
else
    echo "  [E2E] -K --max-clients 1 queues the next client ... FAIL (exit $CRC, ${ELAPSED}s)"; FAIL=$((FAIL + 1))
fi

# ── -K --auth-fail-limit: an address is refused after repeated wrong passwords
P=$(free_port); mkdir -p "$WORK/rx-lock"
"$BIN" -l -p "$P" -k "$KEY" -K --auth-fail-limit 2 --recv "$WORK/rx-lock" \
    >/dev/null 2>"$WORK/lock.err" & PIDS+=($!)
wait_port "$P"
for _ in 1 2; do
    timeout 10 "$BIN" -k "wrong-password-x" 127.0.0.1 "$P" < /dev/null >/dev/null 2>&1
    sleep 0.3
done
START=$SECONDS
timeout 10 "$BIN" -k "$KEY" --send "$WORK/src/data.bin" 127.0.0.1 "$P" >/dev/null 2>&1
LRC=$?
ELAPSED=$((SECONDS - START))
if [ "$LRC" -ne 0 ] && [ "$ELAPSED" -le 2 ] && [ ! -e "$WORK/rx-lock/data.bin" ] &&
   grep -q 'authentication failure from 127.0.0.1 (2/2): blocking' "$WORK/lock.err"; then
    echo "  [E2E] -K --auth-fail-limit 2 blocks the address (correct password refused) ... PASS"; PASS=$((PASS + 1))
else
    echo "  [E2E] -K --auth-fail-limit 2 blocks the address ... FAIL (exit $LRC, ${ELAPSED}s)"; FAIL=$((FAIL + 1))
fi

# ── -K --max-per-ip: one address cannot take every slot ────────────────
P=$(free_port); mkdir -p "$WORK/rx-ip"
"$BIN" -l -p "$P" -k "$KEY" -K --max-per-ip 1 --handshake-timeout 20 --recv "$WORK/rx-ip" \
    >/dev/null 2>/dev/null & PIDS+=($!)
wait_port "$P"
silent_client "$P" 3; SIL=$!
sleep 0.5
START=$SECONDS
timeout 10 "$BIN" -k "$KEY" --send "$WORK/src/data.bin" 127.0.0.1 "$P" >/dev/null 2>&1
IRC1=$?
ELAPSED=$((SECONDS - START))
wait "$SIL" 2>/dev/null; sleep 0.5            # the silent client leaves, its slot frees up
timeout 20 "$BIN" -k "$KEY" --send "$WORK/src/data.bin" 127.0.0.1 "$P" >/dev/null 2>&1
IRC2=$?
if [ "$IRC1" -ne 0 ] && [ "$ELAPSED" -le 2 ] && [ "$IRC2" -eq 0 ] &&
   cmp -s "$PAYLOAD" "$WORK/rx-ip/data.bin"; then
    echo "  [E2E] -K --max-per-ip 1 refuses a 2nd connection, then serves ... PASS"; PASS=$((PASS + 1))
else
    echo "  [E2E] -K --max-per-ip 1 ... FAIL (exit $IRC1 in ${ELAPSED}s, then $IRC2)"; FAIL=$((FAIL + 1))
fi

# ── Per-user login: --users on the server, --user on the client ────────
UF="$WORK/users"; mkdir -p "$WORK/rx-users"
CLAWSEC_PASSWORD='alice-E2e-passw0rd' "$BIN" --users "$UF" --add-user alice >/dev/null 2>&1
CLAWSEC_PASSWORD='bob-E2e-passw0rd-2' "$BIN" --users "$UF" --add-user bob >/dev/null 2>&1
P=$(free_port)
"$BIN" -l -p "$P" -K --users "$UF" --auth-fail-limit 0 --recv "$WORK/rx-users" \
    </dev/null >/dev/null 2>"$WORK/users-srv.err" & PIDS+=($!)
wait_port "$P"
CLAWSEC_PASSWORD='alice-E2e-passw0rd' timeout 15 "$BIN" --user alice --send "$PAYLOAD" 127.0.0.1 "$P" >/dev/null 2>&1
U_OK=$?
CLAWSEC_PASSWORD='bob-E2e-passw0rd-2' timeout 10 "$BIN" --user alice 127.0.0.1 "$P" </dev/null >/dev/null 2>"$WORK/u-wrong.err"
U_WRONG=$?
CLAWSEC_PASSWORD='alice-E2e-passw0rd' timeout 10 "$BIN" --user mallory 127.0.0.1 "$P" </dev/null >/dev/null 2>"$WORK/u-unknown.err"
U_UNKNOWN=$?
CLAWSEC_PASSWORD='alice-E2e-passw0rd' timeout 10 "$BIN" 127.0.0.1 "$P" </dev/null >/dev/null 2>"$WORK/u-none.err"
U_NONE=$?
sleep 0.3
if [ "$U_OK" -eq 0 ] && cmp -s "$PAYLOAD" "$WORK/rx-users/payload.bin" &&
   grep -q "user 'alice' logged in" "$WORK/users-srv.err" &&
   [ "$(stat -c %a "$UF")" = 600 ]; then
    echo "  [E2E] --users/--user: alice logs in and sends a file ... PASS"; PASS=$((PASS + 1))
else
    echo "  [E2E] --users/--user: alice logs in ... FAIL (exit $U_OK)"; FAIL=$((FAIL + 1))
fi
if [ "$U_WRONG" -eq 1 ] && [ "$U_UNKNOWN" -eq 1 ] &&
   [ "$(grep -c 'authentication failed' "$WORK/u-wrong.err")" -eq "$(grep -c 'authentication failed' "$WORK/u-unknown.err")" ] &&
   grep -q "user 'mallory'" "$WORK/users-srv.err"; then
    echo "  [E2E] --users: wrong password and unknown user fail alike ... PASS"; PASS=$((PASS + 1))
else
    echo "  [E2E] --users: wrong password / unknown user ... FAIL ($U_WRONG/$U_UNKNOWN)"; FAIL=$((FAIL + 1))
fi
if [ "$U_NONE" -eq 1 ] && grep -q 'connect with --user' "$WORK/u-none.err"; then
    echo "  [E2E] --users server, client without --user: clear error ... PASS"; PASS=$((PASS + 1))
else
    echo "  [E2E] --users server, client without --user ... FAIL ($U_NONE)"; FAIL=$((FAIL + 1))
fi

# ── Per-user options: SOCKS destinations, disabling an account ─────────
UF2="$WORK/users2"
CLAWSEC_PASSWORD='alice-Opt-passw0rd1' "$BIN" --users "$UF2" --add-user alice \
    --user-option socks-allow=127.0.0.1/32 >/dev/null 2>&1
CLAWSEC_PASSWORD='bob-Opt-passw0rd-22' "$BIN" --users "$UF2" --add-user bob >/dev/null 2>&1
P=$(free_port)
"$BIN" -l -p "$P" -K --users "$UF2" --auth-fail-limit 0 --socks 0 </dev/null >/dev/null 2>&1 & PIDS+=($!)
wait_port "$P"
socks_as() {   # socks_as <user> <password> -> exit status of curl through the proxy
    local sp; sp=$(free_port)
    CLAWSEC_PASSWORD="$2" "$BIN" --user "$1" --socks "$sp" 127.0.0.1 "$P" </dev/null >/dev/null 2>&1 &
    local cp=$!
    wait_port "$sp"
    timeout 10 curl -s -o "$WORK/socks-$1.out" --socks5 "127.0.0.1:$sp" "http://127.0.0.1:$WEB$URL_PATH"
    local rc=$?
    kill "$cp" 2>/dev/null; wait "$cp" 2>/dev/null
    return $rc
}
if socks_as alice 'alice-Opt-passw0rd1' && cmp -s "$PAYLOAD" "$WORK/socks-alice.out" &&
   ! socks_as bob 'bob-Opt-passw0rd-22'; then
    echo "  [E2E] per-user socks-allow (alice: loopback allowed, bob: server default) ... PASS"; PASS=$((PASS + 1))
else
    echo "  [E2E] per-user socks-allow ... FAIL"; FAIL=$((FAIL + 1))
fi
"$BIN" --users "$UF2" --set-user bob --user-option disabled >/dev/null 2>&1
CLAWSEC_PASSWORD='bob-Opt-passw0rd-22' timeout 10 "$BIN" --user bob 127.0.0.1 "$P" </dev/null >/dev/null 2>"$WORK/disabled.err"
DRC=$?
if [ "$DRC" -eq 1 ] && grep -q 'authentication failed' "$WORK/disabled.err" &&
   grep -q 'bob:v1:[0-9a-f]*:disabled' "$UF2"; then
    echo "  [E2E] --set-user disabled: login refused without a restart ... PASS"; PASS=$((PASS + 1))
else
    echo "  [E2E] --set-user disabled ... FAIL ($DRC)"; FAIL=$((FAIL + 1))
fi
if "$BIN" --users "$UF2" --del-user bob >/dev/null 2>&1 && ! grep -q '^bob:' "$UF2" &&
   ! "$BIN" --users "$UF2" --del-user bob >/dev/null 2>&1; then
    echo "  [E2E] --del-user ... PASS"; PASS=$((PASS + 1))
else
    echo "  [E2E] --del-user ... FAIL"; FAIL=$((FAIL + 1))
fi

# ── --persistent: stop on a wrong password, reconnect after a drop ─────
P=$(free_port)
"$BIN" -l -p "$P" -k "$KEY" -K >/dev/null 2>&1 & PIDS+=($!)
wait_port "$P"
START=$SECONDS
timeout 20 "$BIN" -k "wrong-password-x" --persistent 127.0.0.1 "$P" < "$HOLD" >/dev/null 2>"$WORK/pers.err"
PRC=$?
if [ "$PRC" -eq 1 ] && [ $((SECONDS - START)) -le 5 ] && grep -q 'giving up' "$WORK/pers.err"; then
    echo "  [E2E] --persistent gives up on a wrong password ... PASS"; PASS=$((PASS + 1))
else
    echo "  [E2E] --persistent gives up on a wrong password ... FAIL (exit $PRC)"; FAIL=$((FAIL + 1))
fi

P=$(free_port); mkdir -p "$WORK/rx-p1" "$WORK/rx-p2"
"$BIN" -l -p "$P" -k "$KEY" --recv "$WORK/rx-p1" >/dev/null 2>&1 &
S1=$!
wait_port "$P"
timeout 25 "$BIN" -k "$KEY" --persistent --send "$WORK/src/data.bin" 127.0.0.1 "$P" >/dev/null 2>&1 &
CLI=$!
wait "$S1"                                  # first session completes, server exits
"$BIN" -l -p "$P" -k "$KEY" --recv "$WORK/rx-p2" >/dev/null 2>&1 &
S2=$!
for _ in $(seq 60); do [ -e "$WORK/rx-p2/data.bin" ] && break; sleep 0.25; done
kill "$CLI" "$S2" 2>/dev/null; wait "$CLI" "$S2" 2>/dev/null
if cmp -s "$PAYLOAD" "$WORK/rx-p1/data.bin" && cmp -s "$PAYLOAD" "$WORK/rx-p2/data.bin"; then
    echo "  [E2E] --persistent reconnects after the server restarts ... PASS"; PASS=$((PASS + 1))
else
    echo "  [E2E] --persistent reconnects after the server restarts ... FAIL"; FAIL=$((FAIL + 1))
fi

# ── Wrong password: no data, explicit error, failure exit on both ends ───
P=$(free_port); rm -f "$WORK/wrong.out"
timeout 15 "$BIN" -l -p "$P" -k "$KEY" < "$HOLD" > "$WORK/wrong.out" 2>"$WORK/wrong-srv.err" &
SRV=$!
wait_port "$P"
timeout 10 "$BIN" -k "not-the-password" 127.0.0.1 "$P" < "$PAYLOAD" >/dev/null 2>"$WORK/wrong-cli.err"
CRC=$?
wait "$SRV"; SRC=$?
if [ ! -s "$WORK/wrong.out" ] && [ "$CRC" -eq 1 ] && [ "$SRC" -eq 1 ] &&
   grep -q 'wrong password' "$WORK/wrong-cli.err"; then
    echo "  [E2E] wrong password: rejected on both ends, no data ... PASS"; PASS=$((PASS + 1))
else
    echo "  [E2E] wrong password: rejected on both ends, no data ... FAIL (client $CRC, server $SRC)"
    FAIL=$((FAIL + 1))
fi

echo
echo "=== E2E results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
