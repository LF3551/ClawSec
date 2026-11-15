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
    timeout 25 "$BIN" -l -p "$port" -k "$KEY" "$@" < <(sleep 20) > "$out" 2>/dev/null &
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
    timeout 20 "$BIN" -k "$KEY" "$@" 127.0.0.1 "$p" < <(sleep 20) > "$out" 2>/dev/null
    kill "$srv" "$tgt" 2>/dev/null; wait "$srv" "$tgt" 2>/dev/null
    check "$label" "$PAYLOAD" "$out"
}
forward_test "-L port forwarding"
forward_test "-L port forwarding -z --pad" -z --pad

# ── --mux -L: multiplexed port forwarding (max-size frames) ─────────────
P=$(free_port); LP=$(free_port)
"$BIN" -l -p "$P" -k "$KEY" -L "127.0.0.1:$WEB" --mux >/dev/null 2>&1 & PIDS+=($!)
wait_port "$P"
"$BIN" -k "$KEY" -p "$LP" --mux 127.0.0.1 "$P" >/dev/null 2>&1 & PIDS+=($!)
wait_port "$LP"
timeout 15 curl -s -o "$WORK/mux.out" "http://127.0.0.1:$LP$URL_PATH"
check "--mux -L port forwarding" "$PAYLOAD" "$WORK/mux.out"
expect_loopback "--mux local port (default)" "$LP"

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
timeout 15 "$BIN" -l -p "$P" --key-file "$WORK/key" < <(sleep 10) > "$WORK/pw.out" 2>/dev/null &
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
"$BIN" -l -p "$P" -k "$KEY" < <(sleep 10) >/dev/null 2>&1 &
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
timeout 15 "$BIN" -l -p "$P" -k "$KEY" --handshake-timeout 2 < <(sleep 14) >/dev/null 2>"$WORK/hs.err" &
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

# ── Wrong password: no data, explicit error, failure exit on both ends ───
P=$(free_port); rm -f "$WORK/wrong.out"
timeout 15 "$BIN" -l -p "$P" -k "$KEY" < <(sleep 10) > "$WORK/wrong.out" 2>"$WORK/wrong-srv.err" &
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
