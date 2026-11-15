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
    local port out
    port=$(free_port); out="$WORK/stream.out"; rm -f "$out"
    # Keep the server's stdin open so it does not half-close the session early
    (sleep 20 | timeout 25 "$BIN" -l -p "$port" -k "$KEY" "$@" > "$out" 2>/dev/null) &
    local srv=$!
    wait_port "$port" || { echo "  [E2E] $label ... FAIL (server not listening)"; FAIL=$((FAIL + 1)); return; }
    timeout 20 "$BIN" -k "$KEY" "$@" 127.0.0.1 "$port" < "$PAYLOAD" > /dev/null 2>&1
    sleep 0.3; kill "$srv" 2>/dev/null; wait "$srv" 2>/dev/null
    check "$label" "$PAYLOAD" "$out"
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
stream_test "stream --pq --tofu" --pq --tofu

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

# ── --mux -L: multiplexed port forwarding (max-size frames) ─────────────
P=$(free_port); LP=$(free_port)
"$BIN" -l -p "$P" -k "$KEY" -L "127.0.0.1:$WEB" --mux >/dev/null 2>&1 & PIDS+=($!)
wait_port "$P"
"$BIN" -k "$KEY" -p "$LP" --mux 127.0.0.1 "$P" >/dev/null 2>&1 & PIDS+=($!)
wait_port "$LP"
timeout 15 curl -s -o "$WORK/mux.out" "http://127.0.0.1:$LP$URL_PATH"
check "--mux -L port forwarding" "$PAYLOAD" "$WORK/mux.out"

# ── --socks: SOCKS5 through the tunnel ─────────────────────────────────
P=$(free_port); SP=$(free_port)
"$BIN" -l -p "$P" -k "$KEY" --socks 0 >/dev/null 2>&1 & PIDS+=($!)
wait_port "$P"
"$BIN" -k "$KEY" --socks "$SP" 127.0.0.1 "$P" >/dev/null 2>&1 & PIDS+=($!)
wait_port "$SP"
timeout 15 curl -s --socks5 "127.0.0.1:$SP" -o "$WORK/socks.out" "http://127.0.0.1:$WEB$URL_PATH"
check "--socks SOCKS5 proxy" "$PAYLOAD" "$WORK/socks.out"

# ── -R: reverse tunnel ─────────────────────────────────────────────────
P=$(free_port); RP=$(free_port)
"$BIN" -l -p "$P" -k "$KEY" -R "127.0.0.1:$RP" >/dev/null 2>&1 & PIDS+=($!)
wait_port "$P"
"$BIN" -k "$KEY" -R "127.0.0.1:$WEB" 127.0.0.1 "$P" >/dev/null 2>&1 & PIDS+=($!)
wait_port "$RP"
timeout 15 curl -s -o "$WORK/rev.out" "http://127.0.0.1:$RP$URL_PATH"
check "-R reverse tunnel" "$PAYLOAD" "$WORK/rev.out"

# ── --send / --recv: file transfer with SHA-256 verification ────────────
P=$(free_port); mkdir -p "$WORK/inbox"
timeout 20 "$BIN" -l -p "$P" -k "$KEY" --recv "$WORK/inbox" >/dev/null 2>&1 &
RX=$!
wait_port "$P"
timeout 20 "$BIN" -k "$KEY" --send "$PAYLOAD" 127.0.0.1 "$P" >/dev/null 2>&1
wait "$RX" 2>/dev/null
check "--send/--recv file transfer" "$PAYLOAD" "$WORK/inbox/payload.bin"

# ── Wrong password must not leak data ──────────────────────────────────
P=$(free_port); rm -f "$WORK/wrong.out"
(sleep 10 | timeout 15 "$BIN" -l -p "$P" -k "$KEY" > "$WORK/wrong.out" 2>/dev/null) &
SRV=$!
wait_port "$P"
timeout 10 "$BIN" -k "not-the-password" 127.0.0.1 "$P" < "$PAYLOAD" >/dev/null 2>&1
sleep 0.3; kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null
if [ ! -s "$WORK/wrong.out" ]; then
    echo "  [E2E] wrong password delivers nothing ... PASS"; PASS=$((PASS + 1))
else
    echo "  [E2E] wrong password delivers nothing ... FAIL"; FAIL=$((FAIL + 1))
fi

echo
echo "=== E2E results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
