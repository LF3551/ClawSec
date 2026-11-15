#!/usr/bin/env bash
#
# e2e_vpn.sh — End-to-end test of the TUN VPN (--tun, --tun-udp).
#
# Usage: sudo tests/e2e_vpn.sh [path/to/clawsec]   (default: src/clawsec)
#
# Builds two isolated network namespaces joined by a veth pair, runs a
# ClawSec VPN server in one and a client in the other, and pings through the
# tunnel with near-MTU packets, over the TCP relay and the UDP data channel.
# Requires Linux, root, iproute2 and ping. Skips (exit 0) when unavailable.
#
set -u

BIN=$(realpath "${1:-src/clawsec}")
KEY='E2e-Vpn-Passw0rd!'
NS_S=clawsec-e2e-srv
NS_C=clawsec-e2e-cli
WORK=$(mktemp -d)
PASS=0
FAIL=0

skip() { echo "e2e_vpn: SKIP ($*)"; rm -rf "$WORK"; exit 0; }
[ "$(uname -s)" = Linux ] || skip "Linux only"
[ "$(id -u)" -eq 0 ] || skip "requires root"
command -v ip >/dev/null && command -v ping >/dev/null || skip "requires iproute2 and ping"
[ -x "$BIN" ] || { echo "e2e_vpn: binary not found: $BIN" >&2; exit 2; }

if [ ! -c /dev/net/tun ]; then
    mkdir -p /dev/net && mknod /dev/net/tun c 10 200 && chmod 666 /dev/net/tun \
        || skip "/dev/net/tun unavailable"
fi

cleanup() {
    [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null
    [ -n "${CLI:-}" ] && kill "$CLI" 2>/dev/null
    wait 2>/dev/null
    ip netns del "$NS_S" 2>/dev/null
    ip netns del "$NS_C" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

ip netns del "$NS_S" 2>/dev/null; ip netns del "$NS_C" 2>/dev/null
ip netns add "$NS_S" && ip netns add "$NS_C" || skip "network namespaces unavailable"
ip link add cs-e2e0 type veth peer name cs-e2e1
ip link set cs-e2e0 netns "$NS_S"
ip link set cs-e2e1 netns "$NS_C"
ip -n "$NS_S" addr add 192.168.231.1/24 dev cs-e2e0
ip -n "$NS_C" addr add 192.168.231.2/24 dev cs-e2e1
for ns in "$NS_S" "$NS_C"; do
    ip -n "$ns" link set lo up
done
ip -n "$NS_S" link set cs-e2e0 up
ip -n "$NS_C" link set cs-e2e1 up

vpn_test() {   # vpn_test <label> [extra options...]
    local label=$1; shift
    SRV=; CLI=
    ip netns exec "$NS_S" timeout 30 "$BIN" -v -l -p 9000 -k "$KEY" \
        --tun 10.231.0.1/24 "$@" >/dev/null 2>"$WORK/srv.log" &
    SRV=$!
    for _ in $(seq 50); do
        ip netns exec "$NS_S" grep -q ':2328 [0-9A-F:]* 0A ' /proc/net/tcp /proc/net/tcp6 2>/dev/null && break
        sleep 0.1
    done
    ip netns exec "$NS_C" timeout 30 "$BIN" -v -k "$KEY" 192.168.231.1 9000 \
        --tun 10.231.0.2/24 "$@" >/dev/null 2>"$WORK/cli.log" &
    CLI=$!

    # Wait for both relays to come up
    for _ in $(seq 100); do
        grep -q 'relay started' "$WORK/srv.log" 2>/dev/null &&
            grep -q 'relay started' "$WORK/cli.log" 2>/dev/null && break
        sleep 0.1
    done

    local ok=1
    ip netns exec "$NS_C" ping -c 5 -i 0.2 -W 2 -s 1300 10.231.0.1 >"$WORK/ping.log" 2>&1 || ok=0
    grep -q ' 0% packet loss' "$WORK/ping.log" || ok=0
    if [ "$label" = "--tun-udp" ]; then
        grep -q 'client UDP channel ready' "$WORK/cli.log" || ok=0
        grep -q 'server UDP channel ready' "$WORK/srv.log" || ok=0
    fi

    if [ "$ok" -eq 1 ]; then
        echo "  [E2E] VPN $label ... PASS"; PASS=$((PASS + 1))
    else
        echo "  [E2E] VPN $label ... FAIL"; FAIL=$((FAIL + 1))
        echo "--- server log"; cat "$WORK/srv.log"
        echo "--- client log"; cat "$WORK/cli.log"
        echo "--- ping";       cat "$WORK/ping.log"
    fi
    kill "$SRV" "$CLI" 2>/dev/null; wait "$SRV" "$CLI" 2>/dev/null
    SRV=; CLI=
    sleep 0.3
}

result() {   # result <label> <ok>
    if [ "$2" -eq 1 ]; then
        echo "  [E2E] $1 ... PASS"; PASS=$((PASS + 1))
    else
        echo "  [E2E] $1 ... FAIL"; FAIL=$((FAIL + 1))
        echo "--- server log"; cat "$WORK/srv.log"
        echo "--- client log"; cat "$WORK/cli.log"
    fi
}

# Full tunnel (--default-route) + exit node (--masquerade): state must be
# applied during the session and fully undone after SIGINT / SIGTERM.
full_tunnel_test() {
    local ok=1 fwd_before
    ip -n "$NS_C" route replace default via 192.168.231.1 dev cs-e2e1
    fwd_before=$(ip netns exec "$NS_S" cat /proc/sys/net/ipv4/ip_forward)

    ip netns exec "$NS_S" timeout 30 "$BIN" -v -l -p 9000 -k "$KEY" \
        --tun 10.231.0.1/24 --masquerade >/dev/null 2>"$WORK/srv.log" &
    SRV=$!
    for _ in $(seq 50); do
        ip netns exec "$NS_S" grep -q ':2328 [0-9A-F:]* 0A ' /proc/net/tcp /proc/net/tcp6 2>/dev/null && break
        sleep 0.1
    done
    ip netns exec "$NS_C" timeout 30 "$BIN" -v -k "$KEY" 192.168.231.1 9000 \
        --tun 10.231.0.2/24 --default-route >/dev/null 2>"$WORK/cli.log" &
    CLI=$!
    for _ in $(seq 100); do
        grep -q 'relay started' "$WORK/srv.log" 2>/dev/null &&
            grep -q 'relay started' "$WORK/cli.log" 2>/dev/null && break
        sleep 0.1
    done
    sleep 0.3

    ip netns exec "$NS_S" iptables -t nat -S POSTROUTING 2>/dev/null |
        grep -q -- '-s 10.231.0.0/24 .*MASQUERADE' || { echo "    NAT rule missing"; ok=0; }
    ip -n "$NS_C" route show default | grep -q 'dev tun' || { echo "    default route not via tun"; ok=0; }
    ip netns exec "$NS_C" ping -c 2 -W 2 10.231.0.1 >/dev/null 2>&1 || { echo "    ping failed"; ok=0; }

    # Ctrl-C on the client: routes restored, device gone
    kill -INT "$CLI" 2>/dev/null; wait "$CLI" 2>/dev/null; CLI=
    ip -n "$NS_C" route show default | grep -q 'via 192.168.231.1 dev cs-e2e1' ||
        { echo "    client default route not restored"; ok=0; }
    ip -n "$NS_C" link show 2>/dev/null | grep -q ': tun' && { echo "    client tun device left behind"; ok=0; }

    # SIGTERM on the server: NAT rule removed, forwarding restored
    kill -TERM "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null; SRV=
    ip netns exec "$NS_S" iptables -t nat -S POSTROUTING 2>/dev/null |
        grep -q 'MASQUERADE' && { echo "    NAT rule left behind"; ok=0; }
    [ "$(ip netns exec "$NS_S" cat /proc/sys/net/ipv4/ip_forward)" = "$fwd_before" ] ||
        { echo "    ip_forward not restored"; ok=0; }

    result "VPN --default-route + --masquerade, cleanup on SIGINT/SIGTERM" "$ok"
    ip -n "$NS_C" route del default 2>/dev/null
    sleep 0.3
}

echo
echo "=== ClawSec VPN end-to-end tests ($BIN) ==="
vpn_test "tcp relay"
vpn_test "--tun-udp" --tun-udp
if command -v iptables >/dev/null && ip netns exec "$NS_S" iptables -t nat -S >/dev/null 2>&1; then
    full_tunnel_test
else
    echo "  [E2E] VPN --default-route + --masquerade ... SKIP (iptables unavailable)"
fi

# SYN (half-open) scan needs root as well: it must find an open port
python3 -c 'import socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",18999)); s.listen(5); time.sleep(15)' &
LST=$!
sleep 0.5
if "$BIN" -v --scan 18995-19003 127.0.0.1 2>&1 | grep -q 'SYN (half-open)' &&
   "$BIN" --scan 18995-19003 127.0.0.1 2>/dev/null | grep -q '18999/tcp  open'; then
    echo "  [E2E] SYN scan (raw socket) finds an open port ... PASS"; PASS=$((PASS + 1))
else
    echo "  [E2E] SYN scan (raw socket) finds an open port ... FAIL"; FAIL=$((FAIL + 1))
fi
kill "$LST" 2>/dev/null; wait "$LST" 2>/dev/null

echo
echo "=== VPN E2E results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
