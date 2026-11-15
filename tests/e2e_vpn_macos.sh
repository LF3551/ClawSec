#!/usr/bin/env bash
#
# e2e_vpn_macos.sh — macOS TUN smoke test (utun + pf NAT), run as root.
#
# Usage: sudo tests/e2e_vpn_macos.sh [path/to/clawsec]
#
# Starts a --tun server with --masquerade and a --tun client on 127.0.0.1 and
# checks what the macOS-specific code does: utun interfaces with the right
# addresses and netmask, the NAT rule in the com.apple/clawsec pf anchor, and
# that interfaces and the anchor are cleaned up after SIGTERM.
# (--default-route is not exercised: it would cut the CI runner's network.)
set -u

BIN=$(cd "$(dirname "${1:-src/clawsec}")" && pwd)/$(basename "${1:-src/clawsec}")
KEY='E2e-Macos-Vpn-Passw0rd!'
WORK=$(mktemp -d)
PASS=0
FAIL=0
SRV=; CLI=

[ "$(uname -s)" = Darwin ] || { echo "e2e_vpn_macos: SKIP (macOS only)"; exit 0; }
[ "$(id -u)" -eq 0 ] || { echo "e2e_vpn_macos: SKIP (requires root)"; exit 0; }

cleanup() {
    [ -n "$SRV" ] && kill "$SRV" 2>/dev/null
    [ -n "$CLI" ] && kill "$CLI" 2>/dev/null
    wait 2>/dev/null
    pfctl -a com.apple/clawsec -F all >/dev/null 2>&1
    rm -rf "$WORK"
}
trap cleanup EXIT

check() {   # check <name> <ok 0/1>
    if [ "$2" -eq 1 ]; then echo "  [E2E] $1 ... PASS"; PASS=$((PASS + 1))
    else echo "  [E2E] $1 ... FAIL"; FAIL=$((FAIL + 1)); fi
}

utun_with() {   # utun_with <ip>: name of the utun interface carrying <ip>
    ifconfig | awk -v ip="$1" '/^utun[0-9]+:/ {dev=$1; sub(":","",dev)} $1=="inet" && $2==ip {print dev}'
}

echo
echo "=== ClawSec macOS VPN smoke test ($BIN) ==="

"$BIN" -v -l -p 19443 -k "$KEY" --tun 10.231.0.1/24 --masquerade >"$WORK/srv.out" 2>"$WORK/srv.log" &
SRV=$!
sleep 1
"$BIN" -v -k "$KEY" 127.0.0.1 19443 --tun 10.231.0.2/24 >"$WORK/cli.out" 2>"$WORK/cli.log" &
CLI=$!
for _ in $(seq 50); do
    grep -q 'relay started' "$WORK/srv.log" 2>/dev/null &&
        grep -q 'relay started' "$WORK/cli.log" 2>/dev/null && break
    sleep 0.2
done

SDEV=$(utun_with 10.231.0.1)
CDEV=$(utun_with 10.231.0.2)
check "server utun configured with 10.231.0.1 ($SDEV)" "$([ -n "$SDEV" ] && echo 1 || echo 0)"
check "client utun configured with 10.231.0.2 ($CDEV)" "$([ -n "$CDEV" ] && echo 1 || echo 0)"
MASK=$(ifconfig "${SDEV:-none}" 2>/dev/null | awk '$1=="inet" {print $NF}')
check "netmask follows the /24 prefix (got ${MASK:-none})" "$([ "$MASK" = 0xffffff00 ] && echo 1 || echo 0)"
pfctl -a com.apple/clawsec -s nat 2>/dev/null | tee "$WORK/nat.txt" >/dev/null
check "NAT rule loaded into the com.apple/clawsec anchor" \
      "$(grep -q '10.231.0.0/24' "$WORK/nat.txt" && echo 1 || echo 0)"

kill -TERM "$CLI" "$SRV" 2>/dev/null
wait "$CLI" "$SRV" 2>/dev/null
SRV=; CLI=
sleep 1

check "utun interfaces removed after SIGTERM" \
      "$([ -z "$(utun_with 10.231.0.1)$(utun_with 10.231.0.2)" ] && echo 1 || echo 0)"
check "pf anchor flushed after SIGTERM" \
      "$([ -z "$(pfctl -a com.apple/clawsec -s nat 2>/dev/null)" ] && echo 1 || echo 0)"

if [ "$FAIL" -ne 0 ]; then
    echo "--- server log"; cat "$WORK/srv.log"
    echo "--- client log"; cat "$WORK/cli.log"
fi
echo
echo "=== macOS VPN results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
