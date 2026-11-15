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
    case "$label" in *--pad*)    # full packet + header = one 1400-byte record
        ip netns exec "$NS_C" ip -o link show | grep -q 'mtu 1392' || ok=0 ;;
    esac
    if [[ "$label" == *--tun-udp* ]]; then
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
# Multi-client hub (-K --tun --tun6): three clients in their own namespaces
hub_test() {
    local S=clawsec-hub-srv H=() i ok
    for i in 1 2 3; do H+=("clawsec-hub-c$i"); done
    ip netns add "$S"; ip netns exec "$S" ip link set lo up
    for i in 1 2 3; do
        ip netns add "${H[$((i-1))]}"; ip netns exec "${H[$((i-1))]}" ip link set lo up
        ip link add "chv$i" type veth peer name "chp$i"
        ip link set "chv$i" netns "$S"; ip link set "chp$i" netns "${H[$((i-1))]}"
        ip netns exec "$S" ip addr add "192.168.24$i.1/24" dev "chv$i"
        ip netns exec "$S" ip link set "chv$i" up
        ip netns exec "${H[$((i-1))]}" ip addr add "192.168.24$i.2/24" dev "chp$i"
        ip netns exec "${H[$((i-1))]}" ip link set "chp$i" up
        ip netns exec "${H[$((i-1))]}" ip route add default via "192.168.24$i.1"
    done
    ip netns exec "$S" sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
    ip netns exec "$S" timeout 60 "$BIN" -v -l -p 9000 -k "$KEY" -K --tun 10.232.0.1/24 \
        --tun6 fd00:232::1/64 </dev/null >/dev/null 2>"$WORK/hub.log" &
    local HUB=$!
    sleep 0.8
    local C=()
    ip netns exec "${H[0]}" timeout 60 "$BIN" -v -k "$KEY" --tun auto --default-route \
        192.168.241.1 9000 </dev/null >/dev/null 2>"$WORK/hc1.log" & C+=($!)
    ip netns exec "${H[1]}" timeout 60 "$BIN" -v -k "$KEY" --tun auto \
        192.168.242.1 9000 </dev/null >/dev/null 2>"$WORK/hc2.log" & C+=($!)
    ip netns exec "${H[2]}" timeout 60 "$BIN" -v -k "$KEY" --tun 10.232.0.50/24 \
        192.168.243.1 9000 </dev/null >/dev/null 2>"$WORK/hc3.log" & C+=($!)
    for _ in $(seq 80); do
        [ "$(grep -c 'vpn hub: client' "$WORK/hub.log" 2>/dev/null)" -ge 3 ] &&
            ip netns exec "${H[0]}" ip -o -6 addr show scope global | grep -q tun &&
            ip netns exec "${H[1]}" ip -o -6 addr show scope global | grep -q tun && break
        sleep 0.1
    done
    sleep 0.3
    hub_check() {   # hub_check <label> <command...>
        local label=$1; shift
        if "$@" >/dev/null 2>&1; then
            echo "  [E2E] VPN hub: $label ... PASS"; PASS=$((PASS + 1))
        else
            echo "  [E2E] VPN hub: $label ... FAIL"; FAIL=$((FAIL + 1))
        fi
    }
    # auto clients get .2/.3 in connection order: read the actual addresses
    local A1 A2 A1v6 A2v6
    A1=$(ip netns exec "${H[0]}" ip -o -4 addr show | awk '/tun/ {split($4,a,"/"); print a[1]}')
    A2=$(ip netns exec "${H[1]}" ip -o -4 addr show | awk '/tun/ {split($4,a,"/"); print a[1]}')
    A1v6=$(ip netns exec "${H[0]}" ip -o -6 addr show scope global | awk '/tun/ {split($4,a,"/"); print a[1]}')
    A2v6=$(ip netns exec "${H[1]}" ip -o -6 addr show scope global | awk '/tun/ {split($4,a,"/"); print a[1]}')
    hub_check "auto addresses: distinct, IPv4 and IPv6 host numbers match" \
        sh -c "[ '$A1' != '$A2' ] &&
               case '$A1' in 10.232.0.2|10.232.0.3) ;; *) exit 1;; esac &&
               case '$A2' in 10.232.0.2|10.232.0.3) ;; *) exit 1;; esac &&
               [ 'fd00:232::${A1##*.}' = '$A1v6' ] && [ 'fd00:232::${A2##*.}' = '$A2v6' ]"
    hub_check "client -> server IPv4 and IPv6" \
        sh -c "ip netns exec ${H[1]} ping -c2 -i0.2 -W2 10.232.0.1 &&
               ip netns exec ${H[1]} ping -6 -c2 -i0.2 -W2 fd00:232::1"
    hub_check "explicit address 10.232.0.50" ip netns exec "${H[2]}" ping -c2 -i0.2 -W2 10.232.0.1
    hub_check "client -> client (IPv4, IPv6)" \
        sh -c "ip netns exec ${H[0]} ping -c2 -i0.2 -W2 $A2 &&
               ip netns exec ${H[1]} ping -6 -c2 -i0.2 -W2 $A1v6"
    hub_check "--default-route adds ::/1 and 8000::/1" \
        sh -c "ip netns exec ${H[0]} ip -6 route | grep -q '^::/1 dev tun' &&
               ip netns exec ${H[0]} ip -6 route | grep -q '^8000::/1 dev tun'"
    # spoofing: a second address on the client's device, used as the source
    local DEV
    DEV=$(ip netns exec "${H[1]}" ip -o link | awk -F': ' '/tun/ {print $2; exit}')
    ip netns exec "${H[1]}" ip addr add 10.232.0.99/32 dev "$DEV"
    ip netns exec "${H[1]}" ping -c2 -i0.2 -W1 -I 10.232.0.99 10.232.0.1 >/dev/null 2>&1
    sleep 0.3
    hub_check "spoofed source dropped and reported" \
        sh -c "! ip netns exec ${H[1]} ping -c1 -W1 -I 10.232.0.99 10.232.0.1 &&
               grep -q 'not its own: dropped' '$WORK/hub.log'"
    ip netns exec "${H[2]}" timeout 8 "$BIN" -k "$KEY" --tun "$A2/24" 192.168.243.1 9000 \
        </dev/null >/dev/null 2>"$WORK/hc4.log"
    hub_check "address in use is refused" grep -q 'already in use' "$WORK/hc4.log"
    kill -INT "${C[0]}" 2>/dev/null; wait "${C[0]}" 2>/dev/null
    hub_check "--default-route IPv6 routes removed on exit" \
        sh -c "! ip netns exec ${H[0]} ip -6 route | grep -q '^::/1'"
    kill "${C[@]}" "$HUB" 2>/dev/null; wait "${C[@]}" "$HUB" 2>/dev/null
    # per-user fixed address: users file ip=, client asks for --tun auto
    local UF="$WORK/vpn-users"
    CLAWSEC_PASSWORD='dana-Vpn-passw0rd-1' "$BIN" --users "$UF" --add-user dana \
        --user-option ip=10.232.0.77 >/dev/null 2>&1
    ip netns exec "$S" timeout 30 "$BIN" -l -p 9001 -K --users "$UF" --tun 10.232.0.1/24 \
        --tun6 fd00:232::1/64 </dev/null >/dev/null 2>"$WORK/hub2.log" &
    HUB=$!
    sleep 0.8
    ip netns exec "${H[1]}" env CLAWSEC_PASSWORD='dana-Vpn-passw0rd-1' timeout 30 "$BIN" \
        --user dana --tun auto 192.168.242.1 9001 </dev/null >/dev/null 2>&1 &
    C=($!)
    for _ in $(seq 40); do
        ip netns exec "${H[1]}" ip -o addr 2>/dev/null | grep -q '10.232.0.77/24' && break
        sleep 0.1
    done
    hub_check "users file ip=: fixed address 10.232.0.77 (+ fd00:232::4d)" \
        sh -c "ip netns exec ${H[1]} ip -o addr | grep -q '10.232.0.77/24' &&
               ip netns exec ${H[1]} ip -o addr | grep -q 'fd00:232::4d/64' &&
               ip netns exec ${H[1]} ping -c1 -W2 10.232.0.1"
    kill "${C[@]}" "$HUB" 2>/dev/null; wait "${C[@]}" "$HUB" 2>/dev/null
    ip netns del "$S"; for n in "${H[@]}"; do ip netns del "$n"; done
}

# IPv6 NAT (--masquerade with --tun6): the host behind the server has no
# route back to the VPN prefix, so replies only arrive if the server NATs
nat6_test() {
    local S=clawsec-n6-srv C=clawsec-n6-cli I=clawsec-n6-net n
    for n in "$S" "$C" "$I"; do ip netns add "$n"; ip netns exec "$n" ip link set lo up; done
    ip link add n6a type veth peer name n6b
    ip link set n6a netns "$S"; ip link set n6b netns "$C"
    ip netns exec "$S" ip addr add 192.168.239.1/24 dev n6a; ip netns exec "$S" ip link set n6a up
    ip netns exec "$C" ip addr add 192.168.239.2/24 dev n6b; ip netns exec "$C" ip link set n6b up
    ip netns exec "$C" ip route add default via 192.168.239.1
    ip link add n6c type veth peer name n6d
    ip link set n6c netns "$S"; ip link set n6d netns "$I"
    ip netns exec "$S" ip -6 addr add 2001:db8:239::1/64 dev n6c nodad
    ip netns exec "$S" ip link set n6c up
    ip netns exec "$I" ip -6 addr add 2001:db8:239::2/64 dev n6d nodad
    ip netns exec "$I" ip link set n6d up
    ip netns exec "$S" timeout 30 "$BIN" -l -p 9000 -k "$KEY" -K --tun 10.239.0.1/24 \
        --tun6 fd00:239::1/64 --masquerade </dev/null >/dev/null 2>&1 &
    local SV=$!
    sleep 0.8
    ip netns exec "$C" timeout 30 "$BIN" -k "$KEY" --tun auto --default-route 192.168.239.1 9000 \
        </dev/null >/dev/null 2>&1 &
    local CL=$!
    for _ in $(seq 40); do
        ip netns exec "$C" ip -6 route 2>/dev/null | grep -q '^::/1' && break
        sleep 0.1
    done
    if ip netns exec "$C" ping -6 -c2 -i0.2 -W2 2001:db8:239::2 >/dev/null 2>&1; then
        echo "  [E2E] VPN hub: IPv6 NAT (--masquerade --tun6) ... PASS"; PASS=$((PASS + 1))
    else
        echo "  [E2E] VPN hub: IPv6 NAT (--masquerade --tun6) ... FAIL"; FAIL=$((FAIL + 1))
    fi
    kill -INT "$CL" "$SV" 2>/dev/null; wait "$CL" "$SV" 2>/dev/null
    if ip netns exec "$S" sh -c 'ip6tables -t nat -S 2>/dev/null; nft list tables 2>/dev/null' |
       grep -qE 'fd00:239|clawsec6'; then
        echo "  [E2E] VPN hub: IPv6 NAT removed on exit ... FAIL"; FAIL=$((FAIL + 1))
    else
        echo "  [E2E] VPN hub: IPv6 NAT removed on exit ... PASS"; PASS=$((PASS + 1))
    fi
    for n in "$S" "$C" "$I"; do ip netns del "$n"; done
}

vpn_test "tcp relay"
vpn_test "--tun-udp" --tun-udp
vpn_test "tcp relay --pad" --pad
vpn_test "--tun-udp --pad" --tun-udp --pad
hub_test
if command -v ip6tables >/dev/null || command -v nft >/dev/null; then
    nat6_test
else
    echo "  [E2E] VPN hub: IPv6 NAT ... SKIP (no ip6tables/nft)"
fi
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

# Pipelined SYN scan in the server namespace: 5 open ports, 200 ports dropped
# by the firewall (no reply), IPv4 and IPv6. A sequential scan would wait a
# full timeout for every dropped port.
if command -v iptables >/dev/null && command -v ip6tables >/dev/null &&
   ip netns exec "$NS_S" iptables -S >/dev/null 2>&1; then
    ip netns exec "$NS_S" iptables -A INPUT -i lo -p tcp --dport 1000:1199 -j DROP
    ip netns exec "$NS_S" ip6tables -A INPUT -i lo -p tcp --dport 1000:1199 -j DROP
    ip netns exec "$NS_S" python3 -c '
import socket, time
keep = []
for port in (22, 80, 443, 1500, 1999):
    for fam, addr in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
        s = socket.socket(fam); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if fam == socket.AF_INET6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.bind((addr, port)); s.listen(64); keep.append(s)
time.sleep(40)' &
    LST=$!
    sleep 0.5
    for target in 127.0.0.1 ::1; do
        fam=; [ "$target" = ::1 ] && fam=-6
        START=$SECONDS
        found=$(ip netns exec "$NS_S" timeout 30 "$BIN" -v $fam --scan-rate 2000 --scan 1-2000 "$target" \
                2>"$WORK/scan.err" | awk '/\/tcp  open/ {print $1}' | sort -n | tr '\n' ' ')
        T=$((SECONDS - START))
        if [ "$found" = "22/tcp 80/tcp 443/tcp 1500/tcp 1999/tcp " ] && [ "$T" -le 10 ] &&
           grep -q '1795 closed, 200 filtered' "$WORK/scan.err"; then
            echo "  [E2E] SYN scan $target: 2000 ports, 200 filtered, exact result (${T}s) ... PASS"; PASS=$((PASS + 1))
        else
            echo "  [E2E] SYN scan $target ... FAIL (found '$found' in ${T}s)"; FAIL=$((FAIL + 1))
            cat "$WORK/scan.err"
        fi
    done
    kill "$LST" 2>/dev/null; wait "$LST" 2>/dev/null
else
    echo "  [E2E] pipelined SYN scan ... SKIP (iptables/ip6tables unavailable)"
fi

echo
echo "=== VPN E2E results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
