"""
e2e_socks.py — SOCKS5 through a ClawSec tunnel (mux v2), called by e2e.sh.

Usage: e2e_socks.py <socks_proxy_port> <unused> [label]
Starts three local destinations on free ports (keep-alive echo,
read-until-EOF reverser, 8 MiB bulk sender) and prints one line per check in
e2e.sh format. Exit status 0 if all checks pass.
"""
import socket, struct, sys, threading, time, os
PROXY, BASE = int(sys.argv[1]), int(sys.argv[2])
LABEL = sys.argv[3] if len(sys.argv) > 3 else "--socks"
BULK_SIZE = 8 * 1024 * 1024

def serve(handler):
    """Listen on a free port chosen by the kernel; returns the port"""
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0)); s.listen(64)
    def loop():
        while True:
            c, _ = s.accept(); threading.Thread(target=handler, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    return s.getsockname()[1]

def closed_port():
    """A port with nothing listening (bound briefly, then released)"""
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    return port

def echo(c):                       # keeps the connection open, echoes
    try:
        while (d := c.recv(65536)): c.sendall(d)
    except OSError: pass
def reverse(c):                    # reads until EOF, then answers and closes
    data = b""
    while (d := c.recv(65536)): data += d
    c.sendall(data[::-1]); c.close()
def bulk(c):                       # sends BULK_SIZE bytes
    try: c.sendall(os.urandom(1024) * (BULK_SIZE // 1024)); c.close()
    except OSError: pass

ECHO, REVERSE, BULK = serve(echo), serve(reverse), serve(bulk)
time.sleep(0.2)

def socks(port, host=b"localhost", timeout=10):
    c = socket.create_connection(("127.0.0.1", PROXY), timeout=timeout)
    c.sendall(b"\x05\x01\x00")
    assert c.recv(2) == b"\x05\x00", "greeting"
    c.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack(">H", port))
    rep = b""
    while len(rep) < 10: rep += c.recv(10 - len(rep))
    return c, rep

results = {}
def check(name, fn):
    t = time.time()
    try: ok = fn()
    except Exception as e: ok = False; print(f"    {name}: {e!r}")
    results[name] = ok
    print(f"  [E2E] {LABEL} {name} ... {'PASS' if ok else 'FAIL'}", flush=True)

def sequential_keepalive():
    for i in range(5):
        c, rep = socks(ECHO); assert rep[1] == 0
        c.sendall(b"x%d" % i); assert c.recv(10) == b"x%d" % i
        c.close()
    return True

def parallel_keepalive():
    conns = [socks(ECHO)[0] for _ in range(40)]
    for i, c in enumerate(conns): c.sendall(b"msg-%d" % i)
    ok = all(c.recv(20) == b"msg-%d" % i for i, c in enumerate(conns))
    for c in conns: c.close()
    return ok

def half_close():
    c, rep = socks(REVERSE); assert rep[1] == 0
    payload = os.urandom(300000)
    c.sendall(payload); c.shutdown(socket.SHUT_WR)
    got = b""
    while (d := c.recv(65536)): got += d
    return got == payload[::-1]

def slow_reader_does_not_block():
    stalled, rep = socks(BULK); assert rep[1] == 0    # never read: window fills up
    time.sleep(1.0)
    c, rep = socks(ECHO); assert rep[1] == 0
    t = time.time(); c.sendall(b"ping"); r = c.recv(10)
    fast = time.time() - t < 1.0
    # now drain the stalled stream completely
    got = 0
    stalled.settimeout(20)
    while (d := stalled.recv(1 << 20)): got += len(d)
    return r == b"ping" and fast and got == BULK_SIZE

def refused_and_unreachable():
    c, rep = socks(closed_port())     # nothing listens there
    return rep[1] != 0

def bad_socks_version():
    c = socket.create_connection(("127.0.0.1", PROXY), timeout=5)
    c.sendall(b"\x04\x01\x00\x50\x7f\x00\x00\x01\x00")   # SOCKS4
    d = c.recv(10)
    return d in (b"", b"\x05\xff")

def many_streams_reused():
    for i in range(300):            # > 255 ids: ids must be reused
        c, rep = socks(ECHO); assert rep[1] == 0, f"conn {i}"
        c.sendall(b"r"); assert c.recv(1) == b"r"; c.close()
    return True

for name, fn in [("sequential keep-alive connections", sequential_keepalive),
                 ("40 parallel keep-alive connections", parallel_keepalive),
                 ("half-close: request, EOF, response", half_close),
                 ("stalled reader does not block other streams (8 MiB)", slow_reader_does_not_block),
                 ("connect failure reported to the SOCKS client", refused_and_unreachable),
                 ("non-SOCKS5 client rejected", bad_socks_version),
                 ("300 sequential connections (id reuse)", many_streams_reused)]:
    check(name, fn)
sys.exit(0 if all(results.values()) else 1)
