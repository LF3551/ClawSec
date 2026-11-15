/*
 * tun.c — TUN VPN implementation for ClawSec
 *
 * Creates a virtual network interface and relays encrypted IP packets
 * between the TUN device and the encrypted tunnel.
 *
 * Platform support:
 *   - macOS:  utun via sys/kern_control.h
 *   - Linux:  /dev/net/tun via linux/if_tun.h
 */
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#ifdef __linux__
#define _GNU_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <sys/wait.h>
#include <poll.h>
#include <time.h>

#ifdef __APPLE__
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if_utun.h>
#endif

#ifdef __linux__
#include <linux/if_tun.h>
#endif

#include "tun.h"
#include "farm9crypt.h"
#include "util.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

/* ─────────────────────────────────────────────
 * Run a system tool without a shell.
 *
 * Commands are argv vectors passed to execvp(), so no argument is ever
 * interpreted by /bin/sh: an interface name or address containing shell
 * metacharacters is just an (invalid) argument to `ip`, never a command.
 * SIGCHLD is blocked while waiting so a process-wide reaper (-K mode)
 * cannot steal the child's exit status.
 * Returns the exit status (0 = success), or -1 if it could not run.
 * ───────────────────────────────────────────── */
static int run_argv(char *const argv[], int quiet) {
    sigset_t block, old;
    sigemptyset(&block);
    sigaddset(&block, SIGCHLD);
    sigprocmask(SIG_BLOCK, &block, &old);

    int rc = -1;
    pid_t pid = fork();
    if (pid == 0) {
        sigprocmask(SIG_SETMASK, &old, NULL);
        if (quiet) {
            int null_fd = open("/dev/null", O_WRONLY);
            if (null_fd >= 0) {
                dup2(null_fd, STDOUT_FILENO);
                dup2(null_fd, STDERR_FILENO);
                if (null_fd > STDERR_FILENO) close(null_fd);
            }
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    if (pid > 0) {
        int status;
        pid_t w;
        do {
            w = waitpid(pid, &status, 0);
        } while (w < 0 && errno == EINTR);
        if (w == pid && WIFEXITED(status))
            rc = WEXITSTATUS(status);
    }
    sigprocmask(SIG_SETMASK, &old, NULL);
    return rc;
}

/* RUN(quiet, "tool", "arg", ...) — argv literal, NULL-terminated */
#define RUN(quiet, ...) run_argv((char *const[]){ __VA_ARGS__, NULL }, (quiet))

#define TUN_SIG_VPN   "TVPN"
#define TUN_SIG_LEN   4

/* Cast helper for farm9crypt which takes char* */
static inline int tun_crypt_write(int fd, const char *msg, int len) {
    return farm9crypt_write(fd, (char *)msg, len);
}

/* ─────────────────────────────────────────────
 * Parse CIDR notation: "10.0.0.1/24"
 * ───────────────────────────────────────────── */
int tun_parse_cidr(const char *cidr, char *ip, size_t ip_len, int *prefix_len) {
    if (!cidr || !ip || !prefix_len || ip_len == 0) return -1;

    const char *slash = strchr(cidr, '/');
    size_t host_len = slash ? (size_t)(slash - cidr) : strlen(cidr);
    if (host_len == 0 || host_len >= ip_len) return -1;
    memcpy(ip, cidr, host_len);
    ip[host_len] = '\0';

    int prefix = 24;                       /* default when no "/N" is given */
    if (slash) {
        const char *ps = slash + 1;
        size_t n = strlen(ps);
        if (n == 0 || n > 2) return -1;
        prefix = 0;
        for (size_t i = 0; i < n; i++) {
            if (ps[i] < '0' || ps[i] > '9') return -1;
            prefix = prefix * 10 + (ps[i] - '0');
        }
    }

    /* The address ends up in shell commands: accept only a dotted IPv4 */
    if (tun_validate_config(ip, prefix) != 0) return -1;
    *prefix_len = prefix;
    return 0;
}

int tun_validate_config(const char *ip, int prefix_len) {
    struct in_addr addr;
    if (!ip || inet_pton(AF_INET, ip, &addr) != 1) return -1;
    if (prefix_len < 8 || prefix_len > 30) return -1;
    return 0;
}

/* Interface names come from the kernel or from `route`/`ip` output and are
 * interpolated into commands: allow only the usual name characters. */
int tun_valid_ifname(const char *name) {
    if (!name || !*name || strlen(name) >= IFNAMSIZ) return 0;
    for (const char *p = name; *p; p++) {
        char c = *p;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'))
            return 0;
    }
    return 1;
}

static int valid_ipv4(const char *s) {
    struct in_addr a;
    return s && inet_pton(AF_INET, s, &a) == 1;
}

#ifdef __APPLE__
/* Prefix length -> dotted netmask, e.g. 24 -> "255.255.255.0" */
static void prefix_to_netmask(int prefix, char *out, size_t out_len) {
    struct in_addr m;
    m.s_addr = htonl(prefix <= 0 ? 0 : 0xFFFFFFFFu << (32 - prefix));
    inet_ntop(AF_INET, &m, out, (socklen_t)out_len);
}
#endif

/* ─────────────────────────────────────────────
 * macOS: utun device
 * ───────────────────────────────────────────── */
#ifdef __APPLE__

int tun_open(const char *ip, int prefix_len, char *dev_name, size_t dev_name_len) {
    /* Create utun socket */
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
        perror("tun: socket(PF_SYSTEM)");
        return -1;
    }

    struct ctl_info ci;
    memset(&ci, 0, sizeof(ci));
    strncpy(ci.ctl_name, UTUN_CONTROL_NAME, sizeof(ci.ctl_name));
    if (ioctl(fd, CTLIOCGINFO, &ci) < 0) {
        perror("tun: ioctl(CTLIOCGINFO)");
        close(fd);
        return -1;
    }

    struct sockaddr_ctl sc;
    memset(&sc, 0, sizeof(sc));
    sc.sc_id = ci.ctl_id;
    sc.sc_len = sizeof(sc);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;

    /* Try utun0..utun15 */
    int unit = -1;
    for (int i = 0; i < 16; i++) {
        sc.sc_unit = i + 1; /* 1-based */
        if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) == 0) {
            unit = i;
            break;
        }
    }

    if (unit < 0) {
        fprintf(stderr, "tun: cannot allocate utun device\n");
        close(fd);
        return -1;
    }

    snprintf(dev_name, dev_name_len, "utun%d", unit);
    log_msg(1, "tun: opened %s", dev_name);

    /* Configure IP address via ifconfig */

    /* Calculate peer address for point-to-point link */
    struct in_addr addr, peer;
    inet_pton(AF_INET, ip, &addr);
    /* Peer = .1 (gateway) if we're not .1, otherwise .2 */
    peer.s_addr = addr.s_addr;
    unsigned char *p = (unsigned char *)&peer.s_addr;
    p[3] = (p[3] == 1) ? 2 : 1;
    char peer_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &peer, peer_ip, sizeof(peer_ip));

    char netmask[INET_ADDRSTRLEN];
    prefix_to_netmask(prefix_len, netmask, sizeof(netmask));
    if (RUN(0, "ifconfig", dev_name, "inet", (char *)ip, peer_ip,
            "netmask", netmask, "up") != 0) {
        fprintf(stderr, "tun: failed to configure %s\n", dev_name);
        close(fd);
        return -1;
    }

    /* Set MTU */
    char mtu[16];
    snprintf(mtu, sizeof(mtu), "%d", TUN_MTU);
    (void)RUN(0, "ifconfig", dev_name, "mtu", mtu);

    log_msg(1, "tun: %s configured %s/%d (peer %s)", dev_name, ip, prefix_len, peer_ip);
    return fd;
}

void tun_close(int tun_fd, const char *dev_name) {
    if (dev_name) {
        (void)RUN(1, "ifconfig", (char *)dev_name, "down");
    }
    if (tun_fd >= 0) close(tun_fd);
}

/* macOS utun prepends a 4-byte protocol header (AF_INET = 2) */
#define UTUN_HDR_SIZE 4

static int tun_read_packet(int tun_fd, char *buf, int buf_size) {
    char tmp[TUN_MTU + UTUN_HDR_SIZE];
    int n = (int)read(tun_fd, tmp, sizeof(tmp));
    if (n <= UTUN_HDR_SIZE) return -1;
    int pkt_len = n - UTUN_HDR_SIZE;
    if (pkt_len > buf_size) return -1;
    memcpy(buf, tmp + UTUN_HDR_SIZE, pkt_len);
    return pkt_len;
}

static int tun_write_packet(int tun_fd, const char *buf, int len) {
    char tmp[TUN_MTU + UTUN_HDR_SIZE];
    if (len + UTUN_HDR_SIZE > (int)sizeof(tmp)) return -1;
    /* AF_INET in network byte order */
    uint32_t proto = htonl(AF_INET);
    memcpy(tmp, &proto, UTUN_HDR_SIZE);
    memcpy(tmp + UTUN_HDR_SIZE, buf, len);
    int n = (int)write(tun_fd, tmp, len + UTUN_HDR_SIZE);
    return (n == len + UTUN_HDR_SIZE) ? len : -1;
}

#endif /* __APPLE__ */

/* ─────────────────────────────────────────────
 * Linux: /dev/net/tun
 * ───────────────────────────────────────────── */
#ifdef __linux__

int tun_open(const char *ip, int prefix_len, char *dev_name, size_t dev_name_len) {
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        perror("tun: open(/dev/net/tun)");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    /* Let kernel assign name */
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        perror("tun: ioctl(TUNSETIFF)");
        close(fd);
        return -1;
    }

    snprintf(dev_name, dev_name_len, "%s", ifr.ifr_name);
    log_msg(1, "tun: opened %s", dev_name);

    /* Configure IP */
    char addr_cidr[32], mtu[16];
    snprintf(addr_cidr, sizeof(addr_cidr), "%s/%d", ip, prefix_len);
    snprintf(mtu, sizeof(mtu), "%d", TUN_MTU);
    if (RUN(0, "ip", "addr", "add", addr_cidr, "dev", dev_name) != 0) {
        fprintf(stderr, "tun: failed to assign IP to %s\n", dev_name);
        close(fd);
        return -1;
    }

    if (RUN(0, "ip", "link", "set", "dev", dev_name, "mtu", mtu, "up") != 0) {
        fprintf(stderr, "tun: failed to bring up %s\n", dev_name);
        close(fd);
        return -1;
    }

    log_msg(1, "tun: %s configured %s/%d", dev_name, ip, prefix_len);
    return fd;
}

void tun_close(int tun_fd, const char *dev_name) {
    if (dev_name) {
        (void)RUN(1, "ip", "link", "set", (char *)dev_name, "down");
    }
    if (tun_fd >= 0) close(tun_fd);
}

/* Linux TUN with IFF_NO_PI: raw IP packets, no header */
static int tun_read_packet(int tun_fd, char *buf, int buf_size) {
    int n = (int)read(tun_fd, buf, buf_size);
    return (n > 0) ? n : -1;
}

static int tun_write_packet(int tun_fd, const char *buf, int len) {
    int n = (int)write(tun_fd, buf, len);
    return (n == len) ? len : -1;
}

#endif /* __linux__ */

/* ─────────────────────────────────────────────
 * NAT / IP forwarding
 * ───────────────────────────────────────────── */
/* NAT state, so tun_disable_nat() can undo exactly what was done */
enum { NAT_NONE = 0, NAT_IPTABLES, NAT_NFT, NAT_PF };
static int  s_nat_backend = NAT_NONE;
static char s_nat_dev[IFNAMSIZ];
static char s_nat_subnet[32];
static char s_prev_forwarding = 0;       /* '0'/'1' before we enabled it, 0 = unknown */

#ifdef __APPLE__
/* Interface of the current default route, e.g. "en0" */
static int default_iface(char *out, size_t out_len) {
    out[0] = '\0';
    FILE *fp = popen("route -n get default 2>/dev/null | awk '/interface:/{print $2}'", "r");
    if (!fp) return -1;
    if (fgets(out, (int)out_len, fp)) out[strcspn(out, "\n")] = '\0';
    pclose(fp);
    return tun_valid_ifname(out) ? 0 : -1;
}
#endif

int tun_enable_nat(const char *dev_name, const char *subnet) {
    if (!tun_valid_ifname(dev_name) || !subnet || strlen(subnet) >= sizeof(s_nat_subnet)) {
        fprintf(stderr, "tun: refusing NAT setup with invalid interface/subnet\n");
        return -1;
    }
    {   /* subnet must be a.b.c.d/N built from a validated address */
        char ip[INET_ADDRSTRLEN]; int pfx;
        if (tun_parse_cidr(subnet, ip, sizeof(ip), &pfx) != 0) {
            fprintf(stderr, "tun: refusing NAT setup with invalid subnet\n");
            return -1;
        }
    }
    snprintf(s_nat_dev, sizeof(s_nat_dev), "%s", dev_name);
    snprintf(s_nat_subnet, sizeof(s_nat_subnet), "%s", subnet);

#ifdef __linux__
    /* Enable IP forwarding, remembering the previous setting */
    FILE *f = fopen("/proc/sys/net/ipv4/ip_forward", "r");
    if (f) {
        int c = fgetc(f);
        if (c == '0' || c == '1') s_prev_forwarding = (char)c;
        fclose(f);
    }
    (void)RUN(1, "sysctl", "-w", "net.ipv4.ip_forward=1");

    if (RUN(1, "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", s_nat_subnet,
            "!", "-o", s_nat_dev, "-j", "MASQUERADE") == 0) {
        s_nat_backend = NAT_IPTABLES;
    } else {
        /* nftables: a dedicated table, removed as a whole on teardown */
        char oif[IFNAMSIZ + 2];
        snprintf(oif, sizeof(oif), "\"%s\"", s_nat_dev);
        if (RUN(1, "nft", "add", "table", "ip", "clawsec") == 0 &&
            RUN(1, "nft", "add", "chain", "ip", "clawsec", "postrouting", "{",
                "type", "nat", "hook", "postrouting", "priority", "100", ";", "}") == 0 &&
            RUN(1, "nft", "add", "rule", "ip", "clawsec", "postrouting", "ip", "saddr",
                s_nat_subnet, "oifname", "!=", oif, "masquerade") == 0) {
            s_nat_backend = NAT_NFT;
        } else {
            fprintf(stderr, "tun: failed to set up NAT (need iptables or nftables)\n");
            return -1;
        }
    }
    log_msg(1, "tun: NAT enabled for %s via %s", subnet, dev_name);
    return 0;
#elif defined(__APPLE__)
    /* NOTE: not exercised by CI (no TUN on macOS runners). */
    char out_if[IFNAMSIZ];
    if (default_iface(out_if, sizeof(out_if)) != 0) {
        fprintf(stderr, "tun: cannot determine default interface for NAT\n");
        return -1;
    }
    FILE *f = popen("sysctl -n net.inet.ip.forwarding 2>/dev/null", "r");
    if (f) {
        int c = fgetc(f);
        if (c == '0' || c == '1') s_prev_forwarding = (char)c;
        pclose(f);
    }
    (void)RUN(1, "sysctl", "-w", "net.inet.ip.forwarding=1");

    /* Load the rule into the com.apple/clawsec anchor (referenced by the
     * default "nat-anchor com.apple/<any>" rule), never replacing the main ruleset. */
    char pf_conf[] = "/tmp/clawsec_nat.XXXXXX";
    int fd = mkstemp(pf_conf);
    if (fd < 0) { perror("tun: mkstemp"); return -1; }
    FILE *pf = fdopen(fd, "w");
    if (!pf) { close(fd); unlink(pf_conf); return -1; }
    fprintf(pf, "nat on %s from %s to any -> (%s)\n", out_if, subnet, out_if);
    fclose(pf);
    int rc = RUN(1, "pfctl", "-a", "com.apple/clawsec", "-f", pf_conf);
    if (rc == 0)
        (void)RUN(1, "pfctl", "-e");      /* fails harmlessly if already enabled */
    unlink(pf_conf);
    if (rc != 0) {
        fprintf(stderr, "tun: failed to load pf NAT rule\n");
        return -1;
    }
    s_nat_backend = NAT_PF;
    log_msg(1, "tun: NAT enabled for %s via %s", subnet, out_if);
    return 0;
#else
    fprintf(stderr, "tun: NAT not supported on this platform\n");
    return -1;
#endif
}

void tun_disable_nat(void) {
    switch (s_nat_backend) {
    case NAT_IPTABLES:
        (void)RUN(1, "iptables", "-t", "nat", "-D", "POSTROUTING", "-s", s_nat_subnet,
                  "!", "-o", s_nat_dev, "-j", "MASQUERADE");
        break;
    case NAT_NFT:
        (void)RUN(1, "nft", "delete", "table", "ip", "clawsec");
        break;
    case NAT_PF:
        (void)RUN(1, "pfctl", "-a", "com.apple/clawsec", "-F", "all");
        break;
    default:
        return;
    }
    if (s_prev_forwarding == '0') {
#ifdef __linux__
        (void)RUN(1, "sysctl", "-w", "net.ipv4.ip_forward=0");
#elif defined(__APPLE__)
        (void)RUN(1, "sysctl", "-w", "net.inet.ip.forwarding=0");
#endif
    }
    s_nat_backend = NAT_NONE;
    log_msg(1, "tun: NAT removed");
}

/* ─────────────────────────────────────────────
 * Default route: redirect ALL traffic through VPN
 *
 * 1. Save original default gateway
 * 2. Add host route to VPN server via original gateway
 *    (so the tunnel itself doesn't loop)
 * 3. Replace default route → VPN gateway via TUN
 * 4. On restore: undo everything
 * ───────────────────────────────────────────── */

/* Saved state for route restoration */
static char s_orig_gateway[64] = {0};
static char s_orig_iface[32] = {0};
static char s_server_ip[256] = {0};
static char s_tun_dev[32] = {0};
static int  s_routes_modified = 0;

/* Forward declaration */
int tun_restore_default_route(void);

/* Set by SIGINT/SIGTERM/SIGHUP. The handler only records the request
 * (fork/exec and stdio are not async-signal-safe); the relay loops see it,
 * return, and the caller restores routes/NAT on the normal path. */
static volatile sig_atomic_t s_stop_requested = 0;

static void tun_signal_handler(int sig) {
    (void)sig;
    s_stop_requested = 1;
}

int tun_stop_requested(void) {
    return s_stop_requested != 0;
}

static void tun_atexit_cleanup(void) {
    tun_restore_default_route();
    tun_disable_nat();
}

/* Install signal handlers (no SA_RESTART, so a blocking poll() returns
 * EINTR) and an atexit hook for paths that call exit() directly. */
void tun_install_cleanup_handlers(void) {
    static int installed = 0;
    if (installed) return;
    installed = 1;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = tun_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    atexit(tun_atexit_cleanup);
}

/* Resolve hostname to IP if needed */
static int resolve_to_ip(const char *host, char *ip_out, size_t ip_out_len) {
    struct in_addr addr;
    if (inet_pton(AF_INET, host, &addr) == 1) {
        snprintf(ip_out, ip_out_len, "%s", host);
        return 0;
    }
    /* Resolve hostname */
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    if (getaddrinfo(host, NULL, &hints, &res) != 0) return -1;
    struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &sa->sin_addr, ip_out, ip_out_len);
    freeaddrinfo(res);
    return 0;
}

int tun_set_default_route(const char *server_host, const char *gateway_ip, const char *dev_name) {
    char server_resolved[64];

    if (!valid_ipv4(gateway_ip) || !tun_valid_ifname(dev_name)) {
        fprintf(stderr, "tun: invalid VPN gateway or interface\n");
        return -1;
    }

    /* Resolve server hostname to IP */
    if (resolve_to_ip(server_host, server_resolved, sizeof(server_resolved)) < 0) {
        fprintf(stderr, "tun: cannot resolve server '%s'\n", server_host);
        return -1;
    }

    snprintf(s_server_ip, sizeof(s_server_ip), "%s", server_resolved);
    snprintf(s_tun_dev, sizeof(s_tun_dev), "%s", dev_name);

#ifdef __APPLE__
    /* Get current default gateway */
    FILE *fp = popen("route -n get default 2>/dev/null | awk '/gateway:/{print $2}'", "r");
    if (fp) {
        if (fgets(s_orig_gateway, sizeof(s_orig_gateway), fp)) {
            s_orig_gateway[strcspn(s_orig_gateway, "\n")] = '\0';
        }
        pclose(fp);
    }
    /* Get current default interface */
    fp = popen("route -n get default 2>/dev/null | awk '/interface:/{print $2}'", "r");
    if (fp) {
        if (fgets(s_orig_iface, sizeof(s_orig_iface), fp)) {
            s_orig_iface[strcspn(s_orig_iface, "\n")] = '\0';
        }
        pclose(fp);
    }

    /* Values parsed from `route`/`ip` output go back into commands */
    if (!valid_ipv4(s_orig_gateway) ||
        (s_orig_iface[0] && !tun_valid_ifname(s_orig_iface))) {
        fprintf(stderr, "tun: cannot determine current default gateway "
                        "(need a default route via an IPv4 gateway)\n");
        s_orig_gateway[0] = '\0';
        s_orig_iface[0] = '\0';
        return -1;
    }

    log_msg(1, "tun: original gateway %s via %s", s_orig_gateway, s_orig_iface);

    /* 1. Add host route to VPN server via original gateway */
    (void)RUN(0, "route", "add", "-host", s_server_ip, s_orig_gateway);

    /* 2. Delete old default route */
    (void)RUN(1, "route", "delete", "default");

    /* 3. Add new default route via VPN */
    (void)RUN(0, "route", "add", "default", (char *)gateway_ip);

#elif defined(__linux__)
    /* Get current default gateway */
    FILE *fp = popen("ip route show default | awk '{print $3}'", "r");
    if (fp) {
        if (fgets(s_orig_gateway, sizeof(s_orig_gateway), fp)) {
            s_orig_gateway[strcspn(s_orig_gateway, "\n")] = '\0';
        }
        pclose(fp);
    }
    fp = popen("ip route show default | awk '{print $5}'", "r");
    if (fp) {
        if (fgets(s_orig_iface, sizeof(s_orig_iface), fp)) {
            s_orig_iface[strcspn(s_orig_iface, "\n")] = '\0';
        }
        pclose(fp);
    }

    /* Values parsed from `route`/`ip` output go back into commands */
    if (!valid_ipv4(s_orig_gateway) ||
        (s_orig_iface[0] && !tun_valid_ifname(s_orig_iface))) {
        fprintf(stderr, "tun: cannot determine current default gateway "
                        "(need a default route via an IPv4 gateway)\n");
        s_orig_gateway[0] = '\0';
        s_orig_iface[0] = '\0';
        return -1;
    }

    log_msg(1, "tun: original gateway %s via %s", s_orig_gateway, s_orig_iface);

    /* 1. Add host route to VPN server via original gateway */
    if (s_orig_iface[0])
        (void)RUN(0, "ip", "route", "add", s_server_ip, "via", s_orig_gateway,
                  "dev", s_orig_iface);
    else
        (void)RUN(0, "ip", "route", "add", s_server_ip, "via", s_orig_gateway);

    /* 2. Replace default route via VPN */
    (void)RUN(0, "ip", "route", "replace", "default", "via", (char *)gateway_ip,
              "dev", (char *)dev_name);
#endif

    s_routes_modified = 1;
    tun_install_cleanup_handlers();
    log_msg(1, "tun: default route → %s via %s (full tunnel)", gateway_ip, dev_name);
    return 0;
}

int tun_restore_default_route(void) {
    if (!s_routes_modified) return 0;

    log_msg(1, "tun: restoring original default route via %s", s_orig_gateway);

#ifdef __APPLE__
    /* Remove VPN default */
    (void)RUN(1, "route", "delete", "default");
    /* Restore original default */
    (void)RUN(0, "route", "add", "default", s_orig_gateway);
    /* Remove server host route */
    (void)RUN(1, "route", "delete", "-host", s_server_ip);

#elif defined(__linux__)
    /* Restore original default */
    if (s_orig_iface[0])
        (void)RUN(0, "ip", "route", "replace", "default", "via", s_orig_gateway,
                  "dev", s_orig_iface);
    else
        (void)RUN(0, "ip", "route", "replace", "default", "via", s_orig_gateway);
    /* Remove server host route */
    (void)RUN(1, "ip", "route", "delete", s_server_ip);
#endif

    s_routes_modified = 0;
    log_msg(1, "tun: default route restored");
    return 0;
}

/* ─────────────────────────────────────────────
 * Relay: TUN ↔ encrypted tunnel
 *
 * Wire format per packet:
 *   "TVPN" (4 bytes) + uint16_be length (2 bytes) + IP packet
 * ───────────────────────────────────────────── */
int tun_relay(int tun_fd, int tunnel_fd) {
    char pkt_buf[TUN_MTU];
    char wire_buf[TUN_BUF_SIZE];
    char recv_buf[TUN_BUF_SIZE];
    int fds[2] = { tun_fd, tunnel_fd }, rdy[2];

    log_msg(1, "tun: VPN relay started");

    for (;;) {
        /* 30 s timeout for keepalive */
        int rc = wait_readable(fds, rdy, 2, 30000);
        if (tun_stop_requested()) {
            log_msg(1, "tun: stop requested");
            break;
        }
        if (rc < 0) {
            if (errno == EINTR) continue;
            perror("tun: select");
            break;
        }

        if (rc == 0) {
            /* Timeout: send keepalive */
            const char *hb = "THB\n";
            tun_crypt_write(tunnel_fd, hb, 4);
            continue;
        }

        /* TUN device → encrypted tunnel */
        if (rdy[0]) {
            int pkt_len = tun_read_packet(tun_fd, pkt_buf, sizeof(pkt_buf));
            if (pkt_len <= 0) continue; /* spurious or too large */

            /* Build wire frame: TVPN + 2-byte length + packet */
            memcpy(wire_buf, TUN_SIG_VPN, TUN_SIG_LEN);
            wire_buf[TUN_SIG_LEN] = (pkt_len >> 8) & 0xFF;
            wire_buf[TUN_SIG_LEN + 1] = pkt_len & 0xFF;
            memcpy(wire_buf + TUN_HDR_SIZE, pkt_buf, pkt_len);

            if (tun_crypt_write(tunnel_fd, wire_buf, TUN_HDR_SIZE + pkt_len) < 0) {
                log_msg(1, "tun: tunnel write failed");
                break;
            }
        }

        /* Encrypted tunnel → TUN device */
        if (rdy[1]) {
            int n = farm9crypt_read(tunnel_fd, recv_buf, sizeof(recv_buf));
            if (n <= 0) {
                log_msg(1, "tun: tunnel closed");
                break;
            }

            /* Check for heartbeat */
            if (n == 4 && memcmp(recv_buf, "THB\n", 4) == 0) {
                continue; /* keepalive, ignore */
            }

            /* Validate wire frame header */
            if (n < TUN_HDR_SIZE || memcmp(recv_buf, TUN_SIG_VPN, TUN_SIG_LEN) != 0) {
                log_msg(1, "tun: invalid packet (len=%d)", n);
                continue;
            }

            int pkt_len = ((unsigned char)recv_buf[TUN_SIG_LEN] << 8) |
                          (unsigned char)recv_buf[TUN_SIG_LEN + 1];

            if (pkt_len <= 0 || pkt_len > TUN_MTU || pkt_len + TUN_HDR_SIZE > n) {
                log_msg(1, "tun: bad packet length %d", pkt_len);
                continue;
            }

            tun_write_packet(tun_fd, recv_buf + TUN_HDR_SIZE, pkt_len);
        }
    }

    log_msg(1, "tun: VPN relay stopped");
    return 0;
}

/* ═════════════════════════════════════════════
 * UDP VPN data channel
 *
 * After the TCP handshake (ECDHE key exchange), both sides open a
 * separate UDP socket for VPN data.  Each UDP datagram is independently
 * encrypted with AES-256-GCM using the session key exported from
 * farm9crypt.
 *
 * Advantages over TCP relay:
 *   - No TCP-over-TCP meltdown
 *   - Lower latency (no head-of-line blocking)
 *   - Better fit for real-time / VPN traffic
 *
 * Wire format per UDP datagram:
 *   [4B "CVPN"] [12B nonce] [ciphertext] [16B GCM tag]
 *   nonce = seq_be(4B) + random(8B)
 *   AAD   = "CVPN" (4B)
 *
 * Control messages (sent over TCP or UDP):
 *   "THB\n" — keepalive heartbeat
 * ═════════════════════════════════════════════ */

/* ── AES-256-GCM encrypt/decrypt (C, OpenSSL EVP) ─── */

static int udp_vpn_encrypt(const unsigned char *key, uint32_t seq,
                            const unsigned char *pt, int pt_len,
                            unsigned char *out, int *out_len)
{
    /*  out layout: CVPN(4) | nonce(12) | ciphertext(pt_len) | tag(16)  */
    unsigned char nonce[TUN_UDP_NONCE_LEN];
    nonce[0] = (seq >> 24) & 0xFF;
    nonce[1] = (seq >> 16) & 0xFF;
    nonce[2] = (seq >> 8)  & 0xFF;
    nonce[3] =  seq        & 0xFF;
    if (RAND_bytes(nonce + 4, 8) != 1) return -1;

    /* Header: magic */
    memcpy(out, TUN_UDP_MAGIC, TUN_UDP_MAGIC_LEN);

    /* Header: nonce */
    memcpy(out + TUN_UDP_MAGIC_LEN, nonce, TUN_UDP_NONCE_LEN);

    int hdr_len = TUN_UDP_MAGIC_LEN + TUN_UDP_NONCE_LEN; /* 16 */

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ok = 0;
    int len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, TUN_UDP_NONCE_LEN, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;

    /* AAD = "CVPN" */
    if (EVP_EncryptUpdate(ctx, NULL, &len, (const unsigned char *)TUN_UDP_MAGIC, TUN_UDP_MAGIC_LEN) != 1) goto done;

    /* Encrypt payload */
    if (EVP_EncryptUpdate(ctx, out + hdr_len, &len, pt, pt_len) != 1) goto done;
    int ct_len = len;

    if (EVP_EncryptFinal_ex(ctx, out + hdr_len + ct_len, &len) != 1) goto done;
    ct_len += len;

    /* Append GCM tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TUN_UDP_TAG_LEN,
                             out + hdr_len + ct_len) != 1) goto done;

    *out_len = hdr_len + ct_len + TUN_UDP_TAG_LEN;
    ok = 1;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

static int udp_vpn_decrypt(const unsigned char *key,
                            const unsigned char *in, int in_len,
                            unsigned char *pt, int *pt_len, uint32_t *seq_out)
{
    /*  in layout: CVPN(4) | nonce(12) | ciphertext(N) | tag(16) */
    int hdr_len = TUN_UDP_MAGIC_LEN + TUN_UDP_NONCE_LEN; /* 16 */

    if (in_len < hdr_len + TUN_UDP_TAG_LEN) return -1;
    if (memcmp(in, TUN_UDP_MAGIC, TUN_UDP_MAGIC_LEN) != 0) return -1;

    const unsigned char *nonce = in + TUN_UDP_MAGIC_LEN;
    int ct_len = in_len - hdr_len - TUN_UDP_TAG_LEN;
    if (ct_len <= 0 || ct_len > TUN_MTU) return -1;

    const unsigned char *ct  = in + hdr_len;
    const unsigned char *tag = in + hdr_len + ct_len;

    /* Extract seq from nonce[0..3] */
    *seq_out = ((uint32_t)nonce[0] << 24) | ((uint32_t)nonce[1] << 16) |
               ((uint32_t)nonce[2] << 8)  |  (uint32_t)nonce[3];

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ok = 0;
    int len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, TUN_UDP_NONCE_LEN, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;

    /* AAD = "CVPN" */
    if (EVP_DecryptUpdate(ctx, NULL, &len, (const unsigned char *)TUN_UDP_MAGIC, TUN_UDP_MAGIC_LEN) != 1) goto done;

    /* Decrypt */
    if (EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len) != 1) goto done;
    *pt_len = len;

    /* Set expected tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TUN_UDP_TAG_LEN,
                             (void *)tag) != 1) goto done;

    /* Verify tag — if this fails, packet is tampered/forged */
    if (EVP_DecryptFinal_ex(ctx, pt + *pt_len, &len) != 1) goto done;
    *pt_len += len;
    ok = 1;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

/* ── Public wrappers for testing ──────────────────────── */

int tun_udp_encrypt(const unsigned char *key, uint32_t seq,
                     const unsigned char *pt, int pt_len,
                     unsigned char *out, int *out_len)
{
    return udp_vpn_encrypt(key, seq, pt, pt_len, out, out_len);
}

int tun_udp_decrypt(const unsigned char *key,
                     const unsigned char *in, int in_len,
                     unsigned char *pt, int *pt_len, uint32_t *seq_out)
{
    return udp_vpn_decrypt(key, in, in_len, pt, pt_len, seq_out);
}

/* ── Replay protection: sliding window ───────────────── */

#define REPLAY_WINDOW_SIZE 256

static uint32_t replay_max_seq = 0;
static uint64_t replay_bitmap[REPLAY_WINDOW_SIZE / 64] = {0};

static void replay_reset(void) {
    replay_max_seq = 0;
    memset(replay_bitmap, 0, sizeof(replay_bitmap));
}

static int replay_check_and_update(uint32_t seq) {
    /* seq 0 is reserved for the negotiation probe/ACK and never valid data */
    if (seq == 0) return -1;

    if (seq > replay_max_seq) {
        /* Advance window */
        uint32_t shift = seq - replay_max_seq;
        if (shift >= REPLAY_WINDOW_SIZE) {
            memset(replay_bitmap, 0, sizeof(replay_bitmap));
        } else {
            /* Shift bitmap left by 'shift' bits */
            for (uint32_t s = 0; s < shift; s++) {
                for (int i = (REPLAY_WINDOW_SIZE / 64) - 1; i > 0; i--) {
                    replay_bitmap[i] = (replay_bitmap[i] << 1) | (replay_bitmap[i-1] >> 63);
                }
                replay_bitmap[0] <<= 1;
            }
        }
        replay_max_seq = seq;
        /* Mark current seq as seen (bit 0) */
        replay_bitmap[0] |= 1;
        return 0; /* accept */
    }

    /* seq <= replay_max_seq: check if within window */
    uint32_t diff = replay_max_seq - seq;
    if (diff >= REPLAY_WINDOW_SIZE) return -1; /* too old */

    uint32_t idx = diff / 64;
    uint32_t bit = diff % 64;
    if (replay_bitmap[idx] & (1ULL << bit)) return -1; /* already seen */

    /* Mark as seen */
    replay_bitmap[idx] |= (1ULL << bit);
    return 0;
}

void tun_udp_replay_reset(void) {
    replay_reset();
}

int tun_udp_replay_check(uint32_t seq) {
    return replay_check_and_update(seq);
}

/* ── UDP socket setup ────────────────────────────────── */

static int udp_bind(const char *port) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(NULL, port, &hints, &res) != 0) return -1;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    if (bind(fd, res->ai_addr, res->ai_addrlen) < 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int udp_connect(const char *host, const char *port) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }

    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* ── Negotiate UDP channel over TCP ──────────────────── */

/*
 * Protocol (over the existing encrypted TCP channel):
 *   1. Server binds UDP on the same port (before step 2, so no probe races it)
 *   2. Both sides exchange: "TUDP" + 16-byte random token
 *   3. Client sends the server's token as UDP probe (seq 0, client tx key),
 *      retransmitting every TUDP_PROBE_INTERVAL_MS until ACKed
 *   4. Server validates the probe (ignoring unrelated datagrams) and
 *      connects to the client address
 *   5. Server returns the client's token (seq 0, server tx key) as ACK,
 *      TUDP_ACK_COPIES times; extra copies are dropped by the replay window
 *   Everything must complete within TUDP_NEGOTIATE_TIMEOUT_MS.
 */

#define TUDP_SIG  "TUDP"
#define TUDP_SIG_LEN 4
#define TUDP_TOKEN_LEN 16
#define TUDP_NEGOTIATE_TIMEOUT_MS 10000  /* overall UDP setup deadline */
#define TUDP_PROBE_INTERVAL_MS    250    /* client probe retransmit interval */
#define TUDP_ACK_COPIES           3      /* redundant server ACKs */

static int64_t monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int tun_udp_negotiate_keys(int tcp_fd, const char *host, const char *port,
                                  int is_server,
                                  const unsigned char *tx_key,
                                  const unsigned char *rx_key,
                                  unsigned char *my_token,
                                  unsigned char *peer_token,
                                  char *msg);

int tun_udp_negotiate(int tcp_fd, const char *host, const char *port,
                       int is_server)
{
    unsigned char my_token[TUDP_TOKEN_LEN];
    unsigned char peer_token[TUDP_TOKEN_LEN];
    unsigned char tx_key[32], rx_key[32];
    char msg[TUDP_SIG_LEN + TUDP_TOKEN_LEN];
    int result;

    /* Directional UDP keys: tx for what we send, rx for what we receive */
    if (farm9crypt_export_udp_keys(tx_key, rx_key) < 0) {
        fprintf(stderr, "tun-udp: cannot export session keys\n");
        return -1;
    }

    result = tun_udp_negotiate_keys(tcp_fd, host, port, is_server,
                                    tx_key, rx_key, my_token, peer_token, msg);
    OPENSSL_cleanse(tx_key, sizeof(tx_key));
    OPENSSL_cleanse(rx_key, sizeof(rx_key));
    OPENSSL_cleanse(my_token, sizeof(my_token));
    OPENSSL_cleanse(peer_token, sizeof(peer_token));
    return result;
}

static int tun_udp_negotiate_keys(int tcp_fd, const char *host, const char *port,
                                  int is_server,
                                  const unsigned char *tx_key,
                                  const unsigned char *rx_key,
                                  unsigned char *my_token,
                                  unsigned char *peer_token,
                                  char *msg)
{
    int udp_fd = -1;

    /* Server: bind the UDP socket *before* announcing its token, so the
     * client's first probe can never race ahead of the bind. */
    if (is_server) {
        udp_fd = udp_bind(port);
        if (udp_fd < 0) {
            fprintf(stderr, "tun-udp: failed to bind UDP on port %s\n", port);
            return -1;
        }
    }

    /* Generate our random token */
    if (RAND_bytes(my_token, TUDP_TOKEN_LEN) != 1) {
        fprintf(stderr, "tun-udp: RAND_bytes failed\n");
        goto fail;
    }

    /* Send "TUDP" + token over TCP */
    memcpy(msg, TUDP_SIG, TUDP_SIG_LEN);
    memcpy(msg + TUDP_SIG_LEN, my_token, TUDP_TOKEN_LEN);
    if (tun_crypt_write(tcp_fd, msg, TUDP_SIG_LEN + TUDP_TOKEN_LEN) < 0) {
        fprintf(stderr, "tun-udp: failed to send TUDP\n");
        goto fail;
    }

    /* Receive peer's "TUDP" + token */
    char recv_msg[64];
    int n = farm9crypt_read(tcp_fd, recv_msg, sizeof(recv_msg));
    if (n != TUDP_SIG_LEN + TUDP_TOKEN_LEN ||
        memcmp(recv_msg, TUDP_SIG, TUDP_SIG_LEN) != 0) {
        fprintf(stderr, "tun-udp: invalid TUDP response\n");
        goto fail;
    }
    memcpy(peer_token, recv_msg + TUDP_SIG_LEN, TUDP_TOKEN_LEN);

    log_msg(1, "tun-udp: tokens exchanged, setting up UDP channel");

    const int64_t deadline = monotonic_ms() + TUDP_NEGOTIATE_TIMEOUT_MS;
    unsigned char dgram[TUN_UDP_OVERHEAD + TUDP_TOKEN_LEN + 32];
    unsigned char dec_token[TUDP_TOKEN_LEN + 16];

    if (is_server) {
        /* Wait for a valid client probe (our token, seq 0, client->server key).
         * Unrelated or forged datagrams are ignored until the deadline. */
        struct sockaddr_storage client_addr;
        socklen_t addr_len = 0;
        int got_probe = 0;
        while (!got_probe) {
            int64_t left = deadline - monotonic_ms();
            if (left <= 0) break;
            struct pollfd pfd = { .fd = udp_fd, .events = POLLIN, .revents = 0 };
            int pr = poll(&pfd, 1, (int)left);
            if (pr < 0 && errno == EINTR) continue;
            if (pr <= 0) break;

            addr_len = sizeof(client_addr);
            ssize_t nr = recvfrom(udp_fd, dgram, sizeof(dgram), 0,
                                  (struct sockaddr *)&client_addr, &addr_len);
            if (nr <= 0) continue;

            int dec_len = 0;
            uint32_t seq = 0;
            if (udp_vpn_decrypt(rx_key, dgram, (int)nr, dec_token, &dec_len, &seq) == 0 &&
                seq == 0 && dec_len == TUDP_TOKEN_LEN &&
                CRYPTO_memcmp(dec_token, my_token, TUDP_TOKEN_LEN) == 0)
                got_probe = 1;
        }
        if (!got_probe) {
            fprintf(stderr, "tun-udp: no valid UDP probe from client\n");
            goto fail;
        }

        /* Connect to client addr so we can use send/recv */
        if (connect(udp_fd, (struct sockaddr *)&client_addr, addr_len) < 0) {
            perror("tun-udp: connect");
            goto fail;
        }

        /* ACK = encrypted client token. Sent a few times so a single lost
         * datagram does not break the channel; duplicates are harmless since
         * seq 0 is rejected by the data-channel replay window. */
        int ack_len = 0;
        if (udp_vpn_encrypt(tx_key, 0, peer_token, TUDP_TOKEN_LEN, dgram, &ack_len) < 0)
            goto fail;
        for (int i = 0; i < TUDP_ACK_COPIES; i++)
            (void)send(udp_fd, dgram, (size_t)ack_len, 0);

        log_msg(1, "tun-udp: server UDP channel ready on port %s", port);
        return udp_fd;
    }

    /* Client: connect UDP to server */
    udp_fd = udp_connect(host, port);
    if (udp_fd < 0) {
        fprintf(stderr, "tun-udp: failed to connect UDP to %s:%s\n", host, port);
        return -1;
    }

    /* Probe = encrypted server token; retransmitted until a valid ACK arrives */
    unsigned char probe[TUN_UDP_OVERHEAD + TUDP_TOKEN_LEN + 32];
    int probe_len = 0;
    if (udp_vpn_encrypt(tx_key, 0, peer_token, TUDP_TOKEN_LEN, probe, &probe_len) < 0)
        goto fail;

    int64_t next_send = 0;
    for (;;) {
        int64_t now = monotonic_ms();
        if (now >= deadline) {
            fprintf(stderr, "tun-udp: no ACK from server\n");
            goto fail;
        }
        if (now >= next_send) {
            /* ECONNREFUSED (ICMP unreachable) is transient here: just retry */
            (void)send(udp_fd, probe, (size_t)probe_len, 0);
            next_send = now + TUDP_PROBE_INTERVAL_MS;
        }
        int64_t wait = next_send - now;
        if (deadline - now < wait) wait = deadline - now;
        struct pollfd pfd = { .fd = udp_fd, .events = POLLIN, .revents = 0 };
        int pr = poll(&pfd, 1, (int)wait);
        if (pr < 0 && errno == EINTR) continue;
        if (pr <= 0) continue;

        ssize_t nr = recv(udp_fd, dgram, sizeof(dgram), 0);
        if (nr <= 0) continue;   /* e.g. ECONNREFUSED before server is ready */

        int dec_len = 0;
        uint32_t seq = 0;
        if (udp_vpn_decrypt(rx_key, dgram, (int)nr, dec_token, &dec_len, &seq) == 0 &&
            seq == 0 && dec_len == TUDP_TOKEN_LEN &&
            CRYPTO_memcmp(dec_token, my_token, TUDP_TOKEN_LEN) == 0)
            break;
    }

    log_msg(1, "tun-udp: client UDP channel ready to %s:%s", host, port);
    return udp_fd;

fail:
    if (udp_fd >= 0) close(udp_fd);
    return -1;
}

/* ── UDP VPN relay loop ──────────────────────────────── */

int tun_udp_relay(int tun_fd, int udp_fd, int tcp_fd,
                   const unsigned char *tx_key, const unsigned char *rx_key)
{
    unsigned char pkt_buf[TUN_MTU];
    unsigned char enc_buf[TUN_UDP_OVERHEAD + TUN_MTU + 32];
    unsigned char recv_buf[TUN_UDP_OVERHEAD + TUN_MTU + 32];
    int rdy[3];

    /* seq 0 belongs to the negotiation probe/ACK; data starts at 1.
     * 64-bit counter so exhaustion of the 32-bit wire space is detectable. */
    uint64_t send_seq = 1;
    replay_reset();

    log_msg(1, "tun-udp: VPN relay started (UDP data channel)");

    for (;;) {
        int fds[3] = { tun_fd, udp_fd, tcp_fd };   /* tcp_fd -1 = ignored */
        int rc = wait_readable(fds, rdy, 3, 30000);
        if (tun_stop_requested()) {
            log_msg(1, "tun-udp: stop requested");
            break;
        }
        if (rc < 0) {
            if (errno == EINTR) continue;
            perror("tun-udp: select");
            break;
        }

        if (rc == 0) {
            /* Timeout: send keepalive via UDP */
            unsigned char hb_enc[TUN_UDP_OVERHEAD + 16];
            int hb_len = 0;
            const unsigned char hb[] = "THB\n";
            if (send_seq > UINT32_MAX) {
                log_msg(1, "tun-udp: sequence space exhausted, reconnect required");
                break;
            }
            if (udp_vpn_encrypt(tx_key, (uint32_t)send_seq++, hb, 4, hb_enc, &hb_len) == 0) {
                send(udp_fd, hb_enc, hb_len, 0);
            }
            continue;
        }

        /* TUN → encrypt → UDP */
        if (rdy[0]) {
            int pkt_len = tun_read_packet(tun_fd, (char *)pkt_buf, sizeof(pkt_buf));
            if (pkt_len <= 0) continue;

            int enc_len = 0;
            if (send_seq > UINT32_MAX) {
                log_msg(1, "tun-udp: sequence space exhausted, reconnect required");
                break;
            }
            if (udp_vpn_encrypt(tx_key, (uint32_t)send_seq++, pkt_buf, pkt_len,
                                 enc_buf, &enc_len) < 0) {
                log_msg(1, "tun-udp: encrypt failed");
                continue;
            }

            if (send(udp_fd, enc_buf, enc_len, 0) < 0) {
                if (errno == EINTR) continue;
                log_msg(1, "tun-udp: UDP send failed");
                break;
            }
        }

        /* UDP → decrypt → TUN */
        if (rdy[1]) {
            ssize_t nr = recv(udp_fd, recv_buf, sizeof(recv_buf), 0);
            if (nr <= 0) {
                if (errno == EINTR) continue;
                log_msg(1, "tun-udp: UDP recv failed");
                break;
            }

            unsigned char dec_buf[TUN_MTU];
            int dec_len = 0;
            uint32_t seq = 0;

            if (udp_vpn_decrypt(rx_key, recv_buf, (int)nr, dec_buf, &dec_len, &seq) < 0) {
                /* Tampered or corrupted — silently drop */
                continue;
            }

            /* Replay check */
            if (replay_check_and_update(seq) < 0) {
                continue; /* duplicate or too old */
            }

            /* Heartbeat? */
            if (dec_len == 4 && memcmp(dec_buf, "THB\n", 4) == 0) {
                continue;
            }

            tun_write_packet(tun_fd, (const char *)dec_buf, dec_len);
        }

        /* TCP control channel (if still open) */
        if (tcp_fd >= 0 && rdy[2]) {
            char ctrl[64];
            int cn = farm9crypt_read(tcp_fd, ctrl, sizeof(ctrl));
            if (cn <= 0) {
                log_msg(1, "tun-udp: TCP control channel closed");
                tcp_fd = -1; /* stop monitoring, keep UDP going */
            }
            /* Any TCP control messages can be handled here */
        }
    }

    log_msg(1, "tun-udp: VPN relay stopped");
    return 0;
}
