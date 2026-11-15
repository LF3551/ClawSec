/*
 * tun_dev.c — TUN devices (Linux /dev/net/tun, macOS utun), addresses, system tools
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
#include "vpn.h"
#include "tun_internal.h"
#include "util.h"

/* Hub children exchange raw IP packets with the hub process over a
 * SOCK_SEQPACKET socket instead of a TUN device (one packet per message). */
static int s_raw_fd = -1;
void tun_set_raw_fd(int fd) { s_raw_fd = fd; }


int tun_effective_mtu(void) {
    return farm9crypt_padding() ? FARM9_PAD_UNIT - 2 - TUN_HDR_SIZE : TUN_MTU;
}
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
int tun_run_argv(char *const argv[], int quiet) {
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

int tun_valid_ipv4(const char *s) {
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
    return tun_open_peer(ip, prefix_len, NULL, dev_name, dev_name_len);
}

int tun_open_peer(const char *ip, int prefix_len, const char *gw,
                  char *dev_name, size_t dev_name_len) {
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

    /* Point-to-point peer: the gateway the server announced, or (legacy)
     * .1 if we are not .1, otherwise .2 */
    char peer_ip[INET_ADDRSTRLEN];
    if (gw && tun_valid_ipv4(gw)) {
        snprintf(peer_ip, sizeof(peer_ip), "%s", gw);
    } else {
        struct in_addr addr, peer;
        inet_pton(AF_INET, ip, &addr);
        peer.s_addr = addr.s_addr;
        unsigned char *p = (unsigned char *)&peer.s_addr;
        p[3] = (p[3] == 1) ? 2 : 1;
        inet_ntop(AF_INET, &peer, peer_ip, sizeof(peer_ip));
    }

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
    snprintf(mtu, sizeof(mtu), "%d", tun_effective_mtu());
    (void)RUN(0, "ifconfig", dev_name, "mtu", mtu);

    log_msg(1, "tun: %s configured %s/%d (peer %s)", dev_name, ip, prefix_len, peer_ip);
    return fd;
}

int tun_open_cfg(const vpn_cfg_t *cfg, char *dev_name, size_t dev_name_len) {
    char ip[INET_ADDRSTRLEN], gw[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &cfg->v4, ip, sizeof(ip));
    inet_ntop(AF_INET, &cfg->v4_gw, gw, sizeof(gw));
    int fd = tun_open_peer(ip, cfg->v4_prefix, cfg->v4_gw.s_addr ? gw : NULL,
                           dev_name, dev_name_len);
    if (fd < 0) return -1;
    if (cfg->has_v6 && tun_add_ipv6(dev_name, &cfg->v6, cfg->v6_prefix) != 0) {
        tun_close(fd, dev_name);
        return -1;
    }
    return fd;
}

int tun_add_ipv6(const char *dev_name, const struct in6_addr *addr, int prefix) {
    char a[INET6_ADDRSTRLEN], pfx[8];
    if (!tun_valid_ifname(dev_name) || prefix < 1 || prefix > 128) return -1;
    inet_ntop(AF_INET6, addr, a, sizeof(a));
    snprintf(pfx, sizeof(pfx), "%d", prefix);
    if (RUN(0, "ifconfig", (char *)dev_name, "inet6", a, "prefixlen", pfx, "alias") != 0) {
        fprintf(stderr, "tun: failed to assign IPv6 %s/%d to %s\n", a, prefix, dev_name);
        return -1;
    }
    log_msg(1, "tun: %s IPv6 %s/%d", dev_name, a, prefix);
    return 0;
}

void tun_close(int tun_fd, const char *dev_name) {
    if (dev_name) {
        (void)RUN(1, "ifconfig", (char *)dev_name, "down");
    }
    if (tun_fd >= 0) close(tun_fd);
}

/* macOS utun prepends a 4-byte protocol header (AF_INET = 2) */
#define UTUN_HDR_SIZE 4

int tun_read_packet(int tun_fd, char *buf, int buf_size) {
    if (tun_fd == s_raw_fd) {
        int r = (int)read(tun_fd, buf, buf_size);
        return r > 0 ? r : -1;
    }
    char tmp[TUN_MTU + UTUN_HDR_SIZE];
    int n = (int)read(tun_fd, tmp, sizeof(tmp));
    if (n <= UTUN_HDR_SIZE) return -1;
    int pkt_len = n - UTUN_HDR_SIZE;
    if (pkt_len > buf_size) return -1;
    memcpy(buf, tmp + UTUN_HDR_SIZE, pkt_len);
    return pkt_len;
}

int tun_write_packet(int tun_fd, const char *buf, int len) {
    if (tun_fd == s_raw_fd) {
        int w = (int)send(tun_fd, buf, (size_t)len, 0);
        return w == len ? len : -1;
    }
    char tmp[TUN_MTU + UTUN_HDR_SIZE];
    if (len < 1 || len + UTUN_HDR_SIZE > (int)sizeof(tmp)) return -1;
    /* utun header: address family of the packet, network byte order */
    uint32_t proto = htonl(((unsigned char)buf[0] >> 4) == 6 ? AF_INET6 : AF_INET);
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
    return tun_open_peer(ip, prefix_len, NULL, dev_name, dev_name_len);
}

int tun_open_peer(const char *ip, int prefix_len, const char *gw,
                  char *dev_name, size_t dev_name_len) {
    (void)gw;                       /* Linux: the subnet route covers the gateway */
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
    snprintf(mtu, sizeof(mtu), "%d", tun_effective_mtu());
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

int tun_open_cfg(const vpn_cfg_t *cfg, char *dev_name, size_t dev_name_len) {
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &cfg->v4, ip, sizeof(ip));
    int fd = tun_open_peer(ip, cfg->v4_prefix, NULL, dev_name, dev_name_len);
    if (fd < 0) return -1;
    if (cfg->has_v6 && tun_add_ipv6(dev_name, &cfg->v6, cfg->v6_prefix) != 0) {
        tun_close(fd, dev_name);
        return -1;
    }
    return fd;
}

int tun_add_ipv6(const char *dev_name, const struct in6_addr *addr, int prefix) {
    char a[INET6_ADDRSTRLEN + 8];
    if (!tun_valid_ifname(dev_name) || prefix < 1 || prefix > 128) return -1;
    char txt[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, addr, txt, sizeof(txt));
    snprintf(a, sizeof(a), "%s/%d", txt, prefix);
    /* nodad: the address is ours by assignment; DAD would delay it ~2 s */
    if (RUN(0, "ip", "-6", "addr", "add", a, "dev", (char *)dev_name, "nodad") != 0) {
        fprintf(stderr, "tun: failed to assign IPv6 %s to %s\n", a, dev_name);
        return -1;
    }
    log_msg(1, "tun: %s IPv6 %s", dev_name, a);
    return 0;
}

void tun_close(int tun_fd, const char *dev_name) {
    if (dev_name) {
        (void)RUN(1, "ip", "link", "set", (char *)dev_name, "down");
    }
    if (tun_fd >= 0) close(tun_fd);
}

/* Linux TUN with IFF_NO_PI: raw IP packets, no header */
int tun_read_packet(int tun_fd, char *buf, int buf_size) {
    int n = (int)read(tun_fd, buf, buf_size);
    return (n > 0) ? n : -1;
}

int tun_write_packet(int tun_fd, const char *buf, int len) {
    int n = tun_fd == s_raw_fd ? (int)send(tun_fd, buf, (size_t)len, 0)
                               : (int)write(tun_fd, buf, len);
    return (n == len) ? len : -1;
}

#endif /* __linux__ */

/* ── Device access for the hub ───────────────────────── */

int tun_device_read(int tun_fd, char *buf, int len) { return tun_read_packet(tun_fd, buf, len); }
int tun_device_write(int tun_fd, const char *buf, int len) { return tun_write_packet(tun_fd, buf, len); }

int tun_add_subnet_route(const char *dev_name, const vpn_cfg_t *cfg) {
#ifdef __APPLE__
    /* utun is point-to-point: route the whole client subnet to it.
     * NOTE: not exercised by CI. */
    char net[INET_ADDRSTRLEN + 4];
    struct in_addr n = cfg->v4;
    uint32_t mask = cfg->v4_prefix ? htonl(0xffffffffu << (32 - cfg->v4_prefix)) : 0;
    n.s_addr &= mask;
    char a[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &n, a, sizeof(a));
    snprintf(net, sizeof(net), "%s/%d", a, cfg->v4_prefix);
    if (!tun_valid_ifname(dev_name)) return -1;
    return RUN(0, "route", "-n", "add", "-net", net, "-interface", (char *)dev_name) == 0 ? 0 : -1;
#else
    (void)dev_name; (void)cfg;
    return 0;                       /* Linux: the address prefix already routes it */
#endif
}

