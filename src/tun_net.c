/*
 * tun_net.c — NAT/forwarding (IPv4, IPv6), full-tunnel routes, signal cleanup
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

/* ─────────────────────────────────────────────
 * NAT / IP forwarding
 * ───────────────────────────────────────────── */
/* NAT state, so tun_disable_nat() can undo exactly what was done */
enum { NAT_NONE = 0, NAT_IPTABLES, NAT_NFT, NAT_PF };
static int  s_nat_backend = NAT_NONE;
static char s_nat_dev[IFNAMSIZ];
static char s_nat_subnet[32];
static char s_prev_forwarding = 0;       /* '0'/'1' before we enabled it, 0 = unknown */
enum { NAT6_NONE = 0, NAT6_IP6TABLES, NAT6_NFT, NAT6_PF };
static int  s_nat6_backend = NAT6_NONE;
static char s_nat6_subnet[64];
static char s_prev_forwarding6 = 0;

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

int tun_enable_nat6(const char *dev_name, const char *subnet6) {
    struct in6_addr a;
    int pfx;
    if (!tun_valid_ifname(dev_name) || !subnet6 || strlen(subnet6) >= sizeof(s_nat6_subnet) ||
        vpn_parse_cidr6(subnet6, &a, &pfx) != 0) {
        fprintf(stderr, "tun: refusing IPv6 NAT setup with invalid interface/prefix\n");
        return -1;
    }
    snprintf(s_nat6_subnet, sizeof(s_nat6_subnet), "%s", subnet6);
    snprintf(s_nat_dev, sizeof(s_nat_dev), "%s", dev_name);
#ifdef __linux__
    FILE *f = fopen("/proc/sys/net/ipv6/conf/all/forwarding", "r");
    if (f) {
        int c = fgetc(f);
        if (c == '0' || c == '1') s_prev_forwarding6 = (char)c;
        fclose(f);
    }
    (void)RUN(1, "sysctl", "-w", "net.ipv6.conf.all.forwarding=1");
    if (RUN(1, "ip6tables", "-t", "nat", "-A", "POSTROUTING", "-s", s_nat6_subnet,
            "!", "-o", s_nat_dev, "-j", "MASQUERADE") == 0) {
        s_nat6_backend = NAT6_IP6TABLES;
    } else {
        char oif[IFNAMSIZ + 2];
        snprintf(oif, sizeof(oif), "\"%s\"", s_nat_dev);
        if (RUN(1, "nft", "add", "table", "ip6", "clawsec6") == 0 &&
            RUN(1, "nft", "add", "chain", "ip6", "clawsec6", "postrouting", "{",
                "type", "nat", "hook", "postrouting", "priority", "100", ";", "}") == 0 &&
            RUN(1, "nft", "add", "rule", "ip6", "clawsec6", "postrouting", "ip6", "saddr",
                s_nat6_subnet, "oifname", "!=", oif, "masquerade") == 0) {
            s_nat6_backend = NAT6_NFT;
        } else {
            fprintf(stderr, "tun: failed to set up IPv6 NAT (need ip6tables or nftables)\n");
            return -1;
        }
    }
    log_msg(1, "tun: IPv6 NAT enabled for %s via %s", subnet6, dev_name);
    return 0;
#elif defined(__APPLE__)
    /* NOTE: not exercised by CI. pf anchors are replaced as a whole, so the
     * IPv6 rule goes into its own anchor. */
    char out_if[IFNAMSIZ];
    if (default_iface(out_if, sizeof(out_if)) != 0) return -1;
    FILE *fw = popen("sysctl -n net.inet6.ip6.forwarding 2>/dev/null", "r");
    if (fw) {
        int c = fgetc(fw);
        if (c == '0' || c == '1') s_prev_forwarding6 = (char)c;
        pclose(fw);
    }
    (void)RUN(1, "sysctl", "-w", "net.inet6.ip6.forwarding=1");
    char pf_conf[] = "/tmp/clawsec_nat6.XXXXXX";
    int fd = mkstemp(pf_conf);
    if (fd < 0) return -1;
    FILE *pf = fdopen(fd, "w");
    if (!pf) { close(fd); unlink(pf_conf); return -1; }
    fprintf(pf, "nat on %s inet6 from %s to any -> (%s)\n", out_if, subnet6, out_if);
    fclose(pf);
    int rc = RUN(1, "pfctl", "-a", "com.apple/clawsec6", "-f", pf_conf);
    unlink(pf_conf);
    if (rc != 0) return -1;
    (void)RUN(1, "pfctl", "-e");
    s_nat6_backend = NAT6_PF;
    return 0;
#else
    return -1;
#endif
}

static void tun_disable_nat6(void) {
    switch (s_nat6_backend) {
    case NAT6_IP6TABLES:
        (void)RUN(1, "ip6tables", "-t", "nat", "-D", "POSTROUTING", "-s", s_nat6_subnet,
                  "!", "-o", s_nat_dev, "-j", "MASQUERADE");
        break;
    case NAT6_NFT:
        (void)RUN(1, "nft", "delete", "table", "ip6", "clawsec6");
        break;
    case NAT6_PF:
        (void)RUN(1, "pfctl", "-a", "com.apple/clawsec6", "-F", "all");
        break;
    default:
        return;
    }
    if (s_prev_forwarding6 == '0') {
#ifdef __linux__
        (void)RUN(1, "sysctl", "-w", "net.ipv6.conf.all.forwarding=0");
#elif defined(__APPLE__)
        (void)RUN(1, "sysctl", "-w", "net.inet6.ip6.forwarding=0");
#endif
    }
    s_nat6_backend = NAT6_NONE;
}

void tun_disable_nat(void) {
    tun_disable_nat6();
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
static int  s_routes6_modified = 0;
static char s_tun6_dev[32] = {0};

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

    if (!tun_valid_ipv4(gateway_ip) || !tun_valid_ifname(dev_name)) {
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
    if (!tun_valid_ipv4(s_orig_gateway) ||
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
    if (!tun_valid_ipv4(s_orig_gateway) ||
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

int tun_set_default_route6(const char *dev_name) {
    if (!tun_valid_ifname(dev_name)) return -1;
    snprintf(s_tun6_dev, sizeof(s_tun6_dev), "%s", dev_name);
#ifdef __linux__
    if (RUN(0, "ip", "-6", "route", "replace", "::/1", "dev", (char *)dev_name) != 0 ||
        RUN(0, "ip", "-6", "route", "replace", "8000::/1", "dev", (char *)dev_name) != 0)
        return -1;
#elif defined(__APPLE__)
    if (RUN(0, "route", "-n", "add", "-inet6", "::/1", "-interface", (char *)dev_name) != 0 ||
        RUN(0, "route", "-n", "add", "-inet6", "8000::/1", "-interface", (char *)dev_name) != 0)
        return -1;
#else
    return -1;
#endif
    s_routes6_modified = 1;
    tun_install_cleanup_handlers();
    log_msg(1, "tun: IPv6 default route via %s (::/1, 8000::/1)", dev_name);
    return 0;
}

static void restore_routes6(void) {
    if (!s_routes6_modified) return;
#ifdef __linux__
    (void)RUN(1, "ip", "-6", "route", "del", "::/1", "dev", s_tun6_dev);
    (void)RUN(1, "ip", "-6", "route", "del", "8000::/1", "dev", s_tun6_dev);
#elif defined(__APPLE__)
    (void)RUN(1, "route", "-n", "delete", "-inet6", "::/1");
    (void)RUN(1, "route", "-n", "delete", "-inet6", "8000::/1");
#endif
    s_routes6_modified = 0;
}

int tun_restore_default_route(void) {
    restore_routes6();
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

