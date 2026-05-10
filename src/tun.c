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
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>

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
    if (!cidr || !ip || !prefix_len) return -1;

    const char *slash = strchr(cidr, '/');
    if (!slash) {
        /* No prefix, default to /24 */
        if (strlen(cidr) >= ip_len) return -1;
        strncpy(ip, cidr, ip_len);
        ip[ip_len - 1] = '\0';
        *prefix_len = 24;
        return 0;
    }

    size_t host_len = slash - cidr;
    if (host_len == 0 || host_len >= ip_len) return -1;

    memcpy(ip, cidr, host_len);
    ip[host_len] = '\0';

    *prefix_len = atoi(slash + 1);
    if (*prefix_len < 8 || *prefix_len > 30) return -1;

    return 0;
}

int tun_validate_config(const char *ip, int prefix_len) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) return -1;
    if (prefix_len < 8 || prefix_len > 30) return -1;
    return 0;
}

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
    char cmd[512];

    /* Calculate peer address for point-to-point link */
    struct in_addr addr, peer;
    inet_pton(AF_INET, ip, &addr);
    /* Peer = .1 (gateway) if we're not .1, otherwise .2 */
    peer.s_addr = addr.s_addr;
    unsigned char *p = (unsigned char *)&peer.s_addr;
    p[3] = (p[3] == 1) ? 2 : 1;
    char peer_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &peer, peer_ip, sizeof(peer_ip));

    snprintf(cmd, sizeof(cmd), "ifconfig %s inet %s %s netmask 255.255.255.0 up",
             dev_name, ip, peer_ip);
    if (system(cmd) != 0) {
        fprintf(stderr, "tun: failed to configure %s\n", dev_name);
        close(fd);
        return -1;
    }

    /* Set MTU */
    snprintf(cmd, sizeof(cmd), "ifconfig %s mtu %d", dev_name, TUN_MTU);
    system(cmd);

    log_msg(1, "tun: %s configured %s/%d (peer %s)", dev_name, ip, prefix_len, peer_ip);
    return fd;
}

void tun_close(int tun_fd, const char *dev_name) {
    if (dev_name) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "ifconfig %s down 2>/dev/null", dev_name);
        system(cmd);
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
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ip addr add %s/%d dev %s", ip, prefix_len, dev_name);
    if (system(cmd) != 0) {
        fprintf(stderr, "tun: failed to assign IP to %s\n", dev_name);
        close(fd);
        return -1;
    }

    snprintf(cmd, sizeof(cmd), "ip link set dev %s mtu %d up", dev_name, TUN_MTU);
    if (system(cmd) != 0) {
        fprintf(stderr, "tun: failed to bring up %s\n", dev_name);
        close(fd);
        return -1;
    }

    log_msg(1, "tun: %s configured %s/%d", dev_name, ip, prefix_len);
    return fd;
}

void tun_close(int tun_fd, const char *dev_name) {
    if (dev_name) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "ip link set %s down 2>/dev/null", dev_name);
        system(cmd);
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
int tun_enable_nat(const char *dev_name, const char *subnet) {
#ifdef __linux__
    /* Enable IP forwarding */
    system("sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1");

    /* Add iptables masquerade rule */
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "iptables -t nat -A POSTROUTING -s %s ! -o %s -j MASQUERADE 2>/dev/null",
             subnet, dev_name);
    int rc = system(cmd);
    if (rc != 0) {
        /* Try nftables as fallback */
        snprintf(cmd, sizeof(cmd),
                 "nft add rule ip nat POSTROUTING oifname != \"%s\" ip saddr %s masquerade 2>/dev/null",
                 dev_name, subnet);
        rc = system(cmd);
    }
    log_msg(1, "tun: NAT enabled for %s via %s", subnet, dev_name);
    return 0;
#elif defined(__APPLE__)
    /* macOS: enable forwarding + pf NAT */
    system("sysctl -w net.inet.ip.forwarding=1 >/dev/null 2>&1");

    /* Create a temporary pf anchor */
    char pf_conf[256];
    snprintf(pf_conf, sizeof(pf_conf), "/tmp/clawsec_nat.conf");
    FILE *f = fopen(pf_conf, "w");
    if (f) {
        fprintf(f, "nat on en0 from %s to any -> (en0)\n", subnet);
        fclose(f);
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "pfctl -f %s -e 2>/dev/null", pf_conf);
        system(cmd);
    }
    log_msg(1, "tun: NAT enabled for %s via %s", subnet, dev_name);
    (void)dev_name;
    return 0;
#else
    (void)dev_name; (void)subnet;
    fprintf(stderr, "tun: NAT not supported on this platform\n");
    return -1;
#endif
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

/* Signal handler: restore routes on SIGINT/SIGTERM/SIGPIPE then exit */
static void tun_signal_handler(int sig) {
    tun_restore_default_route();
    /* Re-raise with default handler so exit code is correct */
    signal(sig, SIG_DFL);
    raise(sig);
}

/* Install signal handlers + atexit to guarantee route restoration */
static void tun_install_route_safety(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = tun_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);
    atexit((void(*)(void))tun_restore_default_route);
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
    char cmd[512];
    char server_resolved[64];

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

    if (s_orig_gateway[0] == '\0') {
        fprintf(stderr, "tun: cannot determine current default gateway\n");
        return -1;
    }

    log_msg(1, "tun: original gateway %s via %s", s_orig_gateway, s_orig_iface);

    /* 1. Add host route to VPN server via original gateway */
    snprintf(cmd, sizeof(cmd), "route add -host %s %s", s_server_ip, s_orig_gateway);
    system(cmd);

    /* 2. Delete old default route */
    system("route delete default 2>/dev/null");

    /* 3. Add new default route via VPN */
    snprintf(cmd, sizeof(cmd), "route add default %s", gateway_ip);
    system(cmd);

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

    if (s_orig_gateway[0] == '\0') {
        fprintf(stderr, "tun: cannot determine current default gateway\n");
        return -1;
    }

    log_msg(1, "tun: original gateway %s via %s", s_orig_gateway, s_orig_iface);

    /* 1. Add host route to VPN server via original gateway */
    snprintf(cmd, sizeof(cmd), "ip route add %s via %s dev %s",
             s_server_ip, s_orig_gateway, s_orig_iface);
    system(cmd);

    /* 2. Replace default route via VPN */
    snprintf(cmd, sizeof(cmd), "ip route replace default via %s dev %s",
             gateway_ip, dev_name);
    system(cmd);
#endif

    s_routes_modified = 1;
    tun_install_route_safety();
    log_msg(1, "tun: default route → %s via %s (full tunnel)", gateway_ip, dev_name);
    return 0;
}

int tun_restore_default_route(void) {
    if (!s_routes_modified) return 0;

    char cmd[512];
    log_msg(1, "tun: restoring original default route via %s", s_orig_gateway);

#ifdef __APPLE__
    /* Remove VPN default */
    system("route delete default 2>/dev/null");
    /* Restore original default */
    snprintf(cmd, sizeof(cmd), "route add default %s", s_orig_gateway);
    system(cmd);
    /* Remove server host route */
    snprintf(cmd, sizeof(cmd), "route delete -host %s", s_server_ip);
    system(cmd);

#elif defined(__linux__)
    /* Restore original default */
    snprintf(cmd, sizeof(cmd), "ip route replace default via %s dev %s",
             s_orig_gateway, s_orig_iface);
    system(cmd);
    /* Remove server host route */
    snprintf(cmd, sizeof(cmd), "ip route delete %s", s_server_ip);
    system(cmd);
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
    fd_set rfds;
    int maxfd = (tun_fd > tunnel_fd ? tun_fd : tunnel_fd) + 1;

    log_msg(1, "tun: VPN relay started");

    for (;;) {
        FD_ZERO(&rfds);
        FD_SET(tun_fd, &rfds);
        FD_SET(tunnel_fd, &rfds);

        /* Timeout for keepalive */
        struct timeval tv;
        tv.tv_sec = 30;
        tv.tv_usec = 0;

        int rc = select(maxfd, &rfds, NULL, NULL, &tv);
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
        if (FD_ISSET(tun_fd, &rfds)) {
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
        if (FD_ISSET(tunnel_fd, &rfds)) {
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
    if (seq == 0) return 0; /* seq 0 is always ok (first packet) */

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
 *   1. Both sides exchange: "TUDP" + 16-byte random token
 *   2. Server binds UDP on the same port
 *   3. Client sends token as first UDP datagram (encrypted)
 *   4. Server receives, validates, connects to client addr
 *   5. Server sends token back (encrypted) as ACK
 */

#define TUDP_SIG  "TUDP"
#define TUDP_SIG_LEN 4
#define TUDP_TOKEN_LEN 16

int tun_udp_negotiate(int tcp_fd, const char *host, const char *port,
                       int is_server)
{
    unsigned char my_token[TUDP_TOKEN_LEN];
    unsigned char peer_token[TUDP_TOKEN_LEN];
    unsigned char key[32];
    char msg[TUDP_SIG_LEN + TUDP_TOKEN_LEN];

    /* Get session key for UDP encryption */
    if (farm9crypt_export_key(key, 32) < 0) {
        fprintf(stderr, "tun-udp: cannot export session key\n");
        return -1;
    }

    /* Generate our random token */
    if (RAND_bytes(my_token, TUDP_TOKEN_LEN) != 1) {
        fprintf(stderr, "tun-udp: RAND_bytes failed\n");
        return -1;
    }

    /* Send "TUDP" + token over TCP */
    memcpy(msg, TUDP_SIG, TUDP_SIG_LEN);
    memcpy(msg + TUDP_SIG_LEN, my_token, TUDP_TOKEN_LEN);
    if (tun_crypt_write(tcp_fd, msg, sizeof(msg)) < 0) {
        fprintf(stderr, "tun-udp: failed to send TUDP\n");
        return -1;
    }

    /* Receive peer's "TUDP" + token */
    char recv_msg[64];
    int n = farm9crypt_read(tcp_fd, recv_msg, sizeof(recv_msg));
    if (n < (int)sizeof(msg) || memcmp(recv_msg, TUDP_SIG, TUDP_SIG_LEN) != 0) {
        fprintf(stderr, "tun-udp: invalid TUDP response\n");
        return -1;
    }
    memcpy(peer_token, recv_msg + TUDP_SIG_LEN, TUDP_TOKEN_LEN);

    log_msg(1, "tun-udp: tokens exchanged, setting up UDP channel");

    if (is_server) {
        /* Server: bind UDP on the same port */
        int udp_fd = udp_bind(port);
        if (udp_fd < 0) {
            fprintf(stderr, "tun-udp: failed to bind UDP on port %s\n", port);
            return -1;
        }

        /* Wait for client's probe (encrypted token) */
        unsigned char probe[TUN_UDP_OVERHEAD + TUDP_TOKEN_LEN + 32];
        struct sockaddr_storage client_addr;
        socklen_t addr_len = sizeof(client_addr);

        /* Set a 10-second timeout for the probe */
        struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
        setsockopt(udp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        ssize_t nr = recvfrom(udp_fd, probe, sizeof(probe), 0,
                              (struct sockaddr *)&client_addr, &addr_len);
        if (nr <= 0) {
            fprintf(stderr, "tun-udp: no UDP probe from client\n");
            close(udp_fd);
            return -1;
        }

        /* Decrypt and verify token */
        unsigned char dec_token[TUDP_TOKEN_LEN + 16];
        int dec_len = 0;
        uint32_t seq = 0;
        if (udp_vpn_decrypt(key, probe, (int)nr, dec_token, &dec_len, &seq) < 0 ||
            dec_len != TUDP_TOKEN_LEN ||
            memcmp(dec_token, my_token, TUDP_TOKEN_LEN) != 0) {
            fprintf(stderr, "tun-udp: invalid probe token\n");
            close(udp_fd);
            return -1;
        }

        /* Connect to client addr so we can use send/recv */
        if (connect(udp_fd, (struct sockaddr *)&client_addr, addr_len) < 0) {
            perror("tun-udp: connect");
            close(udp_fd);
            return -1;
        }

        /* Send ACK: encrypt peer's token */
        unsigned char ack[TUN_UDP_OVERHEAD + TUDP_TOKEN_LEN + 32];
        int ack_len = 0;
        if (udp_vpn_encrypt(key, 0, peer_token, TUDP_TOKEN_LEN, ack, &ack_len) < 0) {
            close(udp_fd);
            return -1;
        }
        send(udp_fd, ack, ack_len, 0);

        /* Clear receive timeout */
        tv.tv_sec = 0;
        setsockopt(udp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        log_msg(1, "tun-udp: server UDP channel ready on port %s", port);
        return udp_fd;
    } else {
        /* Client: connect UDP to server */
        int udp_fd = udp_connect(host, port);
        if (udp_fd < 0) {
            fprintf(stderr, "tun-udp: failed to connect UDP to %s:%s\n", host, port);
            return -1;
        }

        /* Send probe: encrypt server's token */
        unsigned char probe[TUN_UDP_OVERHEAD + TUDP_TOKEN_LEN + 32];
        int probe_len = 0;
        if (udp_vpn_encrypt(key, 0, peer_token, TUDP_TOKEN_LEN, probe, &probe_len) < 0) {
            close(udp_fd);
            return -1;
        }
        send(udp_fd, probe, probe_len, 0);

        /* Wait for ACK */
        unsigned char ack[TUN_UDP_OVERHEAD + TUDP_TOKEN_LEN + 32];
        struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
        setsockopt(udp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        ssize_t nr = recv(udp_fd, ack, sizeof(ack), 0);
        if (nr <= 0) {
            fprintf(stderr, "tun-udp: no ACK from server\n");
            close(udp_fd);
            return -1;
        }

        unsigned char dec_token[TUDP_TOKEN_LEN + 16];
        int dec_len = 0;
        uint32_t seq = 0;
        if (udp_vpn_decrypt(key, ack, (int)nr, dec_token, &dec_len, &seq) < 0 ||
            dec_len != TUDP_TOKEN_LEN ||
            memcmp(dec_token, my_token, TUDP_TOKEN_LEN) != 0) {
            fprintf(stderr, "tun-udp: invalid ACK token\n");
            close(udp_fd);
            return -1;
        }

        /* Clear receive timeout */
        tv.tv_sec = 0;
        setsockopt(udp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        log_msg(1, "tun-udp: client UDP channel ready to %s:%s", host, port);
        return udp_fd;
    }
}

/* ── UDP VPN relay loop ──────────────────────────────── */

int tun_udp_relay(int tun_fd, int udp_fd, int tcp_fd,
                   const unsigned char *key)
{
    unsigned char pkt_buf[TUN_MTU];
    unsigned char enc_buf[TUN_UDP_OVERHEAD + TUN_MTU + 32];
    unsigned char recv_buf[TUN_UDP_OVERHEAD + TUN_MTU + 32];
    fd_set rfds;
    int maxfd = tun_fd;
    if (udp_fd > maxfd) maxfd = udp_fd;
    if (tcp_fd > maxfd) maxfd = tcp_fd;
    maxfd++;

    uint32_t send_seq = 1;
    replay_reset();

    log_msg(1, "tun-udp: VPN relay started (UDP data channel)");

    for (;;) {
        FD_ZERO(&rfds);
        FD_SET(tun_fd, &rfds);
        FD_SET(udp_fd, &rfds);
        if (tcp_fd >= 0) FD_SET(tcp_fd, &rfds);

        struct timeval tv;
        tv.tv_sec = 30;
        tv.tv_usec = 0;

        int rc = select(maxfd, &rfds, NULL, NULL, &tv);
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
            if (udp_vpn_encrypt(key, send_seq++, hb, 4, hb_enc, &hb_len) == 0) {
                send(udp_fd, hb_enc, hb_len, 0);
            }
            continue;
        }

        /* TUN → encrypt → UDP */
        if (FD_ISSET(tun_fd, &rfds)) {
            int pkt_len = tun_read_packet(tun_fd, (char *)pkt_buf, sizeof(pkt_buf));
            if (pkt_len <= 0) continue;

            int enc_len = 0;
            if (udp_vpn_encrypt(key, send_seq++, pkt_buf, pkt_len,
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
        if (FD_ISSET(udp_fd, &rfds)) {
            ssize_t nr = recv(udp_fd, recv_buf, sizeof(recv_buf), 0);
            if (nr <= 0) {
                if (errno == EINTR) continue;
                log_msg(1, "tun-udp: UDP recv failed");
                break;
            }

            unsigned char dec_buf[TUN_MTU];
            int dec_len = 0;
            uint32_t seq = 0;

            if (udp_vpn_decrypt(key, recv_buf, (int)nr, dec_buf, &dec_len, &seq) < 0) {
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
        if (tcp_fd >= 0 && FD_ISSET(tcp_fd, &rfds)) {
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
