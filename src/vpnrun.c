/*
 * vpnrun.c — VPN sessions and the multi-client hub (see vpnrun.h)
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <openssl/crypto.h>

#include "farm9crypt.h"
#include "util.h"
#include "net.h"
#include "tun.h"
#include "vpn.h"
#include "hub.h"
#include "options.h"
#include "children.h"
#include "session.h"
#include "vpnrun.h"
#include "control.h"

/* --tun / --tun6: this side's own configuration (server, or a client that
 * gets no answer from a ClawSec < 4.2 server) */
static int local_vpn_cfg(vpn_cfg_t *cfg, int with_v6) {
    char ip[64];
    int prefix = 24;
    memset(cfg, 0, sizeof(*cfg));
    if (tun_parse_cidr(g_opt.tun_cidr, ip, sizeof(ip), &prefix) != 0 ||
        inet_pton(AF_INET, ip, &cfg->v4) != 1)
        return -1;
    cfg->v4_prefix = prefix;
    cfg->mtu = tun_effective_mtu();
    if (with_v6 && g_opt.tun6_cidr) {
        if (vpn_parse_cidr6(g_opt.tun6_cidr, &cfg->v6, &cfg->v6_prefix) != 0) return -1;
        cfg->has_v6 = 1;
    }
    return 0;
}

static void legacy_gateway(const struct in_addr *self, char *out, size_t len) {
    struct in_addr gw = *self;
    unsigned char *gp = (unsigned char *)&gw.s_addr;
    gp[3] = (gp[3] == 1) ? 2 : 1;
    inet_ntop(AF_INET, &gw, out, len);
}

static void vpn_relay(int tun_fd, int sockfd, int is_server, const char *peer_host,
                      const char *peer_port) {
    if (!g_opt.tun_udp) {
        tun_relay(tun_fd, sockfd);
        return;
    }
    int udp_fd = tun_udp_negotiate(sockfd, peer_host ? peer_host : "0.0.0.0",
                                   peer_port ? peer_port : g_opt.bind_port, is_server);
    if (udp_fd < 0) {
        fprintf(stderr, "Warning: UDP VPN channel unavailable, using the TCP channel\n");
        tun_relay(tun_fd, sockfd);
        return;
    }
    unsigned char vpn_tx[32], vpn_rx[32];
    if (farm9crypt_export_udp_keys(vpn_tx, vpn_rx) == 0) {
        tun_udp_relay(tun_fd, udp_fd, sockfd, vpn_tx, vpn_rx);
    } else {
        fprintf(stderr, "ERROR: Cannot export key for UDP VPN\n");
        tun_relay(tun_fd, sockfd);
    }
    OPENSSL_cleanse(vpn_tx, sizeof(vpn_tx));
    OPENSSL_cleanse(vpn_rx, sizeof(vpn_rx));
    close(udp_fd);
}

/* One VPN session: single-session server, hub session (-K), or client */
int run_vpn_session(int sockfd, int is_server, const char *peer_host,
                           const char *peer_port) {
    char dev_name[32];
    vpn_cfg_t cfg;

    if (is_server && g_opt.hub_fd >= 0)                  /* -K: the hub owns the device */
        return hub_session(sockfd, g_opt.hub_fd) == 0 ? 0 : 1;

    if (is_server) {
        if (local_vpn_cfg(&cfg, 1) != 0) {
            fprintf(stderr, "ERROR: invalid --tun/--tun6 configuration\n");
            return 1;
        }
        tun_install_cleanup_handlers();
        int tun_fd = tun_open_cfg(&cfg, dev_name, sizeof(dev_name));
        if (tun_fd < 0) {
            fprintf(stderr, "ERROR: Failed to open TUN device (need root/sudo)\n");
            return 1;
        }
        vpn_pool_t *pool = vpn_pool_new(cfg.v4, cfg.v4_prefix, cfg.has_v6 ? &cfg.v6 : NULL,
                                        cfg.v6_prefix, cfg.mtu);
        vpn_server_ctx_t ctx = { pool, -1, g_opt.tun_udp, 0 };
        tun_set_control_handler(pool ? vpn_server_control : NULL, &ctx);
        if (g_opt.masquerade) {
            char sub4[64], sub6[80];
            if (pool) {
                vpn_pool_subnets(pool, sub4, sizeof(sub4), sub6, sizeof(sub6));
                tun_enable_nat(dev_name, sub4);
                if (sub6[0]) tun_enable_nat6(dev_name, sub6);
            }
        }
        vpn_relay(tun_fd, sockfd, 1, peer_host, peer_port);
        tun_set_control_handler(NULL, NULL);
        vpn_pool_free(pool);
        tun_disable_nat();
        tun_close(tun_fd, dev_name);
        return 0;
    }

    /* Client: ask the server for an address (ClawSec 4.2+) */
    int auto_addr = strcmp(g_opt.tun_cidr, "auto") == 0;
    vpn_cfg_t mine;
    struct in_addr want = { 0 };
    if (!auto_addr) {
        if (local_vpn_cfg(&mine, 0) != 0) {
            fprintf(stderr, "ERROR: invalid --tun\n");
            return 1;
        }
        want = mine.v4;
    }
    int status = -1;
    int got = tun_request_config(sockfd, want, 3000, &cfg, &status);
    if (got < 0) {
        if (status >= 0)
            fprintf(stderr, "ERROR: the VPN server refused the address: %s\n",
                    vpn_cfg_status_str(status));
        else
            fprintf(stderr, "ERROR: VPN address configuration failed\n");
        return HC_PERMANENT;
    }
    if (got == 0) {
        if (auto_addr) {
            fprintf(stderr, "ERROR: the server does not assign addresses (ClawSec < 4.2); "
                            "use --tun <ip/prefix>\n");
            return HC_PERMANENT;
        }
        log_msg(1, "vpn: server < 4.2, using the local --tun address");
        cfg = mine;                                   /* legacy point-to-point */
    }

    tun_install_cleanup_handlers();
    int tun_fd = tun_open_cfg(&cfg, dev_name, sizeof(dev_name));
    if (tun_fd < 0) {
        fprintf(stderr, "ERROR: Failed to open TUN device (need root/sudo)\n");
        return 1;
    }
    {
        char a4[INET_ADDRSTRLEN], a6[INET6_ADDRSTRLEN] = "";
        inet_ntop(AF_INET, &cfg.v4, a4, sizeof(a4));
        if (cfg.has_v6) inet_ntop(AF_INET6, &cfg.v6, a6, sizeof(a6));
        log_msg(0, "vpn: %s up: %s/%d%s%s%s", dev_name, a4, cfg.v4_prefix,
                cfg.has_v6 ? ", " : "", a6, cfg.has_v6 ? "" : "");
    }
    if (g_opt.default_route && peer_host) {
        char gw_ip[INET_ADDRSTRLEN];
        if (cfg.v4_gw.s_addr) inet_ntop(AF_INET, &cfg.v4_gw, gw_ip, sizeof(gw_ip));
        else legacy_gateway(&cfg.v4, gw_ip, sizeof(gw_ip));
        tun_set_default_route(peer_host, gw_ip, dev_name);
        if (cfg.has_v6) tun_set_default_route6(dev_name);
    }
    vpn_relay(tun_fd, sockfd, 0, peer_host, peer_port);
    tun_restore_default_route();
    tun_close(tun_fd, dev_name);
    return 0;
}

/*
 * -K --tun: multi-client VPN hub. This process owns the TUN device and the
 * address pool and routes packets; each client session runs in a child
 * (handshake, encryption) connected by a SOCK_SEQPACKET socket that carries
 * raw IP packets and the HUB_ASSIGN/HUB_RESULT messages (see hub.h).
 * Packets from a client are accepted only with that client's own source
 * address; packets from the TUN device go to the client that owns the
 * destination (unknown, broadcast and multicast destinations are dropped).
 */
typedef struct {
    int fd;
    pid_t pid;
    int assigned;
    int spoof_warned;
    char v4[INET_ADDRSTRLEN];
    char v6[INET6_ADDRSTRLEN];
    unsigned long long rx_pkts, rx_bytes, tx_pkts, tx_bytes;   /* from / to the client */
} hub_client_t;

static hub_client_t *s_hub_clients;   /* (defined again below: tentative) */
static int s_hub_max;

/* --status for the hub: sessions with their VPN addresses and traffic */
static void hub_status(FILE *out, void *ctx) {
    (void)ctx;
    children_status(out, NULL);
    int any = 0;
    for (int k = 0; k < s_hub_max; k++) {
        hub_client_t *c = &s_hub_clients[k];
        if (c->fd < 0) continue;
        if (!any) {
            fprintf(out, "\nVPN %-6s %-8s %-16s %-16s %-24s %14s %14s\n", "SLOT", "PID", "USER",
                    "IPV4", "IPV6", "RX (pkts/B)", "TX (pkts/B)");
            any = 1;
        }
        const char *u = children_user(c->pid);
        char rx[48], tx[48];
        snprintf(rx, sizeof(rx), "%llu/%llu", c->rx_pkts, c->rx_bytes);
        snprintf(tx, sizeof(tx), "%llu/%llu", c->tx_pkts, c->tx_bytes);
        fprintf(out, "    %-6d %-8d %-16s %-16s %-24s %14s %14s\n", k, (int)c->pid, u ? u : "-",
                c->v4[0] ? c->v4 : "-", c->v6[0] ? c->v6 : "-", rx, tx);
    }
}

/* Hub <-> session socket: one IP packet per message. SOCK_SEQPACKET reports
 * the session's end as EOF; macOS/BSD have no AF_UNIX SOCK_SEQPACKET, so
 * they use (reliable) AF_UNIX datagrams and rely on the SIGCHLD hook. */
#if defined(__linux__) && !defined(HUB_FORCE_DGRAM)   /* (tests: macOS behaviour) */
#define HUB_SOCK_TYPE SOCK_SEQPACKET
#else
#define HUB_SOCK_TYPE SOCK_DGRAM
#endif

static int hub_socketpair(int sv[2]) {
    if (socketpair(AF_UNIX, HUB_SOCK_TYPE, 0, sv) != 0) return -1;
    int buf = 1024 * 1024;                     /* macOS default: ~2 packets */
    for (int i = 0; i < 2; i++) {
        setsockopt(sv[i], SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
        setsockopt(sv[i], SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
    }
    return 0;
}

static hub_client_t *s_hub_clients;
static void hub_status(FILE *out, void *ctx);
static int s_hub_max;
static vpn_pool_t *s_hub_pool;

static void hub_drop_client(vpn_pool_t *pool, hub_client_t *c, int k);

/* A session process ended (works without EOF on datagram sockets) */
static void hub_child_exited(pid_t pid) {
    for (int k = 0; k < s_hub_max; k++)
        if (s_hub_clients[k].fd >= 0 && s_hub_clients[k].pid == pid)
            hub_drop_client(s_hub_pool, &s_hub_clients[k], k);
}

static void hub_drop_client(vpn_pool_t *pool, hub_client_t *c, int k) {
    vpn_pool_release(pool, k);
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
    c->assigned = 0;
}

int run_vpn_hub(int listen_fd, const char *password) {
    vpn_cfg_t scfg;
    char dev[32];
    if (local_vpn_cfg(&scfg, 1) != 0) {
        fprintf(stderr, "ERROR: invalid --tun/--tun6 configuration\n");
        return 1;
    }
    vpn_pool_t *pool = vpn_pool_new(scfg.v4, scfg.v4_prefix, scfg.has_v6 ? &scfg.v6 : NULL,
                                    scfg.v6_prefix, scfg.mtu);
    if (!pool) {
        fprintf(stderr, "ERROR: unsupported VPN subnet for -K (IPv4 /8../30; the --tun6 "
                        "prefix must leave room for every IPv4 host number)\n");
        return 1;
    }
    tun_install_cleanup_handlers();
    int tun_fd = tun_open_cfg(&scfg, dev, sizeof(dev));
    if (tun_fd < 0) {
        fprintf(stderr, "ERROR: Failed to open TUN device (need root/sudo)\n");
        vpn_pool_free(pool);
        return 1;
    }
    tun_add_subnet_route(dev, &scfg);
    fcntl(tun_fd, F_SETFL, fcntl(tun_fd, F_GETFL) | O_NONBLOCK);
    if (g_opt.masquerade) {
        char sub4[64], sub6[80];
        vpn_pool_subnets(pool, sub4, sizeof(sub4), sub6, sizeof(sub6));
        tun_enable_nat(dev, sub4);
        if (sub6[0]) tun_enable_nat6(dev, sub6);
    }

    install_sigchld();
    iplimit_configure(g_opt.max_per_ip, g_opt.auth_fail_limit, AUTH_FAIL_WINDOW, AUTH_BLOCK_TIME);
    int max = g_opt.max_clients;
    hub_client_t *cl = calloc((size_t)max, sizeof(*cl));
    struct pollfd *pfd = calloc((size_t)max + 4, sizeof(*pfd));
    children_reports_init();
    int control_fd = g_opt.control_path ? control_listen(g_opt.control_path) : -1;
    if (g_opt.control_path && control_fd < 0) return 1;
    if (!cl || !pfd) {
        perror("calloc");
        return 1;
    }
    for (int k = 0; k < max; k++) cl[k].fd = -1;
    s_hub_clients = cl;
    s_hub_max = max;
    s_hub_pool = pool;
    g_child_exit_hook = hub_child_exited;
    {
        char a4[INET_ADDRSTRLEN], a6[INET6_ADDRSTRLEN] = "";
        inet_ntop(AF_INET, &scfg.v4, a4, sizeof(a4));
        if (scfg.has_v6) inet_ntop(AF_INET6, &scfg.v6, a6, sizeof(a6));
        log_msg(0, "vpn hub: %s %s/%d%s%s, up to %d clients", dev, a4, scfg.v4_prefix,
                scfg.has_v6 ? " " : "", a6, max);
    }

    sigset_t chld, prev;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    char buf[TUN_MTU + 64];

    while (!tun_stop_requested()) {
        sigprocmask(SIG_BLOCK, &chld, &prev);
        reap_handler_exits();
        int room = g_active_children < max;
        sigprocmask(SIG_SETMASK, &prev, NULL);

        pfd[0] = (struct pollfd){ tun_fd, POLLIN, 0 };
        pfd[1] = (struct pollfd){ room ? listen_fd : -1, POLLIN, 0 };
        pfd[2] = (struct pollfd){ control_fd, POLLIN, 0 };
        pfd[3] = (struct pollfd){ children_reports_fd(), POLLIN, 0 };
        for (int k = 0; k < max; k++) pfd[k + 4] = (struct pollfd){ cl[k].fd, POLLIN, 0 };
        int rc = poll(pfd, (nfds_t)max + 4, 1000);
        if (rc < 0) {
            if (errno == EINTR) continue;
            perror("vpn hub: poll");
            break;
        }

        /* TUN -> the client that owns the destination */
        if (pfd[3].revents & POLLIN) children_reports_read();
        if (pfd[2].revents & POLLIN) control_serve(control_fd, hub_status, NULL);
        if (pfd[0].revents & POLLIN) {
            for (int burst = 0; burst < 64; burst++) {
                int n = tun_device_read(tun_fd, buf, sizeof(buf));
                if (n <= 0) break;
                int owner = vpn_pool_route(pool, (unsigned char *)buf, (size_t)n);
                if (owner >= 0 && owner < max && cl[owner].fd >= 0)
                    if (send(cl[owner].fd, buf, (size_t)n, 0) == n) {   /* non-blocking: dropped if full */
                        cl[owner].tx_pkts++;
                        cl[owner].tx_bytes += (unsigned long long)n;
                    }
            }
        }

        /* New client: its own session process */
        if (pfd[1].revents & POLLIN) {
            char ipkey[IPLIMIT_KEY_LEN];
            int have_key = 0;
            int client_fd = accept_admitted(listen_fd, ipkey, &have_key);
            int k = -1;
            if (client_fd >= 0)
                for (int i = 0; i < max; i++)
                    if (cl[i].fd < 0) { k = i; break; }
            int sv[2];
            if (client_fd >= 0 && k < 0) {
                log_msg(0, "vpn hub: no free client slot, connection refused");
                close(client_fd);
                client_fd = -1;
            } else if (client_fd >= 0 && hub_socketpair(sv) != 0) {
                log_msg(0, "vpn hub: socketpair: %s", strerror(errno));
                close(client_fd);
                client_fd = -1;
            }
            if (client_fd >= 0) {
                sigprocmask(SIG_BLOCK, &chld, &prev);
                pid_t pid = fork();
                if (pid > 0) {
                    g_active_children++;
                    if (have_key) iplimit_started(ipkey, pid, time(NULL));
                }
                sigprocmask(SIG_SETMASK, &prev, NULL);
                if (pid == 0) {
                    signal(SIGCHLD, SIG_DFL);
                    close(listen_fd);
                    close(tun_fd);
                    if (control_fd >= 0) close(control_fd);
                    close(sv[0]);
                    for (int i = 0; i < max; i++)
                        if (cl[i].fd >= 0) close(cl[i].fd);
                    g_opt.hub_fd = sv[1];
                    int child_rc = handle_client(client_fd, password, 1, 1, NULL, NULL, NULL,
                                                 NULL, NULL);
                    if (child_rc == 0) _exit(CHILD_OK);
                    _exit(farm9crypt_last_failure() == FARM9_FAIL_AUTH ? CHILD_AUTH_FAILED
                                                                       : CHILD_ERROR);
                }
                close(client_fd);
                close(sv[1]);
                if (pid < 0) {
                    perror("fork");
                    close(sv[0]);
                } else {
                    fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL) | O_NONBLOCK);
                    memset(&cl[k], 0, sizeof(cl[k]));
                    cl[k].fd = sv[0];
                    cl[k].pid = pid;
                    children_track(pid, have_key ? ipkey : NULL);
                }
            }
        }

        /* Sessions -> TUN, address requests */
        for (int k = 0; k < max; k++) {
            if (cl[k].fd < 0 || !(pfd[k + 4].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            for (int burst = 0; burst < 64; burst++) {
                ssize_t n = recv(cl[k].fd, buf, sizeof(buf), 0);            /* non-blocking socket */
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) break;
                if (n <= 0) {                                  /* session ended */
                    hub_drop_client(pool, &cl[k], k);
                    break;
                }
                unsigned char t = (unsigned char)buf[0];
                if (t == HUB_ASSIGN && n == HUB_ASSIGN_LEN) {
                    struct in_addr want;
                    memcpy(&want.s_addr, buf + 1, 4);
                    vpn_cfg_t c;
                    int st = vpn_pool_assign(pool, want, k, &c);
                    unsigned char r[HUB_RESULT_LEN];
                    r[0] = HUB_RESULT;
                    r[1] = (unsigned char)st;
                    vpn_cfg_build_reply(r + 2, VPN_CFG_REP_LEN, st, &c);
                    if (send(cl[k].fd, r, sizeof(r), 0) != (ssize_t)sizeof(r)) {
                        hub_drop_client(pool, &cl[k], k);
                        break;
                    }
                    if (st == VPN_CFG_OK) {
                        char a4[INET_ADDRSTRLEN], a6[INET6_ADDRSTRLEN] = "";
                        inet_ntop(AF_INET, &c.v4, a4, sizeof(a4));
                        if (c.has_v6) inet_ntop(AF_INET6, &c.v6, a6, sizeof(a6));
                        log_msg(0, "vpn hub: client %d (pid %d) at %s%s%s", k, (int)cl[k].pid,
                                a4, c.has_v6 ? " " : "", a6);
                        cl[k].assigned = 1;
                        snprintf(cl[k].v4, sizeof(cl[k].v4), "%s", a4);
                        snprintf(cl[k].v6, sizeof(cl[k].v6), "%s", a6);
                    }
                } else if (cl[k].assigned && (t >> 4 == 4 || t >> 4 == 6)) {
                    if (vpn_pool_src_ok(pool, k, (unsigned char *)buf, (size_t)n)) {
                        tun_device_write(tun_fd, buf, (int)n);
                        cl[k].rx_pkts++;
                        cl[k].rx_bytes += (unsigned long long)n;
                    } else if (vpn_packet_local_noise((unsigned char *)buf, (size_t)n)) {
                        /* the client's kernel: IPv6 link-local / unspecified source
                         * (router solicitation, MLD, DAD); not routed, not a spoof */
                    } else if (!cl[k].spoof_warned) {
                        log_msg(0, "vpn hub: client %d sent a packet with a source address "
                                   "that is not its own: dropped", k);
                        cl[k].spoof_warned = 1;
                    }
                }
            }
        }
    }

    g_child_exit_hook = NULL;
    log_msg(1, "vpn hub: stopping");
    for (int k = 0; k < max; k++) {
        if (cl[k].fd >= 0) {
            kill(cl[k].pid, SIGTERM);
            close(cl[k].fd);
        }
    }
    free(cl);
    free(pfd);
    tun_disable_nat();
    tun_close(tun_fd, dev);
    vpn_pool_free(pool);
    return 0;
}

