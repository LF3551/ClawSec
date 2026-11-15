#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <poll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <time.h>
#include <openssl/crypto.h>

#include "farm9crypt.h"
#include "util.h"
#include "net.h"
#include "relay.h"
#include "exec.h"
#include "obfs.h"
#include "mux.h"
#include "fallback.h"
#include "fingerprint.h"
#include "tofu.h"
#include "pqkem.h"
#include "portscan.h"
#include "socks5.h"
#include "filetx.h"
#include "reverse.h"
#include "persistent.h"
#include "tun.h"
#include "version.h"
#include "secret.h"
#include "acl.h"
#include "iplimit.h"
#include "users.h"
#include "vpn.h"
#include "hub.h"
#include "ecdhe.h"

/* Global config */
int g_verbose = 0;
int g_chat_mode = 0;
int g_udp_mode = 0;
int g_af_family; /* AF_UNSPEC */
int g_pq = 0;    /* --pq: post-quantum hybrid */

static volatile sig_atomic_t g_child_exited = 0;
static const char *s_mux_port = NULL;
static int g_socks = 0;
static const char *s_socks_port = NULL;
static const char *s_send_file = NULL;
static const char *s_recv_dir = NULL;
static const char *s_reverse_spec = NULL;  /* -R host:port (reverse tunnel) */
static int g_persistent = 0;               /* --persistent auto-reconnect */
static const char *s_tun_cidr = NULL;      /* --tun 10.0.0.1/24 (VPN mode), client: or "auto" */
static const char *s_tun6_cidr = NULL;     /* --tun6 fd00::1/64 (server) */
static int s_hub_fd = -1;                  /* -K --tun session: socket to the hub */
static int g_masquerade = 0;               /* --masquerade (NAT for VPN) */
static int g_default_route = 0;            /* --default-route (all traffic via VPN) */
static int g_tun_udp = 0;                  /* --tun-udp (UDP data channel for VPN) */
static const char *s_bind_port = NULL;     /* -p <port> (also used by --tun-udp server) */

/* -K: live handler processes (decremented by the SIGCHLD handler) */
static volatile sig_atomic_t g_active_children = 0;
static int g_max_clients = 16;              /* --max-clients */
static int g_max_per_ip = 8;                /* --max-per-ip (0 = unlimited) */
static int g_auth_fail_limit = 5;           /* --auth-fail-limit per 10 min (0 = off) */
#define AUTH_FAIL_WINDOW 600                /* seconds */
#define AUTH_BLOCK_TIME  600                /* seconds */

/* Handler exit codes (-K) */
#define CHILD_OK          0
#define CHILD_ERROR       1
#define CHILD_AUTH_FAILED 3

/* Exited handlers, recorded by the SIGCHLD handler and consumed by the accept
 * loop (iplimit accounting). Live handlers <= 4096, so the ring cannot
 * overflow between two drains. */
#define EXIT_RING 4096
static volatile pid_t s_exit_pid[EXIT_RING];
static volatile int s_exit_status[EXIT_RING];
static volatile sig_atomic_t s_exit_head = 0;   /* written by the handler only */
static sig_atomic_t s_exit_tail = 0;            /* read side: SIGCHLD blocked */
static int g_handshake_timeout = 15;        /* --handshake-timeout (seconds, 0 = off) */
static char s_password[SECRET_MAX + 1];     /* session password (never in argv) */

static void sigchld_handler(int sig) {
    (void)sig;
    int saved_errno = errno;
    g_child_exited = 1;
    pid_t pid;
    int status;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (g_active_children > 0) g_active_children--;
        s_exit_pid[s_exit_head % EXIT_RING] = pid;
        s_exit_status[s_exit_head % EXIT_RING] = status;
        s_exit_head++;
    }
    errno = saved_errno;
}

/* Bound blocking socket I/O during session setup, so a client that connects
 * and stays silent cannot hold a handler (or the single-session server)
 * forever. 0 removes the bound. */
static void set_io_timeout(int fd, int seconds) {
    struct timeval tv = { .tv_sec = seconds, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static int setup_timed_out(int err) {
    return err == EAGAIN || err == EWOULDBLOCK || err == ETIMEDOUT;
}

static void ignore_sigpipe(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
}

/* -K: account for finished handlers (call with SIGCHLD blocked) */
static void reap_handler_exits(void) {
    while (s_exit_tail != s_exit_head) {
        int i = s_exit_tail % EXIT_RING;
        pid_t pid = s_exit_pid[i];
        int st = s_exit_status[i];
        s_exit_tail++;
        int auth_failed = WIFEXITED(st) && WEXITSTATUS(st) == CHILD_AUTH_FAILED;
        char key[IPLIMIT_KEY_LEN];
        int fails = iplimit_finished(pid, auth_failed, time(NULL), key);
        if (auth_failed && key[0]) {
            if (g_auth_fail_limit && fails >= g_auth_fail_limit)
                log_msg(0, "authentication failure from %s (%d/%d): blocking it for %d s",
                        key, fails, g_auth_fail_limit, AUTH_BLOCK_TIME);
            else if (g_auth_fail_limit)
                log_msg(1, "authentication failure from %s (%d/%d)", key, fails,
                        g_auth_fail_limit);
            else
                log_msg(1, "authentication failure from %s", key);
        }
    }
}

/* -K: accept one connection and apply the per-address limits.
 * Returns the client fd (ipkey/have_key filled) or -1 if it was refused. */
static int accept_admitted(int listen_fd, char ipkey[IPLIMIT_KEY_LEN], int *have_key) {
    struct sockaddr_storage peer;
    socklen_t peer_len = sizeof(peer);
    int client_fd = net_accept_peer(listen_fd, &peer, &peer_len);
    *have_key = iplimit_key((struct sockaddr *)&peer, peer_len, ipkey) == 0;

    sigset_t chld, prev;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    sigprocmask(SIG_BLOCK, &chld, &prev);
    reap_handler_exits();
    int verdict = IPLIMIT_OK, retry = 0;
    if (*have_key) verdict = iplimit_admit(ipkey, time(NULL), &retry);
    sigprocmask(SIG_SETMASK, &prev, NULL);
    if (verdict == IPLIMIT_OK) return client_fd;
    if (verdict == IPLIMIT_BLOCKED)
        log_msg(1, "refused %s: blocked for %d s after repeated authentication failures",
                ipkey, retry);
    else
        log_msg(1, "refused %s: %d handlers already running for this address (--max-per-ip)",
                ipkey, g_max_per_ip);
    close(client_fd);
    return -1;
}

static void install_sigchld(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld_handler;
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);
}

/* Local listener addresses (resolved once from the command line) */
static char s_socks_host[256], s_socks_lport[8];   /* --socks [host:]port (client) */
static char s_mux_host[256], s_mux_lport[8];       /* -p [host:]port with --mux (client) */

/* Handle one client connection (used by keep-open and normal mode) */
/* Returns 0 on success, 1 if the session could not be set up or failed,
 * HC_PERMANENT if it failed for a reason a retry cannot fix (wrong password,
 * incompatible peer). main() maps every failure to exit status 1. */
#define HC_PERMANENT 2
/* --tun / --tun6: this side's own configuration (server, or a client that
 * gets no answer from a ClawSec < 4.2 server) */
static int local_vpn_cfg(vpn_cfg_t *cfg, int with_v6) {
    char ip[64];
    int prefix = 24;
    memset(cfg, 0, sizeof(*cfg));
    if (tun_parse_cidr(s_tun_cidr, ip, sizeof(ip), &prefix) != 0 ||
        inet_pton(AF_INET, ip, &cfg->v4) != 1)
        return -1;
    cfg->v4_prefix = prefix;
    cfg->mtu = tun_effective_mtu();
    if (with_v6 && s_tun6_cidr) {
        if (vpn_parse_cidr6(s_tun6_cidr, &cfg->v6, &cfg->v6_prefix) != 0) return -1;
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
    if (!g_tun_udp) {
        tun_relay(tun_fd, sockfd);
        return;
    }
    int udp_fd = tun_udp_negotiate(sockfd, peer_host ? peer_host : "0.0.0.0",
                                   peer_port ? peer_port : s_bind_port, is_server);
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
static int run_vpn_session(int sockfd, int is_server, const char *peer_host,
                           const char *peer_port) {
    char dev_name[32];
    vpn_cfg_t cfg;

    if (is_server && s_hub_fd >= 0)                  /* -K: the hub owns the device */
        return hub_session(sockfd, s_hub_fd) == 0 ? 0 : 1;

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
        vpn_server_ctx_t ctx = { pool, -1, g_tun_udp, 0 };
        tun_set_control_handler(pool ? vpn_server_control : NULL, &ctx);
        if (g_masquerade) {
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
    int auto_addr = strcmp(s_tun_cidr, "auto") == 0;
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
    if (g_default_route && peer_host) {
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

static int handle_client_inner(int sockfd, const char *password, int is_server,
                          int send_first, const char *exec_prog,
                          const char *fwd_host, const char *fwd_port,
                          const char *peer_host, const char *peer_port) {
    /* Each encrypted frame is written with one send(): disable Nagle so small
     * frames (keystrokes, mux control frames) are not held back ~40 ms */
    {
        int one = 1, type = 0;
        socklen_t tl = sizeof(type);
        if (getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &type, &tl) == 0 && type == SOCK_STREAM)
            setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }

    /* Everything up to key confirmation must finish within the timeout */
    if (g_handshake_timeout > 0)
        set_io_timeout(sockfd, g_handshake_timeout);

    /* TLS camouflage: wrap socket in TLS before any crypto handshake */
    if (obfs_get_mode() == OBFS_TLS) {
        errno = 0;
        int tls_rc = is_server ? obfs_tls_accept(sockfd) : obfs_tls_connect(sockfd);
        if (tls_rc < 0) {
            if (setup_timed_out(errno))
                fprintf(stderr, "ERROR: handshake timed out after %d s\n", g_handshake_timeout);
            fprintf(stderr, "ERROR: TLS camouflage handshake failed\n");
            close(sockfd);
            return 1;
        }
        log_msg(1, "TLS 1.3 camouflage established");
    }

    /* Fallback: knock protocol for active probing resistance */
    if (g_fallback && obfs_get_mode() == OBFS_TLS) {
        if (is_server) {
            int knock = fallback_check_knock(sockfd);
            if (knock == 0) {
                /* Not a ClawSec client — proxy to fallback site */
                log_msg(1, "fallback: non-ClawSec probe detected, proxying");
                set_io_timeout(sockfd, 0);   /* the proxy has its own idle timeout */
                fallback_proxy(sockfd, g_fallback_host, g_fallback_port,
                               NULL, 0);
                close(sockfd);
                return 0;
            } else if (knock < 0) {
                log_msg(1, "fallback: connection error during knock");
                close(sockfd);
                return 1;
            }
            log_msg(1, "knock verified — ClawSec client");
        } else {
            /* Client sends knock before the handshake */
            if (fallback_send_knock(sockfd) < 0) {
                fprintf(stderr, "ERROR: Failed to send knock\n");
                close(sockfd);
                return 1;
            }
        }
    }

    errno = 0;
    if (g_pq) {
        if (farm9crypt_init_ecdhe_pq(sockfd, password, strlen(password),
                                     send_first, peer_host, peer_port) != 0) {
            if (setup_timed_out(errno))
                fprintf(stderr, "ERROR: handshake timed out after %d s\n", g_handshake_timeout);
            fprintf(stderr, "ERROR: post-quantum hybrid handshake failed\n");
            close(sockfd);
            return farm9crypt_last_failure() != FARM9_FAIL_NONE ? HC_PERMANENT : 1;
        }
        if (g_tofu)
            log_msg(1, "session established (SPAKE2 + ML-KEM-768 + Ed25519 TOFU)");
        else
            log_msg(1, "session established (SPAKE2 + ML-KEM-768)");
    } else if (g_tofu) {
        if (farm9crypt_init_ecdhe_tofu(sockfd, password, strlen(password),
                                       send_first, peer_host, peer_port) != 0) {
            if (setup_timed_out(errno))
                fprintf(stderr, "ERROR: handshake timed out after %d s\n", g_handshake_timeout);
            fprintf(stderr, "ERROR: handshake failed (TOFU)\n");
            close(sockfd);
            return farm9crypt_last_failure() != FARM9_FAIL_NONE ? HC_PERMANENT : 1;
        }
        log_msg(1, "session established (SPAKE2 + Ed25519 TOFU)");
    } else {
        if (farm9crypt_init_ecdhe(sockfd, password, strlen(password), send_first) != 0) {
            if (setup_timed_out(errno))
                fprintf(stderr, "ERROR: handshake timed out after %d s\n", g_handshake_timeout);
            fprintf(stderr, "ERROR: handshake failed\n");
            close(sockfd);
            return farm9crypt_last_failure() != FARM9_FAIL_NONE ? HC_PERMANENT : 1;
        }
        log_msg(1, "session established (SPAKE2 password-authenticated key exchange)");
    }
    if (is_server && ecdhe_peer_user()) {
        log_msg(0, "user '%s' logged in", ecdhe_peer_user());
        setenv("CLAWSEC_USER", ecdhe_peer_user(), 1);      /* for -e programs */
    }

    /* Session established: no artificial bound on the data phase */
    set_io_timeout(sockfd, 0);

    /* SOCKS5 proxy mode */
    if (g_socks) {
        if (is_server) {
            socks5_server(sockfd);
        } else {
            socks5_client(sockfd, s_socks_host, s_socks_lport);
        }
        close(sockfd);
        farm9crypt_cleanup();
        return 0;
    }

    /* File transfer mode */
    if (s_send_file) {
        int rc = filetx_send(sockfd, s_send_file) == 0 ? 0 : 1;
        close(sockfd);
        farm9crypt_cleanup();
        return rc;
    }
    if (s_recv_dir) {
        int rc = filetx_recv(sockfd, s_recv_dir) == 0 ? 0 : 1;
        close(sockfd);
        farm9crypt_cleanup();
        return rc;
    }

    /* TUN VPN mode (--tun) */
    if (s_tun_cidr) {
        int rc = run_vpn_session(sockfd, is_server, peer_host, peer_port);
        close(sockfd);
        farm9crypt_cleanup();
        return rc;
    }

    /* Reverse tunnel mode (-R) */
    if (s_reverse_spec) {
        if (is_server) {
            /* Server: listen on reverse port, relay through tunnel */
            char rev_host[256], rev_port[32];
            if (net_parse_host_port(s_reverse_spec, rev_host, sizeof(rev_host),
                                rev_port, sizeof(rev_port)) == 0) {
                reverse_server(sockfd, rev_host, rev_port);
            }
        } else {
            /* Client: wait for ROPEN, connect to local target, relay back */
            char rev_host[256], rev_port[32];
            if (net_parse_host_port(s_reverse_spec, rev_host, sizeof(rev_host),
                                rev_port, sizeof(rev_port)) == 0) {
                reverse_client(sockfd, rev_host, rev_port);
            }
        }
        close(sockfd);
        farm9crypt_cleanup();
        return 0;
    }

    /* Mux mode: multiplex streams over single tunnel */
    if (g_mux) {
        if (is_server && fwd_host && fwd_port) {
            mux_relay_server(sockfd, fwd_host, fwd_port);
        } else if (!is_server && s_mux_port) {
            mux_relay_client(sockfd, s_mux_host, s_mux_lport);
        }
        close(sockfd);
        farm9crypt_cleanup();
        return 0;
    }

    /* Port forwarding mode: connect to target and relay */
    if (fwd_host && fwd_port) {
        int target_fd = net_connect(fwd_host, fwd_port, 5);
        log_msg(1, "forwarding to %s:%s", fwd_host, fwd_port);
        relay_encrypted_plain(sockfd, target_fd);
        close(target_fd);
        close(sockfd);
        farm9crypt_cleanup();
        return 0;
    }

#ifdef GAPING_SECURITY_HOLE
    if (exec_prog) {
        run_encrypted_exec(sockfd, exec_prog);
        farm9crypt_cleanup();
        return 0;
    }
#else
    (void)exec_prog;
#endif

    relay_socket_stdio(sockfd, is_server, g_chat_mode);
    close(sockfd);
    farm9crypt_cleanup();
    return 0;
}

/* One session: run it, then release per-session TLS state (the socket is
 * already closed by handle_client_inner). */
static int handle_client(int sockfd, const char *password, int is_server,
                         int send_first, const char *exec_prog,
                         const char *fwd_host, const char *fwd_port,
                         const char *peer_host, const char *peer_port) {
    int rc = handle_client_inner(sockfd, password, is_server, send_first, exec_prog,
                                 fwd_host, fwd_port, peer_host, peer_port);
    obfs_tls_cleanup();
    return rc;
}

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s [password] [-u] [-4|-6] [-c] [-v] [-w sec] host port\n"
            "  %s -l [password] -p port [-K] [-u] [-4|-6] [-c] [-v]", prog, prog);
#ifdef GAPING_SECURITY_HOLE
    fprintf(stderr, " [-e prog]");
#endif
    fprintf(stderr, "\n"
            "  %s -l [password] -p port -L host:port  (port forwarding)\n"
            "  [password] = --key-file <file> | -k <password>, or CLAWSEC_PASSWORD, or prompt\n\n", prog);
    fprintf(stderr,
            "Options:\n"
            "  -k <password>     Encryption password (visible in ps; prefer the next two)\n"
            "  --key-file <f>    Read the password from the first line of a file (0600)\n"
            "  --user <name>     Client: log in as <name> (server uses --users)\n"
            "  --users <file>    Server: per-user passwords instead of a shared one\n"
            "  --add-user <name> With --users: add a user / change its password, exit\n"
            "                    (or set CLAWSEC_PASSWORD; without either you are prompted)\n"
            "  -l                Listen mode (server)\n"
            "  -p <port>         Local port in listen mode\n"
            "                    (with --mux on the client: [host:]port, default 127.0.0.1)\n"
            "  -K                Keep-open: accept multiple clients (fork per client)\n"
            "  --max-clients <n> With -K: concurrent handlers (default 16)\n"
            "  --max-per-ip <n>  With -K: concurrent handlers per address, IPv6 per /64\n"
            "                    (default 8, 0=unlimited)\n"
            "  --auth-fail-limit <n>  With -K: refuse an address for 10 min after n wrong\n"
            "                    passwords within 10 min (default 5, 0=off)\n"
            "  --handshake-timeout <s>  Abort session setup after s seconds (default 15, 0=off)\n"
            "  -L <host:port>    Port forwarding: forward decrypted traffic to host:port\n"
            "  -R <host:port>    Reverse tunnel. Server: address to listen on (127.0.0.1,\n"
            "                    or 0.0.0.0 to expose publicly). Client: target to connect to\n"
            "  --tun <ip/mask>   TUN VPN mode: create encrypted VPN tunnel\n"
            "                    (client: --tun auto = address from the server;\n"
            "                    server with -K: one device, many clients)\n"
            "  --tun6 <ip6/pfx>  Server: IPv6 inside the tunnel (e.g. fd00:c1a5::1/64)\n"
            "  --tun-udp         Use UDP data channel for VPN (avoids TCP-over-TCP)\n"
            "  --masquerade      Enable NAT (use with --tun on server for internet access)\n"
            "  --default-route   Route ALL traffic through VPN (client-side full tunnel)\n"
            "  --persistent      Auto-reconnect with exponential backoff (client mode)\n"
            "  --obfs http       Obfuscate traffic as HTTP requests (anti-DPI)\n"
            "  --obfs tls        Run inside TLS 1.3 (self-signed certificate)\n"
            "  --ech             Add a GREASE Encrypted Client Hello extension\n"
            "  --mux             Multiplex streams over one tunnel (with -L)\n"
            "  --fallback <h:p>  Proxy clients without the ClawSec knock to h:p\n"
            "  --fingerprint <p> Browser-like TLS ClientHello (chrome, firefox, safari)\n"
            "  --tofu            Trust On First Use (SSH-like server identity)\n"
            "  --pq              Post-quantum hybrid (SPAKE2 + ML-KEM-768)\n"
            "  --scan <range>    Port scan (SYN as root on Linux, else connect; random order)\n"
            "  --scan-rate <pps> SYN scan probes per second (default 1000)\n"
            "                    range: 1-1024, 22-443, all (default: 1-1024)\n"
            "  -b                Banner grab (show service version on open ports)\n"
            "  --socks-allow <l> SOCKS server: only allow destinations in l (CIDR list);\n"
            "                    default: all except loopback/link-local/cloud metadata\n"
            "  --socks [h:]port  SOCKS5 proxy through encrypted tunnel (client listens on\n"
            "                    127.0.0.1 by default; the proxy has no authentication)\n"
            "  --send <file>     Send file (encrypted, with SHA-256 verify + resume)\n"
            "  --recv <dir>      Receive file (save to dir, with resume support)\n"
            "  --pad             Pad all packets to uniform 1400 bytes (anti-analysis)\n"
            "  --jitter <ms>     Add random 0-N ms delay between packets (anti-timing)\n"
            "  -z                Compress data with zlib before encryption\n"
            "  -P                Show transfer progress bar\n"
            "  -V                SHA-256 end-to-end file verification\n"
            "  -n <name>         Chat nickname (default: Server/Client)\n"
            "  -u                UDP mode (default: TCP)\n"
            "  -4                Force IPv4 only\n"
            "  -6                Force IPv6 only\n"
            "  -c                Chat mode (timestamps, roles)\n"
            "  -w <sec>          Connect timeout in seconds\n"
            "  -v                Verbose output\n"
            "  --version         Print version and wire protocol, then exit\n");
#ifdef GAPING_SECURITY_HOLE
    fprintf(stderr,
            "  -e <program>      Execute program after connect (encrypted)\n");
#endif
}

/* Long-only options */
enum {
    OPT_KEY_FILE = 256,
    OPT_USER,
    OPT_USERS,
    OPT_ADD_USER,
    OPT_MAX_CLIENTS,
    OPT_MAX_PER_IP,
    OPT_SCAN_RATE,
    OPT_TUN6,
    OPT_AUTH_FAIL_LIMIT,
    OPT_HANDSHAKE_TIMEOUT,
    OPT_SOCKS_ALLOW,
};

/* Parse a non-negative decimal integer option. Returns -1 if invalid. */
static long parse_count(const char *s, long max) {
    char *end;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || end == s || *end != '\0' || v < 0 || v > max) return -1;
    return v;
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
} hub_client_t;

static void hub_drop_client(vpn_pool_t *pool, hub_client_t *c, int k) {
    vpn_pool_release(pool, k);
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
    c->assigned = 0;
}

static int run_vpn_hub(int listen_fd, const char *password) {
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
    if (g_masquerade) {
        char sub4[64], sub6[80];
        vpn_pool_subnets(pool, sub4, sizeof(sub4), sub6, sizeof(sub6));
        tun_enable_nat(dev, sub4);
        if (sub6[0]) tun_enable_nat6(dev, sub6);
    }

    install_sigchld();
    iplimit_configure(g_max_per_ip, g_auth_fail_limit, AUTH_FAIL_WINDOW, AUTH_BLOCK_TIME);
    int max = g_max_clients;
    hub_client_t *cl = calloc((size_t)max, sizeof(*cl));
    struct pollfd *pfd = calloc((size_t)max + 2, sizeof(*pfd));
    if (!cl || !pfd) {
        perror("calloc");
        return 1;
    }
    for (int k = 0; k < max; k++) cl[k].fd = -1;
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
        for (int k = 0; k < max; k++) pfd[k + 2] = (struct pollfd){ cl[k].fd, POLLIN, 0 };
        int rc = poll(pfd, (nfds_t)max + 2, 1000);
        if (rc < 0) {
            if (errno == EINTR) continue;
            perror("vpn hub: poll");
            break;
        }

        /* TUN -> the client that owns the destination */
        if (pfd[0].revents & POLLIN) {
            for (int burst = 0; burst < 64; burst++) {
                int n = tun_device_read(tun_fd, buf, sizeof(buf));
                if (n <= 0) break;
                int owner = vpn_pool_route(pool, (unsigned char *)buf, (size_t)n);
                if (owner >= 0 && owner < max && cl[owner].fd >= 0)
                    (void)send(cl[owner].fd, buf, (size_t)n, MSG_DONTWAIT);   /* drop if full */
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
            if (client_fd >= 0 && (k < 0 || socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) != 0)) {
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
                    close(sv[0]);
                    for (int i = 0; i < max; i++)
                        if (cl[i].fd >= 0) close(cl[i].fd);
                    s_hub_fd = sv[1];
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
                    cl[k] = (hub_client_t){ sv[0], pid, 0, 0 };
                }
            }
        }

        /* Sessions -> TUN, address requests */
        for (int k = 0; k < max; k++) {
            if (cl[k].fd < 0 || !(pfd[k + 2].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            for (int burst = 0; burst < 64; burst++) {
                ssize_t n = recv(cl[k].fd, buf, sizeof(buf), MSG_DONTWAIT);
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
                    }
                } else if (cl[k].assigned && (t >> 4 == 4 || t >> 4 == 6)) {
                    if (vpn_pool_src_ok(pool, k, (unsigned char *)buf, (size_t)n)) {
                        tun_device_write(tun_fd, buf, (int)n);
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

int main(int argc, char **argv) {
    const char *password = NULL;
    const char *bind_port = NULL;  /* set to s_bind_port below after parsing */
    const char *fwd_spec = NULL;
    const char *scan_range = NULL;
    int listen_mode = 0;
    const char *login_user = NULL;    /* --user (client) */
    const char *users_file = NULL;    /* --users (server) */
    const char *add_user = NULL;      /* --add-user (with --users) */
    int keep_open = 0;
    int timeout_sec = 0;
    int scan_mode = 0;
    int banner_grab = 0;
    int password_from_argv = 0;
    const char *key_file = NULL;
#ifdef GAPING_SECURITY_HOLE
    const char *exec_prog = NULL;
#endif

    static struct option long_opts[] = {
        {"obfs",        required_argument, NULL, 'O'},
        {"pad",         no_argument,       NULL, 'D'},
        {"jitter",      required_argument, NULL, 'J'},
        {"ech",         no_argument,       NULL, 'E'},
        {"mux",         no_argument,       NULL, 'M'},
        {"fallback",    required_argument, NULL, 'F'},
        {"fingerprint", required_argument, NULL, 'T'},
        {"tofu",        no_argument,       NULL, 'U'},
        {"pq",          no_argument,       NULL, 'Q'},
        {"scan",        required_argument, NULL, 'S'},
        {"socks",       required_argument, NULL, 'X'},
        {"send",        required_argument, NULL, 'W'},
        {"recv",        required_argument, NULL, 'Y'},
        {"persistent",  no_argument,       NULL, 'Z'},
        {"tun",         required_argument, NULL, 'N'},
        {"masquerade",  no_argument,       NULL, 'A'},
        {"default-route", no_argument,     NULL, 'G'},
        {"tun-udp",     no_argument,       NULL, 'B'},
        {"help",        no_argument,       NULL, 'h'},
        {"version",     no_argument,       NULL, 'I'},
        {"key-file",    required_argument, NULL, OPT_KEY_FILE},
        {"user",        required_argument, NULL, OPT_USER},
        {"users",       required_argument, NULL, OPT_USERS},
        {"add-user",    required_argument, NULL, OPT_ADD_USER},
        {"max-clients", required_argument, NULL, OPT_MAX_CLIENTS},
        {"max-per-ip", required_argument, NULL, OPT_MAX_PER_IP},
        {"scan-rate", required_argument, NULL, OPT_SCAN_RATE},
        {"tun6", required_argument, NULL, OPT_TUN6},
        {"auth-fail-limit", required_argument, NULL, OPT_AUTH_FAIL_LIMIT},
        {"handshake-timeout", required_argument, NULL, OPT_HANDSHAKE_TIMEOUT},
        {"socks-allow", required_argument, NULL, OPT_SOCKS_ALLOW},
        {NULL, 0, NULL, 0}
    };

#ifdef GAPING_SECURITY_HOLE
    const char *optstring = "hblKu46ck:p:w:ve:L:R:zPVn:";
#else
    /* -e is recognised only to explain how to enable it */
    const char *optstring = "hblKu46ck:p:w:ve:L:R:zPVn:";
#endif

    int opt;
    while ((opt = getopt_long(argc, argv, optstring, long_opts, NULL)) != -1) {
        switch (opt) {
        case 'h': usage(argv[0]); return 0;
        case 'I':
            printf("ClawSec %s (wire protocol %d)\n", CLAWSEC_VERSION, FARM9_VERSION);
            return 0;
        case 'b': banner_grab = 1; break;
        case 'l': listen_mode = 1; break;
        case 'K': keep_open = 1; break;
        case 'u': g_udp_mode = 1; break;
        case '4': g_af_family = AF_INET; break;
        case '6': g_af_family = AF_INET6; break;
        case 'c': g_chat_mode = 1; break;
        case 'k':
            if (secret_from_arg(optarg, s_password, sizeof(s_password)) != 0)
                return 1;
            password = s_password;
            password_from_argv = 1;
            break;
        case OPT_KEY_FILE: key_file = optarg; break;
        case OPT_USER: login_user = optarg; break;
        case OPT_USERS: users_file = optarg; break;
        case OPT_ADD_USER: add_user = optarg; break;
        case OPT_MAX_CLIENTS: {
            long v = parse_count(optarg, 4096);
            if (v < 1) {
                fprintf(stderr, "ERROR: --max-clients must be 1-4096\n");
                return 1;
            }
            g_max_clients = (int)v;
            break;
        }
        case OPT_TUN6: {
            struct in6_addr a6;
            int p6;
            if (vpn_parse_cidr6(optarg, &a6, &p6) != 0) {
                fprintf(stderr, "ERROR: Invalid --tun6 '%s' (use IPv6/prefix, prefix 64-120, "
                                "e.g. fd00:c1a5::1/64)\n", optarg);
                return 1;
            }
            s_tun6_cidr = optarg;
            break;
        }
        case OPT_SCAN_RATE: {
            long v = parse_count(optarg, SCAN_RATE_MAX);
            if (v < 1) {
                fprintf(stderr, "ERROR: --scan-rate must be 1-%d probes per second\n", SCAN_RATE_MAX);
                return 1;
            }
            g_scan_rate = (int)v;
            break;
        }
        case OPT_MAX_PER_IP: {
            long v = parse_count(optarg, 4096);
            if (v < 0) {
                fprintf(stderr, "ERROR: --max-per-ip must be 0-4096\n");
                return 1;
            }
            g_max_per_ip = (int)v;
            break;
        }
        case OPT_AUTH_FAIL_LIMIT: {
            long v = parse_count(optarg, 1000);
            if (v < 0) {
                fprintf(stderr, "ERROR: --auth-fail-limit must be 0-1000\n");
                return 1;
            }
            g_auth_fail_limit = (int)v;
            break;
        }
        case OPT_HANDSHAKE_TIMEOUT: {
            long v = parse_count(optarg, 3600);
            if (v < 0) {
                fprintf(stderr, "ERROR: --handshake-timeout must be 0-3600 seconds\n");
                return 1;
            }
            g_handshake_timeout = (int)v;
            break;
        }
        case OPT_SOCKS_ALLOW:
            if (acl_set_allow_list(optarg) != 0) return 1;
            break;
        case 'p': bind_port = optarg; break;
        case 'L': fwd_spec = optarg; break;
        case 'R': s_reverse_spec = optarg; break;
        case 'O':
            if (strcmp(optarg, "http") == 0) {
                obfs_set_mode(OBFS_HTTP);
            } else if (strcmp(optarg, "tls") == 0) {
                obfs_set_mode(OBFS_TLS);
            } else {
                fprintf(stderr, "ERROR: Unknown obfuscation mode '%s' (supported: http, tls)\n", optarg);
                return 1;
            }
            break;
        case 'w':
            timeout_sec = atoi(optarg);
            if (timeout_sec < 0) timeout_sec = 0;
            break;
        case 'v': g_verbose++; break;
        case 'z': g_compress = 1; break;
        case 'P': g_progress = 1; break;
        case 'V': g_verify = 1; break;
        case 'n': g_nickname = optarg; break;
        case 'D': g_pad = 1; farm9crypt_set_padding(1); break;
        case 'J':
            g_jitter = atoi(optarg);
            if (g_jitter < 0) g_jitter = 0;
            break;
        case 'E':
            obfs_ech_enable();
            /* ECH implies TLS mode */
            if (obfs_get_mode() == OBFS_NONE)
                obfs_set_mode(OBFS_TLS);
            break;
        case 'M':
            g_mux = 1;
            break;
        case 'F':
            g_fallback = 1;
            if (net_parse_host_port(optarg, g_fallback_host, sizeof(g_fallback_host),
                                g_fallback_port, sizeof(g_fallback_port)) < 0) {
                fprintf(stderr, "ERROR: Invalid fallback target '%s' (use host:port)\n", optarg);
                return 1;
            }
            /* Fallback implies TLS mode */
            if (obfs_get_mode() == OBFS_NONE)
                obfs_set_mode(OBFS_TLS);
            break;
        case 'T':
            if (strcmp(optarg, "chrome") == 0) {
                fp_set_profile(FP_CHROME);
            } else if (strcmp(optarg, "firefox") == 0) {
                fp_set_profile(FP_FIREFOX);
            } else if (strcmp(optarg, "safari") == 0) {
                fp_set_profile(FP_SAFARI);
            } else {
                fprintf(stderr, "ERROR: Unknown fingerprint profile '%s' (supported: chrome, firefox, safari)\n", optarg);
                return 1;
            }
            /* Fingerprint implies TLS mode */
            if (obfs_get_mode() == OBFS_NONE)
                obfs_set_mode(OBFS_TLS);
            break;
        case 'U':
            g_tofu = 1;
            break;
        case 'Q':
            g_pq = 1;
            break;
        case 'S':
            scan_mode = 1;
            scan_range = optarg;
            break;
        case 'X':
            g_socks = 1;
            s_socks_port = optarg;
            break;
        case 'W':
            s_send_file = optarg;
            break;
        case 'Y':
            s_recv_dir = optarg;
            break;
        case 'Z':
            g_persistent = 1;
            break;
        case 'N': {
            char ip[64]; int pfx;
            if (strcmp(optarg, "auto") == 0) {           /* client: server assigns */
                s_tun_cidr = optarg;
                break;
            }
            if (tun_parse_cidr(optarg, ip, sizeof(ip), &pfx) != 0) {
                fprintf(stderr, "ERROR: Invalid --tun '%s' (use IPv4/prefix, e.g. 10.0.0.1/24, prefix 8-30)\n",
                        optarg);
                return 1;
            }
            s_tun_cidr = optarg;
            break;
        }
        case 'A':
            g_masquerade = 1;
            break;
        case 'G':
            g_default_route = 1;
            break;
        case 'B':
            g_tun_udp = 1;
            break;
#ifdef GAPING_SECURITY_HOLE
        case 'e': exec_prog = optarg; break;
#else
        case 'e':
            fprintf(stderr, "ERROR: -e (execute program) is not built into this binary.\n"
                            "Rebuild with: make <target> DFLAGS=-DGAPING_SECURITY_HOLE\n");
            return 1;
#endif
        default: usage(argv[0]); return 1;
        }
    }

    int exit_status = 0;
#ifdef GAPING_SECURITY_HOLE
    const char *exec_arg = exec_prog;
#else
    const char *exec_arg = NULL;
#endif

    /* Port scan mode — doesn't need password */
    s_bind_port = bind_port;  /* expose to handle_client for --tun-udp */

    if (scan_mode) {
        if (optind >= argc) {
            fprintf(stderr, "ERROR: --scan requires target host\n");
            fprintf(stderr, "Usage: %s --scan <range> [--jitter N] [-v] host\n", argv[0]);
            fprintf(stderr, "  range: 1-1024, 80, 22-443 (default: 1-1024)\n");
            return 1;
        }
        const char *scan_host = argv[optind];
        int sp = 1, ep = 1024;
        if (scan_range && strcmp(scan_range, "all") == 0) {
            sp = 1; ep = 65535;
        } else if (scan_range) {
            if (strchr(scan_range, '-')) {
                sscanf(scan_range, "%d-%d", &sp, &ep);
            } else {
                sp = ep = atoi(scan_range);
            }
        }
        int scan_timeout = timeout_sec > 0 ? timeout_sec * 1000 : 1500;
        int ret = portscan_run(scan_host, sp, ep, g_jitter, scan_timeout, banner_grab);
        return (ret >= 0) ? 0 : 1;
    }

    /* VPN option checks */
    if (s_tun_cidr && listen_mode && strcmp(s_tun_cidr, "auto") == 0) {
        fprintf(stderr, "ERROR: --tun auto is a client option; the server needs --tun <ip/prefix>\n");
        return 1;
    }
    if (s_tun6_cidr && (!s_tun_cidr || !listen_mode)) {
        fprintf(stderr, "ERROR: --tun6 is a server option (with --tun); clients get their "
                        "IPv6 address from the server\n");
        return 1;
    }
    if (s_tun_cidr && listen_mode && keep_open && g_tun_udp) {
        fprintf(stderr, "ERROR: --tun-udp is not available with -K yet (multi-client VPN "
                        "uses the TCP channel)\n");
        return 1;
    }

    /* Per-user login: option checks */
    if (add_user && !users_file) {
        fprintf(stderr, "ERROR: --add-user needs --users <file>\n");
        return 1;
    }
    if (login_user && (listen_mode || users_file)) {
        fprintf(stderr, "ERROR: --user is a client option (the server uses --users <file>)\n");
        return 1;
    }
    if (users_file && !listen_mode && !add_user) {
        fprintf(stderr, "ERROR: --users is a server option (-l); clients use --user <name>\n");
        return 1;
    }
    if ((login_user || users_file) && g_udp_mode && !add_user) {
        fprintf(stderr, "ERROR: per-user login (--user/--users) is not available with -u\n");
        return 1;
    }
    if ((login_user && !user_name_valid(login_user)) || (add_user && !user_name_valid(add_user))) {
        fprintf(stderr, "ERROR: user names are 1-%d characters from A-Z a-z 0-9 . _ -\n",
                USER_NAME_MAX);
        return 1;
    }

    /* --add-user: store the user's password scalar and exit */
    if (add_user) {
        char pw1[SECRET_MAX + 1], pw2[SECRET_MAX + 1];
        int rc;
        if (password_from_argv) {
            snprintf(pw1, sizeof(pw1), "%s", s_password);
            rc = 0;
        } else if (key_file) {
            rc = secret_from_file(key_file, pw1, sizeof(pw1));
        } else if ((rc = secret_from_env(pw1, sizeof(pw1))) == 1) {
            rc = secret_prompt("New password: ", pw1, sizeof(pw1));
            if (rc == 0 && (secret_prompt("Repeat password: ", pw2, sizeof(pw2)) != 0 ||
                            strcmp(pw1, pw2) != 0)) {
                fprintf(stderr, "ERROR: passwords do not match\n");
                rc = -1;
            }
            secret_wipe(pw2, sizeof(pw2));
        }
        unsetenv(SECRET_ENV);
        if (rc != 0 || pw1[0] == '\0') {
            if (rc == 1) fprintf(stderr, "ERROR: no password given (terminal, --key-file or "
                                         SECRET_ENV ")\n");
            secret_wipe(pw1, sizeof(pw1));
            return 1;
        }
        if (strlen(pw1) < 12)
            fprintf(stderr, "Warning: short password; every login attempt is one online "
                            "guess, prefer 12+ random characters\n");
        unsigned char w[32];
        rc = user_password_to_w(add_user, pw1, strlen(pw1), w);
        secret_wipe(pw1, sizeof(pw1));
        if (rc == 0) rc = users_set(users_file, add_user, w);
        secret_wipe(w, sizeof(w));
        if (rc != 0) {
            fprintf(stderr, "ERROR: cannot update %s: %s\n", users_file, strerror(errno));
            return 1;
        }
        printf("user '%s' saved in %s\n", add_user, users_file);
        return 0;
    }

    if (users_file) {
        if (users_check_file(users_file) != 0) return 1;
        ecdhe_set_users_file(users_file);
        if (password_from_argv || key_file)
            fprintf(stderr, "Warning: --users replaces the shared password; -k/--key-file "
                            "are ignored\n");
        unsetenv(SECRET_ENV);
        password = "per-user";        /* placeholder: the handshake uses the users file */
        goto password_done;
    }
    if (login_user && ecdhe_set_user(login_user) != 0) return 1;

    /* Password: -k > --key-file > $CLAWSEC_PASSWORD > prompt on /dev/tty */
    if (password_from_argv) {
        fprintf(stderr, "Warning: -k exposes the password to other local users "
                        "(ps, /proc) and to shell history; prefer --key-file or "
                        "the " SECRET_ENV " environment variable\n");
    } else if (key_file) {
        if (secret_from_file(key_file, s_password, sizeof(s_password)) != 0)
            return 1;
        password = s_password;
    } else {
        int rc = secret_from_env(s_password, sizeof(s_password));
        if (rc < 0) return 1;
        if (rc == 1) {
            rc = secret_prompt("ClawSec password: ", s_password, sizeof(s_password));
            if (rc < 0) return 1;
        }
        if (rc == 0) password = s_password;
    }
    /* Never pass the password on to child processes (-e, --tun tools) */
    unsetenv(SECRET_ENV);

    if (!password || *password == '\0') {
        fprintf(stderr, "ERROR: Encryption password required: use --key-file <file>, "
                        "the " SECRET_ENV " environment variable, or -k <password>.\n");
        usage(argv[0]);
        return 1;
    }

    if (strlen(password) < 8)
        log_msg(1, "Warning: password should be at least 8 characters for security");

    /* Argon2id once per process (not per connection; children inherit it) */
    if (farm9crypt_prepare_password(password, strlen(password)) != 0) {
        fprintf(stderr, "ERROR: password key derivation failed\n");
        return 1;
    }
password_done:

    /* Parse port forwarding target */
    char fwd_host[256] = {0};
    char fwd_port[32] = {0};
    if (fwd_spec) {
        if (net_parse_host_port(fwd_spec, fwd_host, sizeof(fwd_host),
                            fwd_port, sizeof(fwd_port)) < 0) {
            fprintf(stderr, "ERROR: Invalid forward target '%s' (use host:port)\n", fwd_spec);
            return 1;
        }
    }

    ignore_sigpipe();

    /* Validate mux mode */
    if (g_mux) {
        if (listen_mode && !fwd_spec) {
            fprintf(stderr, "ERROR: --mux in server mode requires -L host:port\n");
            return 1;
        }
        if (!listen_mode && !bind_port) {
            fprintf(stderr, "ERROR: --mux in client mode requires -p <local_port>\n");
            return 1;
        }
        if (!listen_mode) {
            /* Local forwarding port: loopback unless an address is given */
            if (net_parse_listen_spec(bind_port, net_loopback_host(),
                                      s_mux_host, sizeof(s_mux_host),
                                      s_mux_lport, sizeof(s_mux_lport)) < 0) {
                fprintf(stderr, "ERROR: Invalid --mux local port '%s' (use port or host:port)\n",
                        bind_port);
                return 1;
            }
            s_mux_port = bind_port;
        }
    }

    /* Validate SOCKS5 mode */
    if (g_socks && listen_mode) {
        /* Server side — no local port needed, will relay outbound */
    } else if (g_socks) {
        /* The proxy is unauthenticated: loopback unless an address is given */
        if (!s_socks_port ||
            net_parse_listen_spec(s_socks_port, net_loopback_host(),
                                  s_socks_host, sizeof(s_socks_host),
                                  s_socks_lport, sizeof(s_socks_lport)) < 0) {
            fprintf(stderr, "ERROR: Invalid --socks '%s' (use port or host:port)\n",
                    s_socks_port ? s_socks_port : "");
            return 1;
        }
    }

    /* Validate reverse tunnel spec */
    if (s_reverse_spec) {
        char h[256], pt[8];
        if (net_parse_host_port(s_reverse_spec, h, sizeof(h), pt, sizeof(pt)) < 0) {
            fprintf(stderr, "ERROR: Invalid -R '%s' (use host:port)\n", s_reverse_spec);
            return 1;
        }
    }

    if (g_udp_mode)
        farm9crypt_set_udp_mode(1);

    /* TOFU: server must initialize identity key before accepting clients */
    if (g_tofu && listen_mode) {
        if (tofu_server_init() < 0) {
            fprintf(stderr, "ERROR: Failed to initialize TOFU identity key\n");
            return 1;
        }
    }

    if (listen_mode) {
        if (!bind_port) {
            fprintf(stderr, "ERROR: -p <port> is required in listen mode.\n");
            return 1;
        }

        int listen_fd = net_listen(bind_port);
        log_msg(1, "listening on *:%s%s%s%s",
                bind_port,
                g_udp_mode ? " (UDP)" : "",
                keep_open ? " [keep-open]" : "",
                fwd_spec ? " [forwarding]" : "");

        if (keep_open && !g_udp_mode && s_tun_cidr) {
            int rc = run_vpn_hub(listen_fd, password);
            close(listen_fd);
            return rc;
        }
        if (keep_open && !g_udp_mode) {
            /* Multi-client mode: fork per connection, at most g_max_clients
             * at a time (each handshake costs ~19 MiB of Argon2id memory) */
            install_sigchld();
            iplimit_configure(g_max_per_ip, g_auth_fail_limit, AUTH_FAIL_WINDOW, AUTH_BLOCK_TIME);
            sigset_t chld, prev;
            sigemptyset(&chld);
            sigaddset(&chld, SIGCHLD);
            for (;;) {
                sigprocmask(SIG_BLOCK, &chld, &prev);
                if (g_active_children >= g_max_clients)
                    log_msg(1, "max clients (%d) reached, waiting for a handler to finish",
                            g_max_clients);
                while (g_active_children >= g_max_clients)
                    sigsuspend(&prev);
                sigprocmask(SIG_SETMASK, &prev, NULL);

                char ipkey[IPLIMIT_KEY_LEN];
                int have_key = 0;
                int client_fd = accept_admitted(listen_fd, ipkey, &have_key);
                if (client_fd < 0) continue;
                sigprocmask(SIG_BLOCK, &chld, &prev);
                pid_t pid = fork();
                if (pid > 0) {
                    g_active_children++;
                    if (have_key) iplimit_started(ipkey, pid, time(NULL));
                }
                sigprocmask(SIG_SETMASK, &prev, NULL);
                if (pid < 0) {
                    perror("fork");
                    close(client_fd);
                    continue;
                }
                if (pid == 0) {
                    /* Child: handle this client */
                    signal(SIGCHLD, SIG_DFL);   /* the parent's reaper is not ours */
                    close(listen_fd);
                    int child_rc = handle_client(client_fd, password, 1, 1, exec_arg,
                                                 fwd_spec ? fwd_host : NULL,
                                                 fwd_spec ? fwd_port : NULL,
                                                 NULL, NULL);
                    if (child_rc == 0) _exit(CHILD_OK);
                    _exit(farm9crypt_last_failure() == FARM9_FAIL_AUTH ? CHILD_AUTH_FAILED
                                                                       : CHILD_ERROR);
                }
                /* Parent: continue accepting */
                close(client_fd);
                log_msg(1, "spawned handler pid=%d", (int)pid);
            }
        } else {
            /* Single-client mode */
            int sockfd;
            if (g_udp_mode) {
                sockfd = net_udp_accept(listen_fd);
            } else {
                sockfd = net_accept(listen_fd);
                close(listen_fd);
            }

            int send_first = g_udp_mode ? 0 : 1;
            exit_status = !!handle_client(sockfd, password, 1, send_first, exec_arg,
                                        fwd_spec ? fwd_host : NULL,
                                        fwd_spec ? fwd_port : NULL,
                                        NULL, NULL);
        }
    } else {
        /* Client mode */
        if (optind + 2 != argc) {
            usage(argv[0]);
            return 1;
        }

        const char *host = argv[optind];
        const char *port = argv[optind + 1];

        if (g_persistent) {
            /* Auto-reconnect loop with exponential backoff */
            int attempt = 0;
            srand(time(NULL));
            log_msg(1, "persistent mode: will auto-reconnect on disconnect");
            for (;;) {
                int sockfd = net_try_connect(host, port, timeout_sec > 0 ? timeout_sec : 10);
                if (sockfd < 0) {
                    int delay = persist_next_delay(attempt++);
                    fprintf(stderr, "persistent: connection failed, retrying in %ds...\n", delay);
                    sleep(delay);
                    continue;
                }
                log_msg(1, "connected to %s:%s", host, port);
                attempt = 0; /* reset on successful connect */

                int send_first = g_udp_mode ? 1 : 0;
                int rc = handle_client(sockfd, password, 0, send_first, NULL,
                                       fwd_spec ? fwd_host : NULL,
                                       fwd_spec ? fwd_port : NULL,
                                       host, port);
                if (rc == HC_PERMANENT) {
                    fprintf(stderr, "persistent: giving up — %s; reconnecting cannot fix this\n",
                            farm9crypt_last_failure() == FARM9_FAIL_AUTH
                                ? "authentication failed (wrong password?)"
                                : farm9crypt_last_failure() == FARM9_FAIL_CONFIG
                                    ? "--tofu / --pq differ between client and server"
                                    : "the server speaks an incompatible protocol version");
                    return 1;
                }

                if (s_tun_cidr && tun_stop_requested())
                    break;          /* Ctrl-C in VPN mode: stop, don't reconnect */
                int delay = persist_next_delay(attempt++);
                fprintf(stderr, "persistent: disconnected, reconnecting in %ds...\n", delay);
                sleep(delay);
            }
        } else {
            int sockfd = net_connect(host, port, timeout_sec);
            log_msg(1, "connected to %s:%s%s", host, port, g_udp_mode ? " (UDP)" : "");

            int send_first = g_udp_mode ? 1 : 0;
            exit_status = !!handle_client(sockfd, password, 0, send_first, NULL,
                                        fwd_spec ? fwd_host : NULL,
                                        fwd_spec ? fwd_port : NULL,
                                        host, port);
        }
    }

    return exit_status;
}
