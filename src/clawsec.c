#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/wait.h>
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
static const char *s_tun_cidr = NULL;      /* --tun 10.0.0.1/24 (VPN mode) */
static int g_masquerade = 0;               /* --masquerade (NAT for VPN) */
static int g_default_route = 0;            /* --default-route (all traffic via VPN) */
static int g_tun_udp = 0;                  /* --tun-udp (UDP data channel for VPN) */
static const char *s_bind_port = NULL;     /* -p <port> (also used by --tun-udp server) */

/* -K: live handler processes (decremented by the SIGCHLD handler) */
static volatile sig_atomic_t g_active_children = 0;
static int g_max_clients = 16;              /* --max-clients */
static int g_handshake_timeout = 15;        /* --handshake-timeout (seconds, 0 = off) */
static char s_password[SECRET_MAX + 1];     /* session password (never in argv) */

static void sigchld_handler(int sig) {
    (void)sig;
    int saved_errno = errno;
    g_child_exited = 1;
    while (waitpid(-1, NULL, WNOHANG) > 0) {
        if (g_active_children > 0) g_active_children--;
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
static int handle_client_inner(int sockfd, const char *password, int is_server,
                          int send_first, const char *exec_prog,
                          const char *fwd_host, const char *fwd_port,
                          const char *peer_host, const char *peer_port) {
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
            /* Client sends knock before ECDHE */
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
            fprintf(stderr, "ERROR: Post-quantum hybrid handshake failed\n");
            close(sockfd);
            return farm9crypt_last_failure() != FARM9_FAIL_NONE ? HC_PERMANENT : 1;
        }
        if (g_tofu)
            log_msg(1, "PFS session established (X25519 + ML-KEM-768 + Ed25519 TOFU + password KDF)");
        else
            log_msg(1, "PFS session established (X25519 + ML-KEM-768 + password KDF)");
    } else if (g_tofu) {
        if (farm9crypt_init_ecdhe_tofu(sockfd, password, strlen(password),
                                       send_first, peer_host, peer_port) != 0) {
            if (setup_timed_out(errno))
                fprintf(stderr, "ERROR: handshake timed out after %d s\n", g_handshake_timeout);
            fprintf(stderr, "ERROR: ECDHE+TOFU handshake failed\n");
            close(sockfd);
            return farm9crypt_last_failure() != FARM9_FAIL_NONE ? HC_PERMANENT : 1;
        }
        log_msg(1, "PFS session established (X25519 + Ed25519 TOFU + password KDF)");
    } else {
        if (farm9crypt_init_ecdhe(sockfd, password, strlen(password), send_first) != 0) {
            if (setup_timed_out(errno))
                fprintf(stderr, "ERROR: handshake timed out after %d s\n", g_handshake_timeout);
            fprintf(stderr, "ERROR: ECDHE handshake failed\n");
            close(sockfd);
            return farm9crypt_last_failure() != FARM9_FAIL_NONE ? HC_PERMANENT : 1;
        }
        log_msg(1, "PFS session established (X25519 + password KDF)");
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
        char tun_ip[64];
        int tun_prefix = 24;
        if (tun_parse_cidr(s_tun_cidr, tun_ip, sizeof(tun_ip), &tun_prefix) < 0) {
            fprintf(stderr, "ERROR: Invalid TUN CIDR '%s'\n", s_tun_cidr);
            close(sockfd);
            farm9crypt_cleanup();
            return 1;
        }
        char dev_name[32];
        tun_install_cleanup_handlers();
        int tun_fd = tun_open(tun_ip, tun_prefix, dev_name, sizeof(dev_name));
        if (tun_fd < 0) {
            fprintf(stderr, "ERROR: Failed to open TUN device (need root/sudo)\n");
            close(sockfd);
            farm9crypt_cleanup();
            return 1;
        }
        if (g_masquerade) {
            char subnet[80];
            /* Build subnet from IP and prefix: e.g. 10.0.0.0/24 */
            struct in_addr addr;
            inet_pton(AF_INET, tun_ip, &addr);
            uint32_t mask = htonl(~((1U << (32 - tun_prefix)) - 1));
            addr.s_addr &= mask;
            char net_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, net_str, sizeof(net_str));
            snprintf(subnet, sizeof(subnet), "%s/%d", net_str, tun_prefix);
            tun_enable_nat(dev_name, subnet);
        }
        if (g_default_route && !is_server && peer_host) {
            /* Calculate VPN gateway (peer) IP — same logic as tun_open */
            struct in_addr gw_addr;
            inet_pton(AF_INET, tun_ip, &gw_addr);
            unsigned char *gp = (unsigned char *)&gw_addr.s_addr;
            gp[3] = (gp[3] == 1) ? 2 : 1;
            char gw_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &gw_addr, gw_ip, sizeof(gw_ip));
            tun_set_default_route(peer_host, gw_ip, dev_name);
        }

        if (g_tun_udp) {
            /* UDP data channel: negotiate over TCP, then relay over UDP */
            int udp_fd = tun_udp_negotiate(sockfd,
                                           peer_host ? peer_host : "0.0.0.0",
                                           peer_port ? peer_port : s_bind_port,
                                           is_server);
            if (udp_fd < 0) {
                fprintf(stderr, "ERROR: UDP VPN negotiation failed, falling back to TCP\n");
                tun_relay(tun_fd, sockfd);
            } else {
                unsigned char vpn_tx[32], vpn_rx[32];
                if (farm9crypt_export_udp_keys(vpn_tx, vpn_rx) == 0) {
                    tun_udp_relay(tun_fd, udp_fd, sockfd, vpn_tx, vpn_rx);
                    OPENSSL_cleanse(vpn_tx, sizeof(vpn_tx));
                    OPENSSL_cleanse(vpn_rx, sizeof(vpn_rx));
                } else {
                    fprintf(stderr, "ERROR: Cannot export key for UDP VPN\n");
                    tun_relay(tun_fd, sockfd);
                }
                close(udp_fd);
            }
        } else {
            tun_relay(tun_fd, sockfd);
        }

        tun_restore_default_route();
        tun_disable_nat();
        tun_close(tun_fd, dev_name);
        close(sockfd);
        farm9crypt_cleanup();
        return 0;
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
            "                    (or set CLAWSEC_PASSWORD; without either you are prompted)\n"
            "  -l                Listen mode (server)\n"
            "  -p <port>         Local port in listen mode\n"
            "                    (with --mux on the client: [host:]port, default 127.0.0.1)\n"
            "  -K                Keep-open: accept multiple clients (fork per client)\n"
            "  --max-clients <n> With -K: concurrent handlers (default 16)\n"
            "  --handshake-timeout <s>  Abort session setup after s seconds (default 15, 0=off)\n"
            "  -L <host:port>    Port forwarding: forward decrypted traffic to host:port\n"
            "  -R <host:port>    Reverse tunnel. Server: address to listen on (127.0.0.1,\n"
            "                    or 0.0.0.0 to expose publicly). Client: target to connect to\n"
            "  --tun <ip/mask>   TUN VPN mode: create encrypted VPN tunnel\n"
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
            "  --pq              Post-quantum hybrid (X25519 + ML-KEM-768)\n"
            "  --scan <range>    Port scan (SYN as root on Linux, else connect; random order)\n"
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
    OPT_MAX_CLIENTS,
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

int main(int argc, char **argv) {
    const char *password = NULL;
    const char *bind_port = NULL;  /* set to s_bind_port below after parsing */
    const char *fwd_spec = NULL;
    const char *scan_range = NULL;
    int listen_mode = 0;
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
        {"max-clients", required_argument, NULL, OPT_MAX_CLIENTS},
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
        case OPT_MAX_CLIENTS: {
            long v = parse_count(optarg, 4096);
            if (v < 1) {
                fprintf(stderr, "ERROR: --max-clients must be 1-4096\n");
                return 1;
            }
            g_max_clients = (int)v;
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
        case 'D': g_pad = 1; break;
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

        if (keep_open && !g_udp_mode) {
            /* Multi-client mode: fork per connection, at most g_max_clients
             * at a time (each handshake costs ~19 MiB of Argon2id memory) */
            install_sigchld();
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

                int client_fd = net_accept(listen_fd);
                sigprocmask(SIG_BLOCK, &chld, &prev);
                pid_t pid = fork();
                if (pid > 0) g_active_children++;
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
                    _exit(child_rc ? 1 : 0);
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
