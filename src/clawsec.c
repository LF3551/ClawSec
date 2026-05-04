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
#include <netdb.h>
#include <errno.h>
#include <time.h>

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

static void sigchld_handler(int sig) {
    (void)sig;
    g_child_exited = 1;
    while (waitpid(-1, NULL, WNOHANG) > 0);
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

/* Forward declaration */
static int parse_host_port(const char *spec, char *host, size_t hlen,
                           char *port, size_t plen);

/* Handle one client connection (used by keep-open and normal mode) */
static void handle_client(int sockfd, const char *password, int is_server,
                          int send_first, const char *exec_prog,
                          const char *fwd_host, const char *fwd_port,
                          const char *peer_host, const char *peer_port) {
    /* TLS camouflage: wrap socket in TLS before any crypto handshake */
    if (obfs_get_mode() == OBFS_TLS) {
        int tls_rc = is_server ? obfs_tls_accept(sockfd) : obfs_tls_connect(sockfd);
        if (tls_rc < 0) {
            fprintf(stderr, "ERROR: TLS camouflage handshake failed\n");
            close(sockfd);
            return;
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
                fallback_proxy(sockfd, g_fallback_host, g_fallback_port,
                               NULL, 0);
                close(sockfd);
                return;
            } else if (knock < 0) {
                log_msg(1, "fallback: connection error during knock");
                close(sockfd);
                return;
            }
            log_msg(1, "knock verified — ClawSec client");
        } else {
            /* Client sends knock before ECDHE */
            if (fallback_send_knock(sockfd) < 0) {
                fprintf(stderr, "ERROR: Failed to send knock\n");
                close(sockfd);
                return;
            }
        }
    }

    if (g_pq) {
        if (farm9crypt_init_ecdhe_pq(sockfd, password, strlen(password),
                                     send_first, peer_host, peer_port) != 0) {
            fprintf(stderr, "ERROR: Post-quantum hybrid handshake failed\n");
            close(sockfd);
            return;
        }
        if (g_tofu)
            log_msg(1, "PFS session established (X25519 + ML-KEM-768 + Ed25519 TOFU + PBKDF2)");
        else
            log_msg(1, "PFS session established (X25519 + ML-KEM-768 + PBKDF2)");
    } else if (g_tofu) {
        if (farm9crypt_init_ecdhe_tofu(sockfd, password, strlen(password),
                                       send_first, peer_host, peer_port) != 0) {
            fprintf(stderr, "ERROR: ECDHE+TOFU handshake failed\n");
            close(sockfd);
            return;
        }
        log_msg(1, "PFS session established (X25519 + Ed25519 TOFU + PBKDF2)");
    } else {
        if (farm9crypt_init_ecdhe(sockfd, password, strlen(password), send_first) != 0) {
            fprintf(stderr, "ERROR: ECDHE handshake failed\n");
            close(sockfd);
            return;
        }
        log_msg(1, "PFS session established (X25519 + PBKDF2)");
    }

    /* SOCKS5 proxy mode */
    if (g_socks) {
        if (is_server) {
            socks5_server(sockfd);
        } else {
            socks5_client(sockfd, s_socks_port);
        }
        close(sockfd);
        farm9crypt_cleanup();
        return;
    }

    /* File transfer mode */
    if (s_send_file) {
        filetx_send(sockfd, s_send_file);
        close(sockfd);
        farm9crypt_cleanup();
        return;
    }
    if (s_recv_dir) {
        filetx_recv(sockfd, s_recv_dir);
        close(sockfd);
        farm9crypt_cleanup();
        return;
    }

    /* Reverse tunnel mode (-R) */
    if (s_reverse_spec) {
        if (is_server) {
            /* Server: listen on reverse port, relay through tunnel */
            char rev_host[256], rev_port[32];
            if (parse_host_port(s_reverse_spec, rev_host, sizeof(rev_host),
                                rev_port, sizeof(rev_port)) == 0) {
                reverse_server(sockfd, rev_port);
            }
        } else {
            /* Client: wait for ROPEN, connect to local target, relay back */
            char rev_host[256], rev_port[32];
            if (parse_host_port(s_reverse_spec, rev_host, sizeof(rev_host),
                                rev_port, sizeof(rev_port)) == 0) {
                reverse_client(sockfd, rev_host, rev_port);
            }
        }
        close(sockfd);
        farm9crypt_cleanup();
        return;
    }

    /* Mux mode: multiplex streams over single tunnel */
    if (g_mux) {
        if (is_server && fwd_host && fwd_port) {
            mux_relay_server(sockfd, fwd_host, fwd_port);
        } else if (!is_server && s_mux_port) {
            mux_relay_client(sockfd, s_mux_port);
        }
        close(sockfd);
        farm9crypt_cleanup();
        return;
    }

    /* Port forwarding mode: connect to target and relay */
    if (fwd_host && fwd_port) {
        int target_fd = net_connect(fwd_host, fwd_port, 5);
        log_msg(1, "forwarding to %s:%s", fwd_host, fwd_port);
        relay_encrypted_plain(sockfd, target_fd);
        close(target_fd);
        close(sockfd);
        farm9crypt_cleanup();
        return;
    }

#ifdef GAPING_SECURITY_HOLE
    if (exec_prog) {
        run_encrypted_exec(sockfd, exec_prog);
        farm9crypt_cleanup();
        return;
    }
#else
    (void)exec_prog;
#endif

    relay_socket_stdio(sockfd, is_server, g_chat_mode);
    close(sockfd);
    farm9crypt_cleanup();
}

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s -k <password> [-u] [-4|-6] [-c] [-v] [-w sec] host port\n"
            "  %s -l -k <password> -p port [-K] [-u] [-4|-6] [-c] [-v]", prog, prog);
#ifdef GAPING_SECURITY_HOLE
    fprintf(stderr, " [-e prog]");
#endif
    fprintf(stderr, "\n"
            "  %s -l -k <password> -p port -L host:port  (port forwarding)\n\n", prog);
    fprintf(stderr,
            "Options:\n"
            "  -k <password>     Encryption password (required)\n"
            "  -l                Listen mode (server)\n"
            "  -p <port>         Local port in listen mode\n"
            "  -K                Keep-open: accept multiple clients (fork per client)\n"
            "  -L <host:port>    Port forwarding: forward decrypted traffic to host:port\n"
            "  -R <host:port>    Reverse tunnel: server listens, client connects to target\n"
            "  --persistent      Auto-reconnect with exponential backoff (client mode)\n"
            "  --obfs http       Obfuscate traffic as HTTP requests (anti-DPI)\n"
            "  --obfs tls        Wrap connection in real TLS 1.3 (stealth mode)\n"            "  --ech              Encrypted Client Hello (hide SNI from DPI)\n"
            "  --mux              Multiplex streams over one tunnel (with -L)\n"            "  --fallback <h:p>  Proxy non-ClawSec probes to real site (REALITY-like)\n"
            "  --fingerprint <p> Mimic browser TLS (chrome, firefox, safari)\n"
            "  --tofu            Trust On First Use (SSH-like server identity)\n"
            "  --pq              Post-quantum hybrid (X25519 + ML-KEM-768)\n"
            "  --scan <range>    Stealth port scan (SYN/connect, randomized order)\n"
            "                    range: 1-1024, 22-443, all (default: 1-1024)\n"
            "  -b                Banner grab (show service version on open ports)\n"
            "  --socks <port>    SOCKS5 proxy through encrypted tunnel\n"
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
            "  -v                Verbose output\n");
#ifdef GAPING_SECURITY_HOLE
    fprintf(stderr,
            "  -e <program>      Execute program after connect (encrypted)\n");
#endif
}

/* Parse host:port string. Returns 0 on success, -1 on error. */
static int parse_host_port(const char *spec, char *host, size_t hlen,
                           char *port, size_t plen) {
    if (!spec) return -1;
    /* [IPv6]:port */
    if (spec[0] == '[') {
        const char *bracket = strchr(spec, ']');
        if (!bracket) return -1;
        size_t hl = bracket - spec - 1;
        if (hl >= hlen) return -1;
        memcpy(host, spec + 1, hl);
        host[hl] = '\0';
        if (bracket[1] != ':') return -1;
        snprintf(port, plen, "%s", bracket + 2);
        return 0;
    }
    /* host:port */
    const char *colon = strrchr(spec, ':');
    if (!colon || colon == spec) return -1;
    size_t hl = colon - spec;
    if (hl >= hlen) return -1;
    memcpy(host, spec, hl);
    host[hl] = '\0';
    snprintf(port, plen, "%s", colon + 1);
    return 0;
}

int main(int argc, char **argv) {
    const char *password = NULL;
    const char *bind_port = NULL;
    const char *fwd_spec = NULL;
    const char *scan_range = NULL;
    int listen_mode = 0;
    int keep_open = 0;
    int timeout_sec = 0;
    int scan_mode = 0;
    int banner_grab = 0;
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
        {"help",        no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

#ifdef GAPING_SECURITY_HOLE
    const char *optstring = "hblKu46ck:p:w:ve:L:R:zPVn:";
#else
    const char *optstring = "hblKu46ck:p:w:vL:R:zPVn:";
#endif

    int opt;
    while ((opt = getopt_long(argc, argv, optstring, long_opts, NULL)) != -1) {
        switch (opt) {
        case 'h': usage(argv[0]); return 0;
        case 'b': banner_grab = 1; break;
        case 'l': listen_mode = 1; break;
        case 'K': keep_open = 1; break;
        case 'u': g_udp_mode = 1; break;
        case '4': g_af_family = AF_INET; break;
        case '6': g_af_family = AF_INET6; break;
        case 'c': g_chat_mode = 1; break;
        case 'k': password = optarg; break;
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
            if (parse_host_port(optarg, g_fallback_host, sizeof(g_fallback_host),
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
#ifdef GAPING_SECURITY_HOLE
        case 'e': exec_prog = optarg; break;
#endif
        default: usage(argv[0]); return 1;
        }
    }

    /* Port scan mode — doesn't need password */
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

    if (!password || *password == '\0') {
        fprintf(stderr, "ERROR: Encryption password required (use -k <password>).\n");
        usage(argv[0]);
        return 1;
    }

    if (strlen(password) < 8)
        log_msg(1, "Warning: password should be at least 8 characters for security");

    /* Parse port forwarding target */
    char fwd_host[256] = {0};
    char fwd_port[32] = {0};
    if (fwd_spec) {
        if (parse_host_port(fwd_spec, fwd_host, sizeof(fwd_host),
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
        if (!listen_mode)
            s_mux_port = bind_port;
    }

    /* Validate SOCKS5 mode */
    if (g_socks && listen_mode) {
        /* Server side — no local port needed, will relay outbound */
    } else if (g_socks && !s_socks_port) {
        fprintf(stderr, "ERROR: --socks requires <port> argument\n");
        return 1;
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
            /* Multi-client mode: fork per connection */
            install_sigchld();
            for (;;) {
                int client_fd = net_accept(listen_fd);
                pid_t pid = fork();
                if (pid < 0) {
                    perror("fork");
                    close(client_fd);
                    continue;
                }
                if (pid == 0) {
                    /* Child: handle this client */
                    close(listen_fd);
#ifdef GAPING_SECURITY_HOLE
                    handle_client(client_fd, password, 1, 1, exec_prog,
                                  fwd_spec ? fwd_host : NULL,
                                  fwd_spec ? fwd_port : NULL,
                                  NULL, NULL);
#else
                    handle_client(client_fd, password, 1, 1, NULL,
                                  fwd_spec ? fwd_host : NULL,
                                  fwd_spec ? fwd_port : NULL,
                                  NULL, NULL);
#endif
                    _exit(0);
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
#ifdef GAPING_SECURITY_HOLE
            handle_client(sockfd, password, 1, send_first, exec_prog,
                          fwd_spec ? fwd_host : NULL,
                          fwd_spec ? fwd_port : NULL,
                          NULL, NULL);
#else
            handle_client(sockfd, password, 1, send_first, NULL,
                          fwd_spec ? fwd_host : NULL,
                          fwd_spec ? fwd_port : NULL,
                          NULL, NULL);
#endif
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
                handle_client(sockfd, password, 0, send_first, NULL,
                              fwd_spec ? fwd_host : NULL,
                              fwd_spec ? fwd_port : NULL,
                              host, port);

                int delay = persist_next_delay(attempt++);
                fprintf(stderr, "persistent: disconnected, reconnecting in %ds...\n", delay);
                sleep(delay);
            }
        } else {
            int sockfd = net_connect(host, port, timeout_sec);
            log_msg(1, "connected to %s:%s%s", host, port, g_udp_mode ? " (UDP)" : "");

            int send_first = g_udp_mode ? 1 : 0;
            handle_client(sockfd, password, 0, send_first, NULL,
                          fwd_spec ? fwd_host : NULL,
                          fwd_spec ? fwd_port : NULL,
                          host, port);
        }
    }

    return 0;
}
