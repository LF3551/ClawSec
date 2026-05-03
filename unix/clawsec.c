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

#include "farm9crypt.h"
#include "util.h"
#include "net.h"
#include "relay.h"
#include "exec.h"
#include "obfs.h"

/* Global config */
int g_verbose = 0;
int g_chat_mode = 0;
int g_udp_mode = 0;
int g_af_family; /* AF_UNSPEC */

static volatile sig_atomic_t g_child_exited = 0;

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

/* Handle one client connection (used by keep-open and normal mode) */
static void handle_client(int sockfd, const char *password, int is_server,
                          int send_first, const char *exec_prog,
                          const char *fwd_host, const char *fwd_port) {
    if (farm9crypt_init_ecdhe(sockfd, password, strlen(password), send_first) != 0) {
        fprintf(stderr, "ERROR: ECDHE handshake failed\n");
        close(sockfd);
        return;
    }
    log_msg(1, "PFS session established (X25519 + PBKDF2)");

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
            "  --obfs http       Obfuscate traffic as HTTP requests (anti-DPI)\n"
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
    int listen_mode = 0;
    int keep_open = 0;
    int timeout_sec = 0;
#ifdef GAPING_SECURITY_HOLE
    const char *exec_prog = NULL;
#endif

    static struct option long_opts[] = {
        {"obfs", required_argument, NULL, 'O'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

#ifdef GAPING_SECURITY_HOLE
    const char *optstring = "hlKu46ck:p:w:ve:L:zPVn:";
#else
    const char *optstring = "hlKu46ck:p:w:vL:zPVn:";
#endif

    int opt;
    while ((opt = getopt_long(argc, argv, optstring, long_opts, NULL)) != -1) {
        switch (opt) {
        case 'h': usage(argv[0]); return 0;
        case 'l': listen_mode = 1; break;
        case 'K': keep_open = 1; break;
        case 'u': g_udp_mode = 1; break;
        case '4': g_af_family = AF_INET; break;
        case '6': g_af_family = AF_INET6; break;
        case 'c': g_chat_mode = 1; break;
        case 'k': password = optarg; break;
        case 'p': bind_port = optarg; break;
        case 'L': fwd_spec = optarg; break;
        case 'O':
            if (strcmp(optarg, "http") == 0) {
                obfs_set_mode(OBFS_HTTP);
            } else {
                fprintf(stderr, "ERROR: Unknown obfuscation mode '%s' (supported: http)\n", optarg);
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
#ifdef GAPING_SECURITY_HOLE
        case 'e': exec_prog = optarg; break;
#endif
        default: usage(argv[0]); return 1;
        }
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

    if (g_udp_mode)
        farm9crypt_set_udp_mode(1);

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
                                  fwd_spec ? fwd_port : NULL);
#else
                    handle_client(client_fd, password, 1, 1, NULL,
                                  fwd_spec ? fwd_host : NULL,
                                  fwd_spec ? fwd_port : NULL);
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
                          fwd_spec ? fwd_port : NULL);
#else
            handle_client(sockfd, password, 1, send_first, NULL,
                          fwd_spec ? fwd_host : NULL,
                          fwd_spec ? fwd_port : NULL);
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

        int sockfd = net_connect(host, port, timeout_sec);
        log_msg(1, "connected to %s:%s%s", host, port, g_udp_mode ? " (UDP)" : "");

        int send_first = g_udp_mode ? 1 : 0;
        handle_client(sockfd, password, 0, send_first, NULL,
                      fwd_spec ? fwd_host : NULL,
                      fwd_spec ? fwd_port : NULL);
    }

    return 0;
}
