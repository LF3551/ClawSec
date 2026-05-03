#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "farm9crypt.h"
#include "util.h"
#include "net.h"
#include "relay.h"
#include "exec.h"

/* Global config (shared with net.c, relay.c, util.c) */
int g_verbose = 0;
int g_chat_mode = 0;
int g_udp_mode = 0;
int g_af_family; /* initialized to AF_UNSPEC (0) */

static void ignore_sigpipe(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
}

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s -k <password> [-u] [-4|-6] [-c] [-v] [-w sec] host port\n"
            "  %s -l -k <password> -p port [-u] [-4|-6] [-c] [-v]", prog, prog);
#ifdef GAPING_SECURITY_HOLE
    fprintf(stderr, " [-e program]\n\n");
#else
    fputc('\n', stderr);
#endif
    fprintf(stderr,
            "\nOptions:\n"
            "  -k <password>  Encryption password (required)\n"
            "  -l             Listen mode (server)\n"
            "  -p <port>      Local port in listen mode\n"
            "  -u             UDP mode (default: TCP)\n"
            "  -4             Force IPv4 only\n"
            "  -6             Force IPv6 only\n"
            "  -c             Chat mode (timestamps, roles)\n"
            "  -w <sec>       Connect timeout in seconds\n"
            "  -v             Verbose output\n");
#ifdef GAPING_SECURITY_HOLE
    fprintf(stderr,
            "  -e <program>   Execute program after connect (encrypted)\n");
#endif
}

int main(int argc, char **argv) {
    const char *password = NULL;
    const char *bind_port = NULL;
    int listen_mode = 0;
    int timeout_sec = 0;
#ifdef GAPING_SECURITY_HOLE
    const char *exec_prog = NULL;
#endif
    int opt;

#ifdef GAPING_SECURITY_HOLE
    const char *optstring = "hlu46ck:p:w:ve:";
#else
    const char *optstring = "hlu46ck:p:w:v";
#endif

    while ((opt = getopt(argc, argv, optstring)) != -1) {
        switch (opt) {
        case 'h': usage(argv[0]); return 0;
        case 'l': listen_mode = 1; break;
        case 'u': g_udp_mode = 1; break;
        case '4': g_af_family = AF_INET; break;
        case '6': g_af_family = AF_INET6; break;
        case 'c': g_chat_mode = 1; break;
        case 'k': password = optarg; break;
        case 'p': bind_port = optarg; break;
        case 'w':
            timeout_sec = atoi(optarg);
            if (timeout_sec < 0) timeout_sec = 0;
            break;
        case 'v': g_verbose++; break;
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

    ignore_sigpipe();

    if (g_udp_mode)
        farm9crypt_set_udp_mode(1);

    int sockfd = -1;

    if (listen_mode) {
        if (!bind_port) {
            fprintf(stderr, "ERROR: -p <port> is required in listen mode.\n");
            return 1;
        }

        int listen_fd = net_listen(bind_port);
        log_msg(1, "listening on *:%s%s", bind_port, g_udp_mode ? " (UDP)" : "");

        if (g_udp_mode) {
            sockfd = net_udp_accept(listen_fd);
        } else {
            sockfd = net_accept(listen_fd);
            close(listen_fd);
        }

        int send_first = g_udp_mode ? 0 : 1;
        if (farm9crypt_init_ecdhe(sockfd, password, strlen(password), send_first) != 0)
            fatal("ECDHE handshake failed");
        log_msg(1, "PFS session established (X25519 + PBKDF2)");

#ifdef GAPING_SECURITY_HOLE
        if (exec_prog) {
            run_encrypted_exec(sockfd, exec_prog);
            farm9crypt_cleanup();
            return 0;
        }
#endif
        relay_socket_stdio(sockfd, 1, g_chat_mode);
    } else {
        if (optind + 2 != argc) {
            usage(argv[0]);
            farm9crypt_cleanup();
            return 1;
        }

        const char *host = argv[optind];
        const char *port = argv[optind + 1];

        sockfd = net_connect(host, port, timeout_sec);
        log_msg(1, "connected to %s:%s%s", host, port, g_udp_mode ? " (UDP)" : "");

        int send_first = g_udp_mode ? 1 : 0;
        if (farm9crypt_init_ecdhe(sockfd, password, strlen(password), send_first) != 0)
            fatal("ECDHE handshake failed");
        log_msg(1, "PFS session established (X25519 + PBKDF2)");

        relay_socket_stdio(sockfd, 0, g_chat_mode);
    }

    close(sockfd);
    farm9crypt_cleanup();
    return 0;
}
