#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "farm9crypt.h"

#define COLOR_RESET   "\033[0m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_CYAN    "\033[36m"

#define BUFSIZE 8192

static int g_verbose = 0;
static int g_chat_mode = 0;

static void vlogf(int level, const char *fmt, va_list ap) {
    if (g_verbose < level) return;
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
}

static void log_msg(int level, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vlogf(level, fmt, ap);
    va_end(ap);
}

static void fatal(const char *fmt, ...) {
    int saved_errno = errno;
    va_list ap;
    fprintf(stderr, "ERROR: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    if (saved_errno) fprintf(stderr, ": %s", strerror(saved_errno));
    fputc('\n', stderr);
    farm9crypt_cleanup();
    exit(EXIT_FAILURE);
}

static void ignore_sigpipe(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
}

static void print_chat_message(const char *sender_label,
                               const char *color,
                               const char *msg,
                               size_t len) {
    time_t now = time(NULL);
    struct tm tm_info;
    char timestamp[16];
    localtime_r(&now, &tm_info);
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", &tm_info);
    fprintf(stdout, "%s[%s %s]%s ", color, timestamp, sender_label, COLOR_RESET);
    for (size_t i = 0; i < len; ++i) {
        fputc((unsigned char)msg[i], stdout);
        if (msg[i] == '\n' && i + 1 < len) {
            fprintf(stdout, "%s[%s %s]%s ", color, timestamp, sender_label, COLOR_RESET);
        }
    }
    if (len > 0 && msg[len - 1] != '\n') fputc('\n', stdout);
    fflush(stdout);
}

static int write_all(int fd, const void *buf, size_t len) {
    const unsigned char *p = buf;
    size_t left = len;
    while (left > 0) {
        ssize_t n = write(fd, p, left);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        p += (size_t)n;
        left -= (size_t)n;
    }
    return 0;
}

static int connect_with_timeout(const char *host,
                                const char *port,
                                int timeout_sec) {
    struct addrinfo hints;
    struct addrinfo *res = NULL, *rp;
    int sock = -1;
    int ret;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    ret = getaddrinfo(host, port, &hints, &res);
    if (ret != 0) fatal("getaddrinfo(%s,%s): %s", host, port, gai_strerror(ret));

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) continue;

        int yes = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        if (timeout_sec > 0) {
            int flags = fcntl(sock, F_GETFL, 0);
            if (flags < 0) flags = 0;
            fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        }

        ret = connect(sock, rp->ai_addr, rp->ai_addrlen);
        if (ret == 0) {
            if (timeout_sec > 0) {
                int flags = fcntl(sock, F_GETFL, 0);
                fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
            }
            break;
        }

        if (timeout_sec > 0 && errno == EINPROGRESS) {
            fd_set wfds;
            struct timeval tv;
            FD_ZERO(&wfds);
            FD_SET(sock, &wfds);
            tv.tv_sec = timeout_sec;
            tv.tv_usec = 0;
            ret = select(sock + 1, NULL, &wfds, NULL, &tv);
            if (ret > 0 && FD_ISSET(sock, &wfds)) {
                int err = 0;
                socklen_t slen = sizeof(err);
                if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &slen) == 0 && err == 0) {
                    int flags = fcntl(sock, F_GETFL, 0);
                    fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
                    break;
                }
                errno = err;
            } else if (ret == 0) {
                errno = ETIMEDOUT;
            }
        }

        close(sock);
        sock = -1;
    }

    freeaddrinfo(res);
    if (sock < 0) fatal("connect to %s:%s failed", host, port);
    return sock;
}

static int listen_on(const char *port) {
    struct addrinfo hints;
    struct addrinfo *res = NULL, *rp;
    int listen_fd = -1;
    int ret;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;

    ret = getaddrinfo(NULL, port, &hints, &res);
    if (ret != 0) fatal("getaddrinfo(*,%s): %s", port, gai_strerror(ret));

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        listen_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listen_fd < 0) continue;

        int yes = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        if (bind(listen_fd, rp->ai_addr, rp->ai_addrlen) < 0) {
            close(listen_fd);
            listen_fd = -1;
            continue;
        }
        if (listen(listen_fd, 1) < 0) {
            close(listen_fd);
            listen_fd = -1;
            continue;
        }
        break;
    }

    freeaddrinfo(res);
    if (listen_fd < 0) fatal("listen on *:%s failed", port);
    return listen_fd;
}

static int accept_one(int listen_fd) {
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    int fd = accept(listen_fd, (struct sockaddr *)&ss, &slen);
    if (fd < 0) fatal("accept failed");

    char host[128];
    char serv[32];
    if (getnameinfo((struct sockaddr *)&ss, slen,
                    host, sizeof(host),
                    serv, sizeof(serv),
                    NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
        log_msg(1, "connect from %s:%s", host, serv);
    }
    return fd;
}

static int relay_socket_stdio(int sockfd, int is_server, int chat_enabled) {
    char inbuf[BUFSIZE];
    char netbuf[BUFSIZE];
    ssize_t n;
    size_t sent = 0, received = 0;
    const char *local_label = is_server ? "Server" : "Client";
    const char *remote_label = is_server ? "Client" : "Server";
    int interactive = isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
    int chat_mode = chat_enabled && interactive;
    int stdin_closed = 0;

    if (chat_mode) {
        fprintf(stdout,
                "%s[Secure chat established] local=%s remote=%s%s\n",
                COLOR_CYAN, local_label, remote_label, COLOR_RESET);
        fflush(stdout);
    }

    for (;;) {
        fd_set rfds;
        int nfds = sockfd;

        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);
        if (!stdin_closed) {
            FD_SET(STDIN_FILENO, &rfds);
            if (STDIN_FILENO > nfds) nfds = STDIN_FILENO;
        }

        int ret = select(nfds + 1, &rfds, NULL, NULL, NULL);
        if (ret < 0) {
            if (errno == EINTR) continue;
            fatal("select failed");
        }

        if (FD_ISSET(sockfd, &rfds)) {
            n = farm9crypt_read(sockfd, netbuf, sizeof(netbuf));
            if (n < 0) fatal("read from network failed");
            if (n == 0) break;
            received += (size_t)n;
            if (chat_mode) {
                print_chat_message(remote_label, COLOR_CYAN, netbuf, (size_t)n);
            } else {
                if (write_all(STDOUT_FILENO, netbuf, (size_t)n) < 0)
                    fatal("write to stdout failed");
            }
        }

        if (!stdin_closed && FD_ISSET(STDIN_FILENO, &rfds)) {
            n = read(STDIN_FILENO, inbuf, sizeof(inbuf));
            if (n < 0) fatal("read from stdin failed");
            if (n == 0) {
                shutdown(sockfd, SHUT_WR);
                stdin_closed = 1;
            } else {
                sent += (size_t)n;
                if (chat_mode) {
                    print_chat_message(local_label, COLOR_GREEN, inbuf, (size_t)n);
                }
                ssize_t wn = farm9crypt_write(sockfd, inbuf, (size_t)n);
                if (wn != n) fatal("write to network failed");
            }
        }
    }

    if (!chat_mode && g_verbose) {
        fprintf(stderr,
                "\n[Transfer complete] Sent %zu bytes, received %zu bytes\n",
                sent, received);
    }
    return 0;
}

#ifdef GAPING_SECURITY_HOLE
static void run_encrypted_exec(int sockfd, const char *prog) {
    int to_child[2];
    int from_child[2];

    if (pipe(to_child) < 0 || pipe(from_child) < 0) fatal("pipe failed");

    pid_t pid = fork();
    if (pid < 0) fatal("fork failed");

    if (pid == 0) {
        char *argv0;
        const char *slash = strrchr(prog, '/');
        if (slash) argv0 = (char *)(slash + 1);
        else argv0 = (char *)prog;

        close(to_child[1]);
        close(from_child[0]);

        dup2(to_child[0], STDIN_FILENO);
        dup2(from_child[1], STDOUT_FILENO);
        dup2(from_child[1], STDERR_FILENO);

        close(to_child[0]);
        close(from_child[1]);

        execl(prog, argv0, (char *)NULL);
        _exit(127);
    }

    close(to_child[0]);
    close(from_child[1]);

    char buf[BUFSIZE];

    for (;;) {
        fd_set rfds;
        int nfds = sockfd;

        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);
        FD_SET(from_child[0], &rfds);
        if (from_child[0] > nfds) nfds = from_child[0];

        int ret = select(nfds + 1, &rfds, NULL, NULL, NULL);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (FD_ISSET(sockfd, &rfds)) {
            ssize_t n = farm9crypt_read(sockfd, buf, sizeof(buf));
            if (n <= 0) break;
            if (write_all(to_child[1], buf, (size_t)n) < 0) break;
        }

        if (FD_ISSET(from_child[0], &rfds)) {
            ssize_t n = read(from_child[0], buf, sizeof(buf));
            if (n <= 0) break;
            ssize_t wn = farm9crypt_write(sockfd, buf, (size_t)n);
            if (wn != n) break;
        }
    }

    close(to_child[1]);
    close(from_child[0]);
    close(sockfd);

    int status;
    (void)waitpid(pid, &status, 0);
}
#endif

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s -k <password> [-c] [-v] [-w sec] host port\n"
            "  %s -l -k <password> -p port [-c] [-v]", prog, prog);
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
    const char *optstring = "hlck:p:w:v";
#else
    const char *optstring = "hlck:p:w:v";
#endif

    while ((opt = getopt(argc, argv, optstring)) != -1) {
        switch (opt) {
        case 'h':
            usage(argv[0]);
            return 0;
        case 'l':
            listen_mode = 1;
            break;
        case 'c':
            g_chat_mode = 1;
            break;
        case 'k':
            password = optarg;
            break;
        case 'p':
            bind_port = optarg;
            break;
        case 'w':
            timeout_sec = atoi(optarg);
            if (timeout_sec < 0) timeout_sec = 0;
            break;
        case 'v':
            g_verbose++;
            break;
#ifdef GAPING_SECURITY_HOLE
        case 'e':
            exec_prog = optarg;
            break;
#endif
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (!password || *password == '\0') {
        fprintf(stderr,
                "ERROR: Encryption password required (use -k <password>).\n");
        usage(argv[0]);
        return 1;
    }

    if (strlen(password) < 8) {
        log_msg(1,
                "Warning: password should be at least 8 characters for security");
    }

    if (farm9crypt_init_password(password, strlen(password)) != 0) {
        fatal("Encryption initialization failed");
    }
    if (!farm9crypt_initialized()) {
        fatal("Encryption not initialized");
    }

    ignore_sigpipe();

    int sockfd = -1;

    if (listen_mode) {
        if (!bind_port) {
            fprintf(stderr, "ERROR: -p <port> is required in listen mode.\n");
            farm9crypt_cleanup();
            return 1;
        }

        int listen_fd = listen_on(bind_port);
        log_msg(1, "listening on *:%s", bind_port);
        sockfd = accept_one(listen_fd);
        close(listen_fd);

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

        sockfd = connect_with_timeout(host, port, timeout_sec);
        log_msg(1, "connected to %s:%s", host, port);
        relay_socket_stdio(sockfd, 0, g_chat_mode);
    }

    close(sockfd);
    farm9crypt_cleanup();
    return 0;
}
