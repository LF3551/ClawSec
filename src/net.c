#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "net.h"
#include "util.h"

int net_connect(const char *host, const char *port, int timeout_sec) {
    struct addrinfo hints, *res = NULL, *rp;
    int sock = -1, ret;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = g_af_family;
    hints.ai_socktype = g_udp_mode ? SOCK_DGRAM : SOCK_STREAM;

    ret = getaddrinfo(host, port, &hints, &res);
    if (ret != 0) fatal("getaddrinfo(%s,%s): %s", host, port, gai_strerror(ret));

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) continue;

        int yes = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        if (!g_udp_mode && timeout_sec > 0) {
            int flags = fcntl(sock, F_GETFL, 0);
            if (flags < 0) flags = 0;
            fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        }

        ret = connect(sock, rp->ai_addr, rp->ai_addrlen);
        if (ret == 0) {
            if (!g_udp_mode && timeout_sec > 0) {
                int flags = fcntl(sock, F_GETFL, 0);
                fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
            }
            break;
        }

        if (!g_udp_mode && timeout_sec > 0 && errno == EINPROGRESS) {
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

int net_try_connect(const char *host, const char *port, int timeout_sec) {
    struct addrinfo hints, *res = NULL, *rp;
    int sock = -1, ret;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = g_af_family;
    hints.ai_socktype = g_udp_mode ? SOCK_DGRAM : SOCK_STREAM;

    ret = getaddrinfo(host, port, &hints, &res);
    if (ret != 0) return -1;

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) continue;

        int yes = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        if (!g_udp_mode && timeout_sec > 0) {
            int flags = fcntl(sock, F_GETFL, 0);
            if (flags < 0) flags = 0;
            fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        }

        ret = connect(sock, rp->ai_addr, rp->ai_addrlen);
        if (ret == 0) {
            if (!g_udp_mode && timeout_sec > 0) {
                int flags = fcntl(sock, F_GETFL, 0);
                fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
            }
            break;
        }

        if (!g_udp_mode && timeout_sec > 0 && errno == EINPROGRESS) {
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
    return sock;
}

/* Create a listening socket on host:port (host NULL = wildcard).
 * Returns fd or -1; *gai_err receives a getaddrinfo error if any. */
static int listen_socket(const char *host, const char *port, int *gai_err) {
    struct addrinfo hints, *res = NULL, *rp;
    int listen_fd = -1, ret;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = g_af_family;
    hints.ai_socktype = g_udp_mode ? SOCK_DGRAM : SOCK_STREAM;
    hints.ai_flags    = host ? 0 : AI_PASSIVE;

    *gai_err = 0;
    ret = getaddrinfo(host, port, &hints, &res);
    if (ret != 0) {
        *gai_err = ret;
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        listen_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listen_fd < 0) continue;

        int yes = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        if (!host && rp->ai_family == AF_INET6 && g_af_family == AF_UNSPEC) {
            int no = 0;
            setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no));
        }

        if (bind(listen_fd, rp->ai_addr, rp->ai_addrlen) < 0) {
            close(listen_fd);
            listen_fd = -1;
            continue;
        }
        if (!g_udp_mode) {
            if (listen(listen_fd, 16) < 0) {
                close(listen_fd);
                listen_fd = -1;
                continue;
            }
        }
        break;
    }

    freeaddrinfo(res);
    return listen_fd;
}

int net_listen(const char *port) {
    int gai_err = 0;
    int listen_fd = listen_socket(NULL, port, &gai_err);
    if (gai_err) fatal("getaddrinfo(*,%s): %s", port, gai_strerror(gai_err));
    if (listen_fd < 0) fatal("listen on *:%s failed", port);
    return listen_fd;
}

int net_listen_on(const char *host, const char *port) {
    int gai_err = 0;
    int saved_udp = g_udp_mode;
    g_udp_mode = 0;                 /* local listeners are always TCP */
    int listen_fd = listen_socket(host, port, &gai_err);
    g_udp_mode = saved_udp;
    if (gai_err) {
        fprintf(stderr, "ERROR: cannot resolve listen address %s:%s: %s\n",
                host ? host : "*", port, gai_strerror(gai_err));
        return -1;
    }
    if (listen_fd < 0)
        fprintf(stderr, "ERROR: cannot listen on %s:%s: %s\n",
                host ? host : "*", port, strerror(errno));
    return listen_fd;
}

const char *net_loopback_host(void) {
    return g_af_family == AF_INET6 ? "::1" : "127.0.0.1";
}

static int valid_port(const char *port) {
    if (!port || !*port || strlen(port) > 5) return 0;
    long v = 0;
    for (const char *p = port; *p; p++) {
        if (*p < '0' || *p > '9') return 0;
        v = v * 10 + (*p - '0');
    }
    return v >= 1 && v <= 65535;
}

int net_parse_host_port(const char *spec, char *host, size_t hlen,
                        char *port, size_t plen) {
    if (!spec || !host || !port || hlen == 0 || plen == 0) return -1;
    const char *port_str;
    size_t hl;

    if (spec[0] == '[') {                       /* [IPv6]:port */
        const char *bracket = strchr(spec, ']');
        if (!bracket || bracket[1] != ':') return -1;
        hl = (size_t)(bracket - spec - 1);
        if (hl == 0 || hl >= hlen) return -1;
        memcpy(host, spec + 1, hl);
        port_str = bracket + 2;
    } else {                                    /* host:port */
        const char *colon = strrchr(spec, ':');
        if (!colon || colon == spec) return -1;
        hl = (size_t)(colon - spec);
        if (hl >= hlen) return -1;
        memcpy(host, spec, hl);
        port_str = colon + 1;
    }
    host[hl] = '\0';
    if (!valid_port(port_str) || strlen(port_str) >= plen) return -1;
    snprintf(port, plen, "%s", port_str);
    return 0;
}

int net_parse_listen_spec(const char *spec, const char *default_host,
                          char *host, size_t hlen, char *port, size_t plen) {
    if (!spec || !default_host) return -1;
    if (strchr(spec, ':'))
        return net_parse_host_port(spec, host, hlen, port, plen);
    if (!valid_port(spec) || strlen(spec) >= plen || strlen(default_host) >= hlen)
        return -1;
    snprintf(host, hlen, "%s", default_host);
    snprintf(port, plen, "%s", spec);
    return 0;
}

int net_accept(int listen_fd) {
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    int fd = accept(listen_fd, (struct sockaddr *)&ss, &slen);
    if (fd < 0) fatal("accept failed");

    char host[128], serv[32];
    if (getnameinfo((struct sockaddr *)&ss, slen,
                    host, sizeof(host), serv, sizeof(serv),
                    NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
        log_msg(1, "connect from %s:%s", host, serv);
    }
    return fd;
}

int net_udp_accept(int udp_fd) {
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    unsigned char peek_buf[64];

    ssize_t n = recvfrom(udp_fd, peek_buf, sizeof(peek_buf), MSG_PEEK,
                         (struct sockaddr *)&ss, &slen);
    if (n < 0) fatal("recvfrom failed");

    if (connect(udp_fd, (struct sockaddr *)&ss, slen) < 0)
        fatal("connect UDP to peer failed");

    char host[128], serv[32];
    if (getnameinfo((struct sockaddr *)&ss, slen,
                    host, sizeof(host), serv, sizeof(serv),
                    NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
        log_msg(1, "UDP peer: %s:%s", host, serv);
    }
    return udp_fd;
}
