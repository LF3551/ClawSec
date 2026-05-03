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

int net_listen(const char *port) {
    struct addrinfo hints, *res = NULL, *rp;
    int listen_fd = -1, ret;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = g_af_family;
    hints.ai_socktype = g_udp_mode ? SOCK_DGRAM : SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;

    ret = getaddrinfo(NULL, port, &hints, &res);
    if (ret != 0) fatal("getaddrinfo(*,%s): %s", port, gai_strerror(ret));

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        listen_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listen_fd < 0) continue;

        int yes = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        if (rp->ai_family == AF_INET6 && g_af_family == AF_UNSPEC) {
            int no = 0;
            setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no));
        }

        if (bind(listen_fd, rp->ai_addr, rp->ai_addrlen) < 0) {
            close(listen_fd);
            listen_fd = -1;
            continue;
        }
        if (!g_udp_mode) {
            if (listen(listen_fd, 1) < 0) {
                close(listen_fd);
                listen_fd = -1;
                continue;
            }
        }
        break;
    }

    freeaddrinfo(res);
    if (listen_fd < 0) fatal("listen on *:%s failed", port);
    return listen_fd;
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
