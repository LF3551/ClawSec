/*
 * fallback.c — REALITY-like fallback for active probing resistance
 *
 * When DPI or a browser connects to our TLS port:
 *   1. Server does TLS accept (looks like normal HTTPS)
 *   2. Server peeks at first 4 bytes through TLS
 *   3. ClawSec client sends "CLAW" knock → proceed to ECDHE
 *   4. Anything else (HTTP GET, random probe) → proxy to fallback server
 *
 * The fallback server is a real website (nginx, apache, etc.) that
 * serves legitimate content. DPI sees a real HTTPS site on the port.
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/select.h>

#include "fallback.h"
#include "obfs.h"
#include "net.h"
#include "util.h"

int g_fallback = 0;
char g_fallback_host[256] = {0};
char g_fallback_port[32] = {0};

int fallback_send_knock(int fd) {
    return obfs_send(fd, FALLBACK_KNOCK_MAGIC, FALLBACK_KNOCK_SIZE);
}

int fallback_check_knock(int fd) {
    char buf[FALLBACK_KNOCK_SIZE];
    int n = obfs_recv(fd, buf, sizeof(buf));
    if (n <= 0) return -1;
    if (n == FALLBACK_KNOCK_SIZE &&
        memcmp(buf, FALLBACK_KNOCK_MAGIC, FALLBACK_KNOCK_SIZE) == 0) {
        return 1;  /* ClawSec client */
    }
    return 0;  /* foreign probe */
}

int fallback_proxy(int client_fd, const char *fallback_host,
                   const char *fallback_port,
                   const void *peeked, size_t peeked_len) {
    int target_fd = net_try_connect(fallback_host, fallback_port, 5);
    if (target_fd < 0) {
        log_msg(1, "fallback: connect to %s:%s failed", fallback_host, fallback_port);
        return -1;
    }

    log_msg(1, "fallback: proxying probe to %s:%s", fallback_host, fallback_port);

    /* Forward any peeked data first */
    if (peeked && peeked_len > 0) {
        if (write_all(target_fd, peeked, peeked_len) < 0) {
            close(target_fd);
            return -1;
        }
    }

    /* Bidirectional relay: client_fd (TLS) <-> target_fd (plain) */
    char buf[8192];
    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(client_fd, &rfds);
        FD_SET(target_fd, &rfds);
        int nfds = client_fd > target_fd ? client_fd : target_fd;

        struct timeval tv;
        tv.tv_sec = 30;  /* timeout idle probes */
        tv.tv_usec = 0;

        int ret = select(nfds + 1, &rfds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ret == 0) break; /* idle timeout */

        if (FD_ISSET(client_fd, &rfds)) {
            int n = obfs_recv(client_fd, buf, sizeof(buf));
            if (n <= 0) break;
            if (write_all(target_fd, buf, (size_t)n) < 0) break;
        }

        if (FD_ISSET(target_fd, &rfds)) {
            ssize_t n = read(target_fd, buf, sizeof(buf));
            if (n <= 0) break;
            if (obfs_send(client_fd, buf, (size_t)n) < 0) break;
        }
    }

    close(target_fd);
    return 0;
}
