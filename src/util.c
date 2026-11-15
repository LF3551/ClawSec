#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>

#include "util.h"
#include "farm9crypt.h"

void log_msg(int level, const char *fmt, ...) {
    if (g_verbose < level) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

void fatal(const char *fmt, ...) {
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

int write_all(int fd, const void *buf, size_t len) {
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

int wait_readable(const int *fds, int *ready, int n, int timeout_ms) {
    struct pollfd pfd[8];
    if (n < 0 || n > 8) { errno = EINVAL; return -1; }
    for (int i = 0; i < n; i++) {
        pfd[i].fd = fds[i];              /* negative fds are ignored by poll() */
        pfd[i].events = POLLIN;
        pfd[i].revents = 0;
        ready[i] = 0;
    }
    int rc = poll(pfd, (nfds_t)n, timeout_ms);
    if (rc > 0)
        for (int i = 0; i < n; i++)
            ready[i] = fds[i] >= 0 && (pfd[i].revents & (POLLIN | POLLHUP | POLLERR)) != 0;
    return rc;
}

int wait_writable(int fd, int timeout_ms) {
    struct pollfd pfd = { .fd = fd, .events = POLLOUT, .revents = 0 };
    int rc;
    do {
        rc = poll(&pfd, 1, timeout_ms);
    } while (rc < 0 && errno == EINTR);
    if (rc <= 0) return rc;
    return (pfd.revents & (POLLOUT | POLLERR | POLLHUP)) ? 1 : 0;
}
