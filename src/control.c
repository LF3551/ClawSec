/*
 * control.c — status socket of a -K server (see control.h)
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include "control.h"

static int fill_addr(const char *path, struct sockaddr_un *a) {
    memset(a, 0, sizeof(*a));
    a->sun_family = AF_UNIX;
    if (!path || strlen(path) >= sizeof(a->sun_path)) {
        fprintf(stderr, "ERROR: control socket path too long\n");
        return -1;
    }
    memcpy(a->sun_path, path, strlen(path));
    return 0;
}

static int bind_listen(int fd, const struct sockaddr_un *a) {
    mode_t old = umask(0177);               /* created as 0600 */
    int rc = bind(fd, (const struct sockaddr *)a, sizeof(*a));
    umask(old);
    return rc == 0 ? listen(fd, 8) : -1;
}

int control_listen(const char *path) {
    struct sockaddr_un a;
    if (fill_addr(path, &a) != 0) return -1;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (bind_listen(fd, &a) == 0) return fd;
    if (errno == EADDRINUSE) {
        /* Something is at path. A live server answers: refuse. A socket
         * left over by a server that died refuses the connection: replace
         * it. (No stat-then-unlink of the name: nothing to race with.) */
        int probe = socket(AF_UNIX, SOCK_STREAM, 0);
        int live = probe >= 0 && connect(probe, (struct sockaddr *)&a, sizeof(a)) == 0;
        int refused = !live && errno == ECONNREFUSED;
        if (probe >= 0) close(probe);
        if (live) {
            fprintf(stderr, "ERROR: --control %s: another server is using it\n", path);
            close(fd);
            return -1;
        }
        /* Only replace a socket: opening a socket file fails with ENXIO,
         * a symlink with ELOOP (O_NOFOLLOW), anything else opens. */
        int is_socket = 0;
        if (refused) {
            int o = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
            if (o >= 0) close(o);
            else is_socket = errno == ENXIO;
            errno = EADDRINUSE;
        }
        if (is_socket && unlink(path) == 0 && bind_listen(fd, &a) == 0) return fd;
    }
    fprintf(stderr, "ERROR: --control %s: %s (use a path in a directory only the server "
                    "user can write, e.g. /run/clawsec/)\n", path, strerror(errno));
    close(fd);
    return -1;
}

void control_serve(int listen_fd, void (*dump)(FILE *out, void *ctx), void *ctx) {
    int c = accept(listen_fd, NULL, NULL);
    if (c < 0) return;
    struct timeval tv = { 1, 0 };
    setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    FILE *out = fdopen(c, "w");
    if (!out) {
        close(c);
        return;
    }
    dump(out, ctx);
    fclose(out);
}

int control_status(const char *path) {
    struct sockaddr_un a;
    if (fill_addr(path, &a) != 0) return 1;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0 || connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        fprintf(stderr, "ERROR: cannot reach the server at %s: %s\n", path, strerror(errno));
        if (fd >= 0) close(fd);
        return 1;
    }
    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0)
        if (fwrite(buf, 1, (size_t)n, stdout) != (size_t)n) break;
    close(fd);
    return 0;
}
