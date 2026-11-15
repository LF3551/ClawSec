/*
 * control.c — status socket of a -K server (see control.h)
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
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

int control_listen(const char *path) {
    struct sockaddr_un a;
    struct stat st;
    if (fill_addr(path, &a) != 0) return -1;
    if (lstat(path, &st) == 0) {
        if (!S_ISSOCK(st.st_mode)) {
            fprintf(stderr, "ERROR: --control %s exists and is not a socket\n", path);
            return -1;
        }
        unlink(path);                       /* stale socket of an earlier run */
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    mode_t old = umask(0177);               /* created as 0600 */
    int rc = bind(fd, (struct sockaddr *)&a, sizeof(a));
    umask(old);
    if (rc != 0 || listen(fd, 8) != 0) {
        fprintf(stderr, "ERROR: --control %s: %s\n", path, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
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
