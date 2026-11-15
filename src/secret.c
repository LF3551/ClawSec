/*
 * secret.c — obtaining the session password without exposing it
 */
#ifdef __APPLE__
#define _DARWIN_C_SOURCE   /* O_NOFOLLOW etc. are hidden under strict POSIX */
#endif
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <sys/stat.h>

#include <openssl/crypto.h>

#include "secret.h"

void secret_wipe(void *buf, size_t len) {
    if (buf && len) OPENSSL_cleanse(buf, len);
}

static int store(const char *src, size_t n, char *out, size_t out_len) {
    if (n == 0) {
        fprintf(stderr, "ERROR: empty password\n");
        return -1;
    }
    if (n >= out_len || n > SECRET_MAX) {
        fprintf(stderr, "ERROR: password longer than %d bytes\n", SECRET_MAX);
        return -1;
    }
    memcpy(out, src, n);
    out[n] = '\0';
    return 0;
}

/* Strip one trailing "\n" or "\r\n" */
static size_t chomp(char *s, size_t n) {
    if (n && s[n - 1] == '\n') n--;
    if (n && s[n - 1] == '\r') n--;
    s[n] = '\0';
    return n;
}

int secret_from_arg(char *arg, char *out, size_t out_len) {
    if (!arg || !out) return -1;
    size_t n = strlen(arg);
    int rc = store(arg, n, out, out_len);
    /* Overwrite the argv copy: /proc/<pid>/cmdline and ps show this memory.
     * (There is still a short window before this runs; prefer --key-file or
     * CLAWSEC_PASSWORD.) */
    memset(arg, 'x', n);
    return rc;
}

int secret_from_file(const char *path, char *out, size_t out_len) {
    if (!path || !out) return -1;
    int fd = open(path, O_RDONLY | O_NOCTTY);
    if (fd < 0) {
        fprintf(stderr, "ERROR: cannot open key file %s: %s\n", path, strerror(errno));
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) == 0) {
        if (!S_ISREG(st.st_mode)) {
            fprintf(stderr, "ERROR: key file %s is not a regular file\n", path);
            close(fd);
            return -1;
        }
        if (st.st_mode & (S_IRWXG | S_IRWXO))
            fprintf(stderr, "Warning: key file %s is accessible by group/others "
                            "(chmod 600 %s)\n", path, path);
    }

    char buf[SECRET_MAX + 3];
    size_t total = 0;
    while (total < sizeof(buf) - 1) {
        ssize_t r = read(fd, buf + total, sizeof(buf) - 1 - total);
        if (r < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "ERROR: cannot read key file %s: %s\n", path, strerror(errno));
            close(fd);
            secret_wipe(buf, sizeof(buf));
            return -1;
        }
        if (r == 0) break;
        total += (size_t)r;
    }
    close(fd);
    buf[total] = '\0';

    char *nl = memchr(buf, '\n', total);       /* first line only */
    size_t n = nl ? (size_t)(nl - buf) + 1 : total;
    n = chomp(buf, n);
    int rc = store(buf, n, out, out_len);
    secret_wipe(buf, sizeof(buf));
    return rc;
}

int secret_from_env(char *out, size_t out_len) {
    if (!out) return -1;
    const char *v = getenv(SECRET_ENV);
    if (!v) return 1;
    int rc = store(v, strlen(v), out, out_len);
    /* Do not leak the password into child processes (-e, tools run by --tun) */
    unsetenv(SECRET_ENV);
    return rc;
}

int secret_prompt(const char *prompt, char *out, size_t out_len) {
    if (!out) return -1;
    int fd = open("/dev/tty", O_RDWR | O_NOCTTY);
    if (fd < 0) return 1;                       /* no terminal */

    struct termios old, quiet;
    int have_termios = tcgetattr(fd, &old) == 0;
    if (have_termios) {
        quiet = old;
        quiet.c_lflag &= ~(tcflag_t)ECHO;
        quiet.c_lflag |= ECHONL;
        tcsetattr(fd, TCSAFLUSH, &quiet);
    }
    if (prompt && write(fd, prompt, strlen(prompt)) < 0) { /* best effort */ }

    char buf[SECRET_MAX + 3];
    size_t n = 0;
    int rc = -1;
    for (;;) {
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0 || c == '\n') break;
        if (n < sizeof(buf) - 1) buf[n++] = c;
    }
    buf[n] = '\0';
    n = chomp(buf, n);

    if (have_termios) tcsetattr(fd, TCSAFLUSH, &old);
    close(fd);
    rc = store(buf, n, out, out_len);
    secret_wipe(buf, sizeof(buf));
    return rc;
}
