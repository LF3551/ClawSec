/*
 * users.c — per-user passwords for the server (--users FILE)
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/crypto.h>

#include "users.h"
#include "spake2.h"

#define USER_SALT "ClawSec v4 SPAKE2 user:"

int user_name_valid(const char *name) {
    size_t n = name ? strlen(name) : 0;
    if (n == 0 || n > USER_NAME_MAX) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '.' || c == '_' || c == '-'))
            return 0;
    }
    return 1;
}

int user_password_to_w(const char *name, const char *password, size_t pass_len,
                       unsigned char w[32]) {
    unsigned char salt[sizeof(USER_SALT) - 1 + USER_NAME_MAX];
    if (!user_name_valid(name) || !password || pass_len == 0) return -1;
    size_t n = strlen(name);
    memcpy(salt, USER_SALT, sizeof(USER_SALT) - 1);
    memcpy(salt + sizeof(USER_SALT) - 1, name, n);
    return spake2_password_to_w(password, pass_len, salt, sizeof(USER_SALT) - 1 + n, w);
}

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Parse "name:v1:hex". Returns 1 and fills name/w, 0 for blank/comment, -1 if malformed */
static int parse_line(char *line, char name[USER_NAME_MAX + 1], unsigned char w[32]) {
    line[strcspn(line, "\r\n")] = '\0';
    char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '\0' || *p == '#') return 0;
    char *c1 = strchr(p, ':');
    if (!c1) return -1;
    *c1 = '\0';
    if (!user_name_valid(p)) return -1;
    char *c2 = strchr(c1 + 1, ':');
    if (!c2 || (size_t)(c2 - (c1 + 1)) != 2 || strncmp(c1 + 1, "v1", 2) != 0) return -1;
    const char *hex = c2 + 1;
    if (strlen(hex) != 64) return -1;
    for (int i = 0; i < 32; i++) {
        int hi = hexval(hex[2 * i]), lo = hexval(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        w[i] = (unsigned char)(hi << 4 | lo);
    }
    snprintf(name, USER_NAME_MAX + 1, "%s", p);
    return 1;
}

int users_lookup(const char *path, const char *name, unsigned char w[32]) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[256], uname[USER_NAME_MAX + 1];
    unsigned char tmp[32];
    int found = 0, lineno = 0, bad = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        int r = parse_line(line, uname, tmp);
        if (r < 0) {
            if (!bad) fprintf(stderr, "users: %s:%d: malformed line ignored\n", path, lineno);
            bad = 1;
            continue;
        }
        if (r == 1 && !found && strcmp(uname, name) == 0) {
            memcpy(w, tmp, 32);
            found = 1;                 /* keep reading: same work for every name */
        }
    }
    OPENSSL_cleanse(tmp, sizeof(tmp));
    OPENSSL_cleanse(line, sizeof(line));
    fclose(f);
    return found;
}

int users_set(const char *path, const char *name, const unsigned char w[32]) {
    if (!user_name_valid(name)) return -1;
    char tmp_path[4096];
    if (snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%ld", path, (long)getpid()) >=
        (int)sizeof(tmp_path))
        return -1;
    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return -1;
    FILE *out = fdopen(fd, "w");
    if (!out) { close(fd); unlink(tmp_path); return -1; }

    FILE *in = fopen(path, "r");
    int replaced = 0;
    if (in) {
        char line[256], copy[256], uname[USER_NAME_MAX + 1];
        unsigned char tmp[32];
        while (fgets(line, sizeof(line), in)) {
            memcpy(copy, line, sizeof(copy));
            int r = parse_line(copy, uname, tmp);
            if (r == 1 && strcmp(uname, name) == 0) {
                if (replaced) continue;  /* drop duplicates */
                replaced = 1;
                fprintf(out, "%s:v1:", name);
                for (int i = 0; i < 32; i++) fprintf(out, "%02x", w[i]);
                fputc('\n', out);
                continue;
            }
            fputs(line, out);
            if (line[0] && line[strlen(line) - 1] != '\n') fputc('\n', out);
        }
        OPENSSL_cleanse(tmp, sizeof(tmp));
        fclose(in);
    } else if (errno != ENOENT) {
        fclose(out);
        unlink(tmp_path);
        return -1;
    } else {
        fputs("# ClawSec users: name:v1:<SPAKE2 password scalar> (keep this file private)\n", out);
    }
    if (!replaced) {
        fprintf(out, "%s:v1:", name);
        for (int i = 0; i < 32; i++) fprintf(out, "%02x", w[i]);
        fputc('\n', out);
    }
    if (fflush(out) != 0 || fsync(fileno(out)) != 0) {
        fclose(out);
        unlink(tmp_path);
        return -1;
    }
    fclose(out);
    if (rename(tmp_path, path) != 0) {
        unlink(tmp_path);
        return -1;
    }
    return 0;
}

int users_check_file(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        fprintf(stderr, "ERROR: --users %s: %s (create it with --add-user)\n", path, strerror(errno));
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "ERROR: --users %s is not a regular file\n", path);
        return -1;
    }
    if (access(path, R_OK) != 0) {
        fprintf(stderr, "ERROR: --users %s is not readable\n", path);
        return -1;
    }
    if (st.st_mode & (S_IRWXG | S_IRWXO))
        fprintf(stderr, "Warning: %s is accessible by group/others; it holds login "
                        "secrets (chmod 600)\n", path);
    return 0;
}
