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
#include <arpa/inet.h>

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

int users_parse_options(const char *opts, user_entry_t *e) {
    user_entry_t tmp;
    if (!e) e = &tmp;
    e->disabled = 0;
    e->has_ip = 0;
    e->socks_allow[0] = '\0';
    e->opts[0] = '\0';
    if (!opts || !*opts || strcmp(opts, "none") == 0) return 0;
    if (strlen(opts) >= USER_OPTS_MAX || strchr(opts, ':') || strpbrk(opts, " \t\r\n")) {
        fprintf(stderr, "users: invalid options '%s'\n", opts);
        return -1;
    }
    char buf[USER_OPTS_MAX];
    snprintf(buf, sizeof(buf), "%s", opts);
    char *save = NULL;
    for (char *tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        if (strcmp(tok, "disabled") == 0) {
            e->disabled = 1;
        } else if (strncmp(tok, "ip=", 3) == 0) {
            if (inet_pton(AF_INET, tok + 3, &e->ip) != 1) {
                fprintf(stderr, "users: invalid ip= '%s'\n", tok + 3);
                return -1;
            }
            e->has_ip = 1;
        } else if (strncmp(tok, "socks-allow=", 12) == 0 && tok[12]) {
            snprintf(e->socks_allow, sizeof(e->socks_allow), "%s", tok + 12);
            for (char *c = e->socks_allow; *c; c++)
                if (*c == ';') *c = ',';
            for (const char *c = e->socks_allow; *c; c++)
                if (!((*c >= '0' && *c <= '9') || (*c >= 'a' && *c <= 'f') ||
                      (*c >= 'A' && *c <= 'F') || *c == '.' || *c == ':' || *c == '/' ||
                      *c == ',')) {
                    fprintf(stderr, "users: invalid socks-allow '%s'\n", tok + 12);
                    return -1;
                }
        } else {
            fprintf(stderr, "users: unknown option '%s' (ip=, socks-allow=, disabled)\n", tok);
            return -1;
        }
    }
    snprintf(e->opts, sizeof(e->opts), "%s", opts);
    return 0;
}

/* Parse "name:v1:hex[:options]". Returns 1 and fills e, 0 for blank/comment, -1 if malformed */
int users_parse_line(char *line, user_entry_t *e) {
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
    char *hex = c2 + 1;
    char *c3 = strchr(hex, ':');
    if (c3) *c3 = '\0';
    if (strlen(hex) != 64) return -1;
    for (int i = 0; i < 32; i++) {
        int hi = hexval(hex[2 * i]), lo = hexval(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        e->w[i] = (unsigned char)(hi << 4 | lo);
    }
    if (users_parse_options(c3 ? c3 + 1 : "", e) != 0) return -1;
    snprintf(e->name, sizeof(e->name), "%s", p);
    return 1;
}

int users_lookup(const char *path, const char *name, user_entry_t *e) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[512];
    user_entry_t tmp;
    int found = 0, lineno = 0, bad = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        int r = users_parse_line(line, &tmp);
        if (r < 0) {
            if (!bad) fprintf(stderr, "users: %s:%d: malformed line ignored\n", path, lineno);
            bad = 1;
            continue;
        }
        if (r == 1 && !found && strcmp(tmp.name, name) == 0) {
            *e = tmp;
            found = 1;                 /* keep reading: same work for every name */
        }
    }
    OPENSSL_cleanse(&tmp, sizeof(tmp));
    OPENSSL_cleanse(line, sizeof(line));
    fclose(f);
    return found;
}

static void write_entry(FILE *out, const char *name, const unsigned char w[32], const char *opts) {
    fprintf(out, "%s:v1:", name);
    for (int i = 0; i < 32; i++) fprintf(out, "%02x", w[i]);
    if (opts && *opts && strcmp(opts, "none") != 0) fprintf(out, ":%s", opts);
    fputc('\n', out);
}

/* Rewrite the file: the line of `name` is replaced (w/opts NULL = keep),
 * removed (del), or appended. Returns 1 if name existed, 0 if not, -1 on error. */
static int rewrite(const char *path, const char *name, const unsigned char *w,
                   const char *opts, int del) {
    char tmp_path[4096];
    if (snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%ld", path, (long)getpid()) >=
        (int)sizeof(tmp_path))
        return -1;
    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return -1;
    FILE *out = fdopen(fd, "w");
    if (!out) { close(fd); unlink(tmp_path); return -1; }

    FILE *in = fopen(path, "r");
    int existed = 0;
    user_entry_t e;
    if (in) {
        char line[512], copy[512];
        while (fgets(line, sizeof(line), in)) {
            memcpy(copy, line, sizeof(copy));
            if (users_parse_line(copy, &e) == 1 && strcmp(e.name, name) == 0) {
                if (!existed && !del)
                    write_entry(out, name, w ? w : e.w, opts ? opts : e.opts);
                existed = 1;           /* duplicates are dropped */
                continue;
            }
            fputs(line, out);
            if (line[0] && line[strlen(line) - 1] != '\n') fputc('\n', out);
        }
        fclose(in);
    } else if (errno != ENOENT) {
        fclose(out);
        unlink(tmp_path);
        return -1;
    } else {
        fputs("# ClawSec users: name:v1:<SPAKE2 password scalar>[:options] "
              "(keep this file private)\n", out);
    }
    OPENSSL_cleanse(&e, sizeof(e));
    if (!existed && !del) {
        if (!w) {                      /* updating options of an unknown user */
            fclose(out);
            unlink(tmp_path);
            errno = ENOENT;
            return -1;
        }
        write_entry(out, name, w, opts);
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
    return existed;
}

int users_set(const char *path, const char *name, const unsigned char *w, const char *opts) {
    if (!user_name_valid(name) || (opts && users_parse_options(opts, NULL) != 0)) {
        errno = EINVAL;
        return -1;
    }
    return rewrite(path, name, w, opts, 0) < 0 ? -1 : 0;
}

int users_delete(const char *path, const char *name) {
    if (!user_name_valid(name)) return -1;
    return rewrite(path, name, NULL, NULL, 1);
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
