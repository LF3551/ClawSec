/*
 * config.c — --config FILE (see config.h)
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>

#include "config.h"

static const struct { const char *key; const char *opt; int has_arg; } aliases[] = {
    { "listen", "-l", 0 }, { "port", "-p", 1 }, { "keep-open", "-K", 0 },
    { "udp", "-u", 0 }, { "ipv4", "-4", 0 }, { "ipv6", "-6", 0 }, { "chat", "-c", 0 },
    { "verbose", "-v", 0 }, { "timeout", "-w", 1 }, { "compress", "-z", 0 },
    { "progress", "-P", 0 }, { "verify", "-V", 0 }, { "name", "-n", 1 },
    { "banner", "-b", 0 }, { "forward", "-L", 1 }, { "reverse", "-R", 1 },
};

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t') s++;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n')) e--;
    *e = '\0';
    return s;
}

/* Append s to the vector: a copy (values from the file), or the original
 * pointer (command-line arguments: -k overwrites them in place so the
 * password does not stay visible in /proc/<pid>/cmdline) */
static int push_ptr(char ***v, int *n, int *cap, char *s) {
    if (*n + 1 >= *cap) {
        int nc = *cap ? *cap * 2 : 32;
        char **nv = realloc(*v, (size_t)nc * sizeof(char *));
        if (!nv) return -1;
        *v = nv;
        *cap = nc;
    }
    (*v)[(*n)++] = s;
    (*v)[*n] = NULL;
    return 0;
}

static int push(char ***v, int *n, int *cap, const char *s) {
    if (*n + 1 >= *cap) {
        int nc = *cap ? *cap * 2 : 32;
        char **nv = realloc(*v, (size_t)nc * sizeof(char *));
        if (!nv) return -1;
        *v = nv;
        *cap = nc;
    }
    if (s && !((*v)[(*n)++] = strdup(s))) return -1;
    (*v)[*n] = NULL;
    return 0;
}

static int load(const char *path, const struct option *lo, char ***v, int *n, int *cap) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "ERROR: --config %s: %s\n", path, strerror(errno));
        return -1;
    }
    struct stat st;
    if (fstat(fileno(f), &st) == 0 && (st.st_mode & (S_IWGRP | S_IWOTH)))
        fprintf(stderr, "Warning: %s is writable by group/others: anyone who can edit it "
                        "controls the server's options\n", path);
    char line[1024];
    int lineno = 0, rc = 0;
    while (rc == 0 && fgets(line, sizeof(line), f)) {
        lineno++;
        char *l = trim(line);
        if (!*l || *l == '#') continue;
        char *eq = strchr(l, '='), *val = NULL;
        if (eq) {
            *eq = '\0';
            val = trim(eq + 1);
            size_t vl = strlen(val);
            if (vl >= 2 && val[0] == '"' && val[vl - 1] == '"') {    /* "quoted" */
                val[vl - 1] = '\0';
                val++;
            }
        }
        char *key = trim(l);
        if (!strcmp(key, "k") || !strcmp(key, "password") || !strcmp(key, "config")) {
            fprintf(stderr, "ERROR: %s:%d: '%s' is not allowed in a config file%s\n", path,
                    lineno, key, strcmp(key, "config") ? " (use key-file)" : "");
            rc = -1;
            break;
        }
        const char *opt = NULL;
        int has_arg = -1;
        char longopt[96];
        for (size_t i = 0; i < sizeof(aliases) / sizeof(aliases[0]); i++)
            if (!strcmp(key, aliases[i].key)) { opt = aliases[i].opt; has_arg = aliases[i].has_arg; }
        if (!opt)
            for (const struct option *o = lo; o->name; o++)
                if (!strcmp(key, o->name)) {
                    snprintf(longopt, sizeof(longopt), "--%s", o->name);
                    opt = longopt;
                    has_arg = o->has_arg == no_argument ? 0 : 1;
                }
        if (!opt) {
            fprintf(stderr, "ERROR: %s:%d: unknown option '%s'\n", path, lineno, key);
            rc = -1;
            break;
        }
        if (has_arg) {
            if (!val || !*val) {
                fprintf(stderr, "ERROR: %s:%d: '%s' needs a value\n", path, lineno, key);
                rc = -1;
                break;
            }
            if (push(v, n, cap, opt) || push(v, n, cap, val)) rc = -1;
        } else {
            if (val && (!strcasecmp(val, "no") || !strcasecmp(val, "false") || !strcmp(val, "0")))
                continue;
            if (val && *val && strcasecmp(val, "yes") && strcasecmp(val, "true") && strcmp(val, "1")) {
                fprintf(stderr, "ERROR: %s:%d: '%s' is a flag (yes/no)\n", path, lineno, key);
                rc = -1;
                break;
            }
            if (push(v, n, cap, opt)) rc = -1;
        }
    }
    fclose(f);
    return rc;
}

int config_expand(int *argc, char ***argv, const struct option *long_opts) {
    const char *path = NULL;
    int at = -1, width = 0;
    for (int i = 1; i < *argc; i++) {
        const char *a = (*argv)[i];
        if (!strcmp(a, "--")) break;
        if (!strcmp(a, "--config")) {
            if (i + 1 >= *argc) {
                fprintf(stderr, "ERROR: --config needs a file\n");
                return -1;
            }
            path = (*argv)[i + 1];
            at = i;
            width = 2;
            break;
        }
        if (!strncmp(a, "--config=", 9)) {
            path = a + 9;
            at = i;
            width = 1;
            break;
        }
    }
    if (!path) return 0;
    char **v = NULL;
    int n = 0, cap = 0;
    if (push_ptr(&v, &n, &cap, (*argv)[0]) || load(path, long_opts, &v, &n, &cap)) return -1;
    for (int i = 1; i < *argc; i++) {
        if (i >= at && i < at + width) continue;
        if (push_ptr(&v, &n, &cap, (*argv)[i])) return -1;
    }
    *argc = n;
    *argv = v;                 /* lives for the whole process */
    return 0;
}
