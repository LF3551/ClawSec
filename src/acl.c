/*
 * acl.c — destination address policy for the SOCKS5 server
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "acl.h"

typedef struct {
    int family;                 /* AF_INET or AF_INET6 */
    unsigned char addr[16];     /* network address, network byte order */
    int prefix;                 /* prefix length */
} cidr_t;

#define ACL_MAX 64

static const char *default_deny[] = {
    "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "100.100.100.200/32",
    "168.63.129.16/32", "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "fe80::/10", "ff00::/8", "fd00:ec2::254/128",
    NULL
};

static cidr_t s_allow[ACL_MAX];
static int s_allow_n = -1;          /* -1 = default policy */
static cidr_t s_deny[ACL_MAX];
static int s_deny_n = -1;           /* lazily parsed default deny list */

static int parse_cidr(const char *s, cidr_t *out) {
    char buf[INET6_ADDRSTRLEN + 8];
    size_t n = strlen(s);
    if (n == 0 || n >= sizeof(buf)) return -1;
    memcpy(buf, s, n + 1);

    int prefix = -1;
    char *slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        char *end;
        long p = strtol(slash + 1, &end, 10);
        if (slash[1] == '\0' || *end != '\0' || p < 0 || p > 128) return -1;
        prefix = (int)p;
    }
    memset(out, 0, sizeof(*out));
    if (inet_pton(AF_INET, buf, out->addr) == 1) {
        out->family = AF_INET;
        if (prefix < 0) prefix = 32;
        if (prefix > 32) return -1;
    } else if (inet_pton(AF_INET6, buf, out->addr) == 1) {
        out->family = AF_INET6;
        if (prefix < 0) prefix = 128;
    } else {
        return -1;
    }
    out->prefix = prefix;
    return 0;
}

static int cidr_match(const cidr_t *c, int family, const unsigned char *addr) {
    if (c->family != family) return 0;
    int full = c->prefix / 8, rest = c->prefix % 8;
    if (memcmp(c->addr, addr, (size_t)full) != 0) return 0;
    if (rest) {
        unsigned char mask = (unsigned char)(0xFF << (8 - rest));
        if ((c->addr[full] & mask) != (addr[full] & mask)) return 0;
    }
    return 1;
}

static void load_defaults(void) {
    if (s_deny_n >= 0) return;
    s_deny_n = 0;
    for (int i = 0; default_deny[i] && s_deny_n < ACL_MAX; i++)
        if (parse_cidr(default_deny[i], &s_deny[s_deny_n]) == 0)
            s_deny_n++;
}

int acl_set_allow_list(const char *list) {
    if (!list) return -1;
    char *copy = strdup(list);
    if (!copy) return -1;
    int n = 0, rc = 0;
    char *save = NULL;
    for (char *tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        while (*tok == ' ') tok++;
        if (*tok == '\0') continue;
        if (n >= ACL_MAX || parse_cidr(tok, &s_allow[n]) != 0) {
            fprintf(stderr, "ERROR: invalid --socks-allow entry '%s' "
                            "(use addresses or CIDRs, e.g. 10.0.0.0/8,2001:db8::/32)\n", tok);
            rc = -1;
            break;
        }
        n++;
    }
    free(copy);
    if (rc == 0 && n == 0) {
        fprintf(stderr, "ERROR: --socks-allow list is empty\n");
        rc = -1;
    }
    s_allow_n = rc == 0 ? n : -1;
    return rc;
}

void acl_reset(void) {
    s_allow_n = -1;
}

int acl_allowed(const struct sockaddr *sa, socklen_t len) {
    unsigned char addr[16];
    int family;

    if (!sa) return 0;
    if (sa->sa_family == AF_INET && len >= (socklen_t)sizeof(struct sockaddr_in)) {
        family = AF_INET;
        memcpy(addr, &((const struct sockaddr_in *)sa)->sin_addr, 4);
    } else if (sa->sa_family == AF_INET6 && len >= (socklen_t)sizeof(struct sockaddr_in6)) {
        const struct in6_addr *a6 = &((const struct sockaddr_in6 *)sa)->sin6_addr;
        static const unsigned char nat64[12] = { 0x00, 0x64, 0xff, 0x9b };
        if (IN6_IS_ADDR_V4MAPPED(a6) ||           /* ::ffff:a.b.c.d */
            memcmp(a6->s6_addr, nat64, 12) == 0) { /* 64:ff9b::a.b.c.d (NAT64) */
            family = AF_INET;
            memcpy(addr, a6->s6_addr + 12, 4);
        } else {
            family = AF_INET6;
            memcpy(addr, a6->s6_addr, 16);
        }
    } else {
        return 0;
    }

    if (s_allow_n >= 0) {                        /* explicit allow list */
        for (int i = 0; i < s_allow_n; i++)
            if (cidr_match(&s_allow[i], family, addr)) return 1;
        return 0;
    }
    load_defaults();
    for (int i = 0; i < s_deny_n; i++)
        if (cidr_match(&s_deny[i], family, addr)) return 0;
    return 1;
}
