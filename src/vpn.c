/*
 * vpn.c — VPN address management (see vpn.h)
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vpn.h"

typedef struct {
    uint32_t idx;                  /* host number */
    int owner;                     /* -2 = reserved for the server */
} slot_t;

struct vpn_pool {
    uint32_t net4, server4;        /* host byte order */
    int prefix4;
    uint32_t hosts;                /* number of host indexes (1 .. hosts) */
    slot_t *used;                  /* sparse: only assigned/reserved numbers */
    size_t nused, cap;
    int has_v6;
    struct in6_addr net6, server6;
    int prefix6;
    int mtu;
};

const char *vpn_cfg_status_str(int status) {
    switch (status) {
    case VPN_CFG_OK: return "ok";
    case VPN_CFG_IN_USE: return "address already in use by another client";
    case VPN_CFG_EXHAUSTED: return "no free address in the VPN subnet";
    case VPN_CFG_OUTSIDE: return "address is not usable in the server's VPN subnet";
    default: return "invalid request";
    }
}

int vpn_cfg_build_request(unsigned char *buf, size_t len, struct in_addr want_v4) {
    if (len < VPN_CFG_REQ_LEN) return -1;
    memcpy(buf, VPN_CFG_REQ_TAG, 4);
    buf[4] = 1;
    buf[5] = 0;
    memcpy(buf + 6, &want_v4.s_addr, 4);
    return VPN_CFG_REQ_LEN;
}

int vpn_cfg_parse_request(const unsigned char *buf, size_t len, struct in_addr *want_v4) {
    if (len != VPN_CFG_REQ_LEN || memcmp(buf, VPN_CFG_REQ_TAG, 4) != 0 || buf[4] != 1)
        return -1;
    memcpy(&want_v4->s_addr, buf + 6, 4);
    return 0;
}

int vpn_cfg_build_reply(unsigned char *buf, size_t len, int status, const vpn_cfg_t *c) {
    if (len < VPN_CFG_REP_LEN) return -1;
    unsigned char *p = buf;
    memcpy(p, VPN_CFG_REP_TAG, 4); p += 4;
    *p++ = 1;
    *p++ = (unsigned char)status;
    vpn_cfg_t zero;
    memset(&zero, 0, sizeof(zero));
    if (!c || status != VPN_CFG_OK) c = &zero;
    memcpy(p, &c->v4.s_addr, 4); p += 4;
    *p++ = (unsigned char)c->v4_prefix;
    memcpy(p, &c->v4_gw.s_addr, 4); p += 4;
    *p++ = (unsigned char)(c->has_v6 ? 1 : 0);
    memcpy(p, &c->v6, 16); p += 16;
    *p++ = (unsigned char)c->v6_prefix;
    memcpy(p, &c->v6_gw, 16); p += 16;
    *p++ = (unsigned char)(c->mtu >> 8);
    *p++ = (unsigned char)(c->mtu & 0xff);
    return (int)(p - buf);
}

int vpn_cfg_parse_reply(const unsigned char *buf, size_t len, int *status, vpn_cfg_t *c) {
    if (len != VPN_CFG_REP_LEN || memcmp(buf, VPN_CFG_REP_TAG, 4) != 0 || buf[4] != 1)
        return -1;
    const unsigned char *p = buf + 5;
    *status = *p++;
    memset(c, 0, sizeof(*c));
    memcpy(&c->v4.s_addr, p, 4); p += 4;
    c->v4_prefix = *p++;
    memcpy(&c->v4_gw.s_addr, p, 4); p += 4;
    c->has_v6 = *p++ != 0;
    memcpy(&c->v6, p, 16); p += 16;
    c->v6_prefix = *p++;
    memcpy(&c->v6_gw, p, 16); p += 16;
    c->mtu = (p[0] << 8) | p[1];
    if (*status == VPN_CFG_OK &&
        (c->v4_prefix < 1 || c->v4_prefix > 32 ||
         (c->has_v6 && (c->v6_prefix < 1 || c->v6_prefix > 128)) ||
         c->mtu < 576 || c->mtu > 1500))
        return -1;
    return 0;
}

/* ── pool ── */

static uint32_t index_of(const vpn_pool_t *p, int family, const unsigned char *a);

static int owner_of(const vpn_pool_t *p, uint32_t idx) {
    for (size_t i = 0; i < p->nused; i++)
        if (p->used[i].idx == idx) return p->used[i].owner;
    return -1;
}

static int set_owner(vpn_pool_t *p, uint32_t idx, int owner) {
    if (p->nused == p->cap) {
        size_t nc = p->cap ? p->cap * 2 : 16;
        slot_t *n = realloc(p->used, nc * sizeof(*n));
        if (!n) return -1;
        p->used = n;
        p->cap = nc;
    }
    p->used[p->nused].idx = idx;
    p->used[p->nused].owner = owner;
    p->nused++;
    return 0;
}

static void v6_with_index(const struct in6_addr *net, uint32_t index, struct in6_addr *out) {
    *out = *net;
    out->s6_addr[12] |= (unsigned char)(index >> 24);
    out->s6_addr[13] |= (unsigned char)(index >> 16);
    out->s6_addr[14] |= (unsigned char)(index >> 8);
    out->s6_addr[15] |= (unsigned char)index;
}

static void v6_mask(struct in6_addr *a, int prefix) {
    for (int i = 0; i < 16; i++) {
        int bits = prefix - i * 8;
        if (bits >= 8) continue;
        a->s6_addr[i] &= bits <= 0 ? 0 : (unsigned char)(0xff << (8 - bits));
    }
}

vpn_pool_t *vpn_pool_new(struct in_addr server4, int prefix4,
                         const struct in6_addr *server6, int prefix6, int mtu) {
    if (prefix4 < 8 || prefix4 > 30) return NULL;
    if (server6 && (prefix6 < 64 || prefix6 > 120)) return NULL;
    vpn_pool_t *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    uint32_t mask = prefix4 == 0 ? 0 : 0xffffffffu << (32 - prefix4);
    p->server4 = ntohl(server4.s_addr);
    p->net4 = p->server4 & mask;
    p->prefix4 = prefix4;
    p->hosts = (1u << (32 - prefix4)) - 2;              /* without network/broadcast */
    uint32_t sidx = p->server4 - p->net4;
    if (sidx == 0 || sidx > p->hosts) { free(p); return NULL; }
    if (set_owner(p, sidx, -2) != 0) { free(p); return NULL; }   /* the server */
    if (server6) {
        p->has_v6 = 1;
        p->server6 = *server6;
        p->net6 = *server6;
        v6_mask(&p->net6, prefix6);
        p->prefix6 = prefix6;
        /* the host numbers of the IPv4 pool must fit into the IPv6 host part */
        if (128 - prefix6 < 32 && p->hosts >= (1u << (128 - prefix6))) {
            vpn_pool_free(p);
            return NULL;
        }
        /* the server's IPv6 host number is not available to clients either */
        uint32_t i6 = index_of(p, 6, server6->s6_addr);
        if (i6 && owner_of(p, i6) == -1 && set_owner(p, i6, -2) != 0) {
            vpn_pool_free(p);
            return NULL;
        }
    }
    p->mtu = mtu;
    return p;
}

void vpn_pool_free(vpn_pool_t *p) {
    if (!p) return;
    free(p->used);
    free(p);
}

static void fill_cfg(const vpn_pool_t *p, uint32_t idx, vpn_cfg_t *out) {
    memset(out, 0, sizeof(*out));
    out->v4.s_addr = htonl(p->net4 + idx);
    out->v4_gw.s_addr = htonl(p->server4);
    out->v4_prefix = p->prefix4;
    if (p->has_v6) {
        out->has_v6 = 1;
        v6_with_index(&p->net6, idx, &out->v6);
        out->v6_gw = p->server6;
        out->v6_prefix = p->prefix6;
    }
    out->mtu = p->mtu;
}

int vpn_pool_assign(vpn_pool_t *p, struct in_addr want_v4, int owner, vpn_cfg_t *out) {
    if (owner < 0) return VPN_CFG_INVALID;
    vpn_pool_release(p, owner);                    /* one address per owner */
    uint32_t idx = 0;
    if (want_v4.s_addr != 0) {
        uint32_t w = ntohl(want_v4.s_addr);
        if ((w & (0xffffffffu << (32 - p->prefix4))) != p->net4) return VPN_CFG_OUTSIDE;
        idx = w - p->net4;
        if (idx == 0 || idx > p->hosts) return VPN_CFG_OUTSIDE;
        int o = owner_of(p, idx);
        if (o == -2) return VPN_CFG_OUTSIDE;
        if (o >= 0) return VPN_CFG_IN_USE;
    } else {
        for (uint32_t i = 1; i <= p->hosts; i++)        /* at most nused + 1 steps */
            if (owner_of(p, i) == -1) { idx = i; break; }
        if (!idx) return VPN_CFG_EXHAUSTED;
    }
    if (set_owner(p, idx, owner) != 0) return VPN_CFG_EXHAUSTED;
    fill_cfg(p, idx, out);
    return VPN_CFG_OK;
}

void vpn_pool_release(vpn_pool_t *p, int owner) {
    if (!p || owner < 0) return;
    for (size_t i = 0; i < p->nused;) {
        if (p->used[i].owner == owner) p->used[i] = p->used[--p->nused];
        else i++;
    }
}

int vpn_packet_addrs(const unsigned char *pkt, size_t len, int *family,
                     unsigned char src[16], unsigned char dst[16]) {
    if (len < 1) return -1;
    int v = pkt[0] >> 4;
    if (v == 4) {
        if (len < 20 || (size_t)(pkt[0] & 0x0f) * 4 < 20) return -1;
        *family = 4;
        memcpy(src, pkt + 12, 4);
        memcpy(dst, pkt + 16, 4);
        return 0;
    }
    if (v == 6) {
        if (len < 40) return -1;
        *family = 6;
        memcpy(src, pkt + 8, 16);
        memcpy(dst, pkt + 24, 16);
        return 0;
    }
    return -1;
}

/* host index of an address in the pool, or 0 */
static uint32_t index_of(const vpn_pool_t *p, int family, const unsigned char *a) {
    if (family == 4) {
        uint32_t x;
        memcpy(&x, a, 4);
        x = ntohl(x);
        if ((x & (0xffffffffu << (32 - p->prefix4))) != p->net4) return 0;
        uint32_t idx = x - p->net4;
        return idx <= p->hosts ? idx : 0;
    }
    if (!p->has_v6) return 0;
    /* assigned addresses are net6 with the host number in the last 4 bytes */
    if (memcmp(a, p->net6.s6_addr, 12) != 0) return 0;
    struct in6_addr masked;
    memcpy(&masked, a, 16);
    v6_mask(&masked, p->prefix6);
    if (memcmp(&masked, &p->net6, 16) != 0) return 0;
    uint32_t idx = 0;
    for (int i = 12; i < 16; i++)
        idx = (idx << 8) | (uint32_t)(a[i] ^ p->net6.s6_addr[i]);
    return idx <= p->hosts ? idx : 0;
}

int vpn_pool_route(const vpn_pool_t *p, const unsigned char *pkt, size_t len) {
    int fam;
    unsigned char src[16], dst[16];
    if (vpn_packet_addrs(pkt, len, &fam, src, dst) != 0) return -1;
    uint32_t idx = index_of(p, fam, dst);
    if (!idx) return -1;
    int o = owner_of(p, idx);
    return o >= 0 ? o : -1;
}

int vpn_pool_src_ok(const vpn_pool_t *p, int owner, const unsigned char *pkt, size_t len) {
    int fam;
    unsigned char src[16], dst[16];
    if (owner < 0 || vpn_packet_addrs(pkt, len, &fam, src, dst) != 0) return 0;
    uint32_t idx = index_of(p, fam, src);
    if (!idx || owner_of(p, idx) != owner) return 0;
    if (fam == 6) {                                   /* exact address, not just the index */
        struct in6_addr want;
        v6_with_index(&p->net6, idx, &want);
        return memcmp(&want, src, 16) == 0;
    }
    return 1;
}

void vpn_pool_subnets(const vpn_pool_t *p, char *v4, size_t v4len, char *v6, size_t v6len) {
    struct in_addr n;
    char b[INET6_ADDRSTRLEN];
    n.s_addr = htonl(p->net4);
    inet_ntop(AF_INET, &n, b, sizeof(b));
    snprintf(v4, v4len, "%s/%d", b, p->prefix4);
    if (v6 && v6len) {
        v6[0] = '\0';
        if (p->has_v6) {
            inet_ntop(AF_INET6, &p->net6, b, sizeof(b));
            snprintf(v6, v6len, "%s/%d", b, p->prefix6);
        }
    }
}

int vpn_packet_local_noise(const unsigned char *pkt, size_t len) {
    int fam;
    unsigned char src[16], dst[16];
    if (vpn_packet_addrs(pkt, len, &fam, src, dst) != 0) return 0;
    if (fam == 4) return src[0] == 0 && src[1] == 0 && src[2] == 0 && src[3] == 0;
    static const unsigned char zero[16] = { 0 };
    return (src[0] == 0xfe && (src[1] & 0xc0) == 0x80) || memcmp(src, zero, 16) == 0;
}

int vpn_parse_cidr6(const char *cidr, struct in6_addr *addr, int *prefix) {
    char buf[INET6_ADDRSTRLEN + 8];
    if (!cidr || strlen(cidr) >= sizeof(buf)) return -1;
    snprintf(buf, sizeof(buf), "%s", cidr);
    char *slash = strchr(buf, '/');
    if (!slash) return -1;
    *slash = '\0';
    char *end;
    long pfx = strtol(slash + 1, &end, 10);
    if (*end != '\0' || pfx < 64 || pfx > 120) return -1;
    if (inet_pton(AF_INET6, buf, addr) != 1) return -1;
    if (IN6_IS_ADDR_UNSPECIFIED(addr) || IN6_IS_ADDR_MULTICAST(addr) ||
        IN6_IS_ADDR_LOOPBACK(addr) || IN6_IS_ADDR_LINKLOCAL(addr))
        return -1;
    *prefix = (int)pfx;
    return 0;
}
