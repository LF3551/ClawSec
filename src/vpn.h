/*
 * vpn.h — VPN address management (--tun / --tun6 / --tun auto, multi-client hub)
 *
 * Address configuration inside the encrypted channel (ClawSec 4.2+):
 *   client -> server  "TCFQ" ver(1)=1 flags(1) want_v4(4)      0.0.0.0 = any
 *   server -> client  "TCFG" ver(1)=1 status(1)
 *                     v4(4) v4_prefix(1) v4_gw(4)
 *                     has_v6(1) v6(16) v6_prefix(1) v6_gw(16) mtu(2)
 * A 4.1 server ignores TCFQ (the client then falls back to its own --tun
 * address); a 4.1 client sends no TCFQ (the hub learns its address from
 * the source of its first packet).
 *
 * Address pool: the server's --tun subnet (IPv4, /8../30) and optional
 * --tun6 prefix (IPv6, /64../120). Client k gets the k-th host address of
 * the IPv4 subnet and the address with the same host number in the IPv6
 * prefix.
 */
#ifndef CLAWSEC_VPN_H
#define CLAWSEC_VPN_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

#define VPN_CFG_REQ_TAG "TCFQ"
#define VPN_CFG_REP_TAG "TCFG"
#define VPN_CFG_REQ_LEN (4 + 1 + 1 + 4)
#define VPN_CFG_REP_LEN (4 + 1 + 1 + 4 + 1 + 4 + 1 + 16 + 1 + 16 + 2)

enum {
    VPN_CFG_OK = 0,
    VPN_CFG_IN_USE = 1,        /* requested address belongs to another client */
    VPN_CFG_EXHAUSTED = 2,     /* no free address */
    VPN_CFG_OUTSIDE = 3,       /* requested address not usable in the subnet */
    VPN_CFG_INVALID = 4        /* malformed request */
};

typedef struct {
    struct in_addr v4, v4_gw;
    int v4_prefix;
    int has_v6;
    struct in6_addr v6, v6_gw;
    int v6_prefix;
    int mtu;
} vpn_cfg_t;

const char *vpn_cfg_status_str(int status);

int vpn_cfg_build_request(unsigned char *buf, size_t len, struct in_addr want_v4);
int vpn_cfg_parse_request(const unsigned char *buf, size_t len, struct in_addr *want_v4);
int vpn_cfg_build_reply(unsigned char *buf, size_t len, int status, const vpn_cfg_t *cfg);
int vpn_cfg_parse_reply(const unsigned char *buf, size_t len, int *status, vpn_cfg_t *cfg);

/* ── Address pool (server) ── */
typedef struct vpn_pool vpn_pool_t;

/* server6 may be NULL (no IPv6). Returns NULL for unsupported prefixes. */
vpn_pool_t *vpn_pool_new(struct in_addr server4, int prefix4,
                         const struct in6_addr *server6, int prefix6, int mtu);
void vpn_pool_free(vpn_pool_t *p);

/* Assign an address to owner (>= 0): want_v4 = 0.0.0.0 picks the lowest
 * free one. Fills out (gateway = server addresses). Returns VPN_CFG_*. */
int vpn_pool_assign(vpn_pool_t *p, struct in_addr want_v4, int owner, vpn_cfg_t *out);
void vpn_pool_release(vpn_pool_t *p, int owner);

/* Owner of the destination of an IP packet, or -1 (unknown, the server
 * itself, broadcast/multicast). */
int vpn_pool_route(const vpn_pool_t *p, const unsigned char *pkt, size_t len);

/* 1 if the packet's source address is one assigned to owner (anti-spoofing) */
int vpn_pool_src_ok(const vpn_pool_t *p, int owner, const unsigned char *pkt, size_t len);

/* Server-side view of the subnet as "a.b.c.d/N" / "xx::/N" (for NAT) */
void vpn_pool_subnets(const vpn_pool_t *p, char *v4, size_t v4len, char *v6, size_t v6len);

/* ── Packet helpers ── */
/* Source / destination of an IPv4 or IPv6 packet. family = 4 or 6;
 * addr receives 4 or 16 bytes. Returns 0 or -1 (not a valid IP packet). */
int vpn_packet_addrs(const unsigned char *pkt, size_t len, int *family,
                     unsigned char src[16], unsigned char dst[16]);

/* 1 for packets a host's own stack sends on a new interface that are never
 * routed: IPv6 from link-local (fe80::/10) or unspecified (::) sources,
 * IPv4 from 0.0.0.0. */
int vpn_packet_local_noise(const unsigned char *pkt, size_t len);

/* Parse "fd00::1/64" (IPv6 CIDR; prefix 64..120). Returns 0 or -1. */
int vpn_parse_cidr6(const char *cidr, struct in6_addr *addr, int *prefix);

#endif
