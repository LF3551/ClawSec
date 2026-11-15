/*
 * test_vpn.c — VPN address configuration, pool, routing, anti-spoofing
 */
#define _POSIX_C_SOURCE 200809L
#include "test.h"
#include <arpa/inet.h>
#include "vpn.h"

static struct in_addr A4(const char *s) { struct in_addr a; inet_pton(AF_INET, s, &a); return a; }
static struct in6_addr A6(const char *s) { struct in6_addr a; inet_pton(AF_INET6, s, &a); return a; }

static int mk_v4(unsigned char *pkt, const char *src, const char *dst) {
    memset(pkt, 0, 20);
    pkt[0] = 0x45;
    struct in_addr s = A4(src), d = A4(dst);
    memcpy(pkt + 12, &s, 4);
    memcpy(pkt + 16, &d, 4);
    return 20;
}

static int mk_v6(unsigned char *pkt, const char *src, const char *dst) {
    memset(pkt, 0, 40);
    pkt[0] = 0x60;
    struct in6_addr s = A6(src), d = A6(dst);
    memcpy(pkt + 8, &s, 16);
    memcpy(pkt + 24, &d, 16);
    return 40;
}

void test_vpn_cfg_messages(void) {
    TEST_BEGIN("vpn: TCFQ/TCFG encode/decode, malformed rejected") {
        unsigned char b[128];
        struct in_addr w;
        int n = vpn_cfg_build_request(b, sizeof(b), A4("10.8.0.7"));
        ASSERT(n == VPN_CFG_REQ_LEN && vpn_cfg_parse_request(b, (size_t)n, &w) == 0 &&
               w.s_addr == A4("10.8.0.7").s_addr, "request roundtrip");
        ASSERT(vpn_cfg_parse_request(b, (size_t)n - 1, &w) == -1, "short request");
        vpn_cfg_t c, d;
        memset(&c, 0, sizeof(c));
        c.v4 = A4("10.8.0.7"); c.v4_gw = A4("10.8.0.1"); c.v4_prefix = 24;
        c.has_v6 = 1; c.v6 = A6("fd00::7"); c.v6_gw = A6("fd00::1"); c.v6_prefix = 64;
        c.mtu = 1400;
        int st;
        n = vpn_cfg_build_reply(b, sizeof(b), VPN_CFG_OK, &c);
        ASSERT(n == VPN_CFG_REP_LEN && vpn_cfg_parse_reply(b, (size_t)n, &st, &d) == 0 &&
               st == VPN_CFG_OK && memcmp(&c, &d, sizeof(c)) == 0, "reply roundtrip");
        b[10] = 99;                                  /* v4 prefix 99 */
        ASSERT(vpn_cfg_parse_reply(b, (size_t)n, &st, &d) == -1, "invalid prefix rejected");
        n = vpn_cfg_build_reply(b, sizeof(b), VPN_CFG_IN_USE, NULL);
        ASSERT(vpn_cfg_parse_reply(b, (size_t)n, &st, &d) == 0 && st == VPN_CFG_IN_USE,
               "error reply");
    } TEST_END;
}

void test_vpn_pool_assign(void) {
    TEST_BEGIN("vpn: pool assigns, refuses conflicts, releases, IPv6 pairs") {
        struct in6_addr s6 = A6("fd00:ab::1");
        vpn_pool_t *p = vpn_pool_new(A4("10.8.0.1"), 24, &s6, 64, 1400);
        ASSERT(p, "pool");
        vpn_cfg_t c;
        char b4[INET_ADDRSTRLEN], b6[INET6_ADDRSTRLEN];
        ASSERT(vpn_pool_assign(p, A4("0.0.0.0"), 1, &c) == VPN_CFG_OK, "auto 1");
        inet_ntop(AF_INET, &c.v4, b4, sizeof(b4));
        inet_ntop(AF_INET6, &c.v6, b6, sizeof(b6));
        ASSERT(strcmp(b4, "10.8.0.2") == 0 && strcmp(b6, "fd00:ab::2") == 0, "first free pair");
        ASSERT(c.v4_gw.s_addr == A4("10.8.0.1").s_addr && c.v4_prefix == 24, "gateway");
        ASSERT(vpn_pool_assign(p, A4("10.8.0.2"), 2, &c) == VPN_CFG_IN_USE, "taken");
        ASSERT(vpn_pool_assign(p, A4("10.8.0.1"), 2, &c) == VPN_CFG_OUTSIDE, "server address");
        ASSERT(vpn_pool_assign(p, A4("10.8.0.255"), 2, &c) == VPN_CFG_OUTSIDE, "broadcast");
        ASSERT(vpn_pool_assign(p, A4("10.9.0.5"), 2, &c) == VPN_CFG_OUTSIDE, "other subnet");
        ASSERT(vpn_pool_assign(p, A4("10.8.0.50"), 2, &c) == VPN_CFG_OK, "explicit");
        ASSERT(vpn_pool_assign(p, A4("0.0.0.0"), 3, &c) == VPN_CFG_OK &&
               c.v4.s_addr == A4("10.8.0.3").s_addr, "next auto");
        vpn_pool_release(p, 1);
        ASSERT(vpn_pool_assign(p, A4("0.0.0.0"), 4, &c) == VPN_CFG_OK &&
               c.v4.s_addr == A4("10.8.0.2").s_addr, "released address reused");
        vpn_pool_free(p);

        vpn_pool_t *small = vpn_pool_new(A4("192.168.9.1"), 30, NULL, 0, 1400);
        ASSERT(small, "small pool");
        ASSERT(vpn_pool_assign(small, A4("0.0.0.0"), 1, &c) == VPN_CFG_OK, "one client");
        ASSERT(vpn_pool_assign(small, A4("0.0.0.0"), 2, &c) == VPN_CFG_EXHAUSTED, "exhausted");
        ASSERT(!c.has_v6 || 1, "no v6");
        vpn_pool_free(small);
        vpn_pool_t *big = vpn_pool_new(A4("10.0.0.1"), 8, NULL, 0, 1400);
        ASSERT(big && vpn_pool_assign(big, A4("10.200.3.4"), 1, &c) == VPN_CFG_OK, "/8 works");
        vpn_pool_free(big);
        ASSERT(vpn_pool_new(A4("10.0.0.1"), 31, NULL, 0, 1400) == NULL, "/31 refused");
        struct in6_addr odd = A6("fd00::99");
        p = vpn_pool_new(A4("10.0.0.1"), 24, &odd, 64, 1400);
        ASSERT(vpn_pool_assign(p, A4("10.0.0.153"), 1, &c) == VPN_CFG_OUTSIDE,
               "host number of the server's IPv6 address is reserved");
        vpn_pool_free(p);
    } TEST_END;
}

void test_vpn_pool_route_spoof(void) {
    TEST_BEGIN("vpn: routing by destination and anti-spoofing (v4/v6)") {
        struct in6_addr s6 = A6("fd00:ab::1");
        vpn_pool_t *p = vpn_pool_new(A4("10.8.0.1"), 24, &s6, 64, 1400);
        vpn_cfg_t c;
        vpn_pool_assign(p, A4("10.8.0.2"), 7, &c);
        vpn_pool_assign(p, A4("10.8.0.3"), 8, &c);
        unsigned char pkt[64];
        int n = mk_v4(pkt, "8.8.8.8", "10.8.0.3");
        ASSERT(vpn_pool_route(p, pkt, (size_t)n) == 8, "v4 to client 8");
        n = mk_v6(pkt, "2001:db8::1", "fd00:ab::2");
        ASSERT(vpn_pool_route(p, pkt, (size_t)n) == 7, "v6 to client 7");
        n = mk_v4(pkt, "8.8.8.8", "10.8.0.1");
        ASSERT(vpn_pool_route(p, pkt, (size_t)n) == -1, "server address: not a client");
        n = mk_v4(pkt, "8.8.8.8", "10.8.0.255");
        ASSERT(vpn_pool_route(p, pkt, (size_t)n) == -1, "broadcast dropped");
        n = mk_v6(pkt, "2001:db8::1", "fd00:ab::1:2");
        ASSERT(vpn_pool_route(p, pkt, (size_t)n) == -1, "v6 outside the assigned form");
        n = mk_v4(pkt, "10.8.0.2", "1.1.1.1");
        ASSERT(vpn_pool_src_ok(p, 7, pkt, (size_t)n) == 1, "own v4 source");
        ASSERT(vpn_pool_src_ok(p, 8, pkt, (size_t)n) == 0, "spoofed v4 source");
        n = mk_v6(pkt, "fd00:ab::3", "2001:db8::1");
        ASSERT(vpn_pool_src_ok(p, 8, pkt, (size_t)n) == 1, "own v6 source");
        ASSERT(vpn_pool_src_ok(p, 7, pkt, (size_t)n) == 0, "spoofed v6 source");
        unsigned char junk[3] = { 0x45, 0, 0 };
        ASSERT(vpn_pool_route(p, junk, 3) == -1 && vpn_pool_src_ok(p, 7, junk, 3) == 0,
               "truncated packet");
        n = mk_v6(pkt, "fe80::1", "ff02::2");
        ASSERT(vpn_packet_local_noise(pkt, (size_t)n) && vpn_pool_src_ok(p, 7, pkt, (size_t)n) == 0,
               "link-local router solicitation: noise, not routed");
        n = mk_v6(pkt, "fd00:ab::2", "ff02::2");
        ASSERT(!vpn_packet_local_noise(pkt, (size_t)n), "global source is not noise");
                char s4[32], s6s[64];
        vpn_pool_subnets(p, s4, sizeof(s4), s6s, sizeof(s6s));
        ASSERT(strcmp(s4, "10.8.0.0/24") == 0 && strcmp(s6s, "fd00:ab::/64") == 0, "subnets");
        vpn_pool_free(p);
        struct in6_addr a;
        int pf;
        ASSERT(vpn_parse_cidr6("fd00::1/64", &a, &pf) == 0 && pf == 64, "cidr6");
        ASSERT(vpn_parse_cidr6("fd00::1/48", &a, &pf) == -1, "too short prefix");
        ASSERT(vpn_parse_cidr6("fe80::1/64", &a, &pf) == -1, "link-local refused");
        ASSERT(vpn_parse_cidr6("fd00::1", &a, &pf) == -1, "no prefix");
    } TEST_END;
}
