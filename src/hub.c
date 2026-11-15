/*
 * hub.c — VPN server side: address configuration and hub sessions
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "hub.h"
#include "tun.h"
#include "farm9crypt.h"
#include "util.h"
#include "options.h"

#define TVPN_HDR 6

/* Ask for an address: locally (single-session server) or from the hub */
static int assign(vpn_server_ctx_t *c, struct in_addr want, int legacy,
                  unsigned char reply[VPN_CFG_REP_LEN]) {
    /* a user with a fixed address (users file "ip=") always gets it; a
     * ClawSec < 4.2 client must already be using it */
    if (g_opt.session_user_ip.s_addr) {
        if (legacy && want.s_addr != g_opt.session_user_ip.s_addr) {
            vpn_cfg_build_reply(reply, VPN_CFG_REP_LEN, VPN_CFG_OUTSIDE, NULL);
            return VPN_CFG_OUTSIDE;
        }
        want = g_opt.session_user_ip;
    }
    if (c->hub_fd < 0) {
        vpn_cfg_t cfg;
        int st = vpn_pool_assign(c->pool, want, 0, &cfg);
        vpn_cfg_build_reply(reply, VPN_CFG_REP_LEN, st, &cfg);
        return st;
    }
    unsigned char q[HUB_ASSIGN_LEN], r[HUB_RESULT_LEN];
    q[0] = HUB_ASSIGN;
    memcpy(q + 1, &want.s_addr, 4);
    q[5] = (unsigned char)(legacy ? 1 : 0);
    if (send(c->hub_fd, q, sizeof(q), 0) != (ssize_t)sizeof(q)) return VPN_CFG_INVALID;
    for (;;) {                       /* packets for us cannot arrive before an address */
        ssize_t n = recv(c->hub_fd, r, sizeof(r), 0);
        if (n < 0 && errno == EINTR) continue;
        if (n != (ssize_t)sizeof(r) || r[0] != HUB_RESULT) return VPN_CFG_INVALID;
        break;
    }
    memcpy(reply, r + 2, VPN_CFG_REP_LEN);
    return r[1];
}

static int answer_request(vpn_server_ctx_t *c, int tunnel_fd, const unsigned char *msg, int len) {
    struct in_addr want;
    unsigned char reply[VPN_CFG_REP_LEN];
    int st;
    if (vpn_cfg_parse_request(msg, (size_t)len, &want) != 0) {
        st = VPN_CFG_INVALID;
        vpn_cfg_build_reply(reply, sizeof(reply), st, NULL);
    } else {
        st = assign(c, want, 0, reply);
    }
    if (farm9crypt_write(tunnel_fd, (char *)reply, (int)sizeof(reply)) != (int)sizeof(reply))
        return -1;
    if (st != VPN_CFG_OK) {
        char w[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &want, w, sizeof(w));
        log_msg(0, "vpn: address request %s refused: %s", want.s_addr ? w : "(any)",
                vpn_cfg_status_str(st));
        return -1;
    }
    vpn_cfg_t cfg;
    int s2;
    if (vpn_cfg_parse_reply(reply, sizeof(reply), &s2, &cfg) == 0) {
        char a4[INET_ADDRSTRLEN], a6[INET6_ADDRSTRLEN] = "";
        inet_ntop(AF_INET, &cfg.v4, a4, sizeof(a4));
        if (cfg.has_v6) inet_ntop(AF_INET6, &cfg.v6, a6, sizeof(a6));
        log_msg(1, "vpn: client address %s%s%s", a4, cfg.has_v6 ? " " : "", a6);
    }
    c->configured = 1;
    return 0;
}

int vpn_server_control(int tunnel_fd, const unsigned char *msg, int len, void *ctx) {
    vpn_server_ctx_t *c = ctx;
    if (len >= 4 && memcmp(msg, VPN_CFG_REQ_TAG, 4) == 0)
        return answer_request(c, tunnel_fd, msg, len);
    if (len >= 4 && memcmp(msg, "TUDP", 4) == 0 && !c->allow_udp) {
        /* refuse fast, so the client falls back to the TCP channel at once */
        return farm9crypt_write(tunnel_fd, (char *)"TUDN", 4) == 4 ? 0 : -1;
    }
    return 0;                                         /* unknown control message */
}

int hub_session(int tunnel_fd, int hub_fd) {
    vpn_server_ctx_t ctx = { NULL, hub_fd, 0, 0 };
    char buf[TVPN_HDR + 2048];

    /* Configuration phase: a 4.2 client asks for its address; a 4.1 client
     * just starts sending packets from its own --tun address. */
    while (!ctx.configured) {
        int n = farm9crypt_read(tunnel_fd, buf, sizeof(buf));
        if (n <= 0) return -1;
        if (n == 4 && memcmp(buf, "THB\n", 4) == 0) continue;
        if (n >= TVPN_HDR && memcmp(buf, "TVPN", 4) == 0) {
            int plen = ((unsigned char)buf[4] << 8) | (unsigned char)buf[5];
            const unsigned char *pkt = (const unsigned char *)buf + TVPN_HDR;
            if (plen <= 0 || plen + TVPN_HDR > n || (pkt[0] >> 4) != 4 || plen < 20) continue;
            struct in_addr src;
            memcpy(&src.s_addr, pkt + 12, 4);
            unsigned char reply[VPN_CFG_REP_LEN];
            int st = assign(&ctx, src, 1, reply);
            char a[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &src, a, sizeof(a));
            if (st != VPN_CFG_OK) {
                log_msg(0, "vpn: client (ClawSec < 4.2) uses %s: %s", a, vpn_cfg_status_str(st));
                return -1;
            }
            log_msg(1, "vpn: client (ClawSec < 4.2) at %s", a);
            if (send(hub_fd, pkt, (size_t)plen, 0) != plen) return -1;
            ctx.configured = 1;
            break;
        }
        if (vpn_server_control(tunnel_fd, (const unsigned char *)buf, n, &ctx) < 0) return -1;
    }

    tun_set_raw_fd(hub_fd);
    tun_set_control_handler(vpn_server_control, &ctx);
    tun_relay(hub_fd, tunnel_fd);
    tun_set_control_handler(NULL, NULL);
    return 0;
}
