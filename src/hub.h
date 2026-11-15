/*
 * hub.h — VPN server side: address configuration and the multi-client hub
 *
 * With -K --tun the listening process owns the TUN device and routes
 * packets; every client session runs in its own process (encryption only)
 * and exchanges raw IP packets with the hub over a SOCK_SEQPACKET socket.
 * Messages hub <-> session that are not IP packets start with 0xC_:
 *   session -> hub  HUB_ASSIGN  want_v4(4) legacy(1)
 *   hub -> session  HUB_RESULT  status(1) TCFG reply (VPN_CFG_REP_LEN)
 *   session -> hub  HUB_UDP_START  keys and tokens of the client's UDP channel
 */
#ifndef CLAWSEC_HUB_H
#define CLAWSEC_HUB_H

#include "vpn.h"

#define HUB_ASSIGN 0xC1
#define HUB_RESULT 0xC2
#define HUB_UDP_START 0xC6       /* session -> hub: UDP channel keys (see below) */
#define HUB_ASSIGN_LEN (1 + 4 + 1)
/* HUB_UDP_START tx_key(32) rx_key(32) hub_token(16) client_token(16)
 * user_ip(4, users file ip= or 0): the
 * hub validates the client's UDP probe and then encrypts/decrypts that
 * client's UDP data channel itself (it sees the plaintext packets anyway,
 * as it writes them to the TUN device) */
#define HUB_UDP_START_LEN (1 + 32 + 32 + 16 + 16 + 4)
#define HUB_RESULT_LEN (1 + 1 + VPN_CFG_REP_LEN)

typedef struct {
    vpn_pool_t *pool;          /* single-session server: local pool, owner 0 */
    int hub_fd;                /* hub session: ask the hub process (-1 otherwise) */
    int allow_udp;             /* server runs --tun-udp: TUDP is handled there */
    int configured;
} vpn_server_ctx_t;

/* tun_control_fn for servers: answers TCFQ (address request) and refuses the
 * UDP channel with "TUDN" when it is not offered. */
int vpn_server_control(int tunnel_fd, const unsigned char *msg, int len, void *ctx);

/* Hub session (child): configuration phase, then relay between the
 * encrypted channel and the hub socket. Returns 0 or -1. */
int hub_session(int tunnel_fd, int hub_fd);

#endif
