/*
 * tun.c — TUN VPN implementation for ClawSec
 *
 * Creates a virtual network interface and relays encrypted IP packets
 * between the TUN device and the encrypted tunnel.
 *
 * Platform support:
 *   - macOS:  utun via sys/kern_control.h
 *   - Linux:  /dev/net/tun via linux/if_tun.h
 */
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#ifdef __linux__
#define _GNU_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <sys/wait.h>
#include <poll.h>
#include <time.h>

#ifdef __APPLE__
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if_utun.h>
#endif

#ifdef __linux__
#include <linux/if_tun.h>
#endif

#include "tun.h"
#include "farm9crypt.h"
#include "vpn.h"
#include "tun_internal.h"
#include "util.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

/* Cast helper for farm9crypt which takes char* */
static inline int tun_crypt_write(int fd, const char *msg, int len) {
    return farm9crypt_write(fd, (char *)msg, len);
}

/* Control messages inside tun_relay (TCFQ, TUDP, ...): see tun.h */
static tun_control_fn s_ctrl_fn = NULL;
static void *s_ctrl_ctx = NULL;
void tun_set_control_handler(tun_control_fn fn, void *ctx) { s_ctrl_fn = fn; s_ctrl_ctx = ctx; }

/* ─────────────────────────────────────────────
 * Relay: TUN ↔ encrypted tunnel
 *
 * Wire format per packet:
 *   "TVPN" (4 bytes) + uint16_be length (2 bytes) + IP packet
 * ───────────────────────────────────────────── */
int tun_relay(int tun_fd, int tunnel_fd) {
    char pkt_buf[TUN_MTU];
    char wire_buf[TUN_BUF_SIZE];
    char recv_buf[TUN_BUF_SIZE];
    int fds[2] = { tun_fd, tunnel_fd }, rdy[2];

    log_msg(1, "tun: VPN relay started");

    for (;;) {
        /* 30 s timeout for keepalive */
        int rc = wait_readable(fds, rdy, 2, 30000);
        if (tun_stop_requested()) {
            log_msg(1, "tun: stop requested");
            break;
        }
        if (rc < 0) {
            if (errno == EINTR) continue;
            perror("tun: select");
            break;
        }

        if (rc == 0) {
            /* Timeout: send keepalive */
            const char *hb = "THB\n";
            tun_crypt_write(tunnel_fd, hb, 4);
            continue;
        }

        /* TUN device → encrypted tunnel */
        if (rdy[0]) {
            int pkt_len = tun_read_packet(tun_fd, pkt_buf, sizeof(pkt_buf));
            if (pkt_len <= 0) continue; /* spurious or too large */

            /* Build wire frame: TVPN + 2-byte length + packet */
            memcpy(wire_buf, TUN_SIG_VPN, TUN_SIG_LEN);
            wire_buf[TUN_SIG_LEN] = (pkt_len >> 8) & 0xFF;
            wire_buf[TUN_SIG_LEN + 1] = pkt_len & 0xFF;
            memcpy(wire_buf + TUN_HDR_SIZE, pkt_buf, pkt_len);

            if (tun_crypt_write(tunnel_fd, wire_buf, TUN_HDR_SIZE + pkt_len) < 0) {
                log_msg(1, "tun: tunnel write failed");
                break;
            }
        }

        /* Encrypted tunnel → TUN device */
        if (rdy[1]) {
            int n = farm9crypt_read(tunnel_fd, recv_buf, sizeof(recv_buf));
            if (n <= 0) {
                log_msg(1, "tun: tunnel closed");
                break;
            }

            /* Check for heartbeat */
            if (n == 4 && memcmp(recv_buf, "THB\n", 4) == 0) {
                continue; /* keepalive, ignore */
            }

            /* Control message (address request, UDP offer, ...) */
            if (n >= 4 && memcmp(recv_buf, TUN_SIG_VPN, TUN_SIG_LEN) != 0 && s_ctrl_fn) {
                if (s_ctrl_fn(tunnel_fd, (const unsigned char *)recv_buf, n, s_ctrl_ctx) < 0)
                    break;
                continue;
            }

            /* Validate wire frame header */
            if (n < TUN_HDR_SIZE || memcmp(recv_buf, TUN_SIG_VPN, TUN_SIG_LEN) != 0) {
                log_msg(1, "tun: invalid packet (len=%d)", n);
                continue;
            }

            int pkt_len = ((unsigned char)recv_buf[TUN_SIG_LEN] << 8) |
                          (unsigned char)recv_buf[TUN_SIG_LEN + 1];

            if (pkt_len <= 0 || pkt_len > TUN_MTU || pkt_len + TUN_HDR_SIZE > n) {
                log_msg(1, "tun: bad packet length %d", pkt_len);
                continue;
            }

            tun_write_packet(tun_fd, recv_buf + TUN_HDR_SIZE, pkt_len);
        }
    }

    log_msg(1, "tun: VPN relay stopped");
    return 0;
}

/* ── Address configuration (client side) ─────────────── */

/* A server offers its UDP channel ("TUDP" + token) as soon as the session
 * starts; if that arrives while we wait for "TCFG" it is kept for
 * tun_udp_negotiate(). */
static unsigned char s_pending_tudp[64];
static int s_pending_tudp_len = 0;

int tun_request_config(int tunnel_fd, struct in_addr want, int timeout_ms,
                       vpn_cfg_t *cfg, int *status) {
    unsigned char req[VPN_CFG_REQ_LEN];
    *status = -1;
    int n = vpn_cfg_build_request(req, sizeof(req), want);
    if (n < 0 || tun_crypt_write(tunnel_fd, (const char *)req, n) < 0) return -1;

    int64_t deadline;
    {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        deadline = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000 + timeout_ms;
    }
    for (;;) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        int64_t left = deadline - ((int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
        if (left <= 0) return 0;                          /* older server: no answer */
        struct pollfd p = { tunnel_fd, POLLIN, 0 };
        int rc = poll(&p, 1, (int)left);
        if (rc < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (rc == 0) return 0;
        char buf[TUN_BUF_SIZE];
        int r = farm9crypt_read(tunnel_fd, buf, sizeof(buf));
        if (r <= 0) return -1;
        if (r >= 4 && memcmp(buf, VPN_CFG_REP_TAG, 4) == 0) {
            if (vpn_cfg_parse_reply((const unsigned char *)buf, (size_t)r, status, cfg) != 0)
                return -1;
            return *status == VPN_CFG_OK ? 1 : -1;
        }
        if (r >= 4 && r <= (int)sizeof(s_pending_tudp) && memcmp(buf, "TUDP", 4) == 0) {
            memcpy(s_pending_tudp, buf, (size_t)r);
            s_pending_tudp_len = r;
        }
        /* anything else before the reply (heartbeat, early packets): ignore */
    }
}

/* ═════════════════════════════════════════════
 * UDP VPN data channel
 *
 * After the TCP handshake (ECDHE key exchange), both sides open a
 * separate UDP socket for VPN data.  Each UDP datagram is independently
 * encrypted with AES-256-GCM using the session key exported from
 * farm9crypt.
 *
 * Advantages over TCP relay:
 *   - No TCP-over-TCP meltdown
 *   - Lower latency (no head-of-line blocking)
 *   - Better fit for real-time / VPN traffic
 *
 * Wire format per UDP datagram:
 *   [4B "CVPN"] [12B nonce] [ciphertext] [16B GCM tag]
 *   nonce = seq_be(4B) + random(8B)
 *   AAD   = "CVPN" (4B)
 *
 * Control messages (sent over TCP or UDP):
 *   "THB\n" — keepalive heartbeat
 * ═════════════════════════════════════════════ */

/* ── AES-256-GCM encrypt/decrypt (C, OpenSSL EVP) ─── */

static int udp_vpn_encrypt(const unsigned char *key, uint32_t seq,
                            const unsigned char *pt, int pt_len,
                            unsigned char *out, int *out_len)
{
    /*  out layout: CVPN(4) | nonce(12) | ciphertext(pt_len) | tag(16)  */
    unsigned char nonce[TUN_UDP_NONCE_LEN];
    nonce[0] = (seq >> 24) & 0xFF;
    nonce[1] = (seq >> 16) & 0xFF;
    nonce[2] = (seq >> 8)  & 0xFF;
    nonce[3] =  seq        & 0xFF;
    if (RAND_bytes(nonce + 4, 8) != 1) return -1;

    /* Header: magic */
    memcpy(out, TUN_UDP_MAGIC, TUN_UDP_MAGIC_LEN);

    /* Header: nonce */
    memcpy(out + TUN_UDP_MAGIC_LEN, nonce, TUN_UDP_NONCE_LEN);

    int hdr_len = TUN_UDP_MAGIC_LEN + TUN_UDP_NONCE_LEN; /* 16 */

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ok = 0;
    int len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, TUN_UDP_NONCE_LEN, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;

    /* AAD = "CVPN" */
    if (EVP_EncryptUpdate(ctx, NULL, &len, (const unsigned char *)TUN_UDP_MAGIC, TUN_UDP_MAGIC_LEN) != 1) goto done;

    /* Encrypt payload */
    if (EVP_EncryptUpdate(ctx, out + hdr_len, &len, pt, pt_len) != 1) goto done;
    int ct_len = len;

    if (EVP_EncryptFinal_ex(ctx, out + hdr_len + ct_len, &len) != 1) goto done;
    ct_len += len;

    /* Append GCM tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TUN_UDP_TAG_LEN,
                             out + hdr_len + ct_len) != 1) goto done;

    *out_len = hdr_len + ct_len + TUN_UDP_TAG_LEN;
    ok = 1;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

static int udp_vpn_decrypt(const unsigned char *key,
                            const unsigned char *in, int in_len,
                            unsigned char *pt, int *pt_len, uint32_t *seq_out)
{
    /*  in layout: CVPN(4) | nonce(12) | ciphertext(N) | tag(16) */
    int hdr_len = TUN_UDP_MAGIC_LEN + TUN_UDP_NONCE_LEN; /* 16 */

    if (in_len < hdr_len + TUN_UDP_TAG_LEN) return -1;
    if (memcmp(in, TUN_UDP_MAGIC, TUN_UDP_MAGIC_LEN) != 0) return -1;

    const unsigned char *nonce = in + TUN_UDP_MAGIC_LEN;
    int ct_len = in_len - hdr_len - TUN_UDP_TAG_LEN;
    if (ct_len <= 0 || ct_len > TUN_MTU + 2) return -1;

    const unsigned char *ct  = in + hdr_len;
    const unsigned char *tag = in + hdr_len + ct_len;

    /* Extract seq from nonce[0..3] */
    *seq_out = ((uint32_t)nonce[0] << 24) | ((uint32_t)nonce[1] << 16) |
               ((uint32_t)nonce[2] << 8)  |  (uint32_t)nonce[3];

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ok = 0;
    int len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, TUN_UDP_NONCE_LEN, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;

    /* AAD = "CVPN" */
    if (EVP_DecryptUpdate(ctx, NULL, &len, (const unsigned char *)TUN_UDP_MAGIC, TUN_UDP_MAGIC_LEN) != 1) goto done;

    /* Decrypt */
    if (EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len) != 1) goto done;
    *pt_len = len;

    /* Set expected tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TUN_UDP_TAG_LEN,
                             (void *)tag) != 1) goto done;

    /* Verify tag — if this fails, packet is tampered/forged */
    if (EVP_DecryptFinal_ex(ctx, pt + *pt_len, &len) != 1) goto done;
    *pt_len += len;
    ok = 1;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

/* ── --pad on the UDP data channel ───────────────────────
 * With record padding negotiated, every datagram carries
 * [u16 length][packet][random] of exactly tun_effective_mtu() + 2 bytes, so
 * datagram sizes no longer reveal packet sizes (heartbeats included). */
static int udp_seal(const unsigned char *key, uint32_t seq, const unsigned char *pkt,
                    int len, unsigned char *out, int *out_len) {
    if (!farm9crypt_padding())
        return udp_vpn_encrypt(key, seq, pkt, len, out, out_len);
    unsigned char padded[TUN_MTU + 2];
    int full = tun_effective_mtu() + 2;
    if (len < 0 || len > full - 2) return -1;
    padded[0] = (unsigned char)(len >> 8);
    padded[1] = (unsigned char)(len & 0xff);
    memcpy(padded + 2, pkt, (size_t)len);
    if (RAND_bytes(padded + 2 + len, full - 2 - len) != 1) return -1;
    return udp_vpn_encrypt(key, seq, padded, full, out, out_len);
}

/* Returns 0 with the packet in pkt/pkt_len (pkt: >= TUN_MTU + 2 bytes) */
static int udp_open(const unsigned char *key, const unsigned char *in, int in_len,
                    unsigned char *pkt, int *pkt_len, uint32_t *seq) {
    if (udp_vpn_decrypt(key, in, in_len, pkt, pkt_len, seq) < 0) return -1;
    if (!farm9crypt_padding()) return 0;
    if (*pkt_len != tun_effective_mtu() + 2) return -1;
    int real = (pkt[0] << 8) | pkt[1];
    if (real > *pkt_len - 2) return -1;
    memmove(pkt, pkt + 2, (size_t)real);
    *pkt_len = real;
    return 0;
}

/* ── Public wrappers for testing ──────────────────────── */

int tun_udp_encrypt(const unsigned char *key, uint32_t seq,
                     const unsigned char *pt, int pt_len,
                     unsigned char *out, int *out_len)
{
    return udp_vpn_encrypt(key, seq, pt, pt_len, out, out_len);
}

int tun_udp_decrypt(const unsigned char *key,
                     const unsigned char *in, int in_len,
                     unsigned char *pt, int *pt_len, uint32_t *seq_out)
{
    return udp_vpn_decrypt(key, in, in_len, pt, pt_len, seq_out);
}

/* ── Replay protection: sliding window ───────────────── */

#define REPLAY_WINDOW_SIZE 256

static uint32_t replay_max_seq = 0;
static uint64_t replay_bitmap[REPLAY_WINDOW_SIZE / 64] = {0};

static void replay_reset(void) {
    replay_max_seq = 0;
    memset(replay_bitmap, 0, sizeof(replay_bitmap));
}

static int replay_check_and_update(uint32_t seq) {
    /* seq 0 is reserved for the negotiation probe/ACK and never valid data */
    if (seq == 0) return -1;

    if (seq > replay_max_seq) {
        /* Advance window */
        uint32_t shift = seq - replay_max_seq;
        if (shift >= REPLAY_WINDOW_SIZE) {
            memset(replay_bitmap, 0, sizeof(replay_bitmap));
        } else {
            /* Shift bitmap left by 'shift' bits */
            for (uint32_t s = 0; s < shift; s++) {
                for (int i = (REPLAY_WINDOW_SIZE / 64) - 1; i > 0; i--) {
                    replay_bitmap[i] = (replay_bitmap[i] << 1) | (replay_bitmap[i-1] >> 63);
                }
                replay_bitmap[0] <<= 1;
            }
        }
        replay_max_seq = seq;
        /* Mark current seq as seen (bit 0) */
        replay_bitmap[0] |= 1;
        return 0; /* accept */
    }

    /* seq <= replay_max_seq: check if within window */
    uint32_t diff = replay_max_seq - seq;
    if (diff >= REPLAY_WINDOW_SIZE) return -1; /* too old */

    uint32_t idx = diff / 64;
    uint32_t bit = diff % 64;
    if (replay_bitmap[idx] & (1ULL << bit)) return -1; /* already seen */

    /* Mark as seen */
    replay_bitmap[idx] |= (1ULL << bit);
    return 0;
}

void tun_udp_replay_reset(void) {
    replay_reset();
}

int tun_udp_replay_check(uint32_t seq) {
    return replay_check_and_update(seq);
}

/* ── UDP socket setup ────────────────────────────────── */

static int udp_bind(const char *port) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(NULL, port, &hints, &res) != 0) return -1;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    if (bind(fd, res->ai_addr, res->ai_addrlen) < 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int udp_connect(const char *host, const char *port) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }

    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* ── Negotiate UDP channel over TCP ──────────────────── */

/*
 * Protocol (over the existing encrypted TCP channel):
 *   1. Server binds UDP on the same port (before step 2, so no probe races it)
 *   2. Both sides exchange: "TUDP" + 16-byte random token
 *   3. Client sends the server's token as UDP probe (seq 0, client tx key),
 *      retransmitting every TUDP_PROBE_INTERVAL_MS until ACKed
 *   4. Server validates the probe (ignoring unrelated datagrams) and
 *      connects to the client address
 *   5. Server returns the client's token (seq 0, server tx key) as ACK,
 *      TUDP_ACK_COPIES times; extra copies are dropped by the replay window
 *   Everything must complete within TUDP_NEGOTIATE_TIMEOUT_MS.
 */

#define TUDP_SIG  "TUDP"
#define TUDP_SIG_LEN 4
#define TUDP_TOKEN_LEN 16
#define TUDP_NEGOTIATE_TIMEOUT_MS 10000  /* overall UDP setup deadline */
#define TUDP_PROBE_INTERVAL_MS    250    /* client probe retransmit interval */
#define TUDP_ACK_COPIES           3      /* redundant server ACKs */

static int64_t monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int tun_udp_negotiate_keys(int tcp_fd, const char *host, const char *port,
                                  int is_server,
                                  const unsigned char *tx_key,
                                  const unsigned char *rx_key,
                                  unsigned char *my_token,
                                  unsigned char *peer_token,
                                  char *msg);

int tun_udp_negotiate(int tcp_fd, const char *host, const char *port,
                       int is_server)
{
    unsigned char my_token[TUDP_TOKEN_LEN];
    unsigned char peer_token[TUDP_TOKEN_LEN];
    unsigned char tx_key[32], rx_key[32];
    char msg[TUDP_SIG_LEN + TUDP_TOKEN_LEN];
    int result;

    /* Directional UDP keys: tx for what we send, rx for what we receive */
    if (farm9crypt_export_udp_keys(tx_key, rx_key) < 0) {
        fprintf(stderr, "tun-udp: cannot export session keys\n");
        return -1;
    }

    result = tun_udp_negotiate_keys(tcp_fd, host, port, is_server,
                                    tx_key, rx_key, my_token, peer_token, msg);
    OPENSSL_cleanse(tx_key, sizeof(tx_key));
    OPENSSL_cleanse(rx_key, sizeof(rx_key));
    OPENSSL_cleanse(my_token, sizeof(my_token));
    OPENSSL_cleanse(peer_token, sizeof(peer_token));
    return result;
}

static int tun_udp_negotiate_keys(int tcp_fd, const char *host, const char *port,
                                  int is_server,
                                  const unsigned char *tx_key,
                                  const unsigned char *rx_key,
                                  unsigned char *my_token,
                                  unsigned char *peer_token,
                                  char *msg)
{
    int udp_fd = -1;

    /* Server: bind the UDP socket *before* announcing its token, so the
     * client's first probe can never race ahead of the bind. */
    if (is_server) {
        udp_fd = udp_bind(port);
        if (udp_fd < 0) {
            fprintf(stderr, "tun-udp: failed to bind UDP on port %s\n", port);
            return -1;
        }
    }

    /* Generate our random token */
    if (RAND_bytes(my_token, TUDP_TOKEN_LEN) != 1) {
        fprintf(stderr, "tun-udp: RAND_bytes failed\n");
        goto fail;
    }

    /* Send "TUDP" + token over TCP */
    memcpy(msg, TUDP_SIG, TUDP_SIG_LEN);
    memcpy(msg + TUDP_SIG_LEN, my_token, TUDP_TOKEN_LEN);
    if (tun_crypt_write(tcp_fd, msg, TUDP_SIG_LEN + TUDP_TOKEN_LEN) < 0) {
        fprintf(stderr, "tun-udp: failed to send TUDP\n");
        goto fail;
    }

    /* Receive peer's "TUDP" + token. A 4.2 client asks for its address
     * ("TCFQ") first: answer it through the control handler and keep
     * waiting. A token that arrived earlier was stashed. */
    char recv_msg[TUN_BUF_SIZE];
    int n;
    if (s_pending_tudp_len) {
        n = s_pending_tudp_len;
        memcpy(recv_msg, s_pending_tudp, (size_t)n);
        s_pending_tudp_len = 0;
    } else {
        for (;;) {
            n = farm9crypt_read(tcp_fd, recv_msg, sizeof(recv_msg));
            if (n >= 4 && memcmp(recv_msg, VPN_CFG_REQ_TAG, 4) == 0 && s_ctrl_fn) {
                if (s_ctrl_fn(tcp_fd, (const unsigned char *)recv_msg, n, s_ctrl_ctx) < 0)
                    goto fail;
                continue;
            }
            if (n == 4 && memcmp(recv_msg, "THB\n", 4) == 0) continue;
            break;
        }
    }
    if (n != TUDP_SIG_LEN + TUDP_TOKEN_LEN ||
        memcmp(recv_msg, TUDP_SIG, TUDP_SIG_LEN) != 0) {
        fprintf(stderr, "tun-udp: the server does not offer the UDP channel%s\n",
                n == 4 && memcmp(recv_msg, "TUDN", 4) == 0 ? " (multi-client hub)" : "");
        goto fail;
    }
    memcpy(peer_token, recv_msg + TUDP_SIG_LEN, TUDP_TOKEN_LEN);

    log_msg(1, "tun-udp: tokens exchanged, setting up UDP channel");

    const int64_t deadline = monotonic_ms() + TUDP_NEGOTIATE_TIMEOUT_MS;
    unsigned char dgram[TUN_UDP_OVERHEAD + TUDP_TOKEN_LEN + 32];
    unsigned char dec_token[TUDP_TOKEN_LEN + 16];

    if (is_server) {
        /* Wait for a valid client probe (our token, seq 0, client->server key).
         * Unrelated or forged datagrams are ignored until the deadline. */
        struct sockaddr_storage client_addr;
        socklen_t addr_len = 0;
        int got_probe = 0;
        while (!got_probe) {
            int64_t left = deadline - monotonic_ms();
            if (left <= 0) break;
            struct pollfd pfd = { .fd = udp_fd, .events = POLLIN, .revents = 0 };
            int pr = poll(&pfd, 1, (int)left);
            if (pr < 0 && errno == EINTR) continue;
            if (pr <= 0) break;

            addr_len = sizeof(client_addr);
            ssize_t nr = recvfrom(udp_fd, dgram, sizeof(dgram), 0,
                                  (struct sockaddr *)&client_addr, &addr_len);
            if (nr <= 0) continue;

            int dec_len = 0;
            uint32_t seq = 0;
            if (udp_vpn_decrypt(rx_key, dgram, (int)nr, dec_token, &dec_len, &seq) == 0 &&
                seq == 0 && dec_len == TUDP_TOKEN_LEN &&
                CRYPTO_memcmp(dec_token, my_token, TUDP_TOKEN_LEN) == 0)
                got_probe = 1;
        }
        if (!got_probe) {
            fprintf(stderr, "tun-udp: no valid UDP probe from client\n");
            goto fail;
        }

        /* Connect to client addr so we can use send/recv */
        if (connect(udp_fd, (struct sockaddr *)&client_addr, addr_len) < 0) {
            perror("tun-udp: connect");
            goto fail;
        }

        /* ACK = encrypted client token. Sent a few times so a single lost
         * datagram does not break the channel; duplicates are harmless since
         * seq 0 is rejected by the data-channel replay window. */
        int ack_len = 0;
        if (udp_vpn_encrypt(tx_key, 0, peer_token, TUDP_TOKEN_LEN, dgram, &ack_len) < 0)
            goto fail;
        for (int i = 0; i < TUDP_ACK_COPIES; i++)
            (void)send(udp_fd, dgram, (size_t)ack_len, 0);

        log_msg(1, "tun-udp: server UDP channel ready on port %s", port);
        return udp_fd;
    }

    /* Client: connect UDP to server */
    udp_fd = udp_connect(host, port);
    if (udp_fd < 0) {
        fprintf(stderr, "tun-udp: failed to connect UDP to %s:%s\n", host, port);
        return -1;
    }

    /* Probe = encrypted server token; retransmitted until a valid ACK arrives */
    unsigned char probe[TUN_UDP_OVERHEAD + TUDP_TOKEN_LEN + 32];
    int probe_len = 0;
    if (udp_vpn_encrypt(tx_key, 0, peer_token, TUDP_TOKEN_LEN, probe, &probe_len) < 0)
        goto fail;

    int64_t next_send = 0;
    for (;;) {
        int64_t now = monotonic_ms();
        if (now >= deadline) {
            fprintf(stderr, "tun-udp: no ACK from server\n");
            goto fail;
        }
        if (now >= next_send) {
            /* ECONNREFUSED (ICMP unreachable) is transient here: just retry */
            (void)send(udp_fd, probe, (size_t)probe_len, 0);
            next_send = now + TUDP_PROBE_INTERVAL_MS;
        }
        int64_t wait = next_send - now;
        if (deadline - now < wait) wait = deadline - now;
        struct pollfd pfd = { .fd = udp_fd, .events = POLLIN, .revents = 0 };
        int pr = poll(&pfd, 1, (int)wait);
        if (pr < 0 && errno == EINTR) continue;
        if (pr <= 0) continue;

        ssize_t nr = recv(udp_fd, dgram, sizeof(dgram), 0);
        if (nr <= 0) continue;   /* e.g. ECONNREFUSED before server is ready */

        int dec_len = 0;
        uint32_t seq = 0;
        if (udp_vpn_decrypt(rx_key, dgram, (int)nr, dec_token, &dec_len, &seq) == 0 &&
            seq == 0 && dec_len == TUDP_TOKEN_LEN &&
            CRYPTO_memcmp(dec_token, my_token, TUDP_TOKEN_LEN) == 0)
            break;
    }

    log_msg(1, "tun-udp: client UDP channel ready to %s:%s", host, port);
    return udp_fd;

fail:
    if (udp_fd >= 0) close(udp_fd);
    return -1;
}

/* ── UDP VPN relay loop ──────────────────────────────── */

int tun_udp_relay(int tun_fd, int udp_fd, int tcp_fd,
                   const unsigned char *tx_key, const unsigned char *rx_key)
{
    unsigned char pkt_buf[TUN_MTU];
    unsigned char enc_buf[TUN_UDP_OVERHEAD + TUN_MTU + 32];
    unsigned char recv_buf[TUN_UDP_OVERHEAD + TUN_MTU + 32];
    int rdy[3];

    /* seq 0 belongs to the negotiation probe/ACK; data starts at 1.
     * 64-bit counter so exhaustion of the 32-bit wire space is detectable. */
    uint64_t send_seq = 1;
    replay_reset();

    log_msg(1, "tun-udp: VPN relay started (UDP data channel)");

    for (;;) {
        int fds[3] = { tun_fd, udp_fd, tcp_fd };   /* tcp_fd -1 = ignored */
        int rc = wait_readable(fds, rdy, 3, 30000);
        if (tun_stop_requested()) {
            log_msg(1, "tun-udp: stop requested");
            break;
        }
        if (rc < 0) {
            if (errno == EINTR) continue;
            perror("tun-udp: select");
            break;
        }

        if (rc == 0) {
            /* Timeout: send keepalive via UDP */
            unsigned char hb_enc[TUN_UDP_OVERHEAD + TUN_MTU + 32];
            int hb_len = 0;
            const unsigned char hb[] = "THB\n";
            if (send_seq > UINT32_MAX) {
                log_msg(1, "tun-udp: sequence space exhausted, reconnect required");
                break;
            }
            if (udp_seal(tx_key, (uint32_t)send_seq++, hb, 4, hb_enc, &hb_len) == 0) {
                send(udp_fd, hb_enc, hb_len, 0);
            }
            continue;
        }

        /* TUN → encrypt → UDP */
        if (rdy[0]) {
            int pkt_len = tun_read_packet(tun_fd, (char *)pkt_buf, sizeof(pkt_buf));
            if (pkt_len <= 0) continue;

            int enc_len = 0;
            if (send_seq > UINT32_MAX) {
                log_msg(1, "tun-udp: sequence space exhausted, reconnect required");
                break;
            }
            if (udp_seal(tx_key, (uint32_t)send_seq++, pkt_buf, pkt_len,
                         enc_buf, &enc_len) < 0) {
                log_msg(1, "tun-udp: encrypt failed");
                continue;
            }

            if (send(udp_fd, enc_buf, enc_len, 0) < 0) {
                if (errno == EINTR) continue;
                log_msg(1, "tun-udp: UDP send failed");
                break;
            }
        }

        /* UDP → decrypt → TUN */
        if (rdy[1]) {
            ssize_t nr = recv(udp_fd, recv_buf, sizeof(recv_buf), 0);
            if (nr <= 0) {
                if (errno == EINTR) continue;
                log_msg(1, "tun-udp: UDP recv failed");
                break;
            }

            unsigned char dec_buf[TUN_MTU + 2];
            int dec_len = 0;
            uint32_t seq = 0;

            if (udp_open(rx_key, recv_buf, (int)nr, dec_buf, &dec_len, &seq) < 0) {
                /* Tampered or corrupted — silently drop */
                continue;
            }

            /* Replay check */
            if (replay_check_and_update(seq) < 0) {
                continue; /* duplicate or too old */
            }

            /* Heartbeat? */
            if (dec_len == 4 && memcmp(dec_buf, "THB\n", 4) == 0) {
                continue;
            }

            tun_write_packet(tun_fd, (const char *)dec_buf, dec_len);
        }

        /* TCP control channel (if still open) */
        if (tcp_fd >= 0 && rdy[2]) {
            char ctrl[64];
            int cn = farm9crypt_read(tcp_fd, ctrl, sizeof(ctrl));
            if (cn <= 0) {
                log_msg(1, "tun-udp: TCP control channel closed");
                tcp_fd = -1; /* stop monitoring, keep UDP going */
            }
            /* Any TCP control messages can be handled here */
        }
    }

    log_msg(1, "tun-udp: VPN relay stopped");
    return 0;
}
