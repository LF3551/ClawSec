#ifndef CLAWSEC_TUN_H
#define CLAWSEC_TUN_H

/*
 * tun.h — TUN VPN interface for ClawSec
 *
 * Creates a virtual network interface (tun) and relays IP packets
 * through the encrypted tunnel. Supports:
 *   - Linux:  /dev/net/tun (TUN/TAP driver)
 *   - macOS:  utun (kernel control socket)
 *
 * Usage:
 *   Server: clawsec -l -k pass -p 9000 --tun 10.0.0.1/24
 *   Client: clawsec -k pass server 9000 --tun 10.0.0.2/24
 *
 * Wire protocol over encrypted channel:
 *   "TVPN\n" + 2-byte big-endian length + IP packet
 *   Heartbeat: "THB\n" (keepalive)
 */

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>
#include "vpn.h"

/* Maximum IP packet size through TUN */
#define TUN_MTU         1400

/* Interface MTU: TUN_MTU, or 1392 with --pad so that a full packet plus the
 * 6-byte TVPN header is exactly one padded record (1398 bytes of data) */
int tun_effective_mtu(void);
/* TUN packet header: "TVPN" + 2-byte length */
#define TUN_HDR_SIZE    6
/* TUN buffer: header + MTU */
#define TUN_BUF_SIZE    (TUN_HDR_SIZE + TUN_MTU)

/* UDP VPN datagram overhead: magic(4) + nonce(12) + tag(16) = 32 bytes */
#define TUN_UDP_OVERHEAD   32
/* UDP VPN magic */
#define TUN_UDP_MAGIC      "CVPN"
#define TUN_UDP_MAGIC_LEN  4
/* AES-GCM constants for UDP VPN */
#define TUN_UDP_NONCE_LEN  12
#define TUN_UDP_TAG_LEN    16

/* Open a TUN device and assign IP/mask. Returns tun_fd or -1 on error.
 * On macOS, dev_name is filled with "utunN".
 * On Linux, dev_name is filled with "tunN". */
int tun_open(const char *ip, int prefix_len, char *dev_name, size_t dev_name_len);

/* Same with an explicit point-to-point gateway (macOS peer address; NULL =
 * legacy .1/.2 rule). */
int tun_open_peer(const char *ip, int prefix_len, const char *gw,
                  char *dev_name, size_t dev_name_len);

/* Open and configure a TUN device from a server-assigned (or local)
 * configuration: IPv4 address/prefix/gateway and optional IPv6. */
int tun_open_cfg(const vpn_cfg_t *cfg, char *dev_name, size_t dev_name_len);

/* Add an IPv6 address to the TUN device. Returns 0 or -1. */
int tun_add_ipv6(const char *dev_name, const struct in6_addr *addr, int prefix);

/* Hub children: fd is a SOCK_SEQPACKET socket carrying raw IP packets
 * (one per message); tun_relay/tun_udp_relay then use it instead of a TUN
 * device. */
void tun_set_raw_fd(int fd);

/* Control messages that arrive on the encrypted channel during tun_relay and
 * are not "TVPN"/"THB" frames are passed to this handler (e.g. "TCFQ",
 * "TUDP"). It may answer on tunnel_fd. Return -1 to end the relay. */
typedef int (*tun_control_fn)(int tunnel_fd, const unsigned char *msg, int len, void *ctx);
void tun_set_control_handler(tun_control_fn fn, void *ctx);

/* Client: ask the server for an address ("TCFQ"), want = 0.0.0.0 for any.
 * Returns 1 with *cfg filled, 0 if the server did not answer within
 * timeout_ms (ClawSec < 4.2: use the local --tun address), -1 if the server
 * refused (*status set) or the channel failed. */
int tun_request_config(int tunnel_fd, struct in_addr want, int timeout_ms,
                       vpn_cfg_t *cfg, int *status);

/* Hub process: packet I/O on the TUN device (handles the utun header) and
 * the route for the client subnet (macOS; Linux needs none). */
int tun_device_read(int tun_fd, char *buf, int len);
int tun_device_write(int tun_fd, const char *buf, int len);
int tun_add_subnet_route(const char *dev_name, const vpn_cfg_t *cfg);

/* Close and clean up TUN device */
void tun_close(int tun_fd, const char *dev_name);

/* Relay IP packets between TUN device and encrypted tunnel.
 * Runs until either side closes. */
int tun_relay(int tun_fd, int tunnel_fd);

/* Enable IP forwarding and masquerade (NAT) on the server.
 * Allows tunnel clients to access the internet through the server.
 * subnet6 (e.g. "fd00::/64") may be NULL: IPv4 only. */
int tun_enable_nat(const char *dev_name, const char *subnet);
int tun_enable_nat6(const char *dev_name, const char *subnet6);

/* Client full tunnel for IPv6: ::/1 and 8000::/1 via the TUN device (the
 * system default route stays; the more specific routes win). Undone by
 * tun_restore_default_route(). */
int tun_set_default_route6(const char *dev_name);

/* Parse "10.0.0.1/24" into ip string and prefix_len. Returns 0 on success. */
int tun_parse_cidr(const char *cidr, char *ip, size_t ip_len, int *prefix_len);

/* Validate an IP/prefix combination. Returns 0 if valid. */
int tun_validate_config(const char *ip, int prefix_len);

/* Set default route through the TUN interface (all traffic via VPN).
 * server_ip: the real IP/hostname of the VPN server (to exclude from tunnel).
 * gateway_ip: the VPN peer IP (e.g. 10.0.0.1).
 * dev_name: the TUN device name (e.g. utun5, tun0).
 * Returns 0 on success. */
int tun_set_default_route(const char *server_ip, const char *gateway_ip, const char *dev_name);

/* Restore original default route when VPN disconnects. */
int tun_restore_default_route(void);

/* Remove the NAT rule added by tun_enable_nat() and restore the previous
 * IP-forwarding setting. No-op if NAT was not enabled. */
void tun_disable_nat(void);

/* Returns 1 if an interface name is safe to use (non-empty, < IFNAMSIZ,
 * only [A-Za-z0-9_.-]). */
int tun_valid_ifname(const char *name);

/* SIGINT/SIGTERM/SIGHUP set a stop flag that makes the relays return, so
 * routes, NAT and the device are cleaned up on the normal path; an atexit
 * hook covers exit() paths. Call before configuring the TUN device. */
void tun_install_cleanup_handlers(void);
int  tun_stop_requested(void);

/* ── UDP VPN data channel ─────────────────────────────── */

/* Negotiate UDP VPN channel over the existing TCP tunnel.
 * Exchanges tokens over TCP, then creates a UDP socket.
 * Returns udp_fd or -1 on error. */
int tun_udp_negotiate(int tcp_fd, const char *host, const char *port, int is_server);

/* Relay IP packets between TUN and UDP VPN channel.
 * Uses per-packet AES-256-GCM with directional 32-byte keys
 * (see farm9crypt_export_udp_keys): tx_key for sending, rx_key for receiving.
 * Wire format: [4B "CVPN"][12B nonce][ciphertext][16B GCM tag]
 * Nonce = seq_be(4B) + random(8B); AAD = "CVPN" (4B).
 * Sequence 0 is reserved for the negotiation probe/ACK; data starts at 1.
 * tcp_fd is kept for control/heartbeat; -1 to disable. */
int tun_udp_relay(int tun_fd, int udp_fd, int tcp_fd,
                  const unsigned char *tx_key, const unsigned char *rx_key);

/* Anti-replay window for one UDP peer (the hub keeps one per client) */
#define TUN_REPLAY_WINDOW 256
typedef struct {
    uint32_t max_seq;
    uint64_t bitmap[TUN_REPLAY_WINDOW / 64];
} tun_replay_t;
void tun_replay_init(tun_replay_t *r);
/* 0 if seq is fresh (and records it), -1: seq 0, duplicate or too old */
int tun_replay_accept(tun_replay_t *r, uint32_t seq);

/* One UDP data-channel datagram, with --pad applied/removed as negotiated
 * (pkt buffers: TUN_MTU + 2 bytes). Return 0 or -1. */
int tun_udp_seal(const unsigned char *key, uint32_t seq, const unsigned char *pkt, int len,
                 unsigned char *out, int *out_len);
int tun_udp_open(const unsigned char *key, const unsigned char *in, int in_len,
                 unsigned char *pkt, int *pkt_len, uint32_t *seq);

/* Anti-replay sliding window for the UDP data channel (exposed for tests).
 * check returns 0 if seq is fresh (and records it), -1 if it must be dropped:
 * seq 0 (reserved), duplicates, or older than the window. */
void tun_udp_replay_reset(void);
int  tun_udp_replay_check(uint32_t seq);

/* Encrypt a single VPN packet for UDP transport (for testing).
 * out must be at least pt_len + TUN_UDP_OVERHEAD bytes.
 * Returns 0 on success, fills *out_len. */
int tun_udp_encrypt(const unsigned char *key, uint32_t seq,
                     const unsigned char *pt, int pt_len,
                     unsigned char *out, int *out_len);

/* Decrypt a single UDP VPN datagram (for testing).
 * Returns 0 on success, fills *pt_len and *seq_out. */
int tun_udp_decrypt(const unsigned char *key,
                     const unsigned char *in, int in_len,
                     unsigned char *pt, int *pt_len, uint32_t *seq_out);

#endif
