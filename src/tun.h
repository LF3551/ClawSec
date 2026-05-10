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

/* Maximum IP packet size through TUN */
#define TUN_MTU         1400
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

/* Close and clean up TUN device */
void tun_close(int tun_fd, const char *dev_name);

/* Relay IP packets between TUN device and encrypted tunnel.
 * Runs until either side closes. */
int tun_relay(int tun_fd, int tunnel_fd);

/* Enable IP forwarding and masquerade (NAT) on the server.
 * Allows tunnel clients to access the internet through the server. */
int tun_enable_nat(const char *dev_name, const char *subnet);

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

/* ── UDP VPN data channel ─────────────────────────────── */

/* Negotiate UDP VPN channel over the existing TCP tunnel.
 * Exchanges tokens over TCP, then creates a UDP socket.
 * Returns udp_fd or -1 on error. */
int tun_udp_negotiate(int tcp_fd, const char *host, const char *port, int is_server);

/* Relay IP packets between TUN and UDP VPN channel.
 * Uses per-packet AES-256-GCM encryption with the given 32-byte key.
 * Wire format: [4B "CVPN"][12B nonce][ciphertext][16B GCM tag]
 * Nonce = seq_be(4B) + random(8B); AAD = "CVPN" (4B).
 * tcp_fd is kept for control/heartbeat; -1 to disable. */
int tun_udp_relay(int tun_fd, int udp_fd, int tcp_fd, const unsigned char *key);

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
