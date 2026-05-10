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

#endif
