#ifndef CLAWSEC_SOCKS5_H
#define CLAWSEC_SOCKS5_H

/*
 * SOCKS5 proxy over encrypted ClawSec tunnel.
 *
 * Client side: listens on local_port, accepts SOCKS5 connections,
 *              forwards connect requests through encrypted tunnel.
 * Server side: receives connect requests, makes outbound connections,
 *              relays data back through tunnel.
 *
 * Protocol over tunnel:
 *   Client → Server: [1: addr_len][N: host][2: port_be]
 *   Server → Client: [1: status (0=ok, 1=fail)]
 *   Then bidirectional relay.
 */

/* Client-side: local SOCKS5 listener + relay through encrypted fd.
 * Blocks until tunnel closes. */
void socks5_client(int tunnel_fd, const char *local_port);

/* Server-side: receive connect requests from tunnel, make outbound
 * connections, relay data. Blocks until tunnel closes. */
void socks5_server(int tunnel_fd);

/* Global */
extern int g_verbose;

#endif
