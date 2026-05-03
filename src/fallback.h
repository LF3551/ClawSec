#ifndef CLAWSEC_FALLBACK_H
#define CLAWSEC_FALLBACK_H

/*
 * Fallback (REALITY-like): when DPI/browser connects to our TLS port,
 * proxy them to a real website. Only ClawSec clients that send the
 * correct knock sequence get the encrypted tunnel.
 *
 * Knock: 4-byte magic "CLAW" (0x43 0x4C 0x41 0x57) sent through TLS
 * before the ECDHE handshake begins.
 */

#define FALLBACK_KNOCK_MAGIC "CLAW"
#define FALLBACK_KNOCK_SIZE  4

/* Send knock from client side (through TLS/obfs layer) */
int fallback_send_knock(int fd);

/* Server: peek first bytes through TLS. Returns:
 *   1  = ClawSec client (knock consumed)
 *   0  = foreign probe (data NOT consumed, proxy to fallback)
 *  -1  = error / EOF
 */
int fallback_check_knock(int fd);

/*
 * Proxy a non-ClawSec TLS connection to the fallback server.
 * The peeked data is forwarded along with the rest of the stream.
 * Returns 0 on completion, -1 on error.
 */
int fallback_proxy(int client_fd, const char *fallback_host,
                   const char *fallback_port,
                   const void *peeked, size_t peeked_len);

extern int g_fallback;
extern char g_fallback_host[256];
extern char g_fallback_port[32];

#endif
