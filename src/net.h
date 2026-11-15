#ifndef CLAWSEC_NET_H
#define CLAWSEC_NET_H

/* Connect to host:port with optional timeout. Returns socket fd or exits on error. */
int net_connect(const char *host, const char *port, int timeout_sec);

#include <stddef.h>

/* Bind and listen (TCP) or bind (UDP) on all interfaces. Returns fd or exits on error. */
int net_listen(const char *port);

/* Bind and listen (TCP) on a specific address (NULL = all interfaces).
 * Returns fd, or -1 on error (errors are reported on stderr). */
int net_listen_on(const char *host, const char *port);

/* Default address for local-only listeners (SOCKS proxy, --mux client):
 * "::1" when forced to IPv6 (-6), otherwise "127.0.0.1". */
const char *net_loopback_host(void);

/* Parse "host:port" or "[ipv6]:port". The port must be a number 1-65535.
 * Returns 0 on success, -1 on error. */
int net_parse_host_port(const char *spec, char *host, size_t hlen,
                        char *port, size_t plen);

/* Parse a listen spec: "port" (host = default_host), "host:port" or
 * "[ipv6]:port". Returns 0 on success, -1 on error. */
int net_parse_listen_spec(const char *spec, const char *default_host,
                          char *host, size_t hlen, char *port, size_t plen);

/* Accept one TCP connection. Returns fd or exits on error. */
int net_accept(int listen_fd);

/* UDP "accept": wait for first datagram, connect to sender. Returns fd. */
int net_udp_accept(int udp_fd);

/* Like net_connect but returns -1 on failure instead of exiting */
int net_try_connect(const char *host, const char *port, int timeout_sec);

/* Global network config (set before calling net_* functions) */
extern int g_udp_mode;
extern int g_af_family;
extern int g_verbose;

#endif
