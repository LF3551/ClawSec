#ifndef CLAWSEC_NET_H
#define CLAWSEC_NET_H

/* Connect to host:port with optional timeout. Returns socket fd or exits on error. */
int net_connect(const char *host, const char *port, int timeout_sec);

/* Bind and listen (TCP) or bind (UDP) on port. Returns fd or exits on error. */
int net_listen(const char *port);

/* Accept one TCP connection. Returns fd or exits on error. */
int net_accept(int listen_fd);

/* UDP "accept": wait for first datagram, connect to sender. Returns fd. */
int net_udp_accept(int udp_fd);

/* Global network config (set before calling net_* functions) */
extern int g_udp_mode;
extern int g_af_family;
extern int g_verbose;

#endif
