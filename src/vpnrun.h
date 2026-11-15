/*
 * vpnrun.h — VPN mode (--tun): one session (point-to-point server, client,
 * or a session process of the -K hub) and the multi-client hub loop
 */
#ifndef CLAWSEC_VPNRUN_H
#define CLAWSEC_VPNRUN_H

/* After the handshake: run the VPN on sockfd. Returns 0, 1 or HC_PERMANENT. */
int run_vpn_session(int sockfd, int is_server, const char *peer_host, const char *peer_port);

/* -K --tun: accept clients on listen_fd and route between them (hub.h). */
int run_vpn_hub(int listen_fd, const char *password);

#endif
