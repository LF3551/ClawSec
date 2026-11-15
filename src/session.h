/*
 * session.h — one ClawSec connection: TLS camouflage, knock, handshake, then
 * the selected mode (stream, chat, files, forwarding, SOCKS, mux, -R, VPN)
 */
#ifndef CLAWSEC_SESSION_H
#define CLAWSEC_SESSION_H

/* handle_client() result for a failure a retry cannot fix (wrong password,
 * incompatible peer or options); main() maps every failure to exit status 1 */
#define HC_PERMANENT 2

/* Run one session on sockfd (which it closes). Returns 0, 1 or HC_PERMANENT. */
int handle_client(int sockfd, const char *password, int is_server,
                  int send_first, const char *exec_prog,
                  const char *fwd_host, const char *fwd_port,
                  const char *peer_host, const char *peer_port);

#endif
