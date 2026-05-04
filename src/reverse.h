#ifndef CLAWSEC_REVERSE_H
#define CLAWSEC_REVERSE_H

/*
 * Reverse tunnel (-R):
 *   Server listens on rev_port, accepts connections, forwards through
 *   encrypted tunnel to client which connects to local target.
 *
 * Protocol over encrypted channel:
 *   Server → Client: "ROPEN\n"  (new incoming connection)
 *   Client connects to target, sends: "ROK\n"
 *   Then bidirectional relay through tunnel.
 */

/* Server side: listen on rev_port, relay through encrypted tunnel_fd */
int reverse_server(int tunnel_fd, const char *rev_port);

/* Client side: wait for ROPEN, connect to target, relay back */
int reverse_client(int tunnel_fd, const char *target_host, const char *target_port);

#endif
