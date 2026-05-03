#ifndef CLAWSEC_RELAY_H
#define CLAWSEC_RELAY_H

/* Relay encrypted data between socket and stdio. Returns 0 on success. */
int relay_socket_stdio(int sockfd, int is_server, int chat_enabled);

/* Relay encrypted socket <-> plaintext socket (for port forwarding).
 * enc_fd: encrypted side (farm9crypt_read/write)
 * plain_fd: plaintext side (read/write)
 * Returns 0 on success. */
int relay_encrypted_plain(int enc_fd, int plain_fd);

/* Globals needed by relay */
extern int g_verbose;
extern int g_chat_mode;

#endif
