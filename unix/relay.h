#ifndef CLAWSEC_RELAY_H
#define CLAWSEC_RELAY_H

/* Relay encrypted data between socket and stdio. Returns 0 on success. */
int relay_socket_stdio(int sockfd, int is_server, int chat_enabled);

/* Globals needed by relay */
extern int g_verbose;
extern int g_chat_mode;

#endif
