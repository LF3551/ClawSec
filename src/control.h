/*
 * control.h — status socket of a -K server (--control PATH, clawsec --status PATH)
 *
 * The server listens on a Unix socket (mode 0600, i.e. its own user and root
 * only) and answers every connection with a plain-text snapshot of its
 * sessions; there are no commands and nothing secret in it.
 */
#ifndef CLAWSEC_CONTROL_H
#define CLAWSEC_CONTROL_H

#include <stdio.h>

/* Server: create the socket (a stale socket file is replaced; any other
 * file at path is refused). Returns the listening fd or -1. */
int control_listen(const char *path);

/* Server: serve one pending connection with dump(out, ctx). Never blocks
 * for long (the reply is written with a short send timeout). */
void control_serve(int listen_fd, void (*dump)(FILE *out, void *ctx), void *ctx);

/* Client (--status PATH): print the server's status. Returns 0 or 1. */
int control_status(const char *path);

#endif
