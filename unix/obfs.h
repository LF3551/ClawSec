#ifndef CLAWSEC_OBFS_H
#define CLAWSEC_OBFS_H

#include <stddef.h>

/* Obfuscation modes */
#define OBFS_NONE 0
#define OBFS_HTTP 1

/* Set obfuscation mode globally */
void obfs_set_mode(int mode);

/* Get current obfuscation mode */
int obfs_get_mode(void);

/*
 * Wrap raw data in HTTP-like framing before sending.
 * Returns bytes of payload on success, -1 on error.
 */
int obfs_send(int fd, const void *data, size_t len);

/*
 * Unwrap HTTP-like framing and return raw payload.
 * Returns payload bytes read, 0 on EOF, -1 on error.
 */
int obfs_recv(int fd, void *buf, size_t buflen);

#endif
