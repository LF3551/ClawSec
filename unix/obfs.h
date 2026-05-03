#ifndef CLAWSEC_OBFS_H
#define CLAWSEC_OBFS_H

#include <stddef.h>

/* Obfuscation modes */
#define OBFS_NONE 0
#define OBFS_HTTP 1
#define OBFS_TLS  2

/* Anti-fingerprint: pad all packets to this size */
#define OBFS_PAD_SIZE 1400

/* Set obfuscation mode globally */
void obfs_set_mode(int mode);

/* Get current obfuscation mode */
int obfs_get_mode(void);

/*
 * TLS camouflage layer — wraps the socket in a real TLS 1.3 session.
 * Must be called AFTER accept/connect, BEFORE any crypto handshake.
 * Returns 0 on success, -1 on error.
 */
int obfs_tls_accept(int fd);
int obfs_tls_connect(int fd);

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

/*
 * Pad buffer to OBFS_PAD_SIZE bytes. Returns padded length.
 * Format: [2-byte real_len big-endian][payload][random padding]
 */
int obfs_pad(const void *data, size_t len, void *out, size_t out_max);

/*
 * Unpad buffer. Returns original payload length, copies to out.
 */
int obfs_unpad(const void *data, size_t len, void *out, size_t out_max);

/*
 * Apply timing jitter — sleep for random 0..max_ms milliseconds.
 */
void obfs_jitter(int max_ms);

#endif
