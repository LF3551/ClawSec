/*
 * ecdhe.h — ClawSec v4 handshake interface (see ecdhe.cc for the wire format)
 *
 * All functions output a 32-byte session key into key_out; the caller
 * (farm9crypt) derives the directional AES-GCM keys from it. Each handshake
 * includes mutual explicit key confirmation: success means the peer proved
 * knowledge of the password.
 *
 * Variants:
 *  - SPAKE2 (password-authenticated key exchange, RFC 9382)
 *  - SPAKE2 + Ed25519 server identity (TOFU)
 *  - SPAKE2 + ML-KEM-768 hybrid (+ TOFU if g_tofu is set)
 */

#ifndef ECDHE_H
#define ECDHE_H

#include <stddef.h>

/* Derive and cache the password scalar (Argon2id, ~19 MiB, done once per
 * process). Call before forking per-connection children so that each
 * handshake does not repeat the expensive derivation. Returns 0 or -1. */
int ecdhe_prepare_password(const char *password, size_t pass_len);
void ecdhe_forget_password(void);

/* SPAKE2 + password.
 * key_out: 32-byte buffer for derived session key.
 * Returns 0 on success, -1 on error. */
int ecdhe_handshake(int sockfd, const char *password, size_t pass_len,
                    int server_mode, unsigned char *key_out);

/* SPAKE2 with TOFU server identity verification.
 * key_out: 32-byte buffer for derived session key.
 * Returns 0 on success, -1 on error. */
int ecdhe_handshake_tofu(int sockfd, const char *password, size_t pass_len,
                         int server_mode, const char *peer_host,
                         const char *peer_port, unsigned char *key_out);

/* Post-quantum hybrid (SPAKE2 + ML-KEM-768, TOFU if g_tofu).
 * key_out: 32-byte buffer for derived session key.
 * Returns 0 on success, -1 on error. */
int ecdhe_handshake_pq(int sockfd, const char *password, size_t pass_len,
                       int server_mode, const char *peer_host,
                       const char *peer_port, unsigned char *key_out);

/* Low-level obfs-aware send/recv helpers */
int ecdhe_send(int sockfd, const void *buf, size_t len);
int ecdhe_recv(int sockfd, void *buf, size_t len);

#endif /* ECDHE_H */
