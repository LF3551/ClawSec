/*
 * ecdhe.h — ECDHE key exchange interface
 *
 * All functions output a 32-byte derived key into key_out.
 * The caller (farm9crypt) uses this key to initialize AES-GCM.
 *
 * Three variants:
 *  - Plain ECDHE (X25519 + password)
 *  - TOFU ECDHE (X25519 + Ed25519 identity + password)
 *  - PQ hybrid ECDHE (X25519 + ML-KEM-768 + optional TOFU + password)
 */

#ifndef ECDHE_H
#define ECDHE_H

#include <stddef.h>

/* Plain X25519 ECDHE + password.
 * key_out: 32-byte buffer for derived session key.
 * Returns 0 on success, -1 on error. */
int ecdhe_handshake(int sockfd, const char *password, size_t pass_len,
                    int server_mode, unsigned char *key_out);

/* ECDHE with TOFU server identity verification.
 * key_out: 32-byte buffer for derived session key.
 * Returns 0 on success, -1 on error. */
int ecdhe_handshake_tofu(int sockfd, const char *password, size_t pass_len,
                         int server_mode, const char *peer_host,
                         const char *peer_port, unsigned char *key_out);

/* Post-quantum hybrid ECDHE (X25519 + ML-KEM-768, optional TOFU).
 * key_out: 32-byte buffer for derived session key.
 * Returns 0 on success, -1 on error. */
int ecdhe_handshake_pq(int sockfd, const char *password, size_t pass_len,
                       int server_mode, const char *peer_host,
                       const char *peer_port, unsigned char *key_out);

/* Low-level obfs-aware send/recv helpers */
int ecdhe_send(int sockfd, const void *buf, size_t len);
int ecdhe_recv(int sockfd, void *buf, size_t len);

#endif /* ECDHE_H */
