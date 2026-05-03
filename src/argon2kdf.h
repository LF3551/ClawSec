/*
 * argon2kdf.h — Argon2id key derivation with PBKDF2 fallback
 */

#ifndef ARGON2KDF_H
#define ARGON2KDF_H

#include <stddef.h>

/* Argon2id parameters (OWASP 2024 recommendations, single-threaded) */
#define ARGON2_T_COST   3       /* iterations */
#define ARGON2_M_COST   19456   /* memory in KiB (19 MiB) — OWASP minimum for t=3 */
#define ARGON2_LANES    1       /* parallelism (OpenSSL thread pool limitation) */

/* Check if Argon2id is available at runtime */
int argon2_available(void);

/* Derive key using Argon2id (or PBKDF2 fallback).
 * password, pass_len — input password
 * salt, salt_len     — salt (min 16 bytes)
 * key_out            — output buffer
 * key_len            — desired key length (typically 32)
 * Returns 0 on success, -1 on error. */
int kdf_derive(const char *password, size_t pass_len,
               const unsigned char *salt, size_t salt_len,
               unsigned char *key_out, size_t key_len);

#endif /* ARGON2KDF_H */
