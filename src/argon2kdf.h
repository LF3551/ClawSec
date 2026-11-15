/*
 * argon2kdf.h — Argon2id password key derivation
 *
 * Always Argon2id (RFC 9106) via the reference library libargon2, so every
 * build derives the same key regardless of the OpenSSL version installed.
 * (Before 3.0, builds silently fell back to PBKDF2 on OpenSSL < 3.2 and could
 * not talk to builds that used Argon2id.)
 */

#ifndef ARGON2KDF_H
#define ARGON2KDF_H

#include <stddef.h>

/* Argon2id parameters — part of the wire protocol: changing them changes
 * every derived key. OWASP minimum profile for t=3, single lane. */
#define CLAWSEC_ARGON2_T_COST   3       /* iterations */
#define CLAWSEC_ARGON2_M_COST   19456   /* memory in KiB (19 MiB) */
#define CLAWSEC_ARGON2_LANES    1       /* parallelism */

/* Kept for API compatibility: Argon2id is always available (returns 1). */
int argon2_available(void);

/* Derive key_len bytes with Argon2id.
 * salt_len must be >= 16. Returns 0 on success, -1 on error. */
int kdf_derive(const char *password, size_t pass_len,
               const unsigned char *salt, size_t salt_len,
               unsigned char *key_out, size_t key_len);

/* Same derivation through OpenSSL's ARGON2ID KDF (OpenSSL >= 3.2), used by
 * tests to cross-check libargon2. Returns 0 on success, -1 on error,
 * -2 if this OpenSSL has no Argon2. */
int kdf_derive_openssl(const char *password, size_t pass_len,
                       const unsigned char *salt, size_t salt_len,
                       unsigned char *key_out, size_t key_len);

#endif /* ARGON2KDF_H */
