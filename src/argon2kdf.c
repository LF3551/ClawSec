/*
 * argon2kdf.c — Argon2id key derivation (OpenSSL 3.2+) with PBKDF2 fallback
 *
 * Argon2id is memory-hard: resistant to GPU/ASIC brute force attacks.
 * Falls back to PBKDF2-SHA256 (100k iterations) on older OpenSSL.
 */

#include "argon2kdf.h"

#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

/* OpenSSL < 3.2 lacks Argon2 parameter names */
#ifndef OSSL_KDF_PARAM_ARGON2_MEMCOST
#define OSSL_KDF_PARAM_ARGON2_MEMCOST "memcost"
#endif
#ifndef OSSL_KDF_PARAM_ARGON2_LANES
#define OSSL_KDF_PARAM_ARGON2_LANES "lanes"
#endif
#ifndef OSSL_KDF_PARAM_THREADS
#define OSSL_KDF_PARAM_THREADS "threads"
#endif

int argon2_available(void) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "ARGON2ID", NULL);
    if (!kdf) return 0;
    EVP_KDF_free(kdf);
    return 1;
}

static int derive_argon2id(const char *password, size_t pass_len,
                            const unsigned char *salt, size_t salt_len,
                            unsigned char *key_out, size_t key_len) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "ARGON2ID", NULL);
    if (!kdf) return -1;

    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!ctx) return -1;

    uint32_t t_cost = ARGON2_T_COST;
    uint32_t m_cost = ARGON2_M_COST;
    uint32_t lanes  = ARGON2_LANES;
    uint32_t threads = ARGON2_LANES;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                          (void *)password, pass_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                          (void *)salt, salt_len),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &t_cost),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &m_cost),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &threads),
        OSSL_PARAM_construct_end()
    };

    int rc = EVP_KDF_derive(ctx, key_out, key_len, params);
    EVP_KDF_CTX_free(ctx);
    return rc > 0 ? 0 : -1;
}

static int derive_pbkdf2(const char *password, size_t pass_len,
                           const unsigned char *salt, size_t salt_len,
                           unsigned char *key_out, size_t key_len) {
    if (PKCS5_PBKDF2_HMAC(password, pass_len, salt, salt_len,
                           100000, EVP_sha256(),
                           (int)key_len, key_out) != 1)
        return -1;
    return 0;
}

int kdf_derive(const char *password, size_t pass_len,
               const unsigned char *salt, size_t salt_len,
               unsigned char *key_out, size_t key_len) {
    if (!password || pass_len == 0 || !salt || salt_len < 16 ||
        !key_out || key_len == 0)
        return -1;

    if (argon2_available())
        return derive_argon2id(password, pass_len, salt, salt_len,
                                key_out, key_len);

    /* Fallback for OpenSSL < 3.2 */
    fprintf(stderr, "[KDF] Warning: Argon2id unavailable, using PBKDF2 fallback\n");
    return derive_pbkdf2(password, pass_len, salt, salt_len,
                          key_out, key_len);
}
