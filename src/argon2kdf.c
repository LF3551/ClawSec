/*
 * argon2kdf.c — Argon2id password key derivation (libargon2)
 *
 * libargon2 is the reference implementation from the Password Hashing
 * Competition; it gives identical results on every platform. OpenSSL's
 * ARGON2ID KDF (3.2+) is only used to cross-check it in tests.
 */

#include "argon2kdf.h"

#include <string.h>
#include <stdint.h>
#include <argon2.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

/* OpenSSL < 3.2 lacks the Argon2 parameter names */
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
    return 1;
}

static int valid_args(const char *password, size_t pass_len,
                      const unsigned char *salt, size_t salt_len,
                      const unsigned char *key_out, size_t key_len) {
    return password && pass_len > 0 && pass_len <= UINT32_MAX &&
           salt && salt_len >= 16 && salt_len <= UINT32_MAX &&
           key_out && key_len >= 4 && key_len <= UINT32_MAX;
}

int kdf_derive(const char *password, size_t pass_len,
               const unsigned char *salt, size_t salt_len,
               unsigned char *key_out, size_t key_len) {
    if (!valid_args(password, pass_len, salt, salt_len, key_out, key_len))
        return -1;
    int rc = argon2id_hash_raw(CLAWSEC_ARGON2_T_COST, CLAWSEC_ARGON2_M_COST,
                               CLAWSEC_ARGON2_LANES,
                               password, pass_len, salt, salt_len,
                               key_out, key_len);
    return rc == ARGON2_OK ? 0 : -1;
}

int kdf_derive_openssl(const char *password, size_t pass_len,
                       const unsigned char *salt, size_t salt_len,
                       unsigned char *key_out, size_t key_len) {
    if (!valid_args(password, pass_len, salt, salt_len, key_out, key_len))
        return -1;
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "ARGON2ID", NULL);
    if (!kdf) return -2;
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!ctx) return -1;

    uint32_t t_cost = CLAWSEC_ARGON2_T_COST;
    uint32_t m_cost = CLAWSEC_ARGON2_M_COST;
    uint32_t lanes  = CLAWSEC_ARGON2_LANES;
    uint32_t threads = CLAWSEC_ARGON2_LANES;

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
