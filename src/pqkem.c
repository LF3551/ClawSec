/*
 * pqkem.c — Post-Quantum Hybrid Key Exchange (ML-KEM-768)
 *
 * Uses OpenSSL 3.5+ EVP_PKEY_encapsulate/decapsulate API
 * for NIST ML-KEM-768 (CRYSTALS-Kyber) key encapsulation.
 */

#include "pqkem.h"

#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

int pq_available(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
    if (!ctx)
        return 0;
    EVP_PKEY_CTX_free(ctx);
    return 1;
}

void *pq_keygen(unsigned char *pubkey_out) {
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
    if (!kctx) return NULL;

    EVP_PKEY *key = NULL;
    if (EVP_PKEY_keygen_init(kctx) <= 0 ||
        EVP_PKEY_keygen(kctx, &key) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(kctx);

    /* Extract public (encapsulation) key */
    size_t publen = PQ_KEM_PUBKEY_LEN;
    if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY,
                                         pubkey_out, publen, &publen) != 1 ||
        publen != PQ_KEM_PUBKEY_LEN) {
        EVP_PKEY_free(key);
        return NULL;
    }

    return (void *)key;
}

int pq_encapsulate(const unsigned char *peer_pubkey, unsigned char *ct_out,
                   unsigned char *ss_out) {
    /* Load peer public key */
    EVP_PKEY_CTX *load_ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
    if (!load_ctx) return -1;

    EVP_PKEY *pub = NULL;
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                (void *)peer_pubkey, PQ_KEM_PUBKEY_LEN),
        OSSL_PARAM_END
    };
    if (EVP_PKEY_fromdata_init(load_ctx) <= 0 ||
        EVP_PKEY_fromdata(load_ctx, &pub, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        EVP_PKEY_CTX_free(load_ctx);
        return -1;
    }
    EVP_PKEY_CTX_free(load_ctx);

    /* Encapsulate */
    EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new_from_pkey(NULL, pub, NULL);
    if (!ectx) { EVP_PKEY_free(pub); return -1; }

    if (EVP_PKEY_encapsulate_init(ectx, NULL) <= 0) {
        EVP_PKEY_CTX_free(ectx);
        EVP_PKEY_free(pub);
        return -1;
    }

    size_t ct_len = PQ_KEM_CT_LEN;
    size_t ss_len = PQ_KEM_SS_LEN;
    if (EVP_PKEY_encapsulate(ectx, ct_out, &ct_len, ss_out, &ss_len) <= 0) {
        EVP_PKEY_CTX_free(ectx);
        EVP_PKEY_free(pub);
        return -1;
    }

    EVP_PKEY_CTX_free(ectx);
    EVP_PKEY_free(pub);
    return 0;
}

int pq_decapsulate(void *handle, const unsigned char *ct, unsigned char *ss_out) {
    EVP_PKEY *key = (EVP_PKEY *)handle;
    if (!key) return -1;

    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (!dctx) return -1;

    if (EVP_PKEY_decapsulate_init(dctx, NULL) <= 0) {
        EVP_PKEY_CTX_free(dctx);
        return -1;
    }

    size_t ss_len = PQ_KEM_SS_LEN;
    if (EVP_PKEY_decapsulate(dctx, ss_out, &ss_len, ct, PQ_KEM_CT_LEN) <= 0) {
        EVP_PKEY_CTX_free(dctx);
        return -1;
    }

    EVP_PKEY_CTX_free(dctx);
    return 0;
}

void pq_free_key(void *handle) {
    if (handle)
        EVP_PKEY_free((EVP_PKEY *)handle);
}
