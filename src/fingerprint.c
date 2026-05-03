/*
 * fingerprint.c — TLS ClientHello browser fingerprinting
 *
 * Shapes cipher suites, extensions, and parameters to match
 * real browser JA3/JA4 fingerprints.  Without this, OpenSSL's
 * default ClientHello is trivially identified as non-browser.
 */

#include "fingerprint.h"

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <string.h>

static int g_fp_profile = FP_NONE;

void fp_set_profile(int profile) { g_fp_profile = profile; }
int  fp_get_profile(void)        { return g_fp_profile; }

/* ──────── application_settings extension (0x4469, ALPS) ──────── */

/*
 * Chrome sends ALPS (Application-Layer Protocol Settings)
 * in ClientHello.  This extension is unique to Chrome and a
 * strong JA4 fingerprint marker.
 * Payload: length-prefixed list of ALPN protocol names.
 */
static int fp_alps_add_cb(SSL *s, unsigned int ext_type,
                          unsigned int context,
                          const unsigned char **out, size_t *outlen,
                          X509 *x, size_t chainidx,
                          int *al, void *add_arg) {
    (void)s; (void)ext_type; (void)context;
    (void)x; (void)chainidx; (void)al; (void)add_arg;

    /* Chrome ALPS payload: supported protocols for ALPS */
    static const unsigned char data[] = {
        0x00, 0x03,  /* protocols length */
        0x02, 'h', '2'  /* h2 */
    };
    *out = data;
    *outlen = sizeof(data);
    return 1;
}

static void fp_alps_free_cb(SSL *s, unsigned int ext_type,
                            unsigned int context,
                            const unsigned char *out,
                            void *add_arg) {
    (void)s; (void)ext_type; (void)context; (void)out; (void)add_arg;
    /* static data — nothing to free */
}

/* ──────── Chrome 124+ ──────── */

static int fp_apply_chrome(SSL_CTX *ctx) {
    /* Browsers list TLS 1.2 in supported_versions alongside 1.3 */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    /* TLS 1.3 ciphersuites — Chrome order */
    SSL_CTX_set_ciphersuites(ctx,
        "TLS_AES_128_GCM_SHA256:"
        "TLS_AES_256_GCM_SHA384:"
        "TLS_CHACHA20_POLY1305_SHA256");

    /* TLS 1.2 ciphersuites — Chrome order */
    SSL_CTX_set_cipher_list(ctx,
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-AES128-SHA:"
        "ECDHE-RSA-AES256-SHA:"
        "AES128-GCM-SHA256:"
        "AES256-GCM-SHA384");

    /* Supported groups — Chrome order (X25519 first) */
    SSL_CTX_set1_groups_list(ctx, "X25519:P-256:P-384");

    /* Signature algorithms — Chrome order */
    SSL_CTX_set1_sigalgs_list(ctx,
        "ECDSA+SHA256:RSA-PSS+SHA256:RSA+SHA256:"
        "ECDSA+SHA384:RSA-PSS+SHA384:RSA+SHA384:"
        "RSA-PSS+SHA512:RSA+SHA512");

    /* ALPN: h2, http/1.1 */
    static const unsigned char alpn[] = {
        2, 'h', '2',
        8, 'h', 't', 't', 'p', '/', '1', '.', '1'
    };
    SSL_CTX_set_alpn_protos(ctx, alpn, sizeof(alpn));

    /* ALPS extension (0x4469) — Chrome-unique fingerprint marker */
    SSL_CTX_add_custom_ext(ctx, 0x4469,
                           SSL_EXT_CLIENT_HELLO,
                           fp_alps_add_cb, fp_alps_free_cb,
                           NULL, NULL, NULL);

    return 0;
}

/* ──────── Firefox 125+ ──────── */

static int fp_apply_firefox(SSL_CTX *ctx) {
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    /* Firefox: CHACHA20 before AES-256 in TLS 1.3 */
    SSL_CTX_set_ciphersuites(ctx,
        "TLS_AES_128_GCM_SHA256:"
        "TLS_CHACHA20_POLY1305_SHA256:"
        "TLS_AES_256_GCM_SHA384");

    SSL_CTX_set_cipher_list(ctx,
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES128-SHA:"
        "ECDHE-RSA-AES256-SHA:"
        "AES128-GCM-SHA256:"
        "AES256-GCM-SHA384:"
        "AES128-SHA:"
        "AES256-SHA");

    /* Firefox includes P-521 */
    SSL_CTX_set1_groups_list(ctx, "X25519:P-256:P-384:P-521");

    /* Firefox groups ECDSA together, then RSA-PSS, then RSA */
    SSL_CTX_set1_sigalgs_list(ctx,
        "ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:"
        "RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:"
        "RSA+SHA256:RSA+SHA384:RSA+SHA512");

    static const unsigned char alpn[] = {
        2, 'h', '2',
        8, 'h', 't', 't', 'p', '/', '1', '.', '1'
    };
    SSL_CTX_set_alpn_protos(ctx, alpn, sizeof(alpn));

    return 0;
}

/* ──────── Safari 17+ ──────── */

static int fp_apply_safari(SSL_CTX *ctx) {
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    SSL_CTX_set_ciphersuites(ctx,
        "TLS_AES_128_GCM_SHA256:"
        "TLS_AES_256_GCM_SHA384:"
        "TLS_CHACHA20_POLY1305_SHA256");

    /* Safari prefers AES-256 first */
    SSL_CTX_set_cipher_list(ctx,
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-CHACHA20-POLY1305:"
        "AES256-GCM-SHA384:"
        "AES128-GCM-SHA256");

    SSL_CTX_set1_groups_list(ctx, "X25519:P-256:P-384:P-521");

    SSL_CTX_set1_sigalgs_list(ctx,
        "ECDSA+SHA256:RSA-PSS+SHA256:"
        "ECDSA+SHA384:RSA-PSS+SHA384:"
        "ECDSA+SHA512:RSA-PSS+SHA512:"
        "RSA+SHA256:RSA+SHA384:RSA+SHA512");

    static const unsigned char alpn[] = {
        2, 'h', '2',
        8, 'h', 't', 't', 'p', '/', '1', '.', '1'
    };
    SSL_CTX_set_alpn_protos(ctx, alpn, sizeof(alpn));

    return 0;
}

/* ──────── Public API ──────── */

int fp_apply_ctx(SSL_CTX *ctx) {
    switch (g_fp_profile) {
    case FP_CHROME:  return fp_apply_chrome(ctx);
    case FP_FIREFOX: return fp_apply_firefox(ctx);
    case FP_SAFARI:  return fp_apply_safari(ctx);
    default: return 0;
    }
}
