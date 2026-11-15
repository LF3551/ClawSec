/*
 * spake2.c — SPAKE2 (RFC 9382), ciphersuite P256-SHA256-HKDF-HMAC
 *
 * Scalar multiplications with secret scalars use OpenSSL's single-scalar
 * EC_POINT_mul paths (fixed-base for the generator, constant-time ladder /
 * nistz256 windowing for other points); x, y and w are flagged constant-time.
 * Received points are validated (on the curve, not the identity), as is K.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>

#include "spake2.h"
#include "argon2kdf.h"

/* RFC 9382 section 6, P-256 (compressed SEC1) */
static const char *M_HEX = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f";
static const char *N_HEX = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49";

#define ID_MAX 64
#define TT_MAX (6 * 8 + 2 * ID_MAX + 3 * SPAKE2_POINT_LEN + SPAKE2_SCALAR_LEN)

struct spake2_ctx {
    int role;
    EC_GROUP *group;
    BN_CTX *bn;
    BIGNUM *w;                      /* password scalar */
    BIGNUM *s;                      /* our secret scalar (x for A, y for B) */
    unsigned char id_a[ID_MAX], id_b[ID_MAX];
    size_t id_a_len, id_b_len;
    unsigned char my_msg[SPAKE2_POINT_LEN];
    int have_msg;
    unsigned char k[SPAKE2_POINT_LEN];
    unsigned char tt[TT_MAX];
    size_t tt_len;
};

static EC_POINT *point_from_hex(const EC_GROUP *g, const char *hex, BN_CTX *bn) {
    unsigned char buf[33];
    for (size_t i = 0; i < sizeof(buf); i++) {
        unsigned int v;
        char tmp[3] = { hex[2 * i], hex[2 * i + 1], 0 };
        v = (unsigned int)strtoul(tmp, NULL, 16);
        buf[i] = (unsigned char)v;
    }
    EC_POINT *p = EC_POINT_new(g);
    if (p && EC_POINT_oct2point(g, p, buf, sizeof(buf), bn) != 1) {
        EC_POINT_free(p);
        p = NULL;
    }
    return p;
}

static int point_encode(const EC_GROUP *g, const EC_POINT *p, unsigned char out[SPAKE2_POINT_LEN],
                        BN_CTX *bn) {
    return EC_POINT_point2oct(g, p, POINT_CONVERSION_UNCOMPRESSED, out,
                              SPAKE2_POINT_LEN, bn) == SPAKE2_POINT_LEN ? 0 : -1;
}

/* len(x) as an 8-byte little-endian integer, then x */
static void tt_append(spake2_ctx *c, const unsigned char *data, size_t len) {
    uint64_t l = len;
    for (int i = 0; i < 8; i++) c->tt[c->tt_len++] = (unsigned char)(l >> (8 * i));
    if (len) memcpy(c->tt + c->tt_len, data, len);
    c->tt_len += len;
}

int spake2_password_to_w(const char *password, size_t pass_len,
                         const unsigned char *salt, size_t salt_len,
                         unsigned char w_out[SPAKE2_SCALAR_LEN]) {
    unsigned char wide[64];
    int rc = -1;
    BIGNUM *x = NULL, *order = NULL;
    BN_CTX *bn = BN_CTX_new();
    EC_GROUP *g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    if (!bn || !g || kdf_derive(password, pass_len, salt, salt_len, wide, sizeof(wide)) != 0)
        goto out;
    x = BN_bin2bn(wide, sizeof(wide), NULL);
    order = BN_new();
    if (!x || !order || !EC_GROUP_get_order(g, order, bn)) goto out;
    BN_set_flags(x, BN_FLG_CONSTTIME);
    if (!BN_nnmod(x, x, order, bn)) goto out;
    if (BN_bn2binpad(x, w_out, SPAKE2_SCALAR_LEN) != SPAKE2_SCALAR_LEN) goto out;
    rc = 0;
out:
    OPENSSL_cleanse(wide, sizeof(wide));
    BN_clear_free(x);
    BN_free(order);
    EC_GROUP_free(g);
    BN_CTX_free(bn);
    return rc;
}

spake2_ctx *spake2_new(int role, const unsigned char w[SPAKE2_SCALAR_LEN],
                       const unsigned char *idA, size_t idA_len,
                       const unsigned char *idB, size_t idB_len) {
    if ((role != SPAKE2_ROLE_A && role != SPAKE2_ROLE_B) || !w ||
        idA_len > ID_MAX || idB_len > ID_MAX)
        return NULL;
    spake2_ctx *c = OPENSSL_zalloc(sizeof(*c));
    if (!c) return NULL;
    c->role = role;
    c->group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    c->bn = BN_CTX_new();
    c->w = BN_bin2bn(w, SPAKE2_SCALAR_LEN, NULL);
    if (!c->group || !c->bn || !c->w) {
        spake2_free(c);
        return NULL;
    }
    BN_set_flags(c->w, BN_FLG_CONSTTIME);
    if (idA_len) memcpy(c->id_a, idA, idA_len);
    if (idB_len) memcpy(c->id_b, idB, idB_len);
    c->id_a_len = idA_len;
    c->id_b_len = idB_len;
    return c;
}

int spake2_set_secret(spake2_ctx *c, const unsigned char s[SPAKE2_SCALAR_LEN]) {
    if (!c || c->s) return -1;
    c->s = BN_bin2bn(s, SPAKE2_SCALAR_LEN, NULL);
    if (!c->s) return -1;
    BN_set_flags(c->s, BN_FLG_CONSTTIME);
    return 0;
}

/* T = s*P + w*X, with X = M (role A) or N (role B) */
int spake2_message(spake2_ctx *c, unsigned char out[SPAKE2_POINT_LEN]) {
    int rc = -1;
    EC_POINT *X = NULL, *T1 = NULL, *T2 = NULL;
    BIGNUM *order = NULL;
    if (!c) return -1;

    if (!c->s) {                                   /* random s in [1, order-1] */
        order = BN_new();
        c->s = BN_new();
        if (!order || !c->s || !EC_GROUP_get_order(c->group, order, c->bn)) goto out;
        do {
            if (!BN_priv_rand_range(c->s, order)) goto out;
        } while (BN_is_zero(c->s));
        BN_set_flags(c->s, BN_FLG_CONSTTIME);
    }

    X = point_from_hex(c->group, c->role == SPAKE2_ROLE_A ? M_HEX : N_HEX, c->bn);
    T1 = EC_POINT_new(c->group);
    T2 = EC_POINT_new(c->group);
    if (!X || !T1 || !T2) goto out;
    if (!EC_POINT_mul(c->group, T1, c->s, NULL, NULL, c->bn)) goto out;    /* s*P */
    if (!EC_POINT_mul(c->group, T2, NULL, X, c->w, c->bn)) goto out;       /* w*X */
    if (!EC_POINT_add(c->group, T1, T1, T2, c->bn)) goto out;
    if (EC_POINT_is_at_infinity(c->group, T1)) goto out;
    if (point_encode(c->group, T1, c->my_msg, c->bn) != 0) goto out;
    memcpy(out, c->my_msg, SPAKE2_POINT_LEN);
    c->have_msg = 1;
    rc = 0;
out:
    EC_POINT_free(X);
    EC_POINT_clear_free(T1);
    EC_POINT_clear_free(T2);
    BN_free(order);
    return rc;
}

static int hkdf_sha256(const unsigned char *ikm, size_t ikm_len,
                       const unsigned char *info, size_t info_len,
                       unsigned char *out, size_t out_len) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) return -1;
    EVP_KDF_CTX *kc = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kc) return -1;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)"SHA256", 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)ikm, ikm_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info, info_len),
        OSSL_PARAM_construct_end()
    };
    int rc = EVP_KDF_derive(kc, out, out_len, params) == 1 ? 0 : -1;
    EVP_KDF_CTX_free(kc);
    return rc;
}

int spake2_finish(spake2_ctx *c, const unsigned char peer[SPAKE2_POINT_LEN],
                  const unsigned char *aad, size_t aad_len,
                  unsigned char ke[SPAKE2_KEY_LEN],
                  unsigned char my_conf[SPAKE2_CONF_LEN],
                  unsigned char peer_conf[SPAKE2_CONF_LEN],
                  unsigned char tt_hash[32]) {
    int rc = -1;
    EC_POINT *P = NULL, *Y = NULL, *K = NULL, *wY = NULL;
    unsigned char h[32], kc[2 * SPAKE2_KEY_LEN], wbuf[SPAKE2_SCALAR_LEN];
    unsigned char *info = NULL;
    unsigned int mlen = 0;

    if (!c || !c->have_msg || !peer || (aad_len && !aad)) return -1;

    /* Peer point: on the curve (oct2point checks) and not the identity */
    P = EC_POINT_new(c->group);
    if (!P || EC_POINT_oct2point(c->group, P, peer, SPAKE2_POINT_LEN, c->bn) != 1 ||
        EC_POINT_is_at_infinity(c->group, P))
        goto out;

    /* K = h * s * (peer - w*Y), Y = N for A, M for B; h = 1 for P-256 */
    Y = point_from_hex(c->group, c->role == SPAKE2_ROLE_A ? N_HEX : M_HEX, c->bn);
    wY = EC_POINT_new(c->group);
    K = EC_POINT_new(c->group);
    if (!Y || !wY || !K) goto out;
    if (!EC_POINT_mul(c->group, wY, NULL, Y, c->w, c->bn)) goto out;
    if (!EC_POINT_invert(c->group, wY, c->bn)) goto out;
    if (!EC_POINT_add(c->group, wY, P, wY, c->bn)) goto out;
    if (!EC_POINT_mul(c->group, K, NULL, wY, c->s, c->bn)) goto out;
    if (EC_POINT_is_at_infinity(c->group, K)) goto out;
    if (point_encode(c->group, K, c->k, c->bn) != 0) goto out;

    /* TT = len(A)||A || len(B)||B || len(pA)||pA || len(pB)||pB || len(K)||K || len(w)||w */
    const unsigned char *pA = c->role == SPAKE2_ROLE_A ? c->my_msg : peer;
    const unsigned char *pB = c->role == SPAKE2_ROLE_A ? peer : c->my_msg;
    if (BN_bn2binpad(c->w, wbuf, SPAKE2_SCALAR_LEN) != SPAKE2_SCALAR_LEN) goto out;
    c->tt_len = 0;
    tt_append(c, c->id_a, c->id_a_len);
    tt_append(c, c->id_b, c->id_b_len);
    tt_append(c, pA, SPAKE2_POINT_LEN);
    tt_append(c, pB, SPAKE2_POINT_LEN);
    tt_append(c, c->k, SPAKE2_POINT_LEN);
    tt_append(c, wbuf, SPAKE2_SCALAR_LEN);

    /* Ke || Ka = Hash(TT) */
    if (!EVP_Digest(c->tt, c->tt_len, h, NULL, EVP_sha256(), NULL)) goto out;
    memcpy(ke, h, SPAKE2_KEY_LEN);
    memcpy(tt_hash, h, 32);

    /* KcA || KcB = HKDF(Ka, nil, "ConfirmationKeys" || AAD, 32) */
    static const char label[] = "ConfirmationKeys";
    info = OPENSSL_malloc(sizeof(label) - 1 + aad_len);
    if (!info) goto out;
    memcpy(info, label, sizeof(label) - 1);
    if (aad_len) memcpy(info + sizeof(label) - 1, aad, aad_len);
    if (hkdf_sha256(h + SPAKE2_KEY_LEN, SPAKE2_KEY_LEN, info, sizeof(label) - 1 + aad_len,
                    kc, sizeof(kc)) != 0)
        goto out;

    /* cA = MAC(KcA, TT), cB = MAC(KcB, TT) */
    unsigned char *mine = my_conf, *theirs = peer_conf;
    const unsigned char *kca = kc, *kcb = kc + SPAKE2_KEY_LEN;
    if (!HMAC(EVP_sha256(), c->role == SPAKE2_ROLE_A ? kca : kcb, SPAKE2_KEY_LEN,
              c->tt, c->tt_len, mine, &mlen) || mlen != SPAKE2_CONF_LEN)
        goto out;
    if (!HMAC(EVP_sha256(), c->role == SPAKE2_ROLE_A ? kcb : kca, SPAKE2_KEY_LEN,
              c->tt, c->tt_len, theirs, &mlen) || mlen != SPAKE2_CONF_LEN)
        goto out;
    rc = 0;
out:
    OPENSSL_cleanse(h, sizeof(h));
    OPENSSL_cleanse(kc, sizeof(kc));
    OPENSSL_cleanse(wbuf, sizeof(wbuf));
    OPENSSL_free(info);
    EC_POINT_free(P);
    EC_POINT_free(Y);
    EC_POINT_clear_free(wY);
    EC_POINT_clear_free(K);
    return rc;
}

int spake2_transcript(const spake2_ctx *c, unsigned char *buf, size_t buf_len) {
    if (!c || buf_len < c->tt_len) return -1;
    memcpy(buf, c->tt, c->tt_len);
    return (int)c->tt_len;
}

int spake2_shared_point(const spake2_ctx *c, unsigned char out[SPAKE2_POINT_LEN]) {
    if (!c || !c->tt_len) return -1;
    memcpy(out, c->k, SPAKE2_POINT_LEN);
    return 0;
}

void spake2_free(spake2_ctx *c) {
    if (!c) return;
    BN_clear_free(c->w);
    BN_clear_free(c->s);
    EC_GROUP_free(c->group);
    BN_CTX_free(c->bn);
    OPENSSL_clear_free(c, sizeof(*c));
}
