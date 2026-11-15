/*
 * test_spake2.c — SPAKE2 (RFC 9382) against the RFC test vectors, and basic
 * protocol properties.
 */
#define _POSIX_C_SOURCE 200809L
#include "test.h"
#include "spake2.h"
#include "spake2_vectors.h"

static int run_vector(int i, char *why, size_t why_len) {
    unsigned char ma[SPAKE2_POINT_LEN], mb[SPAKE2_POINT_LEN];
    unsigned char kea[SPAKE2_KEY_LEN], keb[SPAKE2_KEY_LEN];
    unsigned char ca_mine[SPAKE2_CONF_LEN], ca_peer[SPAKE2_CONF_LEN];
    unsigned char cb_mine[SPAKE2_CONF_LEN], cb_peer[SPAKE2_CONF_LEN];
    unsigned char ha[32], hb[32], tt[512], k[SPAKE2_POINT_LEN];
    const char *ida = spake2_vectors[i].ida, *idb = spake2_vectors[i].idb;
    int ok = 0;
    spake2_ctx *a = spake2_new(SPAKE2_ROLE_A, spake2_vectors[i].w,
                               (const unsigned char *)ida, strlen(ida),
                               (const unsigned char *)idb, strlen(idb));
    spake2_ctx *b = spake2_new(SPAKE2_ROLE_B, spake2_vectors[i].w,
                               (const unsigned char *)ida, strlen(ida),
                               (const unsigned char *)idb, strlen(idb));
#define CHECK(cond, msg) do { if (!(cond)) { snprintf(why, why_len, "vector %d: %s", i, msg); goto out; } } while (0)
    CHECK(a && b, "context");
    CHECK(spake2_set_secret(a, spake2_vectors[i].x) == 0, "set x");
    CHECK(spake2_set_secret(b, spake2_vectors[i].y) == 0, "set y");
    CHECK(spake2_message(a, ma) == 0 && memcmp(ma, spake2_vectors[i].pa, 65) == 0, "pA");
    CHECK(spake2_message(b, mb) == 0 && memcmp(mb, spake2_vectors[i].pb, 65) == 0, "pB");
    CHECK(spake2_finish(a, mb, NULL, 0, kea, ca_mine, ca_peer, ha) == 0, "finish A");
    CHECK(spake2_finish(b, ma, NULL, 0, keb, cb_mine, cb_peer, hb) == 0, "finish B");
    CHECK(spake2_shared_point(a, k) == 0 && memcmp(k, spake2_vectors[i].k, 65) == 0, "K");
    CHECK(spake2_transcript(a, tt, sizeof(tt)) == (int)spake2_vectors[i].tt_len &&
          memcmp(tt, spake2_vectors[i].tt, spake2_vectors[i].tt_len) == 0, "TT");
    CHECK(memcmp(kea, spake2_vectors[i].ke, 16) == 0 && memcmp(keb, kea, 16) == 0, "Ke");
    CHECK(memcmp(ca_mine, spake2_vectors[i].aconf, 32) == 0, "A conf");
    CHECK(memcmp(cb_mine, spake2_vectors[i].bconf, 32) == 0, "B conf");
    CHECK(memcmp(ca_peer, cb_mine, 32) == 0 && memcmp(cb_peer, ca_mine, 32) == 0,
          "expected peer confirmations");
    ok = 1;
#undef CHECK
out:
    spake2_free(a);
    spake2_free(b);
    return ok;
}

void test_spake2_rfc9382_vectors(void) {
    TEST_BEGIN("SPAKE2 matches all RFC 9382 P-256 test vectors") {
        char why[128] = "";
        for (int i = 0; i < SPAKE2_NVEC; i++)
            ASSERT(run_vector(i, why, sizeof(why)), why);
    } TEST_END;
}

/* Random scalars, same/different w, AAD binding */
static int exchange(const unsigned char *wa, const unsigned char *wb,
                    const char *aad_a, const char *aad_b, int *confirm_ok) {
    unsigned char ma[65], mb[65], kea[16], keb[16], ca[32], cpa[32], cb[32], cpb[32], h[32];
    spake2_ctx *a = spake2_new(SPAKE2_ROLE_A, wa, (const unsigned char *)"c", 1,
                               (const unsigned char *)"s", 1);
    spake2_ctx *b = spake2_new(SPAKE2_ROLE_B, wb, (const unsigned char *)"c", 1,
                               (const unsigned char *)"s", 1);
    int rc = a && b && spake2_message(a, ma) == 0 && spake2_message(b, mb) == 0 &&
             spake2_finish(a, mb, (const unsigned char *)aad_a, strlen(aad_a), kea, ca, cpa, h) == 0 &&
             spake2_finish(b, ma, (const unsigned char *)aad_b, strlen(aad_b), keb, cb, cpb, h) == 0;
    *confirm_ok = rc && memcmp(ca, cpb, 32) == 0 && memcmp(cb, cpa, 32) == 0 &&
                  memcmp(kea, keb, 16) == 0;
    spake2_free(a);
    spake2_free(b);
    return rc;
}

void test_spake2_properties(void) {
    TEST_BEGIN("SPAKE2: same password confirms, other password/AAD does not") {
        unsigned char w1[32], w2[32];
        ASSERT(spake2_password_to_w("correct horse", 13, (const unsigned char *)"0123456789abcdef", 16, w1) == 0, "w1");
        ASSERT(spake2_password_to_w("correct horsf", 13, (const unsigned char *)"0123456789abcdef", 16, w2) == 0, "w2");
        int ok;
        ASSERT(exchange(w1, w1, "aad", "aad", &ok) && ok, "same password must confirm");
        ASSERT(exchange(w1, w2, "aad", "aad", &ok) && !ok, "different password must not confirm");
        ASSERT(exchange(w1, w1, "aad", "AAD", &ok) && !ok, "different AAD (transcript) must not confirm");
    } TEST_END;
}

void test_spake2_rejects_bad_points(void) {
    TEST_BEGIN("SPAKE2 rejects off-curve and identity points") {
        unsigned char w[32] = { 1 }, m[65], ke[16], c1[32], c2[32], h[32];
        spake2_ctx *a = spake2_new(SPAKE2_ROLE_A, w, NULL, 0, NULL, 0);
        ASSERT(a && spake2_message(a, m) == 0, "init");
        unsigned char bad[65];
        memcpy(bad, m, 65);
        bad[64] ^= 1;                               /* (x, y+1): not on the curve */
        int r1 = spake2_finish(a, bad, NULL, 0, ke, c1, c2, h);
        unsigned char zero[65] = { 0 };             /* not a valid encoding */
        int r2 = spake2_finish(a, zero, NULL, 0, ke, c1, c2, h);
        spake2_free(a);
        ASSERT(r1 == -1, "off-curve point accepted");
        ASSERT(r2 == -1, "invalid encoding accepted");
    } TEST_END;
}
