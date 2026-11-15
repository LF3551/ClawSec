/*
 * spake2.h — SPAKE2 password-authenticated key exchange (RFC 9382)
 *
 * Ciphersuite P256-SHA256-HKDF-HMAC: group P-256, Hash SHA-256, KDF
 * HKDF-SHA256, MAC HMAC-SHA256. Party A (the ClawSec client) sends
 * pA = x*P + w*M, party B (the server) sends pB = y*P + w*N; both derive
 * K, the transcript TT, the shared secret Ke and the confirmation MACs.
 *
 * An eavesdropper learns nothing about the password, and an active attacker
 * can test exactly one password guess per protocol run (no offline
 * dictionary attack), unlike a plain DH exchange with a password-derived key.
 */
#ifndef CLAWSEC_SPAKE2_H
#define CLAWSEC_SPAKE2_H

#include <stddef.h>

#define SPAKE2_ROLE_A 0           /* initiator: ClawSec client */
#define SPAKE2_ROLE_B 1           /* responder: ClawSec server */

#define SPAKE2_SCALAR_LEN 32      /* w, x, y: big-endian, length of the group order */
#define SPAKE2_POINT_LEN  65      /* uncompressed SEC1 point */
#define SPAKE2_KEY_LEN    16      /* Ke, Ka, KcA, KcB */
#define SPAKE2_CONF_LEN   32      /* HMAC-SHA256 confirmation message */

typedef struct spake2_ctx spake2_ctx;

/* Derive w from a password: Argon2id(password, salt) -> 64 bytes, reduced
 * modulo the group order (bias < 2^-250). Returns 0 or -1. */
int spake2_password_to_w(const char *password, size_t pass_len,
                         const unsigned char *salt, size_t salt_len,
                         unsigned char w_out[SPAKE2_SCALAR_LEN]);

/* Create a context. idA/idB are the party identities (may be empty). */
spake2_ctx *spake2_new(int role, const unsigned char w[SPAKE2_SCALAR_LEN],
                       const unsigned char *idA, size_t idA_len,
                       const unsigned char *idB, size_t idB_len);

/* Tests only: use a fixed secret scalar instead of a random one.
 * Must be called before spake2_message(). */
int spake2_set_secret(spake2_ctx *ctx, const unsigned char s[SPAKE2_SCALAR_LEN]);

/* Our protocol message (pA for A, pB for B). Returns 0 or -1. */
int spake2_message(spake2_ctx *ctx, unsigned char out[SPAKE2_POINT_LEN]);

/* Process the peer's message. aad is the associated data bound into the
 * confirmation keys (RFC 9382 section 4); may be empty.
 * Outputs Ke, our confirmation message and the one expected from the peer,
 * and SHA-256(TT). Returns 0, or -1 if the peer message is invalid (not on
 * the curve, identity) or the shared point is the identity. */
int spake2_finish(spake2_ctx *ctx, const unsigned char peer[SPAKE2_POINT_LEN],
                  const unsigned char *aad, size_t aad_len,
                  unsigned char ke[SPAKE2_KEY_LEN],
                  unsigned char my_conf[SPAKE2_CONF_LEN],
                  unsigned char peer_conf[SPAKE2_CONF_LEN],
                  unsigned char tt_hash[32]);

/* Tests only: copy the transcript TT built by spake2_finish().
 * Returns its length, or -1 if buf is too small. */
int spake2_transcript(const spake2_ctx *ctx, unsigned char *buf, size_t buf_len);

/* Tests only: the K point computed by spake2_finish(). */
int spake2_shared_point(const spake2_ctx *ctx, unsigned char out[SPAKE2_POINT_LEN]);

/* Wipe secrets and free. NULL is fine. */
void spake2_free(spake2_ctx *ctx);

#endif
