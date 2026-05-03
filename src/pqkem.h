/*
 * pqkem.h — Post-Quantum Hybrid Key Exchange (X25519 + ML-KEM-768)
 *
 * Provides quantum-resistant key encapsulation using NIST ML-KEM-768
 * (formerly CRYSTALS-Kyber). Used in hybrid mode with X25519 ECDHE:
 * both shared secrets are combined so the session key is secure
 * against both classical and quantum adversaries.
 *
 * Requires OpenSSL >= 3.5 with ML-KEM support.
 *
 * Sizes (ML-KEM-768):
 *   Public key (encapsulation key): 1184 bytes
 *   Ciphertext:                     1088 bytes
 *   Shared secret:                    32 bytes
 */

#ifndef PQKEM_H
#define PQKEM_H

#include <stddef.h>

#define PQ_KEM_PUBKEY_LEN  1184
#define PQ_KEM_CT_LEN      1088
#define PQ_KEM_SS_LEN        32

extern int g_pq;

/* Check if ML-KEM-768 is available in the current OpenSSL build.
 * Returns 1 if available, 0 if not. */
int pq_available(void);

/* Generate ML-KEM-768 keypair.
 * pubkey_out: buffer of PQ_KEM_PUBKEY_LEN bytes for public key.
 * Returns opaque handle (cast of EVP_PKEY*), or NULL on error.
 * Caller must free with pq_free_key(). */
void *pq_keygen(unsigned char *pubkey_out);

/* Encapsulate: generate shared secret from peer's public key.
 * peer_pubkey: PQ_KEM_PUBKEY_LEN bytes.
 * ct_out:      buffer of PQ_KEM_CT_LEN bytes for ciphertext.
 * ss_out:      buffer of PQ_KEM_SS_LEN bytes for shared secret.
 * Returns 0 on success, -1 on error. */
int pq_encapsulate(const unsigned char *peer_pubkey, unsigned char *ct_out,
                   unsigned char *ss_out);

/* Decapsulate: recover shared secret from ciphertext + private key.
 * handle:  opaque handle from pq_keygen().
 * ct:      PQ_KEM_CT_LEN bytes ciphertext.
 * ss_out:  buffer of PQ_KEM_SS_LEN bytes for shared secret.
 * Returns 0 on success, -1 on error. */
int pq_decapsulate(void *handle, const unsigned char *ct, unsigned char *ss_out);

/* Free ML-KEM key handle. */
void pq_free_key(void *handle);

#endif /* PQKEM_H */
