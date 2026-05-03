/*
 * ecdhe.cc — ECDHE key exchange (X25519, TOFU, post-quantum hybrid)
 *
 * Extracted from farm9crypt.cc. All handshake functions output a
 * 32-byte derived session key; the caller initializes AES-GCM with it.
 */

#ifndef WIN32
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/kdf.h>
#else
#include <fcntl.h>
#include <io.h>
#include <winsock.h>
#endif

extern "C"
{
#include "ecdhe.h"
#include "obfs.h"
#include "tofu.h"
#include "pqkem.h"
#include "argon2kdf.h"
}

static int debug = false;

/* Secure memory cleanup */
static void secure_zero(void *ptr, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) *p++ = 0;
}

/* ---------- obfs-aware I/O ---------- */

extern "C" int ecdhe_send(int sockfd, const void *buf, size_t len) {
    if (obfs_get_mode() != OBFS_NONE)
        return obfs_send(sockfd, buf, len) < 0 ? -1 : 0;
    size_t total = 0;
    const unsigned char *ptr = (const unsigned char *)buf;
    while (total < len) {
        ssize_t n = send(sockfd, ptr + total, len - total, 0);
        if (n <= 0) { if (errno == EINTR) continue; return -1; }
        total += n;
    }
    return 0;
}

extern "C" int ecdhe_recv(int sockfd, void *buf, size_t len) {
    if (obfs_get_mode() != OBFS_NONE)
        return obfs_recv(sockfd, buf, len) <= 0 ? -1 : 0;
    size_t total = 0;
    unsigned char *ptr = (unsigned char *)buf;
    while (total < len) {
        ssize_t n = recv(sockfd, ptr + total, len - total, 0);
        if (n <= 0) { if (n == 0) return -1; if (errno == EINTR) continue; return -1; }
        total += n;
    }
    return 0;
}

/* ---------- Internal helpers ---------- */

/* Generate ephemeral X25519 keypair; return EVP_PKEY* or NULL */
static EVP_PKEY *x25519_keygen(unsigned char pubkey_out[32]) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) return NULL;
    EVP_PKEY *key = NULL;
    if (EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_keygen(pctx, &key) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(pctx);
    size_t len = 32;
    if (EVP_PKEY_get_raw_public_key(key, pubkey_out, &len) != 1) {
        EVP_PKEY_free(key);
        return NULL;
    }
    return key;
}

/* Compute X25519 shared secret (32 bytes) */
static int x25519_derive(EVP_PKEY *my_key, const unsigned char peer_pubkey[32],
                          unsigned char secret_out[32]) {
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pubkey, 32);
    if (!peer) return -1;
    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(my_key, NULL);
    if (!dctx || EVP_PKEY_derive_init(dctx) <= 0 ||
        EVP_PKEY_derive_set_peer(dctx, peer) <= 0) {
        if (dctx) EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(peer);
        return -1;
    }
    size_t len = 32;
    int rc = EVP_PKEY_derive(dctx, secret_out, &len) <= 0 ? -1 : 0;
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(peer);
    return rc;
}

/* Derive final key from shared secret(s) + password.
 * Handles both plain (1 secret) and hybrid (2 secrets) modes.
 * secret1: X25519 shared secret (32 bytes, always present)
 * secret2: ML-KEM shared secret (32 bytes, or NULL for plain mode)
 * server_pubkey/client_pubkey: for salt derivation */
static int derive_session_key(const unsigned char *secret1,
                               const unsigned char *secret2,
                               const unsigned char server_pub[32],
                               const unsigned char client_pub[32],
                               const char *password, size_t pass_len,
                               unsigned char key_out[32]) {
    /* salt = SHA256(server_pub || client_pub) */
    unsigned char salt[32];
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return -1;
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, server_pub, 32);
    EVP_DigestUpdate(mdctx, client_pub, 32);
    unsigned int md_len;
    EVP_DigestFinal_ex(mdctx, salt, &md_len);
    EVP_MD_CTX_free(mdctx);

    /* password_key = Argon2id(password, salt) */
    unsigned char password_key[32];
    if (kdf_derive(password, pass_len, salt, 32, password_key, 32) != 0) {
        return -1;
    }

    /* Final key = SHA256(secret1 [|| secret2] || password_key) */
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) { secure_zero(password_key, 32); return -1; }
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, secret1, 32);
    if (secret2)
        EVP_DigestUpdate(mdctx, secret2, 32);
    EVP_DigestUpdate(mdctx, password_key, 32);
    EVP_DigestFinal_ex(mdctx, key_out, &md_len);
    EVP_MD_CTX_free(mdctx);

    secure_zero(password_key, 32);
    return 0;
}

/* Exchange X25519 pubkeys: server sends first, client receives first */
static int x25519_exchange_plain(int sockfd, int server_mode,
                                  const unsigned char my_pub[32],
                                  unsigned char peer_pub_out[32]) {
    if (server_mode) {
        if (ecdhe_send(sockfd, my_pub, 32) < 0) return -1;
        if (ecdhe_recv(sockfd, peer_pub_out, 32) < 0) return -1;
    } else {
        if (ecdhe_recv(sockfd, peer_pub_out, 32) < 0) return -1;
        if (ecdhe_send(sockfd, my_pub, 32) < 0) return -1;
    }
    return 0;
}

/* Exchange X25519 pubkeys with TOFU identity signing */
static int x25519_exchange_tofu(int sockfd, int server_mode,
                                 const unsigned char my_pub[32],
                                 unsigned char peer_pub_out[32],
                                 const char *peer_host, const char *peer_port) {
    if (server_mode) {
        const unsigned char *id_pub = tofu_server_get_pubkey();
        if (!id_pub) {
            fprintf(stderr, "[ECDHE-TOFU] Error: Identity key not loaded\n");
            return -1;
        }
        unsigned char sig[TOFU_ED25519_SIGLEN];
        if (tofu_server_sign(my_pub, 32, sig) < 0) return -1;

        unsigned char msg[128];
        memcpy(msg, id_pub, 32);
        memcpy(msg + 32, my_pub, 32);
        memcpy(msg + 64, sig, 64);
        if (ecdhe_send(sockfd, msg, 128) < 0) return -1;
        if (ecdhe_recv(sockfd, peer_pub_out, 32) < 0) return -1;
    } else {
        unsigned char msg[128];
        if (ecdhe_recv(sockfd, msg, 128) < 0) return -1;

        unsigned char server_id[32], server_sig[64];
        memcpy(server_id, msg, 32);
        memcpy(peer_pub_out, msg + 32, 32);
        memcpy(server_sig, msg + 64, 64);

        if (!tofu_verify_signature(server_id, peer_pub_out, 32,
                                   server_sig, TOFU_ED25519_SIGLEN)) {
            fprintf(stderr, "[ECDHE-TOFU] Error: Invalid server signature (possible MITM)\n");
            return -1;
        }
        if (peer_host && peer_port) {
            int kh = tofu_check_known_host(peer_host, peer_port, server_id);
            if (kh == -1) return -1;
            if (kh == -2)
                fprintf(stderr, "[ECDHE-TOFU] Warning: Could not access known_hosts\n");
        }
        if (ecdhe_send(sockfd, my_pub, 32) < 0) return -1;
    }
    return 0;
}

/* ML-KEM-768 key encapsulation exchange; fills kem_secret_out[32] */
static int mlkem_exchange(int sockfd, int server_mode,
                           unsigned char kem_secret_out[32]) {
    if (server_mode) {
        unsigned char pubkey[PQ_KEM_PUBKEY_LEN];
        void *handle = pq_keygen(pubkey);
        if (!handle) return -1;
        if (ecdhe_send(sockfd, pubkey, PQ_KEM_PUBKEY_LEN) < 0) {
            pq_free_key(handle); return -1;
        }
        unsigned char ct[PQ_KEM_CT_LEN];
        if (ecdhe_recv(sockfd, ct, PQ_KEM_CT_LEN) < 0) {
            pq_free_key(handle); return -1;
        }
        if (pq_decapsulate(handle, ct, kem_secret_out) < 0) {
            pq_free_key(handle); return -1;
        }
        pq_free_key(handle);
    } else {
        unsigned char pubkey[PQ_KEM_PUBKEY_LEN];
        if (ecdhe_recv(sockfd, pubkey, PQ_KEM_PUBKEY_LEN) < 0) return -1;
        unsigned char ct[PQ_KEM_CT_LEN];
        if (pq_encapsulate(pubkey, ct, kem_secret_out) < 0) return -1;
        if (ecdhe_send(sockfd, ct, PQ_KEM_CT_LEN) < 0) {
            secure_zero(kem_secret_out, 32); return -1;
        }
    }
    return 0;
}

/* ---------- Public handshake functions ---------- */

extern "C" int ecdhe_handshake(int sockfd, const char *password, size_t pass_len,
                                int server_mode, unsigned char *key_out) {
    if (!password || pass_len == 0) return -1;

    unsigned char my_pub[32], peer_pub[32];
    EVP_PKEY *my_key = x25519_keygen(my_pub);
    if (!my_key) return -1;

    if (x25519_exchange_plain(sockfd, server_mode, my_pub, peer_pub) < 0) {
        EVP_PKEY_free(my_key); return -1;
    }

    unsigned char secret[32];
    if (x25519_derive(my_key, peer_pub, secret) < 0) {
        EVP_PKEY_free(my_key); return -1;
    }
    EVP_PKEY_free(my_key);

    const unsigned char *srv_pub = server_mode ? my_pub : peer_pub;
    const unsigned char *cli_pub = server_mode ? peer_pub : my_pub;
    int rc = derive_session_key(secret, NULL, srv_pub, cli_pub,
                                 password, pass_len, key_out);
    secure_zero(secret, 32);
    return rc;
}

extern "C" int ecdhe_handshake_tofu(int sockfd, const char *password, size_t pass_len,
                                     int server_mode, const char *peer_host,
                                     const char *peer_port, unsigned char *key_out) {
    if (!password || pass_len == 0) return -1;

    unsigned char my_pub[32], peer_pub[32];
    EVP_PKEY *my_key = x25519_keygen(my_pub);
    if (!my_key) return -1;

    if (x25519_exchange_tofu(sockfd, server_mode, my_pub, peer_pub,
                              peer_host, peer_port) < 0) {
        EVP_PKEY_free(my_key); return -1;
    }

    unsigned char secret[32];
    if (x25519_derive(my_key, peer_pub, secret) < 0) {
        EVP_PKEY_free(my_key); return -1;
    }
    EVP_PKEY_free(my_key);

    const unsigned char *srv_pub = server_mode ? my_pub : peer_pub;
    const unsigned char *cli_pub = server_mode ? peer_pub : my_pub;
    int rc = derive_session_key(secret, NULL, srv_pub, cli_pub,
                                 password, pass_len, key_out);
    secure_zero(secret, 32);
    return rc;
}

extern "C" int ecdhe_handshake_pq(int sockfd, const char *password, size_t pass_len,
                                   int server_mode, const char *peer_host,
                                   const char *peer_port, unsigned char *key_out) {
    if (!password || pass_len == 0) return -1;

    if (!pq_available()) {
        fprintf(stderr, "[ECDHE-PQ] Error: ML-KEM-768 not available (need OpenSSL >= 3.5)\n");
        return -1;
    }

    /* Phase 1: X25519 (with optional TOFU) */
    unsigned char my_pub[32], peer_pub[32];
    EVP_PKEY *my_key = x25519_keygen(my_pub);
    if (!my_key) return -1;

    int xrc;
    if (g_tofu)
        xrc = x25519_exchange_tofu(sockfd, server_mode, my_pub, peer_pub,
                                    peer_host, peer_port);
    else
        xrc = x25519_exchange_plain(sockfd, server_mode, my_pub, peer_pub);
    if (xrc < 0) { EVP_PKEY_free(my_key); return -1; }

    unsigned char x_secret[32];
    if (x25519_derive(my_key, peer_pub, x_secret) < 0) {
        EVP_PKEY_free(my_key); return -1;
    }
    EVP_PKEY_free(my_key);

    /* Phase 2: ML-KEM-768 */
    unsigned char kem_secret[PQ_KEM_SS_LEN];
    if (mlkem_exchange(sockfd, server_mode, kem_secret) < 0) {
        secure_zero(x_secret, 32);
        return -1;
    }

    /* Phase 3: Derive hybrid key */
    const unsigned char *srv_pub = server_mode ? my_pub : peer_pub;
    const unsigned char *cli_pub = server_mode ? peer_pub : my_pub;
    int rc = derive_session_key(x_secret, kem_secret, srv_pub, cli_pub,
                                 password, pass_len, key_out);
    secure_zero(x_secret, 32);
    secure_zero(kem_secret, PQ_KEM_SS_LEN);
    return rc;
}
