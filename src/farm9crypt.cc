/*
 *  farm9crypt.cpp
 *
 *  Modern C interface between netcat and AES-GCM encryption.
 *
 *  Security features:
 *  - AES-256-GCM authenticated encryption (AEAD)
 *  - PBKDF2-SHA256 key derivation (100,000 iterations)
 *  - Cryptographically secure random IV generation
 *  - Message authentication and integrity verification
 *  - Protocol versioning and magic number validation
 *  - Comprehensive error handling
 *
 *  Protocol format:
 *  [MAGIC:4][VERSION:2][FLAGS:2][LENGTH:4][IV:12][TAG:16][CIPHERTEXT:variable]
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
#include <arpa/inet.h>
#else
#include <fcntl.h>
#include <io.h>
#include <conio.h>
#include <winsock.h>
#include <time.h>
#endif

extern "C"
{
#include "farm9crypt.h"
#include "obfs.h"
#include "tofu.h"
}

#include "aesgcm.h"

/* Protocol message header */
struct __attribute__((packed)) farm9_header {
    uint32_t magic;      /* FARM9_MAGIC */
    uint16_t version;    /* FARM9_VERSION */
    uint16_t flags;      /* Reserved for future use */
    uint32_t seq_num;    /* Message sequence number (replay protection) */
    uint32_t length;     /* Ciphertext length */
};

static int debug = false;
static int initialized = false;
static int udp_mode = false;
static AESGCM* decryptor = NULL;
static AESGCM* encryptor = NULL;
static unsigned char derived_key[32];
static uint64_t send_seq = 0;    /* Outgoing message sequence counter */
static uint64_t recv_seq = 0;    /* Expected incoming sequence counter */

/* Secure memory cleanup */
static void secure_zero(void* ptr, size_t len) {
    volatile unsigned char* p = (volatile unsigned char*)ptr;
    while (len--) *p++ = 0;
}

extern "C" void farm9crypt_debug() {
    debug = true;
}

extern "C" void farm9crypt_set_udp_mode(int enabled) {
    udp_mode = enabled;
}

extern "C" int farm9crypt_initialized() {
    return initialized;
}

/* Initialize with PBKDF2 key derivation from password + salt */
extern "C" int farm9crypt_init_password_with_salt(const char* password, size_t pass_len,
                                                   const unsigned char* salt, size_t salt_len) {
    if (!password || pass_len == 0) {
        if (debug) fprintf(stderr, "[CRYPT] Error: Empty password\n");
        return -1;
    }

    if (!salt || salt_len < FARM9_SALT_LEN) {
        if (debug) fprintf(stderr, "[CRYPT] Error: Invalid salt\n");
        return -1;
    }

    if (pass_len < 8) {
        if (debug) fprintf(stderr, "[CRYPT] Warning: Password should be at least 8 characters\n");
    }

    /* Derive 256-bit key using PBKDF2-HMAC-SHA256 with 100,000 iterations */
    if (PKCS5_PBKDF2_HMAC(
            password, pass_len,
            salt, salt_len,
            100000,  /* iteration count - OWASP recommended minimum */
            EVP_sha256(),
            32,      /* key length */
            derived_key
        ) != 1) {
        if (debug) fprintf(stderr, "[CRYPT] Error: PBKDF2 key derivation failed\n");
        return -1;
    }

    /* Initialize encryptor and decryptor with derived key */
    if (encryptor) delete encryptor;
    if (decryptor) delete decryptor;
    
    encryptor = new AESGCM(derived_key, 32);
    decryptor = new AESGCM(derived_key, 32);
    
    if (!encryptor || !decryptor) {
        if (debug) fprintf(stderr, "[CRYPT] Error: Failed to create cipher instances\n");
        return -1;
    }

    initialized = true;
    send_seq = 0;
    recv_seq = 0;
    if (debug) fprintf(stderr, "[CRYPT] Initialized with PBKDF2-derived key (100k iterations, random salt)\n");
    return 0;
}

/* Initialize with PBKDF2 key derivation from password (legacy fixed salt) */
extern "C" int farm9crypt_init_password(const char* password, size_t pass_len) {
    const unsigned char salt[FARM9_SALT_LEN] = {
        0x43, 0x4c, 0x41, 0x57, 0x53, 0x45, 0x43, 0x32,
        0x30, 0x32, 0x35, 0x41, 0x45, 0x53, 0x47, 0x43
    }; /* "CLAWSEC2025AESGC" - fallback only */
    return farm9crypt_init_password_with_salt(password, pass_len, salt, FARM9_SALT_LEN);
}

/* Generate random salt for handshake */
extern "C" int farm9crypt_generate_salt(unsigned char* salt_out, size_t len) {
    if (!salt_out || len < FARM9_SALT_LEN) return -1;
    if (RAND_bytes(salt_out, (int)len) != 1) {
        if (debug) fprintf(stderr, "[CRYPT] Error: Failed to generate random salt\n");
        return -1;
    }
    return 0;
}

/*
 * ECDHE key exchange with password authentication (Perfect Forward Secrecy)
 *
 * Protocol:
 *   1. Both sides generate ephemeral X25519 keypair
 *   2. Server sends pubkey (32 bytes), client sends pubkey (32 bytes)
 *   3. Both compute shared_secret = ECDH(my_privkey, peer_pubkey)
 *   4. Final key = HKDF(shared_secret || PBKDF2(password, salt))
 *      - This binds the session to the password (MITM cannot derive key without password)
 *   5. Salt = SHA256(server_pubkey || client_pubkey) (deterministic, no extra exchange)
 */

#include <openssl/evp.h>
#include <openssl/kdf.h>

/* Send exactly len bytes (obfs-aware) */
static int ecdhe_send(int sockfd, const void* buf, size_t len) {
    if (obfs_get_mode() != OBFS_NONE) {
        return obfs_send(sockfd, buf, len) < 0 ? -1 : 0;
    }
    size_t total = 0;
    const unsigned char* ptr = (const unsigned char*)buf;
    while (total < len) {
        ssize_t n = send(sockfd, ptr + total, len - total, 0);
        if (n <= 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        total += n;
    }
    return 0;
}

/* Receive exactly len bytes (obfs-aware) */
static int ecdhe_recv(int sockfd, void* buf, size_t len) {
    if (obfs_get_mode() != OBFS_NONE) {
        return obfs_recv(sockfd, buf, len) <= 0 ? -1 : 0;
    }
    size_t total = 0;
    unsigned char* ptr = (unsigned char*)buf;
    while (total < len) {
        ssize_t n = recv(sockfd, ptr + total, len - total, 0);
        if (n <= 0) {
            if (n == 0) return -1;
            if (errno == EINTR) continue;
            return -1;
        }
        total += n;
    }
    return 0;
}

extern "C" int farm9crypt_init_ecdhe(int sockfd, const char* password, size_t pass_len, int server_mode) {
    if (!password || pass_len == 0) {
        if (debug) fprintf(stderr, "[ECDHE] Error: Empty password\n");
        return -1;
    }

    /* Generate ephemeral X25519 keypair */
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) { if (debug) fprintf(stderr, "[ECDHE] Error: CTX alloc failed\n"); return -1; }

    EVP_PKEY* my_key = NULL;
    if (EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_keygen(pctx, &my_key) <= 0) {
        if (debug) fprintf(stderr, "[ECDHE] Error: Keygen failed\n");
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    EVP_PKEY_CTX_free(pctx);

    /* Extract my public key (32 bytes for X25519) */
    unsigned char my_pubkey[32];
    size_t pubkey_len = 32;
    if (EVP_PKEY_get_raw_public_key(my_key, my_pubkey, &pubkey_len) != 1) {
        if (debug) fprintf(stderr, "[ECDHE] Error: Get pubkey failed\n");
        EVP_PKEY_free(my_key);
        return -1;
    }

    /* Exchange public keys */
    unsigned char peer_pubkey[32];

    if (server_mode) {
        /* Server: send first, then receive */
        if (ecdhe_send(sockfd, my_pubkey, 32) < 0) {
            if (debug) fprintf(stderr, "[ECDHE] Error: Send pubkey failed\n");
            EVP_PKEY_free(my_key);
            return -1;
        }
        if (ecdhe_recv(sockfd, peer_pubkey, 32) < 0) {
            if (debug) fprintf(stderr, "[ECDHE] Error: Recv pubkey failed\n");
            EVP_PKEY_free(my_key);
            return -1;
        }
    } else {
        /* Client: receive first, then send */
        if (ecdhe_recv(sockfd, peer_pubkey, 32) < 0) {
            if (debug) fprintf(stderr, "[ECDHE] Error: Recv pubkey failed\n");
            EVP_PKEY_free(my_key);
            return -1;
        }
        if (ecdhe_send(sockfd, my_pubkey, 32) < 0) {
            if (debug) fprintf(stderr, "[ECDHE] Error: Send pubkey failed\n");
            EVP_PKEY_free(my_key);
            return -1;
        }
    }

    /* Load peer public key */
    EVP_PKEY* peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pubkey, 32);
    if (!peer_key) {
        if (debug) fprintf(stderr, "[ECDHE] Error: Load peer key failed\n");
        EVP_PKEY_free(my_key);
        return -1;
    }

    /* Compute shared secret via ECDH */
    EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new(my_key, NULL);
    if (!dctx || EVP_PKEY_derive_init(dctx) <= 0 || EVP_PKEY_derive_set_peer(dctx, peer_key) <= 0) {
        if (debug) fprintf(stderr, "[ECDHE] Error: Derive init failed\n");
        if (dctx) EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(my_key);
        EVP_PKEY_free(peer_key);
        return -1;
    }

    size_t secret_len = 32;
    unsigned char shared_secret[32];
    if (EVP_PKEY_derive(dctx, shared_secret, &secret_len) <= 0) {
        if (debug) fprintf(stderr, "[ECDHE] Error: Derive failed\n");
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(my_key);
        EVP_PKEY_free(peer_key);
        return -1;
    }

    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(my_key);
    EVP_PKEY_free(peer_key);

    /* Derive salt from public keys: SHA256(server_pub || client_pub) */
    unsigned char salt[32];
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    if (server_mode) {
        EVP_DigestUpdate(mdctx, my_pubkey, 32);
        EVP_DigestUpdate(mdctx, peer_pubkey, 32);
    } else {
        EVP_DigestUpdate(mdctx, peer_pubkey, 32);
        EVP_DigestUpdate(mdctx, my_pubkey, 32);
    }
    unsigned int md_len;
    EVP_DigestFinal_ex(mdctx, salt, &md_len);
    EVP_MD_CTX_free(mdctx);

    /* Derive password component: PBKDF2(password, salt[0:16], 100k) */
    unsigned char password_key[32];
    if (PKCS5_PBKDF2_HMAC(password, pass_len, salt, 16, 100000,
                           EVP_sha256(), 32, password_key) != 1) {
        if (debug) fprintf(stderr, "[ECDHE] Error: PBKDF2 failed\n");
        secure_zero(shared_secret, 32);
        return -1;
    }

    /* Final key = SHA256(shared_secret || password_key) */
    /* This ensures both ECDH agreement AND password knowledge are required */
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, shared_secret, 32);
    EVP_DigestUpdate(mdctx, password_key, 32);
    EVP_DigestFinal_ex(mdctx, derived_key, &md_len);
    EVP_MD_CTX_free(mdctx);

    /* Wipe intermediate secrets */
    secure_zero(shared_secret, 32);
    secure_zero(password_key, 32);

    /* Initialize encryptor and decryptor */
    if (encryptor) delete encryptor;
    if (decryptor) delete decryptor;

    encryptor = new AESGCM(derived_key, 32);
    decryptor = new AESGCM(derived_key, 32);

    if (!encryptor || !decryptor) {
        if (debug) fprintf(stderr, "[ECDHE] Error: Cipher init failed\n");
        return -1;
    }

    initialized = true;
    send_seq = 0;
    recv_seq = 0;
    if (debug) fprintf(stderr, "[ECDHE] PFS session established (X25519 + PBKDF2)\n");
    return 0;
}

/*
 * ECDHE with TOFU (Trust On First Use)
 *
 * Enhanced handshake:
 *   Server sends: [ed25519_pubkey(32)][x25519_pubkey(32)][ed25519_sig(64)] = 128 bytes
 *   Client verifies signature, checks known_hosts, sends [x25519_pubkey(32)]
 *   Rest of key derivation identical to plain ECDHE.
 */
extern "C" int farm9crypt_init_ecdhe_tofu(int sockfd, const char* password, size_t pass_len,
                                           int server_mode, const char *peer_host, const char *peer_port) {
    if (!password || pass_len == 0) {
        if (debug) fprintf(stderr, "[ECDHE-TOFU] Error: Empty password\n");
        return -1;
    }

    /* Generate ephemeral X25519 keypair */
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) return -1;

    EVP_PKEY* my_key = NULL;
    if (EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_keygen(pctx, &my_key) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    EVP_PKEY_CTX_free(pctx);

    unsigned char my_pubkey[32];
    size_t pubkey_len = 32;
    if (EVP_PKEY_get_raw_public_key(my_key, my_pubkey, &pubkey_len) != 1) {
        EVP_PKEY_free(my_key);
        return -1;
    }

    unsigned char peer_pubkey[32];

    if (server_mode) {
        /* Server: send [identity_pubkey(32)][x25519_pubkey(32)][signature(64)] */
        const unsigned char *id_pub = tofu_server_get_pubkey();
        if (!id_pub) {
            fprintf(stderr, "[ECDHE-TOFU] Error: Identity key not loaded\n");
            EVP_PKEY_free(my_key);
            return -1;
        }

        /* Sign the ephemeral X25519 pubkey with Ed25519 identity key */
        unsigned char sig[TOFU_ED25519_SIGLEN];
        if (tofu_server_sign(my_pubkey, 32, sig) < 0) {
            fprintf(stderr, "[ECDHE-TOFU] Error: Signing failed\n");
            EVP_PKEY_free(my_key);
            return -1;
        }

        /* Send: identity(32) + ephemeral(32) + signature(64) = 128 bytes */
        unsigned char tofu_msg[128];
        memcpy(tofu_msg, id_pub, 32);
        memcpy(tofu_msg + 32, my_pubkey, 32);
        memcpy(tofu_msg + 64, sig, 64);

        if (ecdhe_send(sockfd, tofu_msg, 128) < 0) {
            EVP_PKEY_free(my_key);
            return -1;
        }

        /* Receive client's ephemeral pubkey */
        if (ecdhe_recv(sockfd, peer_pubkey, 32) < 0) {
            EVP_PKEY_free(my_key);
            return -1;
        }
    } else {
        /* Client: receive [identity(32)][ephemeral(32)][signature(64)] */
        unsigned char tofu_msg[128];
        if (ecdhe_recv(sockfd, tofu_msg, 128) < 0) {
            EVP_PKEY_free(my_key);
            return -1;
        }

        unsigned char server_id_pub[32];
        unsigned char server_sig[64];
        memcpy(server_id_pub, tofu_msg, 32);
        memcpy(peer_pubkey, tofu_msg + 32, 32);
        memcpy(server_sig, tofu_msg + 64, 64);

        /* Verify: Ed25519 signature of ephemeral pubkey */
        if (!tofu_verify_signature(server_id_pub, peer_pubkey, 32,
                                   server_sig, TOFU_ED25519_SIGLEN)) {
            fprintf(stderr, "[ECDHE-TOFU] Error: Invalid server signature (possible MITM)\n");
            EVP_PKEY_free(my_key);
            return -1;
        }

        /* Check known_hosts */
        if (peer_host && peer_port) {
            int kh = tofu_check_known_host(peer_host, peer_port, server_id_pub);
            if (kh == -1) {
                /* Identity changed — abort */
                EVP_PKEY_free(my_key);
                return -1;
            }
            if (kh == -2) {
                fprintf(stderr, "[ECDHE-TOFU] Warning: Could not access known_hosts\n");
            }
            /* kh == 0: new host (saved), kh == 1: known host (verified) */
        }

        /* Send client ephemeral pubkey */
        if (ecdhe_send(sockfd, my_pubkey, 32) < 0) {
            EVP_PKEY_free(my_key);
            return -1;
        }
    }

    /* ECDH shared secret (same as plain ECDHE from here) */
    EVP_PKEY* peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pubkey, 32);
    if (!peer_key) { EVP_PKEY_free(my_key); return -1; }

    EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new(my_key, NULL);
    if (!dctx || EVP_PKEY_derive_init(dctx) <= 0 || EVP_PKEY_derive_set_peer(dctx, peer_key) <= 0) {
        if (dctx) EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(my_key);
        EVP_PKEY_free(peer_key);
        return -1;
    }

    size_t secret_len = 32;
    unsigned char shared_secret[32];
    if (EVP_PKEY_derive(dctx, shared_secret, &secret_len) <= 0) {
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(my_key);
        EVP_PKEY_free(peer_key);
        return -1;
    }

    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(my_key);
    EVP_PKEY_free(peer_key);

    /* Key derivation: SHA256(server_pub || client_pub) for salt */
    unsigned char salt[32];
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    if (server_mode) {
        EVP_DigestUpdate(mdctx, my_pubkey, 32);
        EVP_DigestUpdate(mdctx, peer_pubkey, 32);
    } else {
        EVP_DigestUpdate(mdctx, peer_pubkey, 32);
        EVP_DigestUpdate(mdctx, my_pubkey, 32);
    }
    unsigned int md_len;
    EVP_DigestFinal_ex(mdctx, salt, &md_len);
    EVP_MD_CTX_free(mdctx);

    unsigned char password_key[32];
    if (PKCS5_PBKDF2_HMAC(password, pass_len, salt, 16, 100000,
                           EVP_sha256(), 32, password_key) != 1) {
        secure_zero(shared_secret, 32);
        return -1;
    }

    /* Final key = SHA256(shared_secret || password_key) */
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, shared_secret, 32);
    EVP_DigestUpdate(mdctx, password_key, 32);
    EVP_DigestFinal_ex(mdctx, derived_key, &md_len);
    EVP_MD_CTX_free(mdctx);

    secure_zero(shared_secret, 32);
    secure_zero(password_key, 32);

    if (encryptor) delete encryptor;
    if (decryptor) delete decryptor;
    encryptor = new AESGCM(derived_key, 32);
    decryptor = new AESGCM(derived_key, 32);
    if (!encryptor || !decryptor) return -1;

    initialized = true;
    send_seq = 0;
    recv_seq = 0;
    if (debug) fprintf(stderr, "[ECDHE-TOFU] PFS session established (X25519 + Ed25519 + PBKDF2)\n");
    return 0;
}

/* Legacy init with raw key (deprecated - use farm9crypt_init_password) */
extern "C" void farm9crypt_init(char* keystr) {
    if (!keystr) {
        if (debug) fprintf(stderr, "[CRYPT] Error: NULL key provided\n");
        return;
    }

    size_t keylen = strlen(keystr);
    if (keylen < 8) {
        if (debug) fprintf(stderr, "[CRYPT] Warning: Key too short, use at least 8 characters\n");
    }

    /* Use password-based init for better security */
    farm9crypt_init_password(keystr, keylen);
}

/* Clean up resources */
extern "C" void farm9crypt_cleanup() {
    if (encryptor) {
        delete encryptor;
        encryptor = NULL;
    }
    if (decryptor) {
        delete decryptor;
        decryptor = NULL;
    }
    secure_zero(derived_key, sizeof(derived_key));
    send_seq = 0;
    recv_seq = 0;
    initialized = false;
    if (debug) fprintf(stderr, "[CRYPT] Cleanup complete\n");
}

/* Get session fingerprint: SHA-256(derived_key) truncated to len bytes */
extern "C" int farm9crypt_get_fingerprint(unsigned char *out, size_t len) {
    if (!initialized) return -1;
    unsigned char hash[32];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, derived_key, sizeof(derived_key));
    unsigned int hlen = 32;
    EVP_DigestFinal_ex(ctx, hash, &hlen);
    EVP_MD_CTX_free(ctx);
    size_t copy = len < 32 ? len : 32;
    memcpy(out, hash, copy);
    return (int)copy;
}

/* Secure receive with timeout and exact length validation */
static int recv_exact(int sockfd, void* buf, size_t len) {
    size_t total = 0;
    unsigned char* ptr = (unsigned char*)buf;
    
    while (total < len) {
        ssize_t n = recv(sockfd, ptr + total, len - total, 0);
        if (n <= 0) {
            if (n == 0) {
                if (debug) fprintf(stderr, "[CRYPT] Connection closed by peer\n");
                return 0;  /* Connection closed */
            }
            if (errno == EINTR) continue;  /* Interrupted, retry */
            if (debug) perror("[CRYPT] recv error");
            return -1;  /* Error */
        }
        total += n;
    }
    return total;
}

extern "C" int farm9crypt_read(int sockfd, char* buf, int size) {
    if (!initialized) {
        if (debug) fprintf(stderr, "[CRYPT] Error: Not initialized\n");
        errno = EINVAL;
        return -1;
    }

    if (!buf || size <= 0 || size > FARM9_MAX_MSG) {
        if (debug) fprintf(stderr, "[CRYPT] Error: Invalid buffer or size\n");
        errno = EINVAL;
        return -1;
    }

    struct farm9_header header;
    unsigned char iv[FARM9_IV_LEN];
    unsigned char tag[FARM9_TAG_LEN];
    unsigned char ciphertext[FARM9_MAX_MSG];
    uint32_t ct_len;

    if (udp_mode) {
        /* UDP: receive entire datagram at once */
        unsigned char dgram[sizeof(struct farm9_header) + FARM9_IV_LEN + FARM9_TAG_LEN + FARM9_MAX_MSG];
        ssize_t n = recv(sockfd, dgram, sizeof(dgram), 0);
        if (n <= 0) {
            if (n == 0) return 0;
            if (errno == EINTR) return -1;
            return -1;
        }
        size_t off = 0;
        if ((size_t)n < sizeof(header)) { errno = EPROTO; return -1; }
        memcpy(&header, dgram + off, sizeof(header)); off += sizeof(header);
        if ((size_t)n < off + FARM9_IV_LEN + FARM9_TAG_LEN) { errno = EPROTO; return -1; }
        memcpy(iv, dgram + off, FARM9_IV_LEN); off += FARM9_IV_LEN;
        memcpy(tag, dgram + off, FARM9_TAG_LEN); off += FARM9_TAG_LEN;
        ct_len = ntohl(header.length);
        if (ct_len == 0 || ct_len > FARM9_MAX_MSG || off + ct_len > (size_t)n) { errno = EMSGSIZE; return -1; }
        memcpy(ciphertext, dgram + off, ct_len);
    } else if (obfs_get_mode() != OBFS_NONE) {
        /* Obfuscated TCP: entire frame arrives in one HTTP body */
        unsigned char frame[sizeof(struct farm9_header) + FARM9_IV_LEN + FARM9_TAG_LEN + FARM9_MAX_MSG];
        int flen = obfs_recv(sockfd, frame, sizeof(frame));
        if (flen <= 0) return flen;
        size_t off = 0;
        if ((size_t)flen < sizeof(header)) { errno = EPROTO; return -1; }
        memcpy(&header, frame + off, sizeof(header)); off += sizeof(header);
        if ((size_t)flen < off + FARM9_IV_LEN + FARM9_TAG_LEN) { errno = EPROTO; return -1; }
        memcpy(iv, frame + off, FARM9_IV_LEN); off += FARM9_IV_LEN;
        memcpy(tag, frame + off, FARM9_TAG_LEN); off += FARM9_TAG_LEN;
        ct_len = ntohl(header.length);
        if (ct_len == 0 || ct_len > FARM9_MAX_MSG || off + ct_len > (size_t)flen) { errno = EMSGSIZE; return -1; }
        memcpy(ciphertext, frame + off, ct_len);
    } else {
        /* TCP: read header, then payload */
        int ret = recv_exact(sockfd, &header, sizeof(header));
        if (ret <= 0) return ret;

        ct_len = ntohl(header.length);
        if (ct_len == 0 || ct_len > FARM9_MAX_MSG) {
            if (debug) fprintf(stderr, "[CRYPT] Error: Invalid message length %u\n", ct_len);
            errno = EMSGSIZE;
            return -1;
        }

        int r = recv_exact(sockfd, iv, FARM9_IV_LEN);
        if (r <= 0) return r;
        r = recv_exact(sockfd, tag, FARM9_TAG_LEN);
        if (r <= 0) return r;
        r = recv_exact(sockfd, ciphertext, ct_len);
        if (r <= 0) return r;
    }

    /* Validate magic number */
    uint32_t magic = ntohl(header.magic);
    if (magic != FARM9_MAGIC) {
        if (debug) fprintf(stderr, "[CRYPT] Error: Invalid magic 0x%08x (expected 0x%08x)\n", 
                          magic, FARM9_MAGIC);
        errno = EPROTO;
        return -1;
    }

    /* Validate version */
    uint16_t version = ntohs(header.version);
    if (version != FARM9_VERSION) {
        if (debug) fprintf(stderr, "[CRYPT] Error: Unsupported version %d\n", version);
        errno = EPROTONOSUPPORT;
        return -1;
    }

    /* Validate sequence number (replay protection) */
    uint32_t msg_seq = ntohl(header.seq_num);
    if (msg_seq != (uint32_t)recv_seq) {
        if (debug) fprintf(stderr, "[CRYPT] Error: Sequence mismatch - got %u, expected %u (replay attack?)\n",
                          msg_seq, (uint32_t)recv_seq);
        errno = EPROTO;
        return -1;
    }
    recv_seq++;

    /* Decrypt and verify */
    int plaintext_len;
    bool ok = decryptor->decrypt(
        ciphertext, ct_len,
        iv, FARM9_IV_LEN,
        tag, FARM9_TAG_LEN,
        reinterpret_cast<unsigned char*>(buf),
        plaintext_len
    );

    if (!ok) {
        if (debug) fprintf(stderr, "[CRYPT] Error: Decryption/authentication failed\n");
        errno = EBADMSG;
        return -1;
    }

    if (debug) {
        fprintf(stderr, "[CRYPT] Decrypted %d bytes (ciphertext: %u)\n", 
                plaintext_len, ct_len);
    }

    return plaintext_len;
}

/* Secure send - ensures all data is sent or returns error */
static int send_exact(int sockfd, const void* buf, size_t len) {
    size_t total = 0;
    const unsigned char* ptr = (const unsigned char*)buf;
    
    while (total < len) {
        ssize_t n = send(sockfd, ptr + total, len - total, 0);
        if (n <= 0) {
            if (errno == EINTR) continue;  /* Interrupted, retry */
            if (debug) perror("[CRYPT] send error");
            return -1;
        }
        total += n;
    }
    return total;
}

extern "C" int farm9crypt_write(int sockfd, char* buf, int size) {
    if (!initialized) {
        if (debug) fprintf(stderr, "[CRYPT] Error: Not initialized\n");
        errno = EINVAL;
        return -1;
    }

    if (!buf || size <= 0 || size > FARM9_MAX_MSG) {
        if (debug) fprintf(stderr, "[CRYPT] Error: Invalid buffer or size %d\n", size);
        errno = EINVAL;
        return -1;
    }

    /* Generate cryptographically secure random IV */
    unsigned char iv[FARM9_IV_LEN];
    if (RAND_bytes(iv, FARM9_IV_LEN) != 1) {
        if (debug) fprintf(stderr, "[CRYPT] Error: IV generation failed\n");
        errno = EINVAL;
        return -1;
    }

    /* Encrypt data */
    unsigned char ciphertext[FARM9_MAX_MSG];
    unsigned char tag[FARM9_TAG_LEN];
    int ciphertext_len;

    bool ok = encryptor->encrypt(
        reinterpret_cast<unsigned char*>(buf), size,
        ciphertext,
        iv, FARM9_IV_LEN,
        tag, FARM9_TAG_LEN,
        ciphertext_len
    );

    if (!ok) {
        if (debug) fprintf(stderr, "[CRYPT] Error: Encryption failed\n");
        errno = EINVAL;
        return -1;
    }

    /* Build protocol header */
    struct farm9_header header;
    header.magic = htonl(FARM9_MAGIC);
    header.version = htons(FARM9_VERSION);
    header.flags = htons(0);
    header.seq_num = htonl((uint32_t)send_seq);
    header.length = htonl(ciphertext_len);
    send_seq++;

    if (udp_mode) {
        /* UDP: send everything as a single datagram */
        size_t total = sizeof(header) + FARM9_IV_LEN + FARM9_TAG_LEN + ciphertext_len;
        unsigned char dgram[sizeof(struct farm9_header) + FARM9_IV_LEN + FARM9_TAG_LEN + FARM9_MAX_MSG];
        size_t off = 0;
        memcpy(dgram + off, &header, sizeof(header)); off += sizeof(header);
        memcpy(dgram + off, iv, FARM9_IV_LEN); off += FARM9_IV_LEN;
        memcpy(dgram + off, tag, FARM9_TAG_LEN); off += FARM9_TAG_LEN;
        memcpy(dgram + off, ciphertext, ciphertext_len);
        ssize_t n = send(sockfd, dgram, total, 0);
        if (n < 0 || (size_t)n != total) {
            if (debug) fprintf(stderr, "[CRYPT] Error: Failed to send UDP datagram\n");
            return -1;
        }
    } else if (obfs_get_mode() != OBFS_NONE) {
        /* Obfuscated TCP: pack entire frame and send as one HTTP body */
        size_t total = sizeof(header) + FARM9_IV_LEN + FARM9_TAG_LEN + ciphertext_len;
        unsigned char frame[sizeof(struct farm9_header) + FARM9_IV_LEN + FARM9_TAG_LEN + FARM9_MAX_MSG];
        size_t off = 0;
        memcpy(frame + off, &header, sizeof(header)); off += sizeof(header);
        memcpy(frame + off, iv, FARM9_IV_LEN); off += FARM9_IV_LEN;
        memcpy(frame + off, tag, FARM9_TAG_LEN); off += FARM9_TAG_LEN;
        memcpy(frame + off, ciphertext, ciphertext_len);
        if (obfs_send(sockfd, frame, total) < 0) return -1;
    } else {
        /* TCP: send header, IV, tag, ciphertext separately */
        if (send_exact(sockfd, &header, sizeof(header)) < 0) return -1;
        if (send_exact(sockfd, iv, FARM9_IV_LEN) < 0) return -1;
        if (send_exact(sockfd, tag, FARM9_TAG_LEN) < 0) return -1;
        if (send_exact(sockfd, ciphertext, ciphertext_len) < 0) return -1;
    }

    if (debug) {
        fprintf(stderr, "[CRYPT] Encrypted and sent %d bytes (ciphertext: %d)\n", 
                size, ciphertext_len);
    }

    return size;  /* Return original plaintext size */
}
