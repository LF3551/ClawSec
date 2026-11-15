/*
 *  farm9crypt.cc
 *
 *  C interface between netcat and AES-256-GCM encryption (wire protocol v2).
 *
 *  Key schedule:
 *    session_key  = output of the password-bound handshake (ecdhe.cc) or,
 *                   for local/test use, Argon2id(password, salt)
 *    k_c2s, k_s2c = HKDF-SHA256(session_key, info = "ClawSec v2 tcp c2s|s2c")
 *    udp_c2s/s2c  = HKDF-SHA256(session_key, info = "ClawSec v2 udp c2s|s2c")
 *    fingerprint  = HKDF-SHA256(session_key, info = "ClawSec v2 fingerprint")
 *  Each endpoint encrypts with its own direction key and decrypts with the
 *  peer's, so a frame can never be reflected back to its sender.
 *
 *  Frame format (all integers big-endian):
 *    [MAGIC:4][VERSION:2][FLAGS:2][SEQ:4][LENGTH:4][IV:12][TAG:16][CIPHERTEXT]
 *  The 16-byte header is authenticated as GCM associated data, so the
 *  sequence number, length and flags cannot be altered without detection.
 *
 *  Receive path guarantees:
 *    - plaintext is decrypted into an internal buffer and only copied to the
 *      caller after the tag verifies;
 *    - the caller's buffer is never written beyond `size` bytes;
 *    - sequence numbers must be strictly consecutive; they are never reused
 *      (the session refuses to continue once the 32-bit space is exhausted).
 */

#ifndef WIN32
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <new>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
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
#include "argon2kdf.h"
#include "ecdhe.h"
}

#include "aesgcm.h"

/* Protocol message header (authenticated as AAD) */
struct __attribute__((packed)) farm9_header {
    uint32_t magic;      /* FARM9_MAGIC */
    uint16_t version;    /* FARM9_VERSION */
    uint16_t flags;      /* Reserved, must be 0 */
    uint32_t seq_num;    /* Message sequence number (replay protection) */
    uint32_t length;     /* Ciphertext length (== plaintext length for GCM) */
};

static_assert(sizeof(struct farm9_header) == FARM9_HEADER_LEN,
              "farm9_header must be exactly FARM9_HEADER_LEN bytes");

#define FARM9_FRAME_MAX (FARM9_HEADER_LEN + FARM9_IV_LEN + FARM9_TAG_LEN + FARM9_MAX_MSG)
#define FARM9_SEQ_LIMIT ((uint64_t)UINT32_MAX + 1)   /* first sequence number we must not use */

/* HKDF labels: bound to protocol version, distinct per purpose and direction */
#define LABEL_TCP_C2S "ClawSec v2 tcp c2s"
#define LABEL_TCP_S2C "ClawSec v2 tcp s2c"
#define LABEL_UDP_C2S "ClawSec v2 udp c2s"
#define LABEL_UDP_S2C "ClawSec v2 udp s2c"
#define LABEL_FINGERPRINT "ClawSec v2 fingerprint"

static int debug = false;
static int initialized = false;
static int udp_mode = false;
static int version_warned = false;
static AESGCM* decryptor = NULL;
static AESGCM* encryptor = NULL;
static unsigned char udp_tx_key[FARM9_KEY_LEN];
static unsigned char udp_rx_key[FARM9_KEY_LEN];
static unsigned char session_fp[32];
static uint64_t send_seq = 0;    /* Next outgoing sequence number */
static uint64_t recv_seq = 0;    /* Next expected incoming sequence number */

/* Secure memory cleanup (not optimized away) */
static void secure_zero(void* ptr, size_t len) {
    OPENSSL_cleanse(ptr, len);
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

/* HKDF-SHA256 (RFC 5869) with empty salt: out = HKDF(ikm, info) */
static int hkdf_sha256(const unsigned char* ikm, size_t ikm_len, const char* info,
                       unsigned char* out, size_t out_len) {
    EVP_KDF* kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) return -1;
    EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!ctx) return -1;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char*)"SHA256", 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void*)ikm, ikm_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void*)info, strlen(info)),
        OSSL_PARAM_construct_end()
    };
    int rc = EVP_KDF_derive(ctx, out, out_len, params);
    EVP_KDF_CTX_free(ctx);
    return rc == 1 ? 0 : -1;
}

static void reset_state(void) {
    delete encryptor;
    encryptor = NULL;
    delete decryptor;
    decryptor = NULL;
    secure_zero(udp_tx_key, sizeof(udp_tx_key));
    secure_zero(udp_rx_key, sizeof(udp_rx_key));
    secure_zero(session_fp, sizeof(session_fp));
    send_seq = 0;
    recv_seq = 0;
    initialized = false;
}

/*
 * Derive all per-direction keys from the session key and install them.
 * The session key is wiped before returning (success or failure).
 */
static int install_session(unsigned char session_key[FARM9_KEY_LEN], int server_mode,
                           const char* label) {
    unsigned char c2s[FARM9_KEY_LEN], s2c[FARM9_KEY_LEN];
    unsigned char udp_c2s[FARM9_KEY_LEN], udp_s2c[FARM9_KEY_LEN];
    int rc = -1;

    reset_state();

    if (hkdf_sha256(session_key, FARM9_KEY_LEN, LABEL_TCP_C2S, c2s, sizeof(c2s)) != 0 ||
        hkdf_sha256(session_key, FARM9_KEY_LEN, LABEL_TCP_S2C, s2c, sizeof(s2c)) != 0 ||
        hkdf_sha256(session_key, FARM9_KEY_LEN, LABEL_UDP_C2S, udp_c2s, sizeof(udp_c2s)) != 0 ||
        hkdf_sha256(session_key, FARM9_KEY_LEN, LABEL_UDP_S2C, udp_s2c, sizeof(udp_s2c)) != 0 ||
        hkdf_sha256(session_key, FARM9_KEY_LEN, LABEL_FINGERPRINT, session_fp, sizeof(session_fp)) != 0) {
        fprintf(stderr, "[%s] Error: HKDF key derivation failed\n", label);
        goto out;
    }

    encryptor = new (std::nothrow) AESGCM(server_mode ? s2c : c2s, FARM9_KEY_LEN);
    decryptor = new (std::nothrow) AESGCM(server_mode ? c2s : s2c, FARM9_KEY_LEN);
    if (!encryptor || !decryptor) {
        fprintf(stderr, "[%s] Error: Cipher init failed\n", label);
        goto out;
    }
    memcpy(udp_tx_key, server_mode ? udp_s2c : udp_c2s, FARM9_KEY_LEN);
    memcpy(udp_rx_key, server_mode ? udp_c2s : udp_s2c, FARM9_KEY_LEN);

    initialized = true;
    rc = 0;
    if (debug) fprintf(stderr, "[%s] Session established (%s role, directional keys)\n",
                       label, server_mode ? "server" : "client");

out:
    if (rc != 0) reset_state();
    secure_zero(session_key, FARM9_KEY_LEN);
    secure_zero(c2s, sizeof(c2s));
    secure_zero(s2c, sizeof(s2c));
    secure_zero(udp_c2s, sizeof(udp_c2s));
    secure_zero(udp_s2c, sizeof(udp_s2c));
    return rc;
}

/* Initialize with Argon2id/PBKDF2 key derivation from password + salt */
extern "C" int farm9crypt_init_password_with_salt(const char* password, size_t pass_len,
                                                   const unsigned char* salt, size_t salt_len,
                                                   int server_mode) {
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

    unsigned char session_key[FARM9_KEY_LEN];
    if (kdf_derive(password, pass_len, salt, salt_len, session_key, sizeof(session_key)) != 0) {
        secure_zero(session_key, sizeof(session_key));
        if (debug) fprintf(stderr, "[CRYPT] Error: Key derivation failed\n");
        return -1;
    }
    return install_session(session_key, server_mode, "CRYPT");
}

/* Initialize from password with a fixed salt (tests/local use only) */
extern "C" int farm9crypt_init_password(const char* password, size_t pass_len, int server_mode) {
    const unsigned char salt[FARM9_SALT_LEN] = {
        0x43, 0x4c, 0x41, 0x57, 0x53, 0x45, 0x43, 0x32,
        0x30, 0x32, 0x35, 0x41, 0x45, 0x53, 0x47, 0x43
    }; /* "CLAWSEC2025AESGC" */
    return farm9crypt_init_password_with_salt(password, pass_len, salt, FARM9_SALT_LEN,
                                              server_mode);
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
 * ECDHE wrappers — delegate to ecdhe.cc, then install the session keys.
 */
extern "C" int farm9crypt_init_ecdhe(int sockfd, const char* password, size_t pass_len, int server_mode) {
    unsigned char key[FARM9_KEY_LEN];
    if (ecdhe_handshake(sockfd, password, pass_len, server_mode, key) < 0) {
        secure_zero(key, sizeof(key));
        return -1;
    }
    return install_session(key, server_mode, "ECDHE");
}

extern "C" int farm9crypt_init_ecdhe_tofu(int sockfd, const char* password, size_t pass_len,
                                           int server_mode, const char *peer_host, const char *peer_port) {
    unsigned char key[FARM9_KEY_LEN];
    if (ecdhe_handshake_tofu(sockfd, password, pass_len, server_mode,
                              peer_host, peer_port, key) < 0) {
        secure_zero(key, sizeof(key));
        return -1;
    }
    return install_session(key, server_mode, "ECDHE-TOFU");
}

extern "C" int farm9crypt_init_ecdhe_pq(int sockfd, const char* password, size_t pass_len,
                                         int server_mode, const char *peer_host, const char *peer_port) {
    unsigned char key[FARM9_KEY_LEN];
    if (ecdhe_handshake_pq(sockfd, password, pass_len, server_mode,
                            peer_host, peer_port, key) < 0) {
        secure_zero(key, sizeof(key));
        return -1;
    }
    return install_session(key, server_mode, "ECDHE-PQ");
}

/* Clean up resources */
extern "C" void farm9crypt_cleanup() {
    reset_state();
    if (debug) fprintf(stderr, "[CRYPT] Cleanup complete\n");
}

/* Export directional UDP VPN keys */
extern "C" int farm9crypt_export_udp_keys(unsigned char tx_key[32], unsigned char rx_key[32]) {
    if (!initialized || !tx_key || !rx_key) return -1;
    memcpy(tx_key, udp_tx_key, FARM9_KEY_LEN);
    memcpy(rx_key, udp_rx_key, FARM9_KEY_LEN);
    return 0;
}

/* Session fingerprint: HKDF label of the session key, same on both ends */
extern "C" int farm9crypt_get_fingerprint(unsigned char *out, size_t len) {
    if (!initialized || !out) return -1;
    size_t copy = len < sizeof(session_fp) ? len : sizeof(session_fp);
    memcpy(out, session_fp, copy);
    return (int)copy;
}

/* Receive exactly len bytes. Returns len, 0 on orderly close, -1 on error. */
static int recv_exact(int sockfd, void* buf, size_t len) {
    size_t total = 0;
    unsigned char* ptr = (unsigned char*)buf;

    while (total < len) {
        ssize_t n = recv(sockfd, ptr + total, len - total, 0);
        if (n <= 0) {
            if (n == 0) {
                if (debug) fprintf(stderr, "[CRYPT] Connection closed by peer\n");
                if (total > 0) {           /* EOF inside a frame */
                    errno = EPROTO;
                    return -1;
                }
                return 0;
            }
            if (errno == EINTR) continue;  /* Interrupted, retry */
            if (debug) perror("[CRYPT] recv error");
            return -1;
        }
        total += (size_t)n;
    }
    return (int)total;
}

/* Parse a complete datagram/obfs frame into header, iv, tag and ciphertext */
static int parse_frame(const unsigned char* frame, size_t flen, struct farm9_header* header,
                       unsigned char* iv, unsigned char* tag,
                       unsigned char* ciphertext, uint32_t* ct_len) {
    const size_t fixed = sizeof(*header) + FARM9_IV_LEN + FARM9_TAG_LEN;
    if (flen < fixed) { errno = EPROTO; return -1; }
    memcpy(header, frame, sizeof(*header));
    memcpy(iv, frame + sizeof(*header), FARM9_IV_LEN);
    memcpy(tag, frame + sizeof(*header) + FARM9_IV_LEN, FARM9_TAG_LEN);
    uint32_t len = ntohl(header->length);
    if (len == 0 || len > FARM9_MAX_MSG || flen != fixed + len) {
        errno = EMSGSIZE;
        return -1;
    }
    memcpy(ciphertext, frame + fixed, len);
    *ct_len = len;
    return 0;
}

extern "C" int farm9crypt_read(int sockfd, char* buf, int size) {
    if (!initialized || !decryptor) {
        if (debug) fprintf(stderr, "[CRYPT] Error: Not initialized\n");
        errno = EINVAL;
        return -1;
    }

    if (!buf || size <= 0) {
        if (debug) fprintf(stderr, "[CRYPT] Error: Invalid buffer or size\n");
        errno = EINVAL;
        return -1;
    }

    if (recv_seq >= FARM9_SEQ_LIMIT) {
        errno = EOVERFLOW;
        return -1;
    }

    struct farm9_header header;
    unsigned char iv[FARM9_IV_LEN];
    unsigned char tag[FARM9_TAG_LEN];
    unsigned char ciphertext[FARM9_MAX_MSG];
    uint32_t ct_len = 0;

    if (udp_mode) {
        /* UDP: receive entire datagram at once */
        unsigned char dgram[FARM9_FRAME_MAX];
        ssize_t n = recv(sockfd, dgram, sizeof(dgram), 0);
        if (n <= 0) return n == 0 ? 0 : -1;
        if (parse_frame(dgram, (size_t)n, &header, iv, tag, ciphertext, &ct_len) < 0)
            return -1;
    } else if (obfs_get_mode() != OBFS_NONE) {
        /* Obfuscated TCP: entire frame arrives in one obfs message */
        unsigned char frame[FARM9_FRAME_MAX];
        int flen = obfs_recv(sockfd, frame, sizeof(frame));
        if (flen <= 0) return flen;
        if (parse_frame(frame, (size_t)flen, &header, iv, tag, ciphertext, &ct_len) < 0)
            return -1;
    } else {
        /* TCP: read header, then IV, tag and payload */
        int ret = recv_exact(sockfd, &header, sizeof(header));
        if (ret <= 0) return ret;

        ct_len = ntohl(header.length);
        if (ct_len == 0 || ct_len > FARM9_MAX_MSG) {
            if (debug) fprintf(stderr, "[CRYPT] Error: Invalid message length %u\n", ct_len);
            errno = EMSGSIZE;
            return -1;
        }

        int r = recv_exact(sockfd, iv, FARM9_IV_LEN);
        if (r <= 0) { errno = EPROTO; return -1; }
        r = recv_exact(sockfd, tag, FARM9_TAG_LEN);
        if (r <= 0) { errno = EPROTO; return -1; }
        r = recv_exact(sockfd, ciphertext, ct_len);
        if (r <= 0) { errno = EPROTO; return -1; }
    }

    /* Cheap pre-checks; all of these fields are also authenticated below */
    uint32_t magic = ntohl(header.magic);
    if (magic != FARM9_MAGIC) {
        if (debug) fprintf(stderr, "[CRYPT] Error: Invalid magic 0x%08x (expected 0x%08x)\n",
                          magic, FARM9_MAGIC);
        errno = EPROTO;
        return -1;
    }

    uint16_t version = ntohs(header.version);
    if (version != FARM9_VERSION) {
        if (!version_warned) {
            fprintf(stderr, "[CRYPT] Error: peer uses protocol v%u, this build requires v%u "
                            "(upgrade both ends to the same ClawSec release)\n",
                    version, FARM9_VERSION);
            version_warned = true;
        }
        errno = EPROTONOSUPPORT;
        return -1;
    }

    uint32_t msg_seq = ntohl(header.seq_num);
    if (msg_seq != (uint32_t)recv_seq) {
        if (debug) fprintf(stderr, "[CRYPT] Error: Sequence mismatch - got %u, expected %u (replay attack?)\n",
                          msg_seq, (uint32_t)recv_seq);
        errno = EPROTO;
        return -1;
    }

    /* Decrypt into an internal buffer; release only authenticated plaintext */
    unsigned char plaintext[FARM9_MAX_MSG];
    int plaintext_len = 0;
    bool ok = decryptor->decrypt(
        ciphertext, (int)ct_len,
        iv, FARM9_IV_LEN,
        tag, FARM9_TAG_LEN,
        plaintext, plaintext_len,
        reinterpret_cast<const unsigned char*>(&header), (int)sizeof(header)
    );

    if (!ok) {
        if (debug) fprintf(stderr, "[CRYPT] Error: Decryption/authentication failed\n");
        errno = EBADMSG;
        return -1;
    }

    /* The frame is authentic and consumed: advance the sequence */
    recv_seq++;

    if (plaintext_len > size) {
        if (debug) fprintf(stderr, "[CRYPT] Error: Message of %d bytes exceeds buffer of %d bytes\n",
                          plaintext_len, size);
        secure_zero(plaintext, (size_t)plaintext_len);
        errno = EMSGSIZE;
        return -1;
    }

    memcpy(buf, plaintext, (size_t)plaintext_len);
    secure_zero(plaintext, (size_t)plaintext_len);

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
            if (n < 0 && errno == EINTR) continue;  /* Interrupted, retry */
            if (debug) perror("[CRYPT] send error");
            return -1;
        }
        total += (size_t)n;
    }
    return (int)total;
}

extern "C" int farm9crypt_write(int sockfd, char* buf, int size) {
    if (!initialized || !encryptor) {
        if (debug) fprintf(stderr, "[CRYPT] Error: Not initialized\n");
        errno = EINVAL;
        return -1;
    }

    if (!buf || size <= 0 || size > FARM9_MAX_MSG) {
        if (debug) fprintf(stderr, "[CRYPT] Error: Invalid buffer or size %d\n", size);
        errno = EINVAL;
        return -1;
    }

    /* Never reuse a sequence number: refuse once the 32-bit space is used up */
    if (send_seq >= FARM9_SEQ_LIMIT) {
        if (debug) fprintf(stderr, "[CRYPT] Error: Sequence space exhausted, reconnect required\n");
        errno = EOVERFLOW;
        return -1;
    }

    /* Generate cryptographically secure random IV */
    unsigned char iv[FARM9_IV_LEN];
    if (RAND_bytes(iv, FARM9_IV_LEN) != 1) {
        if (debug) fprintf(stderr, "[CRYPT] Error: IV generation failed\n");
        errno = EIO;
        return -1;
    }

    /* Build the header first: it is authenticated as AAD.
     * GCM ciphertext length equals plaintext length. */
    struct farm9_header header;
    header.magic = htonl(FARM9_MAGIC);
    header.version = htons(FARM9_VERSION);
    header.flags = htons(0);
    header.seq_num = htonl((uint32_t)send_seq);
    header.length = htonl((uint32_t)size);

    unsigned char ciphertext[FARM9_MAX_MSG];
    unsigned char tag[FARM9_TAG_LEN];
    int ciphertext_len = 0;

    bool ok = encryptor->encrypt(
        reinterpret_cast<unsigned char*>(buf), size,
        ciphertext,
        iv, FARM9_IV_LEN,
        tag, FARM9_TAG_LEN,
        ciphertext_len,
        reinterpret_cast<const unsigned char*>(&header), (int)sizeof(header)
    );

    if (!ok || ciphertext_len != size) {
        if (debug) fprintf(stderr, "[CRYPT] Error: Encryption failed\n");
        errno = EIO;
        return -1;
    }

    /* The sequence number is now committed to this frame */
    send_seq++;

    const size_t total = sizeof(header) + FARM9_IV_LEN + FARM9_TAG_LEN + (size_t)ciphertext_len;
    unsigned char frame[FARM9_FRAME_MAX];
    size_t off = 0;
    memcpy(frame + off, &header, sizeof(header)); off += sizeof(header);
    memcpy(frame + off, iv, FARM9_IV_LEN); off += FARM9_IV_LEN;
    memcpy(frame + off, tag, FARM9_TAG_LEN); off += FARM9_TAG_LEN;
    memcpy(frame + off, ciphertext, (size_t)ciphertext_len);

    if (udp_mode) {
        /* UDP: send everything as a single datagram */
        ssize_t n = send(sockfd, frame, total, 0);
        if (n < 0 || (size_t)n != total) {
            if (debug) fprintf(stderr, "[CRYPT] Error: Failed to send UDP datagram\n");
            return -1;
        }
    } else if (obfs_get_mode() != OBFS_NONE) {
        /* Obfuscated TCP: send the frame as one obfs message */
        if (obfs_send(sockfd, frame, total) < 0) return -1;
    } else {
        /* TCP: one contiguous write of the whole frame */
        if (send_exact(sockfd, frame, total) < 0) return -1;
    }

    if (debug) {
        fprintf(stderr, "[CRYPT] Encrypted and sent %d bytes (ciphertext: %d)\n",
                size, ciphertext_len);
    }

    return size;  /* Return original plaintext size */
}
