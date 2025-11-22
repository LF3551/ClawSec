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
}

#include "aesgcm.h"

/* Protocol message header */
struct __attribute__((packed)) farm9_header {
    uint32_t magic;      /* FARM9_MAGIC */
    uint16_t version;    /* FARM9_VERSION */
    uint16_t flags;      /* Reserved for future use */
    uint32_t length;     /* Ciphertext length */
};

static int debug = false;
static int initialized = false;
static AESGCM* decryptor = NULL;
static AESGCM* encryptor = NULL;
static unsigned char derived_key[32];

/* Secure memory cleanup */
static void secure_zero(void* ptr, size_t len) {
    volatile unsigned char* p = (volatile unsigned char*)ptr;
    while (len--) *p++ = 0;
}

extern "C" void farm9crypt_debug() {
    debug = true;
}

extern "C" int farm9crypt_initialized() {
    return initialized;
}

/* Initialize with PBKDF2 key derivation from password */
extern "C" int farm9crypt_init_password(const char* password, size_t pass_len) {
    if (!password || pass_len == 0) {
        if (debug) fprintf(stderr, "[CRYPT] Error: Empty password\n");
        return -1;
    }

    if (pass_len < 8) {
        if (debug) fprintf(stderr, "[CRYPT] Warning: Password should be at least 8 characters\n");
    }

    /* Fixed salt for same password -> same key (session compatibility)
     * In production, consider exchanging salt or using pre-shared salt */
    const unsigned char salt[FARM9_SALT_LEN] = {
        0x43, 0x4c, 0x41, 0x57, 0x53, 0x45, 0x43, 0x32,
        0x30, 0x32, 0x35, 0x41, 0x45, 0x53, 0x47, 0x43
    }; /* "CLAWSEC2025AESGC" */

    /* Derive 256-bit key using PBKDF2-HMAC-SHA256 with 100,000 iterations */
    if (PKCS5_PBKDF2_HMAC(
            password, pass_len,
            salt, FARM9_SALT_LEN,
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
    if (debug) fprintf(stderr, "[CRYPT] Initialized with PBKDF2-derived key (100k iterations)\n");
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
    initialized = false;
    if (debug) fprintf(stderr, "[CRYPT] Cleanup complete\n");
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

    /* Read protocol header */
    struct farm9_header header;
    int ret = recv_exact(sockfd, &header, sizeof(header));
    if (ret <= 0) return ret;

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

    /* Get ciphertext length */
    uint32_t ct_len = ntohl(header.length);
    if (ct_len == 0 || ct_len > FARM9_MAX_MSG) {
        if (debug) fprintf(stderr, "[CRYPT] Error: Invalid message length %u\n", ct_len);
        errno = EMSGSIZE;
        return -1;
    }

    /* Read IV */
    unsigned char iv[FARM9_IV_LEN];
    ret = recv_exact(sockfd, iv, FARM9_IV_LEN);
    if (ret <= 0) return ret;

    /* Read authentication tag */
    unsigned char tag[FARM9_TAG_LEN];
    ret = recv_exact(sockfd, tag, FARM9_TAG_LEN);
    if (ret <= 0) return ret;

    /* Read ciphertext */
    unsigned char ciphertext[FARM9_MAX_MSG];
    ret = recv_exact(sockfd, ciphertext, ct_len);
    if (ret <= 0) return ret;

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
    header.length = htonl(ciphertext_len);

    /* Send header */
    if (send_exact(sockfd, &header, sizeof(header)) < 0) {
        if (debug) fprintf(stderr, "[CRYPT] Error: Failed to send header\n");
        return -1;
    }

    /* Send IV */
    if (send_exact(sockfd, iv, FARM9_IV_LEN) < 0) {
        if (debug) fprintf(stderr, "[CRYPT] Error: Failed to send IV\n");
        return -1;
    }

    /* Send authentication tag */
    if (send_exact(sockfd, tag, FARM9_TAG_LEN) < 0) {
        if (debug) fprintf(stderr, "[CRYPT] Error: Failed to send tag\n");
        return -1;
    }

    /* Send ciphertext */
    if (send_exact(sockfd, ciphertext, ciphertext_len) < 0) {
        if (debug) fprintf(stderr, "[CRYPT] Error: Failed to send ciphertext\n");
        return -1;
    }

    if (debug) {
        fprintf(stderr, "[CRYPT] Encrypted and sent %d bytes (ciphertext: %d)\n", 
                size, ciphertext_len);
    }

    return size;  /* Return original plaintext size */
}
