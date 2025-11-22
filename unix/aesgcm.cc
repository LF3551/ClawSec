#include "aesgcm.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>
#include <cstdio>

/* Secure memory wipe to prevent key leakage */
static void secure_memzero(void* ptr, size_t len) {
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    while (len--) *p++ = 0;
}

AESGCM::AESGCM(const unsigned char* key, size_t key_len) {
    if (!key) {
        fprintf(stderr, "[AESGCM] Error: NULL key provided\n");
        memset(this->key, 0, 32);
        return;
    }
    
    /* Ensure key is exactly 32 bytes (AES-256) */
    memset(this->key, 0, 32);
    
    if (key_len > 32) {
        fprintf(stderr, "[AESGCM] Warning: Key truncated to 32 bytes\n");
        key_len = 32;
    } else if (key_len < 32) {
        fprintf(stderr, "[AESGCM] Warning: Key padded to 32 bytes\n");
    }
    
    memcpy(this->key, key, key_len);
}

AESGCM::~AESGCM() {
    /* Securely wipe key material before destruction */
    secure_memzero(this->key, sizeof(this->key));
}

bool AESGCM::encrypt(const unsigned char* plaintext, int plaintext_len,
                     unsigned char* ciphertext,
                     unsigned char* iv, int iv_len,
                     unsigned char* tag, int tag_len,
                     int& ciphertext_len) 
{
    if (!plaintext || !ciphertext || !iv || !tag) {
        fprintf(stderr, "[AESGCM] Encrypt error: NULL pointer\n");
        return false;
    }

    if (plaintext_len <= 0 || plaintext_len > 8192) {
        fprintf(stderr, "[AESGCM] Encrypt error: Invalid plaintext length %d\n", plaintext_len);
        return false;
    }

    if (iv_len != 12) {
        fprintf(stderr, "[AESGCM] Encrypt error: IV length must be 12 bytes, got %d\n", iv_len);
        return false;
    }

    if (tag_len != 16) {
        fprintf(stderr, "[AESGCM] Encrypt error: Tag length must be 16 bytes, got %d\n", tag_len);
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "[AESGCM] Encrypt error: Failed to create context\n");
        return false;
    }

    bool success = false;
    do {
        /* Initialize encryption with AES-256-GCM */
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
            fprintf(stderr, "[AESGCM] Encrypt error: Init failed\n");
            break;
        }

        /* Set IV length (12 bytes is optimal for GCM) */
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, nullptr)) {
            fprintf(stderr, "[AESGCM] Encrypt error: Failed to set IV length\n");
            break;
        }

        /* Initialize key and IV */
        if (1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv)) {
            fprintf(stderr, "[AESGCM] Encrypt error: Failed to set key/IV\n");
            break;
        }

        /* Encrypt plaintext */
        int len;
        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
            fprintf(stderr, "[AESGCM] Encrypt error: EncryptUpdate failed\n");
            break;
        }
        ciphertext_len = len;

        /* Finalize encryption */
        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
            fprintf(stderr, "[AESGCM] Encrypt error: EncryptFinal failed\n");
            break;
        }
        ciphertext_len += len;

        /* Get authentication tag */
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag)) {
            fprintf(stderr, "[AESGCM] Encrypt error: Failed to get tag\n");
            break;
        }

        success = true;
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    return success;
}

bool AESGCM::decrypt(const unsigned char* ciphertext, int ciphertext_len,
                     const unsigned char* iv, int iv_len,
                     const unsigned char* tag, int tag_len,
                     unsigned char* plaintext, int& plaintext_len)
{
    if (!ciphertext || !plaintext || !iv || !tag) {
        fprintf(stderr, "[AESGCM] Decrypt error: NULL pointer\n");
        return false;
    }

    if (ciphertext_len <= 0 || ciphertext_len > 8192) {
        fprintf(stderr, "[AESGCM] Decrypt error: Invalid ciphertext length %d\n", ciphertext_len);
        return false;
    }

    if (iv_len != 12) {
        fprintf(stderr, "[AESGCM] Decrypt error: IV length must be 12 bytes, got %d\n", iv_len);
        return false;
    }

    if (tag_len != 16) {
        fprintf(stderr, "[AESGCM] Decrypt error: Tag length must be 16 bytes, got %d\n", tag_len);
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "[AESGCM] Decrypt error: Failed to create context\n");
        return false;
    }

    bool success = false;
    do {
        /* Initialize decryption with AES-256-GCM */
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
            fprintf(stderr, "[AESGCM] Decrypt error: Init failed\n");
            break;
        }

        /* Set IV length */
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, nullptr)) {
            fprintf(stderr, "[AESGCM] Decrypt error: Failed to set IV length\n");
            break;
        }

        /* Initialize key and IV */
        if (1 != EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv)) {
            fprintf(stderr, "[AESGCM] Decrypt error: Failed to set key/IV\n");
            break;
        }

        /* Decrypt ciphertext */
        int len;
        if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
            fprintf(stderr, "[AESGCM] Decrypt error: DecryptUpdate failed\n");
            break;
        }
        plaintext_len = len;

        /* Set expected authentication tag */
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, (void*)tag)) {
            fprintf(stderr, "[AESGCM] Decrypt error: Failed to set tag\n");
            break;
        }

        /* Finalize and verify authentication tag */
        int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
        if (ret > 0) {
            plaintext_len += len;
            success = true;
        } else {
            fprintf(stderr, "[AESGCM] Decrypt error: Authentication failed - data may be tampered\n");
            success = false;
        }
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    return success;
}
