#ifndef AESGCM_H
#define AESGCM_H

#include <openssl/evp.h>
#include <cstddef>

/**
 * AES-256-GCM Authenticated Encryption with Associated Data (AEAD)
 * 
 * Provides:
 * - Confidentiality: AES-256 encryption
 * - Integrity: GCM authentication tag
 * - Resistance to tampering and forgery
 * 
 * Thread safety: Each instance should be used by a single thread
 */
class AESGCM {
public:
    /**
     * Constructor
     * @param key Encryption key (will be padded/truncated to 32 bytes)
     * @param key_len Length of the key (recommended: 32 bytes for AES-256)
     */
    AESGCM(const unsigned char* key, size_t key_len = 32);
    
    /**
     * Destructor - securely wipes key material
     */
    ~AESGCM();

    /**
     * Encrypt plaintext using AES-256-GCM
     * @param plaintext Input data to encrypt
     * @param plaintext_len Length of plaintext
     * @param ciphertext Output buffer for encrypted data (must be >= plaintext_len)
     * @param iv Initialization vector (must be unique per message)
     * @param iv_len Length of IV (recommended: 12 bytes for GCM)
     * @param tag Output buffer for authentication tag (16 bytes)
     * @param tag_len Length of tag (must be 16)
     * @param ciphertext_len Output: actual ciphertext length
     * @return true on success, false on error
     */
    bool encrypt(const unsigned char* plaintext, int plaintext_len,
                 unsigned char* ciphertext,
                 unsigned char* iv, int iv_len,
                 unsigned char* tag, int tag_len,
                 int& ciphertext_len);

    /**
     * Decrypt ciphertext and verify authentication tag
     * @param ciphertext Encrypted data
     * @param ciphertext_len Length of ciphertext
     * @param iv Initialization vector used during encryption
     * @param iv_len Length of IV
     * @param tag Authentication tag to verify
     * @param tag_len Length of tag (16 bytes)
     * @param plaintext Output buffer for decrypted data
     * @param plaintext_len Output: actual plaintext length
     * @return true if decryption and authentication succeed, false otherwise
     */
    bool decrypt(const unsigned char* ciphertext, int ciphertext_len,
                 const unsigned char* iv, int iv_len,
                 const unsigned char* tag, int tag_len,
                 unsigned char* plaintext, int& plaintext_len);

private:
    unsigned char key[32];
    
    // Prevent copying (key material should not be duplicated)
    AESGCM(const AESGCM&) = delete;
    AESGCM& operator=(const AESGCM&) = delete;
};

#endif /* AESGCM_H */
