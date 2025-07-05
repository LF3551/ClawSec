#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>
#include <cstdio>

class AESGCM {
public:
    AESGCM(const unsigned char* key, size_t key_len = 32) {
        if (key_len > 32) key_len = 32;
        memset(this->key, 0, 32);
        memcpy(this->key, key, key_len);
    }

    bool encrypt(const unsigned char* plaintext, int plaintext_len,
                 unsigned char* ciphertext,
                 unsigned char* iv, int iv_len,
                 unsigned char* tag, int tag_len,
                 int &ciphertext_len) 
    {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;

        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr))
            return false;

        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, nullptr))
            return false;

        if (1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv))
            return false;

        int len;
        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
            return false;

        ciphertext_len = len;

        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
            return false;

        ciphertext_len += len;

        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag))
            return false;

        EVP_CIPHER_CTX_free(ctx);
        return true;
    }

    bool decrypt(const unsigned char* ciphertext, int ciphertext_len,
                 const unsigned char* iv, int iv_len,
                 const unsigned char* tag, int tag_len,
                 unsigned char* plaintext, int &plaintext_len)
    {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;

        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr))
            return false;

        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, nullptr))
            return false;

        if (1 != EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv))
            return false;

        int len;
        if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
            return false;

        plaintext_len = len;

        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, (void*)tag))
            return false;

        int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
        EVP_CIPHER_CTX_free(ctx);

        if (ret > 0) {
            plaintext_len += len;
            return true;
        } else {
            return false;
        }
    }

private:
    unsigned char key[32];
};
