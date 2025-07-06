#pragma once

#include <openssl/evp.h>
#include <cstddef>

class AESGCM {
public:
    AESGCM(const unsigned char* key, size_t key_len = 32);

    bool encrypt(const unsigned char* plaintext, int plaintext_len,
                 unsigned char* ciphertext,
                 unsigned char* iv, int iv_len,
                 unsigned char* tag, int tag_len,
                 int& ciphertext_len);

    bool decrypt(const unsigned char* ciphertext, int ciphertext_len,
                 const unsigned char* iv, int iv_len,
                 const unsigned char* tag, int tag_len,
                 unsigned char* plaintext, int& plaintext_len);

private:
    unsigned char key[32];
};
