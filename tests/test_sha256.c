/*
 * test_sha256.c — Tests for SHA-256 verification
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#include "test.h"

static void sha256_hex_test(const unsigned char *hash, char *hex) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        hex[i*2]   = hx[hash[i] >> 4];
        hex[i*2+1] = hx[hash[i] & 0x0f];
    }
    hex[64] = '\0';
}

void test_sha256_known_vector(void) {
    TEST_BEGIN("SHA-256 known test vector");
    /* SHA-256("abc") = ba7816bf... */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    ASSERT(ctx != NULL, "EVP_MD_CTX_new failed");
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, "abc", 3);
    unsigned char hash[32];
    unsigned int hlen = 32;
    EVP_DigestFinal_ex(ctx, hash, &hlen);
    EVP_MD_CTX_free(ctx);

    char hex[65];
    sha256_hex_test(hash, hex);
    ASSERT_STR_EQ(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                  "SHA-256(abc) mismatch");
    TEST_END;
}

void test_sha256_incremental(void) {
    TEST_BEGIN("SHA-256 incremental vs single-shot");
    const char *data = "Hello, World! This is a test of incremental hashing.";
    size_t len = strlen(data);

    /* Single shot */
    EVP_MD_CTX *ctx1 = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx1, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx1, data, len);
    unsigned char hash1[32];
    unsigned int hlen = 32;
    EVP_DigestFinal_ex(ctx1, hash1, &hlen);
    EVP_MD_CTX_free(ctx1);

    /* Incremental (byte by byte) */
    EVP_MD_CTX *ctx2 = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx2, EVP_sha256(), NULL);
    for (size_t i = 0; i < len; i++)
        EVP_DigestUpdate(ctx2, data + i, 1);
    unsigned char hash2[32];
    hlen = 32;
    EVP_DigestFinal_ex(ctx2, hash2, &hlen);
    EVP_MD_CTX_free(ctx2);

    ASSERT(memcmp(hash1, hash2, 32) == 0, "hashes should match");
    TEST_END;
}
