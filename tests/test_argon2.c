/*
 * test_argon2.c — Argon2id KDF tests
 */
#include "test.h"
#include "argon2kdf.h"

void test_argon2_available(void) {
    TEST_BEGIN("Argon2id is available") {
        ASSERT(argon2_available(), "argon2id should be available with OpenSSL >= 3.2");
    } TEST_END;
}

void test_argon2_derive(void) {
    TEST_BEGIN("Argon2id key derivation produces 32-byte key") {
        const char *pass = "TestPassword123";
        unsigned char salt[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
        unsigned char key[32];
        int rc = kdf_derive(pass, strlen(pass), salt, 16, key, 32);
        ASSERT_EQ(rc, 0, "kdf_derive should succeed");

        /* Key should not be all zeros */
        int nonzero = 0;
        for (int i = 0; i < 32; i++)
            if (key[i] != 0) nonzero++;
        ASSERT(nonzero > 0, "derived key should not be all zeros");
    } TEST_END;
}

void test_argon2_deterministic(void) {
    TEST_BEGIN("Argon2id same input produces same key") {
        const char *pass = "Deterministic";
        unsigned char salt[16] = {0xCA,0xFE,0xBA,0xBE,0,0,0,0,0,0,0,0,0,0,0,0};
        unsigned char key1[32], key2[32];
        ASSERT_EQ(kdf_derive(pass, strlen(pass), salt, 16, key1, 32), 0, "derive1");
        ASSERT_EQ(kdf_derive(pass, strlen(pass), salt, 16, key2, 32), 0, "derive2");
        ASSERT(memcmp(key1, key2, 32) == 0, "same input must produce same key");
    } TEST_END;
}

void test_argon2_different_passwords(void) {
    TEST_BEGIN("Argon2id different passwords produce different keys") {
        unsigned char salt[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
        unsigned char key1[32], key2[32];
        ASSERT_EQ(kdf_derive("password1", 9, salt, 16, key1, 32), 0, "derive1");
        ASSERT_EQ(kdf_derive("password2", 9, salt, 16, key2, 32), 0, "derive2");
        ASSERT(memcmp(key1, key2, 32) != 0, "different passwords => different keys");
    } TEST_END;
}

void test_argon2_different_salts(void) {
    TEST_BEGIN("Argon2id different salts produce different keys") {
        const char *pass = "SamePassword";
        unsigned char salt1[16] = {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
        unsigned char salt2[16] = {2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2};
        unsigned char key1[32], key2[32];
        ASSERT_EQ(kdf_derive(pass, strlen(pass), salt1, 16, key1, 32), 0, "derive1");
        ASSERT_EQ(kdf_derive(pass, strlen(pass), salt2, 16, key2, 32), 0, "derive2");
        ASSERT(memcmp(key1, key2, 32) != 0, "different salts => different keys");
    } TEST_END;
}

void test_argon2_rejects_bad_input(void) {
    TEST_BEGIN("Argon2id rejects NULL/empty input") {
        unsigned char salt[16] = {0};
        unsigned char key[32];
        ASSERT_EQ(kdf_derive(NULL, 0, salt, 16, key, 32), -1, "NULL password");
        ASSERT_EQ(kdf_derive("x", 1, NULL, 0, key, 32), -1, "NULL salt");
        ASSERT_EQ(kdf_derive("x", 1, salt, 8, key, 32), -1, "salt too short");
    } TEST_END;
}

void test_argon2_roundtrip_encrypt(void) {
    TEST_BEGIN("Argon2id-derived key encrypts/decrypts correctly") {
        int fds[2];
        ASSERT(make_socketpair(fds) == 0, "socketpair");

        /* Use password init which now goes through Argon2id */
        farm9crypt_init_password("Argon2idTest!", 13);

        const char *msg = "Argon2id encryption test";
        int wn = farm9crypt_write(fds[0], (char *)msg, strlen(msg));
        ASSERT_EQ(wn, (int)strlen(msg), "write size");

        char buf[256];
        int rn = farm9crypt_read(fds[1], buf, sizeof(buf));
        ASSERT_EQ(rn, (int)strlen(msg), "read size");
        buf[rn] = '\0';
        ASSERT_STR_EQ(buf, msg, "content");

        close(fds[0]); close(fds[1]);
        farm9crypt_cleanup();
    } TEST_END;
}
