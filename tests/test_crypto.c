/*
 * test_crypto.c — Encryption/decryption tests
 */
#define _POSIX_C_SOURCE 200809L
#include "test.h"

void test_basic_roundtrip(void) {
    int fds[2];
    TEST_BEGIN("basic encrypt/decrypt roundtrip") {
        ASSERT(make_socketpair(fds) == 0, "socketpair");
        farm9crypt_init_password("TestPassword123", 15);

        const char *msg = "Hello, ClawSec!";
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

void test_multiple_messages(void) {
    int fds[2];
    TEST_BEGIN("multiple messages in sequence") {
        ASSERT(make_socketpair(fds) == 0, "socketpair");
        farm9crypt_init_password("SeqTestPass!", 12);

        const char *msgs[] = {"first", "second", "third", "fourth"};
        for (int i = 0; i < 4; i++) {
            int wn = farm9crypt_write(fds[0], (char *)msgs[i], strlen(msgs[i]));
            ASSERT_EQ(wn, (int)strlen(msgs[i]), "write");
        }
        for (int i = 0; i < 4; i++) {
            char buf[64];
            int rn = farm9crypt_read(fds[1], buf, sizeof(buf));
            ASSERT_EQ(rn, (int)strlen(msgs[i]), "read length");
            buf[rn] = '\0';
            ASSERT_STR_EQ(buf, msgs[i], "content");
        }

        close(fds[0]); close(fds[1]);
        farm9crypt_cleanup();
    } TEST_END;
}

void test_salt_generation(void) {
    TEST_BEGIN("random salt generation uniqueness") {
        unsigned char s1[16], s2[16];
        ASSERT(farm9crypt_generate_salt(s1, 16) == 0, "gen salt1");
        ASSERT(farm9crypt_generate_salt(s2, 16) == 0, "gen salt2");
        ASSERT(memcmp(s1, s2, 16) != 0, "salts identical");
    } TEST_END;
}

void test_salt_different_keys(void) {
    int fds1[2], fds2[2];
    TEST_BEGIN("different salts produce different ciphertext") {
        ASSERT(make_socketpair(fds1) == 0, "socketpair1");
        ASSERT(make_socketpair(fds2) == 0, "socketpair2");

        unsigned char salt1[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
        unsigned char salt2[16] = {16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1};
        const char *msg = "same plaintext";

        farm9crypt_init_password_with_salt("SamePassword", 12, salt1, 16);
        farm9crypt_write(fds1[0], (char *)msg, strlen(msg));
        farm9crypt_cleanup();

        farm9crypt_init_password_with_salt("SamePassword", 12, salt2, 16);
        farm9crypt_write(fds2[0], (char *)msg, strlen(msg));
        farm9crypt_cleanup();

        unsigned char raw1[256], raw2[256];
        ssize_t n1 = read(fds1[1], raw1, sizeof(raw1));
        ssize_t n2 = read(fds2[1], raw2, sizeof(raw2));

        ASSERT(n1 > 0 && n2 > 0, "no data");
        ASSERT(n1 != n2 || memcmp(raw1, raw2, n1) != 0, "ciphertext identical");

        close(fds1[0]); close(fds1[1]);
        close(fds2[0]); close(fds2[1]);
    } TEST_END;
}

void test_wrong_password(void) {
    int fds[2];
    TEST_BEGIN("wrong password fails decryption") {
        ASSERT(make_socketpair(fds) == 0, "socketpair");

        farm9crypt_init_password("CorrectPass1", 12);
        farm9crypt_write(fds[0], (char *)"secret data", 11);
        farm9crypt_cleanup();

        farm9crypt_init_password("WrongPassword", 13);
        char buf[256];
        int rn = farm9crypt_read(fds[1], buf, sizeof(buf));
        farm9crypt_cleanup();

        ASSERT(rn <= 0, "decryption should have failed");

        close(fds[0]); close(fds[1]);
    } TEST_END;
}

void test_large_message(void) {
    int fds[2];
    TEST_BEGIN("large message (8000 bytes)") {
        ASSERT(make_socketpair(fds) == 0, "socketpair");
        int bufsize = 65536;
        setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
        setsockopt(fds[1], SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));

        farm9crypt_init_password("LargeMsg!!12", 12);

        char *big = malloc(8000);
        ASSERT(big != NULL, "malloc");
        memset(big, 'A', 8000);
        big[7999] = 'Z';

        int wn = farm9crypt_write(fds[0], big, 8000);
        ASSERT_EQ(wn, 8000, "write");

        char *recv_buf = malloc(8192);
        ASSERT(recv_buf != NULL, "malloc recv");

        int rn = farm9crypt_read(fds[1], recv_buf, 8192);
        ASSERT_EQ(rn, 8000, "read size");
        ASSERT(memcmp(big, recv_buf, 8000) == 0, "content");

        free(big); free(recv_buf);
        close(fds[0]); close(fds[1]);
        farm9crypt_cleanup();
    } TEST_END;
}

void test_null_password(void) {
    TEST_BEGIN("NULL/empty password rejected") {
        ASSERT_EQ(farm9crypt_init_password(NULL, 0), -1, "NULL");
        ASSERT_EQ(farm9crypt_init_password("", 0), -1, "empty");
    } TEST_END;
}

void test_invalid_salt(void) {
    TEST_BEGIN("invalid salt rejected") {
        ASSERT_EQ(farm9crypt_init_password_with_salt("pass", 4, NULL, 16), -1, "NULL salt");
        unsigned char short_salt[4] = {1,2,3,4};
        ASSERT_EQ(farm9crypt_init_password_with_salt("pass", 4, short_salt, 4), -1, "short salt");
    } TEST_END;
}
