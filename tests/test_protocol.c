/*
 * test_protocol.c — Protocol validation tests (replay, magic, format)
 */
#define _POSIX_C_SOURCE 200809L
#include "test.h"

void test_replay_protection(void) {
    int fds[2], fds2[2];
    TEST_BEGIN("replay protection rejects duplicated message") {
        ASSERT(make_socketpair(fds) == 0, "socketpair");

        farm9crypt_init_password("ReplayTest!!", 12);
        const char *msg = "message one";
        farm9crypt_write(fds[0], (char *)msg, strlen(msg));

        /* Capture raw encrypted packet */
        unsigned char captured[512];
        ssize_t cap_len = read(fds[1], captured, sizeof(captured));
        ASSERT(cap_len > 0, "capture");

        /* Replay: write same packet twice into fresh socket */
        ASSERT(make_socketpair(fds2) == 0, "socketpair2");
        write(fds2[0], captured, cap_len);
        write(fds2[0], captured, cap_len);

        farm9crypt_cleanup();
        farm9crypt_init_password("ReplayTest!!", 12);

        char buf[256];
        int rn = farm9crypt_read(fds2[1], buf, sizeof(buf));
        ASSERT_EQ(rn, (int)strlen(msg), "first read");

        /* Second read: same seq=0, should be rejected (expects seq=1) */
        rn = farm9crypt_read(fds2[1], buf, sizeof(buf));
        ASSERT(rn <= 0, "replay not rejected");

        close(fds[0]); close(fds[1]);
        close(fds2[0]); close(fds2[1]);
        farm9crypt_cleanup();
    } TEST_END;
}

void test_bad_magic(void) {
    int fds[2];
    TEST_BEGIN("invalid protocol magic rejected") {
        ASSERT(make_socketpair(fds) == 0, "socketpair");
        farm9crypt_init_password("MagicTest123", 12);

        unsigned char garbage[64];
        memset(garbage, 0xFF, sizeof(garbage));
        write(fds[0], garbage, sizeof(garbage));

        char buf[256];
        int rn = farm9crypt_read(fds[1], buf, sizeof(buf));
        ASSERT(rn <= 0, "should reject bad magic");

        close(fds[0]); close(fds[1]);
        farm9crypt_cleanup();
    } TEST_END;
}
