/*
 * test_util.c — Tests for utility functions and farm9crypt state
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include "test.h"
#include "farm9crypt.h"
#include "util.h"

void test_initialized_flag(void) {
    TEST_BEGIN("farm9crypt_initialized reflects state");
    farm9crypt_cleanup();
    ASSERT_EQ(farm9crypt_initialized(), 0, "should not be initialized after cleanup");

    int rc = farm9crypt_init_password("testpass12", 10);
    ASSERT_EQ(rc, 0, "init_password should succeed");
    ASSERT_EQ(farm9crypt_initialized(), 1, "should be initialized after init");

    farm9crypt_cleanup();
    ASSERT_EQ(farm9crypt_initialized(), 0, "should not be initialized after cleanup");
    TEST_END;
}

void test_raw_key_init(void) {
    TEST_BEGIN("farm9crypt_init with raw 32-byte key");
    char key[32];
    memset(key, 0x42, 32);
    farm9crypt_init(key);
    ASSERT_EQ(farm9crypt_initialized(), 1, "should be initialized");

    int sv[2];
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair failed");

    const char *msg = "raw key test message";
    int mlen = (int)strlen(msg);

    pid_t pid = fork();
    ASSERT(pid >= 0, "fork failed");

    if (pid == 0) {
        close(sv[0]);
        farm9crypt_init(key);
        farm9crypt_write(sv[1], (char*)msg, mlen);
        farm9crypt_cleanup();
        close(sv[1]);
        _exit(0);
    }

    close(sv[1]);
    char buf[256];
    int got = farm9crypt_read(sv[0], buf, sizeof(buf));
    close(sv[0]);

    int status;
    waitpid(pid, &status, 0);
    ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "child failed");
    ASSERT(got == mlen, "wrong length");
    ASSERT(memcmp(buf, msg, mlen) == 0, "data mismatch");

    farm9crypt_cleanup();
    TEST_END;
}

void test_fingerprint_uninitialized(void) {
    TEST_BEGIN("fingerprint returns -1 when not initialized");
    farm9crypt_cleanup();
    unsigned char fp[8];
    int rc = farm9crypt_get_fingerprint(fp, 8);
    ASSERT_EQ(rc, -1, "should return -1 when not initialized");
    TEST_END;
}

void test_write_all_basic(void) {
    TEST_BEGIN("write_all writes full buffer");
    int sv[2];
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair failed");

    const char *data = "write_all test data 1234567890";
    int dlen = (int)strlen(data);
    int rc = write_all(sv[0], data, dlen);
    ASSERT_EQ(rc, 0, "write_all should return 0");
    close(sv[0]);

    char buf[256];
    int total = 0;
    int n;
    while ((n = (int)read(sv[1], buf + total, sizeof(buf) - total)) > 0)
        total += n;
    close(sv[1]);
    ASSERT_EQ(total, dlen, "should read back all bytes");
    ASSERT(memcmp(buf, data, dlen) == 0, "data mismatch");
    TEST_END;
}
