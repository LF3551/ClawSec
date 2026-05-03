/*
 * test_ech.c — ECH (Encrypted Client Hello) tests
 */
#define _POSIX_C_SOURCE 200809L
#include "test.h"
#include "obfs.h"

void test_ech_flag(void) {
    TEST_BEGIN("ECH enable/disable flag") {
        ASSERT_EQ(obfs_ech_enabled(), 0, "should be disabled by default");
        obfs_ech_enable();
        ASSERT_EQ(obfs_ech_enabled(), 1, "should be enabled");
        obfs_ech_disable();
        ASSERT_EQ(obfs_ech_enabled(), 0, "should be disabled after disable");
    } TEST_END;
}

void test_ech_tls_connects(void) {
    TEST_BEGIN("ECH + TLS handshake roundtrip") {
        int fds[2];
        ASSERT(make_socketpair(fds) == 0, "socketpair failed");

        obfs_set_mode(OBFS_TLS);
        obfs_ech_enable();

        pid_t pid = fork();
        ASSERT(pid >= 0, "fork failed");

        if (pid == 0) {
            /* Client: connect with GREASE ECH extension */
            close(fds[0]);
            if (obfs_tls_connect(fds[1]) < 0) _exit(1);
            const char *msg = "ech-hello";
            if (obfs_send(fds[1], msg, 9) < 0) _exit(2);
            char rbuf[64];
            if (obfs_recv(fds[1], rbuf, sizeof(rbuf)) <= 0) _exit(3);
            _exit(0);
        }

        /* Server: accept (ignores ECH extension) */
        close(fds[1]);
        ASSERT(obfs_tls_accept(fds[0]) == 0, "TLS accept failed with ECH");

        char buf[64];
        int n = obfs_recv(fds[0], buf, sizeof(buf));
        ASSERT(n == 9, "recv wrong length");
        ASSERT(memcmp(buf, "ech-hello", 9) == 0, "data mismatch");

        ASSERT(obfs_send(fds[0], "ok", 2) == 2, "send back failed");

        int status;
        waitpid(pid, &status, 0);
        ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "client child failed");

        close(fds[0]);
        obfs_ech_disable();
        obfs_set_mode(OBFS_NONE);
    } TEST_END;
}
