/*
 * test_handshake.c — ECDHE handshake and session tests
 */
#define _POSIX_C_SOURCE 200809L
#include "test.h"

void test_full_handshake(void) {
    int fds[2];
    TEST_BEGIN("full ECDHE handshake (server/client simulation)") {
        ASSERT(make_socketpair(fds) == 0, "socketpair");
        const char *password = "HandshakePass1";

        pid_t pid = fork();
        ASSERT(pid >= 0, "fork");

        if (pid == 0) {
            /* Child: server side (send_first=1) */
            close(fds[1]);
            if (farm9crypt_init_ecdhe(fds[0], password, strlen(password), 1) != 0)
                _exit(1);
            const char *msg = "hello from server";
            int wn = farm9crypt_write(fds[0], (char *)msg, strlen(msg));
            farm9crypt_cleanup();
            close(fds[0]);
            _exit(wn == (int)strlen(msg) ? 0 : 1);
        }

        /* Parent: client side (send_first=0) */
        close(fds[0]);
        int rc = farm9crypt_init_ecdhe(fds[1], password, strlen(password), 0);
        ASSERT_EQ(rc, 0, "client ECDHE");

        char buf[256];
        int rn = farm9crypt_read(fds[1], buf, sizeof(buf));
        farm9crypt_cleanup();
        close(fds[1]);

        int status;
        waitpid(pid, &status, 0);

        ASSERT(rn > 0, "read failed");
        buf[rn] = '\0';
        ASSERT_STR_EQ(buf, "hello from server", "content");
        ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "server failed");
    } TEST_END;
}

void test_bidirectional(void) {
    int fds[2];
    TEST_BEGIN("bidirectional encrypted communication") {
        ASSERT(make_socketpair(fds) == 0, "socketpair");

        unsigned char salt[16];
        farm9crypt_generate_salt(salt, sizeof(salt));
        farm9crypt_init_password_with_salt("BiDirTest123", 12, salt, 16);

        const char *msg_a = "from A";
        farm9crypt_write(fds[0], (char *)msg_a, strlen(msg_a));

        char buf[64];
        int rn = farm9crypt_read(fds[1], buf, sizeof(buf));
        ASSERT_EQ(rn, (int)strlen(msg_a), "read size");
        buf[rn] = '\0';
        ASSERT_STR_EQ(buf, msg_a, "content");

        close(fds[0]); close(fds[1]);
        farm9crypt_cleanup();
    } TEST_END;
}
