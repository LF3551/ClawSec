/*
 * test_fallback.c — Fallback (REALITY-like) tests
 */
#define _POSIX_C_SOURCE 200809L
#include "test.h"
#include "fallback.h"
#include "obfs.h"

#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/wait.h>

/* The client must not close before the server finished SSL_accept: a TLS 1.3
 * server writes session tickets at the end of the handshake, and a closed
 * peer turns that into EPIPE (seen as a flaky "TLS accept failed"). The
 * client therefore waits until the server closes the connection. */
static void wait_for_server_close(int fd) {
    char b[256];
    struct timeval tv = { 5, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    while (read(fd, b, sizeof(b)) > 0) { }
}

void test_fallback_knock_roundtrip(void) {
    TEST_BEGIN("fallback knock send/verify roundtrip") {
        int fds[2];
        ASSERT(make_socketpair(fds) == 0, "socketpair failed");

        obfs_set_mode(OBFS_TLS);
        signal(SIGPIPE, SIG_IGN);

        pid_t pid = fork();
        ASSERT(pid >= 0, "fork failed");

        if (pid == 0) {
            /* Client: TLS connect + send knock */
            close(fds[0]);
            if (obfs_tls_connect(fds[1]) < 0) _exit(1);
            if (fallback_send_knock(fds[1]) < 0) _exit(2);
            /* Send some data after knock to prove channel works */
            if (obfs_send(fds[1], "post-knock", 10) < 0) _exit(3);
            wait_for_server_close(fds[1]);
            _exit(0);
        }

        close(fds[1]);
        test_sleep_ms(50); /* let child start TLS connect first */
        ASSERT(obfs_tls_accept(fds[0]) == 0, "TLS accept failed");

        int result = fallback_check_knock(fds[0]);
        ASSERT_EQ(result, 1, "should detect ClawSec knock");

        /* Verify data still flows after knock */
        char buf[64];
        int n = obfs_recv(fds[0], buf, sizeof(buf));
        ASSERT_EQ(n, 10, "post-knock data wrong length");
        ASSERT(memcmp(buf, "post-knock", 10) == 0, "post-knock data mismatch");

        close(fds[0]);
        int status;
        waitpid(pid, &status, 0);
        ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "client failed");
        obfs_set_mode(OBFS_NONE);
    } TEST_END;
}

void test_fallback_detects_probe(void) {
    TEST_BEGIN("fallback detects non-ClawSec probe") {
        int fds[2];
        ASSERT(make_socketpair(fds) == 0, "socketpair failed");

        obfs_set_mode(OBFS_TLS);
        signal(SIGPIPE, SIG_IGN);

        pid_t pid = fork();
        ASSERT(pid >= 0, "fork failed");

        if (pid == 0) {
            /* Simulate a browser/DPI probe: TLS connect + send HTTP GET */
            close(fds[0]);
            if (obfs_tls_connect(fds[1]) < 0) _exit(1);
            const char *http_req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
            obfs_send(fds[1], http_req, strlen(http_req));
            wait_for_server_close(fds[1]);
            _exit(0);
        }

        close(fds[1]);
        test_sleep_ms(50); /* let child start TLS connect first */
        ASSERT(obfs_tls_accept(fds[0]) == 0, "TLS accept failed");

        int result = fallback_check_knock(fds[0]);
        ASSERT_EQ(result, 0, "should detect foreign probe (not ClawSec)");

        close(fds[0]);
        int status;
        waitpid(pid, &status, 0);
        obfs_set_mode(OBFS_NONE);
    } TEST_END;
}

void test_fallback_knock_magic(void) {
    TEST_BEGIN("fallback knock magic is CLAW") {
        ASSERT_EQ(FALLBACK_KNOCK_SIZE, 4, "knock should be 4 bytes");
        ASSERT(memcmp(FALLBACK_KNOCK_MAGIC, "CLAW", 4) == 0, "magic should be CLAW");
    } TEST_END;
}
