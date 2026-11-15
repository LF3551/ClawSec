/*
 * test_pake.c — protocol v4 handshake (SPAKE2): version/option negotiation,
 * failure reporting on both ends, and transcript integrity against an
 * active man-in-the-middle.
 */
#define _POSIX_C_SOURCE 200809L
#include "test.h"
#include <fcntl.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/wait.h>
#include "farm9crypt.h"
#include "pqkem.h"

#define PAKE_PASS "pake-test-password"

static void pk_timeouts(int fd) {
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static int pk_quiet(void) {
    int saved = dup(STDERR_FILENO);
    int devnull = open("/dev/null", O_WRONLY);
    dup2(devnull, STDERR_FILENO);
    close(devnull);
    return saved;
}

static void pk_restore(int saved) {
    dup2(saved, STDERR_FILENO);
    close(saved);
}

typedef int (*hs_fn)(int fd, const char *pw, int role);

static int hs_plain(int fd, const char *pw, int role) {
    return farm9crypt_init_ecdhe(fd, pw, strlen(pw), role);
}
static int hs_pq(int fd, const char *pw, int role) {
    return farm9crypt_init_ecdhe_pq(fd, pw, strlen(pw), role, NULL, NULL);
}

/* Child process runs one role; exit code = (rc == 0 ? 0 : 10 + failure reason).
 * The child closes the descriptors listed in `others` (-1 terminated) so that
 * the peer's close is seen as EOF instead of waiting for the socket timeout. */
static pid_t spawn_role(int fd, hs_fn fn, const char *pw, int role, const int *others) {
    pid_t pid = fork();
    if (pid == 0) {
        for (; others && *others >= 0; others++) close(*others);
        int rc = fn(fd, pw, role);
        _exit(rc == 0 ? 0 : 10 + farm9crypt_last_failure());
    }
    return pid;
}

static int child_result(pid_t pid) {
    int st;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st)) return -1;
    return WEXITSTATUS(st);
}

void test_pake_wrong_password_reported_on_server(void) {
    TEST_BEGIN("v4: wrong password is FAIL_AUTH on the server too") {
        int fds[2];
        ASSERT(make_socketpair(fds) == 0, "socketpair");
        pk_timeouts(fds[0]); pk_timeouts(fds[1]);
        int saved = pk_quiet();
        int oth[] = { fds[1], -1 };
        pid_t srv = spawn_role(fds[0], hs_plain, "server-password-1", FARM9_ROLE_SERVER, oth);
        int rc = hs_plain(fds[1], "client-password-2", FARM9_ROLE_CLIENT);
        int reason = farm9crypt_last_failure();
        close(fds[1]);
        int srv_res = child_result(srv);
        close(fds[0]);
        pk_restore(saved);
        ASSERT_EQ(rc, -1, "client must reject");
        ASSERT_EQ(reason, FARM9_FAIL_AUTH, "client reason");
        ASSERT_EQ(srv_res, 10 + FARM9_FAIL_AUTH, "server must report an authentication failure");
    } TEST_END;
}

void test_pake_old_v3_server(void) {
    TEST_BEGIN("v4: a v3 server is reported as version mismatch, no hang") {
        int fds[2];
        ASSERT(make_socketpair(fds) == 0, "socketpair");
        pk_timeouts(fds[1]);
        pid_t pid = fork();
        if (pid == 0) {
            /* ClawSec 3.x server: "CS" 0x0003, then a 32-byte X25519 key */
            close(fds[1]);
            pk_timeouts(fds[0]);
            unsigned char m[36] = { 'C', 'S', 0, 3 };
            memset(m + 4, 0x42, 32);
            IGNORE_RESULT(write(fds[0], m, sizeof(m)));
            unsigned char b[64];
            IGNORE_RESULT(read(fds[0], b, sizeof(b)));
            _exit(0);
        }
        int saved = pk_quiet();
        int rc = hs_plain(fds[1], PAKE_PASS, FARM9_ROLE_CLIENT);
        int reason = farm9crypt_last_failure();
        pk_restore(saved);
        close(fds[0]); close(fds[1]);
        waitpid(pid, NULL, 0);
        ASSERT_EQ(rc, -1, "must reject");
        ASSERT_EQ(reason, FARM9_FAIL_VERSION, "reason must be version mismatch");
    } TEST_END;
}

void test_pake_old_v3_client(void) {
    TEST_BEGIN("v4: a v3 client sees our version first, server does not hang") {
        int fds[2];
        ASSERT(make_socketpair(fds) == 0, "socketpair");
        pk_timeouts(fds[0]);
        pid_t pid = fork();
        if (pid == 0) {
            /* ClawSec 3.x client: reads the 4-byte hello and gives up */
            close(fds[0]);
            pk_timeouts(fds[1]);
            unsigned char h[4];
            ssize_t n = read(fds[1], h, sizeof(h));
            int saw_v4 = n == 4 && h[0] == 'C' && h[1] == 'S' && h[2] == 0 && h[3] == 4;
            _exit(saw_v4 ? 0 : 1);
        }
        close(fds[1]);
        int saved = pk_quiet();
        int rc = hs_plain(fds[0], PAKE_PASS, FARM9_ROLE_SERVER);
        int reason = farm9crypt_last_failure();
        pk_restore(saved);
        close(fds[0]);
        ASSERT_EQ(child_result(pid), 0, "old client must see a v4 hello in the first 4 bytes");
        ASSERT_EQ(rc, -1, "server must fail");
        ASSERT(reason != FARM9_FAIL_AUTH, "a disconnect before msg2 is not an auth failure");
    } TEST_END;
}

void test_pake_option_mismatch(void) {
    TEST_BEGIN("v4: --pq on one end only is FAIL_CONFIG, no hang") {
        if (!pq_available()) TEST_SKIP("no ML-KEM-768 in this OpenSSL");
        int fds[2];
        ASSERT(make_socketpair(fds) == 0, "socketpair");
        pk_timeouts(fds[0]); pk_timeouts(fds[1]);
        int saved = pk_quiet();
        int oth[] = { fds[1], -1 };
        pid_t srv = spawn_role(fds[0], hs_plain, PAKE_PASS, FARM9_ROLE_SERVER, oth);
        int rc = hs_pq(fds[1], PAKE_PASS, FARM9_ROLE_CLIENT);
        int reason = farm9crypt_last_failure();
        close(fds[1]);
        int srv_res = child_result(srv);
        close(fds[0]);
        pk_restore(saved);
        ASSERT_EQ(rc, -1, "client must reject");
        ASSERT_EQ(reason, FARM9_FAIL_CONFIG, "client reason must be option mismatch");
        ASSERT(srv_res != 0, "server must fail");
    } TEST_END;
}

void test_pake_pq_roundtrip(void) {
    TEST_BEGIN("v4: SPAKE2 + ML-KEM-768 handshake succeeds") {
        if (!pq_available()) TEST_SKIP("no ML-KEM-768 in this OpenSSL");
        int fds[2];
        ASSERT(make_socketpair(fds) == 0, "socketpair");
        pk_timeouts(fds[0]); pk_timeouts(fds[1]);
        int oth[] = { fds[1], -1 };
        pid_t srv = spawn_role(fds[0], hs_pq, PAKE_PASS, FARM9_ROLE_SERVER, oth);
        int rc = hs_pq(fds[1], PAKE_PASS, FARM9_ROLE_CLIENT);
        farm9crypt_cleanup();
        close(fds[1]);
        int srv_res = child_result(srv);
        close(fds[0]);
        ASSERT_EQ(rc, 0, "client");
        ASSERT_EQ(srv_res, 0, "server");
    } TEST_END;
}

/*
 * Man-in-the-middle relay: forwards both directions and flips one byte at a
 * given offset of the client->server stream. With --pq, offset 6 + 65 + 100
 * is inside the ML-KEM ciphertext, which is not otherwise authenticated by
 * SPAKE2: only the transcript binding (AAD) can detect the change.
 */
static void mitm_relay(int a, int b, long flip_c2s_at) {
    long c2s = 0;
    struct pollfd p[2] = { { a, POLLIN, 0 }, { b, POLLIN, 0 } };
    unsigned char buf[4096];
    for (;;) {
        if (poll(p, 2, 5000) <= 0) return;
        for (int i = 0; i < 2; i++) {
            if (!(p[i].revents & (POLLIN | POLLHUP))) continue;
            ssize_t n = read(p[i].fd, buf, sizeof(buf));
            if (n <= 0) return;
            if (i == 1 && flip_c2s_at >= c2s && flip_c2s_at < c2s + n)
                buf[flip_c2s_at - c2s] ^= 0x01;
            if (i == 1) c2s += n;
            if (write(p[i ^ 1].fd, buf, (size_t)n) != n) return;
        }
    }
}

void test_pake_mitm_transcript_tamper(void) {
    TEST_BEGIN("v4: MITM changing the ML-KEM ciphertext breaks both confirmations") {
        if (!pq_available()) TEST_SKIP("no ML-KEM-768 in this OpenSSL");
        int s[2], c[2];
        ASSERT(make_socketpair(s) == 0 && make_socketpair(c) == 0, "socketpairs");
        pk_timeouts(s[0]); pk_timeouts(c[1]);
        int saved = pk_quiet();
        int oth[] = { s[1], c[0], c[1], -1 };
        pid_t srv = spawn_role(s[0], hs_pq, PAKE_PASS, FARM9_ROLE_SERVER, oth);
        pid_t relay = fork();
        if (relay == 0) {
            close(s[0]); close(c[1]);
            mitm_relay(s[1], c[0], 6 + 65 + 100);
            _exit(0);
        }
        close(s[0]); close(s[1]); close(c[0]);
        int rc = hs_pq(c[1], PAKE_PASS, FARM9_ROLE_CLIENT);
        int reason = farm9crypt_last_failure();
        close(c[1]);
        int srv_res = child_result(srv);
        waitpid(relay, NULL, 0);
        pk_restore(saved);
        ASSERT_EQ(rc, -1, "client must reject a tampered transcript");
        ASSERT_EQ(reason, FARM9_FAIL_AUTH, "client reason");
        ASSERT_EQ(srv_res, 10 + FARM9_FAIL_AUTH, "server must reject a tampered transcript");
    } TEST_END;
}

void test_pake_mitm_passthrough(void) {
    TEST_BEGIN("v4: the same relay without tampering is transparent") {
        int s[2], c[2];
        ASSERT(make_socketpair(s) == 0 && make_socketpair(c) == 0, "socketpairs");
        pk_timeouts(s[0]); pk_timeouts(c[1]);
        int oth[] = { s[1], c[0], c[1], -1 };
        pid_t srv = spawn_role(s[0], hs_plain, PAKE_PASS, FARM9_ROLE_SERVER, oth);
        pid_t relay = fork();
        if (relay == 0) {
            close(s[0]); close(c[1]);
            mitm_relay(s[1], c[0], -1);
            _exit(0);
        }
        close(s[0]); close(s[1]); close(c[0]);
        int rc = hs_plain(c[1], PAKE_PASS, FARM9_ROLE_CLIENT);
        farm9crypt_cleanup();
        close(c[1]);
        int srv_res = child_result(srv);
        waitpid(relay, NULL, 0);
        ASSERT_EQ(rc, 0, "client");
        ASSERT_EQ(srv_res, 0, "server");
    } TEST_END;
}
