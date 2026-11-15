/*
 * test_rekey.c — --rekey key updates (one-way ratchet per direction)
 */
#define _POSIX_C_SOURCE 200809L
#include "test.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/wait.h>
#include "farm9crypt.h"

#define RK_PASS "rekey-test-password"

static void big_buffers(int fds[2]) {
    int big = 1 << 20;
    for (int i = 0; i < 2; i++) {
        setsockopt(fds[i], SOL_SOCKET, SO_SNDBUF, &big, sizeof(big));
        setsockopt(fds[i], SOL_SOCKET, SO_RCVBUF, &big, sizeof(big));
    }
}

/* Writer child sends n messages with the given rekey/padding settings and
 * reports its key-update count as exit status; the parent reads them. */
static int stream(int n, unsigned long long w_records, unsigned long long r_records, int pad,
                  int corrupt_at, unsigned long *sent, unsigned long *received, int *read_errno) {
    int fds[2];
    if (make_socketpair(fds) != 0) return -1;
    big_buffers(fds);
    pid_t pid = fork();
    if (pid == 0) {
        close(fds[1]);
        farm9crypt_set_padding(pad);
        farm9crypt_set_rekey(0, w_records);
        farm9crypt_init_password(RK_PASS, strlen(RK_PASS), FARM9_ROLE_CLIENT);
        for (int i = 0; i < n; i++) {
            char m[64];
            int l = snprintf(m, sizeof(m), "message %d", i);
            if (farm9crypt_write(fds[0], m, l) != l) _exit(255);
        }
        unsigned long s = 0;
        farm9crypt_key_updates(&s, NULL);
        _exit((int)(s > 200 ? 200 : s));
    }
    close(fds[0]);
    if (corrupt_at >= 0) {
        /* man in the middle: flip one byte of the stream at offset corrupt_at */
        int mid[2];
        if (make_socketpair(mid) != 0) return -1;
        big_buffers(mid);
        test_sleep_ms(200);
        char buf[1 << 16];
        ssize_t got = recv(fds[1], buf, sizeof(buf), MSG_DONTWAIT);
        if (got > corrupt_at) buf[corrupt_at] ^= 0x01;
        if (got > 0 && write(mid[0], buf, (size_t)got) != got) return -1;
        close(mid[0]);
        close(fds[1]);
        fds[1] = mid[1];
    }
    farm9crypt_set_padding(pad);
    farm9crypt_set_rekey(0, r_records);
    farm9crypt_init_password(RK_PASS, strlen(RK_PASS), FARM9_ROLE_SERVER);
    int ok = 0;
    *read_errno = 0;
    for (int i = 0; i < n; i++) {
        char m[64], want[64];
        int l = snprintf(want, sizeof(want), "message %d", i);
        int r = farm9crypt_read(fds[1], m, sizeof(m));
        if (r != l || memcmp(m, want, (size_t)l) != 0) {
            *read_errno = r < 0 ? errno : 0;
            break;
        }
        ok++;
    }
    farm9crypt_key_updates(NULL, received);
    farm9crypt_cleanup();
    farm9crypt_set_rekey(0, 0);
    farm9crypt_set_padding(0);
    close(fds[1]);
    int st;
    waitpid(pid, &st, 0);
    *sent = WIFEXITED(st) ? (unsigned long)WEXITSTATUS(st) : 0;
    return ok;
}

void test_rekey_roundtrip(void) {
    TEST_BEGIN("--rekey: key updates every 3 records, data intact") {
        unsigned long s, r;
        int e;
        int ok = stream(40, 3, 3, 0, -1, &s, &r, &e);
        ASSERT_EQ(ok, 40, "all 40 messages must arrive intact");
        ASSERT(s >= 12 && s == r, "writer and reader must agree on the number of updates");
        ok = stream(40, 5, 1000, 1, -1, &s, &r, &e);
        ASSERT_EQ(ok, 40, "with --pad, and a reader with another update interval");
        ASSERT(s >= 7 && s == r, "updates are driven by the sender");
    } TEST_END;
}

void test_rekey_tamper_and_mismatch(void) {
    TEST_BEGIN("--rekey: tampered update rejected; no update without --rekey") {
        unsigned long s, r;
        int e;
        /* record 0 = 'message 0', record 1 = the key update: corrupt its tag */
        int frame0 = 44 + 9;                      /* header+iv+tag + "message 0" */
        int ok = stream(4, 1, 1, 0, frame0 + 16 + 12 + 2, &s, &r, &e);
        ASSERT(ok == 1 && e == EBADMSG, "a modified key-update record must fail authentication");
        ok = stream(4, 1, 0, 0, -1, &s, &r, &e);
        ASSERT(ok == 1 && e == EPROTO, "a key update to a peer without --rekey is rejected");
    } TEST_END;
}

void test_rekey_handshake_flag(void) {
    TEST_BEGIN("--rekey on one end only: FAIL_CONFIG in the handshake") {
        int fds[2];
        ASSERT(make_socketpair(fds) == 0, "socketpair");
        struct timeval tv = { 5, 0 };
        setsockopt(fds[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fds[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        int saved = dup(STDERR_FILENO), dn = open("/dev/null", O_WRONLY);
        dup2(dn, STDERR_FILENO); close(dn);
        pid_t pid = fork();
        if (pid == 0) {
            close(fds[1]);
            farm9crypt_set_rekey(1800, 0);
            int rc = farm9crypt_init_ecdhe(fds[0], RK_PASS, strlen(RK_PASS), FARM9_ROLE_SERVER);
            _exit(rc == 0 ? 0 : 10 + farm9crypt_last_failure());
        }
        close(fds[0]);
        int rc = farm9crypt_init_ecdhe(fds[1], RK_PASS, strlen(RK_PASS), FARM9_ROLE_CLIENT);
        int reason = farm9crypt_last_failure();
        close(fds[1]);
        int st;
        waitpid(pid, &st, 0);
        dup2(saved, STDERR_FILENO); close(saved);
        ASSERT(rc == -1 && reason == FARM9_FAIL_CONFIG, "client: option mismatch");
        ASSERT(WIFEXITED(st) && WEXITSTATUS(st) != 0, "server must reject");
    } TEST_END;
}
