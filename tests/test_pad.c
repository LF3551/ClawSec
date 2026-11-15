/*
 * test_pad.c — --pad record padding (record layer) and its negotiation
 */
#define _POSIX_C_SOURCE 200809L
#include "test.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/wait.h>
#include "farm9crypt.h"

#define PAD_PASS "pad-test-password"
#define FRAME_OVERHEAD 44          /* header 16 + IV 12 + tag 16 */

/* Encrypt one message with the given padding setting and return the raw
 * on-wire frame length; the frame is then decrypted by a receiver with
 * rx_padding. Returns the frame length, and *rt = 1 if the received
 * plaintext equals the input. */
static int roundtrip(int tx_padding, int rx_padding, int len, int *rt, int *rx_errno) {
    int fds[2];
    if (make_socketpair(fds) != 0) return -1;
    char *msg = malloc((size_t)len), *got = malloc(FARM9_MAX_MSG);
    for (int i = 0; i < len; i++) msg[i] = (char)(i * 7 + 3);

    farm9crypt_set_padding(tx_padding);
    farm9crypt_init_password(PAD_PASS, strlen(PAD_PASS), FARM9_ROLE_CLIENT);
    int w = farm9crypt_write(fds[0], msg, len);
    farm9crypt_cleanup();

    int avail = 0;
    unsigned char raw[FARM9_MAX_WIRE + 64];
    avail = (int)recv(fds[1], raw, sizeof(raw), MSG_PEEK);

    farm9crypt_set_padding(rx_padding);
    farm9crypt_init_password(PAD_PASS, strlen(PAD_PASS), FARM9_ROLE_SERVER);
    errno = 0;
    int r = farm9crypt_read(fds[1], got, FARM9_MAX_MSG);
    *rx_errno = r < 0 ? errno : 0;
    *rt = (w == len && r == len && memcmp(msg, got, (size_t)len) == 0);
    farm9crypt_cleanup();
    farm9crypt_set_padding(0);
    free(msg); free(got);
    close(fds[0]); close(fds[1]);
    return avail;
}

void test_pad_record_sizes(void) {
    TEST_BEGIN("--pad: records are whole 1400-byte units, roundtrip ok") {
        int rt, e;
        ASSERT_EQ(roundtrip(1, 1, 1, &rt, &e), FRAME_OVERHEAD + 1400, "1 byte -> 1400");
        ASSERT(rt, "1 byte roundtrip");
        ASSERT_EQ(roundtrip(1, 1, 1398, &rt, &e), FRAME_OVERHEAD + 1400, "1398 bytes -> 1400");
        ASSERT(rt, "1398 roundtrip");
        ASSERT_EQ(roundtrip(1, 1, 1399, &rt, &e), FRAME_OVERHEAD + 2800, "1399 bytes -> 2800");
        ASSERT(rt, "1399 roundtrip");
        ASSERT_EQ(roundtrip(1, 1, FARM9_MAX_MSG, &rt, &e), FRAME_OVERHEAD + FARM9_MAX_WIRE,
                  "8192 bytes -> 8400");
        ASSERT(rt, "8192 roundtrip");
        ASSERT_EQ(roundtrip(0, 0, 1, &rt, &e), FRAME_OVERHEAD + 1, "no padding: exact size");
        ASSERT(rt, "unpadded roundtrip");
        farm9crypt_set_padding(1);
        ASSERT_EQ(farm9crypt_max_payload(), 1398, "max payload with --pad");
        farm9crypt_set_padding(0);
        ASSERT_EQ(farm9crypt_max_payload(), FARM9_MAX_MSG, "max payload without --pad");
    } TEST_END;
}

void test_pad_mismatch_rejected(void) {
    TEST_BEGIN("--pad: padded/unpadded records rejected by the other setting") {
        int rt, e;
        roundtrip(1, 0, 100, &rt, &e);
        ASSERT(!rt && e == EPROTO, "padded record must not be accepted without --pad");
        roundtrip(0, 1, 100, &rt, &e);
        ASSERT(!rt && e == EPROTO, "unpadded record must not be accepted with --pad");
    } TEST_END;
}

void test_pad_handshake_mismatch(void) {
    TEST_BEGIN("--pad on one end only: FAIL_CONFIG in the handshake") {
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
            farm9crypt_set_padding(1);
            int rc = farm9crypt_init_ecdhe(fds[0], PAD_PASS, strlen(PAD_PASS), FARM9_ROLE_SERVER);
            _exit(rc == 0 ? 0 : 10 + farm9crypt_last_failure());
        }
        close(fds[0]);
        farm9crypt_set_padding(0);
        int rc = farm9crypt_init_ecdhe(fds[1], PAD_PASS, strlen(PAD_PASS), FARM9_ROLE_CLIENT);
        int reason = farm9crypt_last_failure();
        close(fds[1]);
        int st;
        waitpid(pid, &st, 0);
        dup2(saved, STDERR_FILENO); close(saved);
        ASSERT_EQ(rc, -1, "client must reject");
        ASSERT_EQ(reason, FARM9_FAIL_CONFIG, "reason must be option mismatch");
        ASSERT(WIFEXITED(st) && WEXITSTATUS(st) != 0, "server must reject");
    } TEST_END;
}

void test_pad_handshake_both(void) {
    TEST_BEGIN("--pad on both ends: handshake and padded data ok") {
        int fds[2];
        ASSERT(make_socketpair(fds) == 0, "socketpair");
        pid_t pid = fork();
        if (pid == 0) {
            close(fds[1]);
            farm9crypt_set_padding(1);
            if (farm9crypt_init_ecdhe(fds[0], PAD_PASS, strlen(PAD_PASS), FARM9_ROLE_SERVER) != 0)
                _exit(1);
            char b[64];
            int n = farm9crypt_read(fds[0], b, sizeof(b));
            _exit(n == 5 && memcmp(b, "hello", 5) == 0 ? 0 : 2);
        }
        close(fds[0]);
        farm9crypt_set_padding(1);
        int rc = farm9crypt_init_ecdhe(fds[1], PAD_PASS, strlen(PAD_PASS), FARM9_ROLE_CLIENT);
        int w = rc == 0 ? farm9crypt_write(fds[1], "hello", 5) : -1;
        farm9crypt_cleanup();
        farm9crypt_set_padding(0);
        int st;
        waitpid(pid, &st, 0);
        close(fds[1]);
        ASSERT_EQ(rc, 0, "handshake");
        ASSERT_EQ(w, 5, "write");
        ASSERT(WIFEXITED(st) && WEXITSTATUS(st) == 0, "server received the padded message");
    } TEST_END;
}
