/*
 * test_security.c — Regression tests for wire-protocol v3 security properties
 *
 * Each test corresponds to a concrete attack that succeeded against protocol v1 (ClawSec <= 2.8.2):
 *   - reflection of a node's own frame back to it
 *   - replay of a captured frame with an edited (unauthenticated) seq number
 *   - tampering with header fields (flags/version)
 *   - writes beyond the caller's buffer, including for forged frames
 */
#define _POSIX_C_SOURCE 200809L
#include "test.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/time.h>

#define SEC_PASS "SecurityRegression!1"
#define HDR_SEQ_OFF     8
#define HDR_FLAGS_OFF   6
#define HDR_VERSION_OFF 4
#define FRAME_OVERHEAD  (FARM9_HEADER_LEN + FARM9_IV_LEN + FARM9_TAG_LEN)

/* Read exactly n bytes from a blocking fd. */
static int read_n(int fd, unsigned char *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

/* Encrypt msg as `role` (sequence 0) and capture the raw wire frame. */
static int capture_frame(int role, const unsigned char *msg, int len,
                         unsigned char *frame) {
    int fds[2];
    if (make_socketpair(fds) != 0) return -1;
    int rc = -1;
    if (farm9crypt_init_password(SEC_PASS, strlen(SEC_PASS), role) == 0 &&
        farm9crypt_write(fds[0], (char *)msg, len) == len &&
        read_n(fds[1], frame, (size_t)(FRAME_OVERHEAD + len)) == 0)
        rc = FRAME_OVERHEAD + len;
    farm9crypt_cleanup();
    close(fds[0]);
    close(fds[1]);
    return rc;
}

/* Feed a raw frame to a fresh receiver with `role` and read it into buf.
 * Returns farm9crypt_read's result; *err receives errno. */
static int deliver(int role, const unsigned char *frame, int flen,
                   char *buf, int size, int *err) {
    int fds[2];
    if (make_socketpair(fds) != 0) return -2;
    if (write(fds[0], frame, (size_t)flen) != flen) return -2;
    if (farm9crypt_init_password(SEC_PASS, strlen(SEC_PASS), role) != 0) return -2;
    errno = 0;
    int rn = farm9crypt_read(fds[1], buf, size);
    *err = errno;
    farm9crypt_cleanup();
    close(fds[0]);
    close(fds[1]);
    return rn;
}

void test_sec_roles_roundtrip(void) {
    TEST_BEGIN("v3: server->client frame decrypts with client role") {
        unsigned char frame[256];
        const char *msg = "hello across roles";
        int flen = capture_frame(FARM9_ROLE_SERVER, (const unsigned char *)msg,
                                 (int)strlen(msg), frame);
        ASSERT(flen > 0, "capture");
        char buf[64];
        int err = 0;
        int rn = deliver(FARM9_ROLE_CLIENT, frame, flen, buf, sizeof(buf), &err);
        ASSERT_EQ(rn, (int)strlen(msg), "client should decrypt server frame");
        ASSERT(memcmp(buf, msg, strlen(msg)) == 0, "content");
    } TEST_END;
}

void test_sec_reflection_rejected(void) {
    TEST_BEGIN("v3: own frame reflected back is rejected") {
        unsigned char frame[256];
        const char *msg = "reflect me";
        int flen = capture_frame(FARM9_ROLE_SERVER, (const unsigned char *)msg,
                                 (int)strlen(msg), frame);
        ASSERT(flen > 0, "capture");
        char buf[64];
        int err = 0;
        int rn = deliver(FARM9_ROLE_SERVER, frame, flen, buf, sizeof(buf), &err);
        ASSERT_EQ(rn, -1, "reflected frame must be rejected");
        ASSERT_EQ(err, EBADMSG, "errno should be EBADMSG");
    } TEST_END;
}

void test_sec_edited_seq_replay_rejected(void) {
    TEST_BEGIN("v3: replay with edited sequence number rejected") {
        unsigned char frame[256];
        const char *msg = "pay 100 EUR";
        int flen = capture_frame(FARM9_ROLE_CLIENT, (const unsigned char *)msg,
                                 (int)strlen(msg), frame);
        ASSERT(flen > 0, "capture");

        int fds[2];
        ASSERT(make_socketpair(fds) == 0, "socketpair");
        /* Original frame, then the same frame re-labelled as seq 1 */
        unsigned char replay[256];
        memcpy(replay, frame, (size_t)flen);
        uint32_t seq1 = htonl(1);
        memcpy(replay + HDR_SEQ_OFF, &seq1, sizeof(seq1));
        ASSERT(write(fds[0], frame, (size_t)flen) == flen, "write original");
        ASSERT(write(fds[0], replay, (size_t)flen) == flen, "write replay");

        ASSERT(farm9crypt_init_password(SEC_PASS, strlen(SEC_PASS), FARM9_ROLE_SERVER) == 0,
               "init");
        char buf[64];
        int rn = farm9crypt_read(fds[1], buf, sizeof(buf));
        ASSERT_EQ(rn, (int)strlen(msg), "original accepted");
        errno = 0;
        rn = farm9crypt_read(fds[1], buf, sizeof(buf));
        int err = errno;
        farm9crypt_cleanup();
        close(fds[0]); close(fds[1]);
        ASSERT_EQ(rn, -1, "replayed frame must be rejected");
        ASSERT_EQ(err, EBADMSG, "header is authenticated, expect EBADMSG");
    } TEST_END;
}

void test_sec_header_flags_tamper_rejected(void) {
    TEST_BEGIN("v3: tampered header flags rejected") {
        unsigned char frame[256];
        const char *msg = "flags are authenticated";
        int flen = capture_frame(FARM9_ROLE_CLIENT, (const unsigned char *)msg,
                                 (int)strlen(msg), frame);
        ASSERT(flen > 0, "capture");
        frame[HDR_FLAGS_OFF + 1] ^= 0x01;
        char buf[64];
        int err = 0;
        int rn = deliver(FARM9_ROLE_SERVER, frame, flen, buf, sizeof(buf), &err);
        ASSERT_EQ(rn, -1, "tampered frame must be rejected");
        ASSERT_EQ(err, EBADMSG, "errno should be EBADMSG");
    } TEST_END;
}

void test_sec_version_mismatch_rejected(void) {
    TEST_BEGIN("v3: frame with other protocol version rejected") {
        unsigned char frame[256];
        const char *msg = "old peer";
        int flen = capture_frame(FARM9_ROLE_CLIENT, (const unsigned char *)msg,
                                 (int)strlen(msg), frame);
        ASSERT(flen > 0, "capture");
        uint16_t v1 = htons(1);
        memcpy(frame + HDR_VERSION_OFF, &v1, sizeof(v1));

        /* The mismatch is reported once on stderr; keep test output clean */
        int saved = dup(STDERR_FILENO);
        int devnull = open("/dev/null", O_WRONLY);
        dup2(devnull, STDERR_FILENO);
        close(devnull);
        char buf[64];
        int err = 0;
        int rn = deliver(FARM9_ROLE_SERVER, frame, flen, buf, sizeof(buf), &err);
        dup2(saved, STDERR_FILENO);
        close(saved);

        ASSERT_EQ(rn, -1, "version 1 frame must be rejected");
        ASSERT_EQ(err, EPROTONOSUPPORT, "errno should be EPROTONOSUPPORT");
    } TEST_END;
}

void test_sec_forged_frame_leaves_buffer_untouched(void) {
    TEST_BEGIN("v3: forged frame never writes caller buffer") {
        unsigned char msg[200];
        memset(msg, 'X', sizeof(msg));
        unsigned char frame[512];
        int flen = capture_frame(FARM9_ROLE_CLIENT, msg, (int)sizeof(msg), frame);
        ASSERT(flen > 0, "capture");
        frame[FRAME_OVERHEAD + 5] ^= 0x80; /* flip a ciphertext bit */

        char buf[256];
        memset(buf, 0xA5, sizeof(buf));
        int err = 0;
        int rn = deliver(FARM9_ROLE_SERVER, frame, flen, buf, sizeof(buf), &err);
        ASSERT_EQ(rn, -1, "forged frame must be rejected");
        ASSERT_EQ(err, EBADMSG, "errno should be EBADMSG");
        int touched = 0;
        for (size_t i = 0; i < sizeof(buf); i++)
            touched += ((unsigned char)buf[i] != 0xA5);
        ASSERT_EQ(touched, 0, "unauthenticated plaintext leaked into buffer");
    } TEST_END;
}

void test_sec_oversized_message_bounded(void) {
    TEST_BEGIN("v3: message larger than buffer is not copied") {
        unsigned char msg[128];
        memset(msg, 'Y', sizeof(msg));
        unsigned char frame[256];
        int flen = capture_frame(FARM9_ROLE_CLIENT, msg, (int)sizeof(msg), frame);
        ASSERT(flen > 0, "capture");

        /* 1-byte destination followed by a guard region */
        struct { char small[1]; unsigned char guard[255]; } dst;
        memset(&dst, 0xA5, sizeof(dst));
        int err = 0;
        int rn = deliver(FARM9_ROLE_SERVER, frame, flen, dst.small, 1, &err);
        ASSERT_EQ(rn, -1, "oversized message must be refused");
        ASSERT_EQ(err, EMSGSIZE, "errno should be EMSGSIZE");
        int touched = ((unsigned char)dst.small[0] != 0xA5);
        for (size_t i = 0; i < sizeof(dst.guard); i++)
            touched += (dst.guard[i] != 0xA5);
        ASSERT_EQ(touched, 0, "bytes written beyond/into undersized buffer");
    } TEST_END;
}

void test_sec_large_caller_buffer_accepted(void) {
    TEST_BEGIN("v3: caller buffer larger than FARM9_MAX_MSG ok") {
        const char *msg = "big buffers are fine";
        unsigned char frame[256];
        int flen = capture_frame(FARM9_ROLE_CLIENT, (const unsigned char *)msg,
                                 (int)strlen(msg), frame);
        ASSERT(flen > 0, "capture");
        char *buf = malloc(FARM9_MAX_MSG * 2);
        ASSERT(buf != NULL, "malloc");
        int err = 0;
        int rn = deliver(FARM9_ROLE_SERVER, frame, flen, buf, FARM9_MAX_MSG * 2, &err);
        int same = (rn == (int)strlen(msg)) && memcmp(buf, msg, strlen(msg)) == 0;
        free(buf);
        ASSERT(same, "read into large buffer failed");
    } TEST_END;
}

void test_sec_write_rejects_oversize(void) {
    TEST_BEGIN("v3: write rejects message > FARM9_MAX_MSG") {
        int fds[2];
        ASSERT(make_socketpair(fds) == 0, "socketpair");
        ASSERT(farm9crypt_init_password(SEC_PASS, strlen(SEC_PASS), FARM9_ROLE_CLIENT) == 0,
               "init");
        char *big = calloc(1, FARM9_MAX_MSG + 1);
        ASSERT(big != NULL, "calloc");
        errno = 0;
        int wn = farm9crypt_write(fds[0], big, FARM9_MAX_MSG + 1);
        int err = errno;
        free(big);
        farm9crypt_cleanup();
        close(fds[0]); close(fds[1]);
        ASSERT_EQ(wn, -1, "oversized write must fail");
        ASSERT_EQ(err, EINVAL, "errno should be EINVAL");
    } TEST_END;
}

void test_sec_ecdhe_directional_keys(void) {
    TEST_BEGIN("v3: ECDHE peers get mirrored directional keys") {
        int fds[2], pipefd[2];
        ASSERT(make_socketpair(fds) == 0, "socketpair");
        ASSERT(pipe(pipefd) == 0, "pipe");

        pid_t pid = fork();
        ASSERT(pid >= 0, "fork");
        if (pid == 0) {
            close(fds[1]); close(pipefd[0]);
            unsigned char out[32 * 2 + 8];
            if (farm9crypt_init_ecdhe(fds[0], SEC_PASS, strlen(SEC_PASS),
                                      FARM9_ROLE_SERVER) != 0 ||
                farm9crypt_export_udp_keys(out, out + 32) != 0 ||
                farm9crypt_get_fingerprint(out + 64, 8) != 8)
                _exit(1);
            int ok = write(pipefd[1], out, sizeof(out)) == (ssize_t)sizeof(out);
            farm9crypt_cleanup();
            _exit(ok ? 0 : 1);
        }
        close(fds[0]); close(pipefd[1]);

        unsigned char tx[32], rx[32], fp[8], peer[32 * 2 + 8];
        int rc = farm9crypt_init_ecdhe(fds[1], SEC_PASS, strlen(SEC_PASS),
                                       FARM9_ROLE_CLIENT);
        int ok_keys = rc == 0 &&
                      farm9crypt_export_udp_keys(tx, rx) == 0 &&
                      farm9crypt_get_fingerprint(fp, 8) == 8;
        farm9crypt_cleanup();
        int got = read_n(pipefd[0], peer, sizeof(peer));
        close(fds[1]); close(pipefd[0]);
        int status;
        waitpid(pid, &status, 0);

        ASSERT(ok_keys, "client handshake/export failed");
        ASSERT(got == 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0,
               "server handshake/export failed");
        ASSERT(memcmp(tx, rx, 32) != 0, "tx and rx keys must differ");
        ASSERT(memcmp(tx, peer + 32, 32) == 0, "client tx must equal server rx");
        ASSERT(memcmp(rx, peer, 32) == 0, "client rx must equal server tx");
        ASSERT(memcmp(fp, peer + 64, 8) == 0, "fingerprints must match on both ends");
    } TEST_END;
}

/* Run a handshake role in a child with a receive timeout so a protocol bug
 * shows up as a failure, not a hung test. */
static void set_timeouts(int fd) {
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static void quiet_stderr(int *saved) {
    *saved = dup(STDERR_FILENO);
    int devnull = open("/dev/null", O_WRONLY);
    dup2(devnull, STDERR_FILENO);
    close(devnull);
}

static void restore_stderr(int saved) {
    dup2(saved, STDERR_FILENO);
    close(saved);
}

void test_sec_wrong_password_detected(void) {
    TEST_BEGIN("v3: wrong password fails the handshake on both ends") {
        int fds[2];
        ASSERT(make_socketpair(fds) == 0, "socketpair");
        set_timeouts(fds[0]); set_timeouts(fds[1]);
        int saved; quiet_stderr(&saved);
        pid_t pid = fork();
        if (pid == 0) {
            close(fds[1]);
            int rc = farm9crypt_init_ecdhe(fds[0], "server-password-1", 17, FARM9_ROLE_SERVER);
            _exit(rc == -1 ? 0 : 1);
        }
        close(fds[0]);
        int rc = farm9crypt_init_ecdhe(fds[1], "client-password-2", 17, FARM9_ROLE_CLIENT);
        int inited = farm9crypt_initialized();
        int status;
        waitpid(pid, &status, 0);
        restore_stderr(saved);
        close(fds[1]);
        ASSERT_EQ(rc, -1, "client must reject the session");
        ASSERT_EQ(inited, 0, "no keys may remain installed after a failed confirmation");
        ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "server must reject the session");
    } TEST_END;
}

void test_sec_old_server_detected(void) {
    TEST_BEGIN("v3: protocol-1 server (no hello) rejected, no hang") {
        int fds[2];
        ASSERT(make_socketpair(fds) == 0, "socketpair");
        set_timeouts(fds[1]);
        pid_t pid = fork();
        if (pid == 0) {
            /* ClawSec <= 2.8.2 server: sends a raw 32-byte X25519 key first */
            close(fds[1]);
            unsigned char pub[32];
            memset(pub, 0x5A, sizeof(pub));
            (void)write(fds[0], pub, sizeof(pub));
            unsigned char buf[64];
            (void)read(fds[0], buf, sizeof(buf));
            _exit(0);
        }
        close(fds[0]);
        int saved; quiet_stderr(&saved);
        int rc = farm9crypt_init_ecdhe(fds[1], SEC_PASS, strlen(SEC_PASS), FARM9_ROLE_CLIENT);
        restore_stderr(saved);
        close(fds[1]);
        waitpid(pid, NULL, 0);
        ASSERT_EQ(rc, -1, "old server must be rejected");
    } TEST_END;
}

void test_sec_old_client_detected(void) {
    TEST_BEGIN("v3: protocol-1 client (no hello) rejected, no hang") {
        int fds[2];
        ASSERT(make_socketpair(fds) == 0, "socketpair");
        set_timeouts(fds[0]);
        pid_t pid = fork();
        if (pid == 0) {
            /* ClawSec <= 2.8.2 client: reads 32 bytes, then sends its key */
            close(fds[0]);
            unsigned char buf[32];
            size_t got = 0;
            while (got < sizeof(buf)) {
                ssize_t n = read(fds[1], buf + got, sizeof(buf) - got);
                if (n <= 0) _exit(1);
                got += (size_t)n;
            }
            unsigned char pub[32];
            memset(pub, 0xA5, sizeof(pub));
            (void)write(fds[1], pub, sizeof(pub));
            _exit(0);
        }
        close(fds[1]);
        int saved; quiet_stderr(&saved);
        int rc = farm9crypt_init_ecdhe(fds[0], SEC_PASS, strlen(SEC_PASS), FARM9_ROLE_SERVER);
        restore_stderr(saved);
        close(fds[0]);
        int status;
        waitpid(pid, &status, 0);
        ASSERT_EQ(rc, -1, "old client must be rejected");
        ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0,
               "server must send hello+key before reading (old client got 32 bytes)");
    } TEST_END;
}
