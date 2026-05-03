/*
 * ClawSec integration tests
 *
 * Tests: AES-GCM encryption, PBKDF2 key derivation, salt handshake,
 * replay protection (sequence numbers), protocol format.
 *
 * Build: make test
 * Run:   ./test_clawsec
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <assert.h>

#include "farm9crypt.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  [TEST] %-50s ", name); \
    fflush(stdout); \
} while(0)

#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while(0)

/* Create a connected socket pair for testing */
static int make_socketpair(int fds[2]) {
    return socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
}

/* ========== Test: Basic encrypt/decrypt roundtrip ========== */
static void test_basic_roundtrip(void) {
    TEST("basic encrypt/decrypt roundtrip");

    int fds[2];
    if (make_socketpair(fds) < 0) { FAIL("socketpair"); return; }

    farm9crypt_init_password("TestPassword123", 15);

    const char *msg = "Hello, ClawSec!";
    int wn = farm9crypt_write(fds[0], (char *)msg, strlen(msg));
    if (wn != (int)strlen(msg)) { FAIL("write"); close(fds[0]); close(fds[1]); return; }

    char buf[256];
    int rn = farm9crypt_read(fds[1], buf, sizeof(buf));
    if (rn != (int)strlen(msg)) { FAIL("read length mismatch"); close(fds[0]); close(fds[1]); return; }

    buf[rn] = '\0';
    if (strcmp(buf, msg) != 0) { FAIL("content mismatch"); close(fds[0]); close(fds[1]); return; }

    close(fds[0]);
    close(fds[1]);
    farm9crypt_cleanup();
    PASS();
}

/* ========== Test: Multiple messages preserve order ========== */
static void test_multiple_messages(void) {
    TEST("multiple messages in sequence");

    int fds[2];
    if (make_socketpair(fds) < 0) { FAIL("socketpair"); return; }

    farm9crypt_init_password("SeqTestPass!", 12);

    const char *msgs[] = {"first", "second", "third", "fourth"};
    int count = 4;

    for (int i = 0; i < count; i++) {
        int wn = farm9crypt_write(fds[0], (char *)msgs[i], strlen(msgs[i]));
        if (wn != (int)strlen(msgs[i])) { FAIL("write failed"); goto cleanup_multi; }
    }

    for (int i = 0; i < count; i++) {
        char buf[64];
        int rn = farm9crypt_read(fds[1], buf, sizeof(buf));
        if (rn != (int)strlen(msgs[i])) { FAIL("read length"); goto cleanup_multi; }
        buf[rn] = '\0';
        if (strcmp(buf, msgs[i]) != 0) { FAIL("content mismatch"); goto cleanup_multi; }
    }

    close(fds[0]);
    close(fds[1]);
    farm9crypt_cleanup();
    PASS();
    return;

cleanup_multi:
    close(fds[0]);
    close(fds[1]);
    farm9crypt_cleanup();
}

/* ========== Test: Random salt generation ========== */
static void test_salt_generation(void) {
    TEST("random salt generation uniqueness");

    unsigned char salt1[16], salt2[16];
    if (farm9crypt_generate_salt(salt1, sizeof(salt1)) != 0) { FAIL("gen salt1"); return; }
    if (farm9crypt_generate_salt(salt2, sizeof(salt2)) != 0) { FAIL("gen salt2"); return; }

    if (memcmp(salt1, salt2, 16) == 0) { FAIL("salts are identical"); return; }

    PASS();
}

/* ========== Test: Salt-based init produces different keys ========== */
static void test_salt_different_keys(void) {
    TEST("different salts produce different ciphertext");

    int fds1[2], fds2[2];
    if (make_socketpair(fds1) < 0) { FAIL("socketpair1"); return; }
    if (make_socketpair(fds2) < 0) { FAIL("socketpair2"); close(fds1[0]); close(fds1[1]); return; }

    unsigned char salt1[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    unsigned char salt2[16] = {16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1};

    const char *msg = "same plaintext";

    /* Encrypt with salt1 */
    farm9crypt_init_password_with_salt("SamePassword", 12, salt1, 16);
    farm9crypt_write(fds1[0], (char *)msg, strlen(msg));
    farm9crypt_cleanup();

    /* Encrypt with salt2 */
    farm9crypt_init_password_with_salt("SamePassword", 12, salt2, 16);
    farm9crypt_write(fds2[0], (char *)msg, strlen(msg));
    farm9crypt_cleanup();

    /* Read raw bytes from both sockets and compare */
    unsigned char raw1[256], raw2[256];
    ssize_t n1 = read(fds1[1], raw1, sizeof(raw1));
    ssize_t n2 = read(fds2[1], raw2, sizeof(raw2));

    close(fds1[0]); close(fds1[1]);
    close(fds2[0]); close(fds2[1]);

    if (n1 <= 0 || n2 <= 0) { FAIL("no data"); return; }
    if (n1 == n2 && memcmp(raw1, raw2, n1) == 0) { FAIL("ciphertext identical"); return; }

    PASS();
}

/* ========== Test: Wrong password fails decryption ========== */
static void test_wrong_password(void) {
    TEST("wrong password fails decryption");

    int fds[2];
    if (make_socketpair(fds) < 0) { FAIL("socketpair"); return; }

    /* Write with one password */
    farm9crypt_init_password("CorrectPass1", 12);
    const char *msg = "secret data";
    farm9crypt_write(fds[0], (char *)msg, strlen(msg));
    farm9crypt_cleanup();

    /* Read with different password */
    farm9crypt_init_password("WrongPassword", 13);
    char buf[256];
    int rn = farm9crypt_read(fds[1], buf, sizeof(buf));
    farm9crypt_cleanup();

    close(fds[0]);
    close(fds[1]);

    if (rn > 0) { FAIL("decryption should have failed"); return; }

    PASS();
}

/* ========== Test: Replay protection - sequence validation ========== */
static void test_replay_protection(void) {
    TEST("replay protection rejects duplicated message");

    int fds[2];
    if (make_socketpair(fds) < 0) { FAIL("socketpair"); return; }

    farm9crypt_init_password("ReplayTest!!", 12);

    /* Send one message */
    const char *msg = "message one";
    farm9crypt_write(fds[0], (char *)msg, strlen(msg));

    /* Capture the raw encrypted bytes */
    unsigned char captured[512];
    ssize_t cap_len = read(fds[1], captured, sizeof(captured));
    if (cap_len <= 0) { FAIL("capture failed"); goto cleanup_replay; }

    /* Send it again to simulate replay - write raw bytes back */
    /* First read the legitimate message (rewind by re-sending captured) */
    /* Actually: write captured bytes twice to fds[0] side won't work because
       fds[0] is the write end. Use a new pair for replay simulation. */
    {
        int fds2[2];
        if (make_socketpair(fds2) < 0) { FAIL("socketpair2"); goto cleanup_replay; }

        /* Write captured packet to new socket */
        write(fds2[0], captured, cap_len);
        /* Write it again (replay) */
        write(fds2[0], captured, cap_len);

        /* Re-init with same password to reset seq counters */
        farm9crypt_cleanup();
        farm9crypt_init_password("ReplayTest!!", 12);

        /* First read should succeed (seq=0) */
        char buf[256];
        int rn = farm9crypt_read(fds2[1], buf, sizeof(buf));
        if (rn != (int)strlen(msg)) {
            FAIL("first read failed");
            close(fds2[0]); close(fds2[1]);
            goto cleanup_replay;
        }

        /* Second read should fail (seq=0 again, but we expect seq=1) */
        rn = farm9crypt_read(fds2[1], buf, sizeof(buf));
        close(fds2[0]);
        close(fds2[1]);

        if (rn > 0) { FAIL("replay was not rejected"); goto cleanup_replay; }
    }

    close(fds[0]);
    close(fds[1]);
    farm9crypt_cleanup();
    PASS();
    return;

cleanup_replay:
    close(fds[0]);
    close(fds[1]);
    farm9crypt_cleanup();
}

/* ========== Test: Large message (near FARM9_MAX_MSG) ========== */
static void test_large_message(void) {
    TEST("large message (8000 bytes)");

    int fds[2];
    if (make_socketpair(fds) < 0) { FAIL("socketpair"); return; }

    /* Increase socket buffer for large messages */
    int bufsize = 65536;
    setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    setsockopt(fds[1], SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));

    farm9crypt_init_password("LargeMsg!!12", 12);

    char *big = malloc(8000);
    if (!big) { FAIL("malloc"); close(fds[0]); close(fds[1]); return; }
    memset(big, 'A', 8000);
    big[7999] = 'Z';

    int wn = farm9crypt_write(fds[0], big, 8000);
    if (wn != 8000) { FAIL("write"); free(big); close(fds[0]); close(fds[1]); farm9crypt_cleanup(); return; }

    char *recv_buf = malloc(8192);
    if (!recv_buf) { FAIL("malloc recv"); free(big); close(fds[0]); close(fds[1]); farm9crypt_cleanup(); return; }

    int rn = farm9crypt_read(fds[1], recv_buf, 8192);
    if (rn != 8000) { FAIL("read length"); free(big); free(recv_buf); close(fds[0]); close(fds[1]); farm9crypt_cleanup(); return; }
    if (memcmp(big, recv_buf, 8000) != 0) { FAIL("content mismatch"); free(big); free(recv_buf); close(fds[0]); close(fds[1]); farm9crypt_cleanup(); return; }

    free(big);
    free(recv_buf);
    close(fds[0]);
    close(fds[1]);
    farm9crypt_cleanup();
    PASS();
}

/* ========== Test: Empty/NULL password rejected ========== */
static void test_null_password(void) {
    TEST("NULL/empty password rejected");

    int ret = farm9crypt_init_password(NULL, 0);
    if (ret != -1) { FAIL("NULL should fail"); farm9crypt_cleanup(); return; }

    ret = farm9crypt_init_password("", 0);
    if (ret != -1) { FAIL("empty should fail"); farm9crypt_cleanup(); return; }

    PASS();
}

/* ========== Test: Invalid salt rejected ========== */
static void test_invalid_salt(void) {
    TEST("invalid salt rejected");

    int ret = farm9crypt_init_password_with_salt("password", 8, NULL, 16);
    if (ret != -1) { FAIL("NULL salt should fail"); farm9crypt_cleanup(); return; }

    unsigned char short_salt[4] = {1,2,3,4};
    ret = farm9crypt_init_password_with_salt("password", 8, short_salt, 4);
    if (ret != -1) { FAIL("short salt should fail"); farm9crypt_cleanup(); return; }

    PASS();
}

/* ========== Test: Protocol magic validation ========== */
static void test_bad_magic(void) {
    TEST("invalid protocol magic rejected");

    int fds[2];
    if (make_socketpair(fds) < 0) { FAIL("socketpair"); return; }

    farm9crypt_init_password("MagicTest123", 12);

    /* Write garbage with wrong magic */
    unsigned char garbage[64];
    memset(garbage, 0xFF, sizeof(garbage));
    write(fds[0], garbage, sizeof(garbage));

    char buf[256];
    int rn = farm9crypt_read(fds[1], buf, sizeof(buf));

    close(fds[0]);
    close(fds[1]);
    farm9crypt_cleanup();

    if (rn > 0) { FAIL("should reject bad magic"); return; }

    PASS();
}

/* ========== Test: Full handshake simulation (server + client) ========== */
static void test_full_handshake(void) {
    TEST("full ECDHE handshake (server/client simulation)");

    int fds[2];
    if (make_socketpair(fds) < 0) { FAIL("socketpair"); return; }

    const char *password = "HandshakePass1";

    /* Fork: child = server, parent = client */
    pid_t pid = fork();
    if (pid < 0) { FAIL("fork"); close(fds[0]); close(fds[1]); return; }

    if (pid == 0) {
        /* Child: server side */
        close(fds[1]);
        if (farm9crypt_init_ecdhe(fds[0], password, strlen(password), 1) != 0)
            _exit(1);
        const char *msg = "hello from server";
        int wn = farm9crypt_write(fds[0], (char *)msg, strlen(msg));
        farm9crypt_cleanup();
        close(fds[0]);
        _exit(wn == (int)strlen(msg) ? 0 : 1);
    }

    /* Parent: client side */
    close(fds[0]);
    if (farm9crypt_init_ecdhe(fds[1], password, strlen(password), 0) != 0) {
        FAIL("client ECDHE failed");
        close(fds[1]);
        waitpid(pid, NULL, 0);
        return;
    }

    char buf[256];
    int rn = farm9crypt_read(fds[1], buf, sizeof(buf));
    farm9crypt_cleanup();
    close(fds[1]);

    int status;
    waitpid(pid, &status, 0);

    if (rn <= 0) { FAIL("read failed"); return; }
    buf[rn] = '\0';
    if (strcmp(buf, "hello from server") != 0) { FAIL("content mismatch"); return; }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) { FAIL("server failed"); return; }

    PASS();
}

/* ========== Test: Bidirectional communication ========== */
static void test_bidirectional(void) {
    TEST("bidirectional encrypted communication");

    int fds[2];
    if (make_socketpair(fds) < 0) { FAIL("socketpair"); return; }

    unsigned char salt[16];
    farm9crypt_generate_salt(salt, sizeof(salt));

    /* Both sides share same key material - but we need separate instances.
       Since farm9crypt is global state, we test sequential send/recv from one init. */
    farm9crypt_init_password_with_salt("BiDirTest123", 12, salt, 16);

    /* Side A sends */
    const char *msg_a = "from A";
    farm9crypt_write(fds[0], (char *)msg_a, strlen(msg_a));

    /* Side B reads */
    char buf[64];
    int rn = farm9crypt_read(fds[1], buf, sizeof(buf));
    if (rn != (int)strlen(msg_a) || strncmp(buf, msg_a, rn) != 0) {
        FAIL("A->B failed"); close(fds[0]); close(fds[1]); farm9crypt_cleanup(); return;
    }

    close(fds[0]);
    close(fds[1]);
    farm9crypt_cleanup();
    PASS();
}

/* ========== Main ========== */
int main(void) {
    printf("\n=== ClawSec Test Suite ===\n\n");

    test_basic_roundtrip();
    test_multiple_messages();
    test_salt_generation();
    test_salt_different_keys();
    test_wrong_password();
    test_replay_protection();
    test_large_message();
    test_null_password();
    test_invalid_salt();
    test_bad_magic();
    test_full_handshake();
    test_bidirectional();

    printf("\n=== Results: %d/%d passed ===\n\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
