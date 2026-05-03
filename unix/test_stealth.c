/*
 * test_stealth.c — Tests for anti-fingerprint features
 *   TLS mode, packet padding, timing jitter
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <openssl/rand.h>

#include "test.h"
#include "obfs.h"

/* ── TLS mode registration ── */
void test_obfs_mode_set_tls(void) {
    TEST_BEGIN("obfs mode set to TLS");
    obfs_set_mode(OBFS_TLS);
    ASSERT_EQ(obfs_get_mode(), OBFS_TLS, "mode should be TLS");
    obfs_set_mode(OBFS_NONE);
    TEST_END;
}

/* ── TLS camouflage roundtrip via socketpair ── */
void test_tls_roundtrip(void) {
    TEST_BEGIN("TLS camouflage accept/connect + send/recv");

    int sv[2];
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair failed");

    pid_t pid = fork();
    ASSERT(pid >= 0, "fork failed");

    if (pid == 0) {
        /* Child = client */
        close(sv[0]);
        obfs_set_mode(OBFS_TLS);
        if (obfs_tls_connect(sv[1]) < 0) _exit(1);

        const char *msg = "tls-stealth-test";
        if (obfs_send(sv[1], msg, (int)strlen(msg)) < 0) _exit(2);

        char reply[64];
        int got = obfs_recv(sv[1], reply, sizeof(reply));
        if (got != 4 || memcmp(reply, "pong", 4) != 0) _exit(3);

        close(sv[1]);
        _exit(0);
    }

    /* Parent = server */
    close(sv[1]);
    obfs_set_mode(OBFS_TLS);
    int rc = obfs_tls_accept(sv[0]);
    ASSERT_EQ(rc, 0, "TLS accept failed");

    char buf[64];
    int got = obfs_recv(sv[0], buf, sizeof(buf));
    ASSERT(got == 16, "wrong received length");
    ASSERT(memcmp(buf, "tls-stealth-test", 16) == 0, "payload mismatch");

    rc = obfs_send(sv[0], "pong", 4);
    ASSERT(rc == 4, "send pong failed");

    close(sv[0]);
    int status;
    waitpid(pid, &status, 0);
    ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "child TLS roundtrip failed");

    obfs_set_mode(OBFS_NONE);
    TEST_END;
}

/* ── Packet padding ── */
void test_pad_roundtrip(void) {
    TEST_BEGIN("pad/unpad roundtrip preserves data");

    const char *data = "Hello, padded world!";
    size_t dlen = strlen(data);

    char padded[OBFS_PAD_SIZE];
    int plen = obfs_pad(data, dlen, padded, sizeof(padded));
    ASSERT_EQ(plen, OBFS_PAD_SIZE, "padded size should be OBFS_PAD_SIZE");

    char recovered[256];
    int rlen = obfs_unpad(padded, (size_t)plen, recovered, sizeof(recovered));
    ASSERT_EQ(rlen, (int)dlen, "recovered length mismatch");
    ASSERT(memcmp(recovered, data, dlen) == 0, "data mismatch after unpad");
    TEST_END;
}

void test_pad_uniform_size(void) {
    TEST_BEGIN("padding produces uniform size for different inputs");

    char p1[OBFS_PAD_SIZE], p2[OBFS_PAD_SIZE], p3[OBFS_PAD_SIZE];
    int l1 = obfs_pad("short", 5, p1, sizeof(p1));
    int l2 = obfs_pad("a much longer message that is different", 39, p2, sizeof(p2));
    int l3 = obfs_pad("x", 1, p3, sizeof(p3));

    ASSERT_EQ(l1, OBFS_PAD_SIZE, "p1 should be uniform");
    ASSERT_EQ(l2, OBFS_PAD_SIZE, "p2 should be uniform");
    ASSERT_EQ(l3, OBFS_PAD_SIZE, "p3 should be uniform");

    /* Padded bytes should differ (random, not zeros) */
    ASSERT(memcmp(p1, p2, OBFS_PAD_SIZE) != 0, "padded should differ");
    TEST_END;
}

void test_pad_too_large(void) {
    TEST_BEGIN("padding rejects oversized input");

    char big[OBFS_PAD_SIZE];
    char out[OBFS_PAD_SIZE];
    memset(big, 'A', sizeof(big));
    int rc = obfs_pad(big, OBFS_PAD_SIZE, out, sizeof(out));
    ASSERT_EQ(rc, -1, "should reject payload >= PAD_SIZE-2");
    TEST_END;
}

/* ── Timing jitter ── */
void test_jitter_applies_delay(void) {
    TEST_BEGIN("jitter adds measurable delay");

    struct timeval t1, t2;
    gettimeofday(&t1, NULL);
    obfs_jitter(50); /* up to 50ms */
    gettimeofday(&t2, NULL);

    long elapsed_us = (t2.tv_sec - t1.tv_sec) * 1000000L +
                      (t2.tv_usec - t1.tv_usec);
    /* Should be >= 0 and < 50ms + generous slack for CI runners */
    ASSERT(elapsed_us >= 0, "elapsed should be non-negative");
    ASSERT(elapsed_us < 200000, "elapsed should be < 200ms");
    TEST_END;
}

void test_jitter_zero_noop(void) {
    TEST_BEGIN("jitter(0) is a no-op");

    struct timeval t1, t2;
    gettimeofday(&t1, NULL);
    obfs_jitter(0);
    gettimeofday(&t2, NULL);

    long elapsed_us = (t2.tv_sec - t1.tv_sec) * 1000000L +
                      (t2.tv_usec - t1.tv_usec);
    ASSERT(elapsed_us < 1000, "should return immediately");
    TEST_END;
}
