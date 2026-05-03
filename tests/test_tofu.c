/*
 * test_tofu.c — Trust On First Use tests
 */
#define _POSIX_C_SOURCE 200809L
#include "test.h"
#include "tofu.h"
#include "obfs.h"

#include <signal.h>
#include <stdio.h>
#include <sys/stat.h>

/* Helper: set HOME to a temp dir for isolated tests */
static char s_tmpdir[256];

static void tofu_test_setup(void) {
    snprintf(s_tmpdir, sizeof(s_tmpdir), "/tmp/clawsec_tofu_test_%d", getpid());
    mkdir(s_tmpdir, 0700);
    setenv("HOME", s_tmpdir, 1);
}

static void tofu_test_cleanup(void) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", s_tmpdir);
    system(cmd);
}

void test_tofu_server_init_generates_key(void) {
    TEST_BEGIN("TOFU server init generates Ed25519 key") {
        tofu_test_setup();

        ASSERT(tofu_server_init() == 0, "server init failed");

        const unsigned char *pub = tofu_server_get_pubkey();
        ASSERT(pub != NULL, "pubkey should not be NULL");

        /* Key should be non-zero */
        int nonzero = 0;
        for (int i = 0; i < TOFU_ED25519_PUBKEY_LEN; i++)
            if (pub[i]) nonzero++;
        ASSERT(nonzero > 0, "pubkey should not be all zeros");

        /* Identity file should exist */
        char path[512];
        snprintf(path, sizeof(path), "%s/.clawsec/identity", s_tmpdir);
        struct stat st;
        ASSERT(stat(path, &st) == 0, "identity file should exist");
        ASSERT((st.st_mode & 0777) == 0600, "identity file should be 0600");

        tofu_server_cleanup();
        tofu_test_cleanup();
    } TEST_END;
}

void test_tofu_server_persistent_key(void) {
    TEST_BEGIN("TOFU server key persists across restarts") {
        tofu_test_setup();

        ASSERT(tofu_server_init() == 0, "first init failed");
        const unsigned char *pub1 = tofu_server_get_pubkey();
        unsigned char saved_pub[32];
        memcpy(saved_pub, pub1, 32);
        tofu_server_cleanup();

        /* Re-init should load same key */
        ASSERT(tofu_server_init() == 0, "second init failed");
        const unsigned char *pub2 = tofu_server_get_pubkey();
        ASSERT(memcmp(saved_pub, pub2, 32) == 0, "key should persist");

        tofu_server_cleanup();
        tofu_test_cleanup();
    } TEST_END;
}

void test_tofu_sign_verify(void) {
    TEST_BEGIN("TOFU Ed25519 sign/verify roundtrip") {
        tofu_test_setup();
        ASSERT(tofu_server_init() == 0, "init failed");

        unsigned char data[32] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                                  17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
        unsigned char sig[TOFU_ED25519_SIGLEN];

        ASSERT(tofu_server_sign(data, 32, sig) == 0, "sign failed");

        const unsigned char *pub = tofu_server_get_pubkey();
        ASSERT(tofu_verify_signature(pub, data, 32, sig, TOFU_ED25519_SIGLEN) == 1,
               "valid signature should verify");

        /* Tamper with data — should fail */
        data[0] ^= 0xFF;
        ASSERT(tofu_verify_signature(pub, data, 32, sig, TOFU_ED25519_SIGLEN) == 0,
               "tampered data should fail");

        tofu_server_cleanup();
        tofu_test_cleanup();
    } TEST_END;
}

void test_tofu_known_hosts(void) {
    TEST_BEGIN("TOFU known_hosts new/match/mismatch") {
        tofu_test_setup();
        ASSERT(tofu_server_init() == 0, "init failed");

        const unsigned char *pub = tofu_server_get_pubkey();

        /* First contact: should return 0 (new host, saved) */
        int r = tofu_check_known_host("example.com", "443", pub);
        ASSERT_EQ(r, 0, "first contact should return 0 (new)");

        /* Second contact: should return 1 (known, match) */
        r = tofu_check_known_host("example.com", "443", pub);
        ASSERT_EQ(r, 1, "repeat contact should return 1 (match)");

        /* Different key for same host: should return -1 (mismatch) */
        unsigned char fake_pub[32];
        memcpy(fake_pub, pub, 32);
        fake_pub[0] ^= 0xFF;
        r = tofu_check_known_host("example.com", "443", fake_pub);
        ASSERT_EQ(r, -1, "changed key should return -1 (mismatch)");

        /* Different host with same key: should return 0 (new) */
        r = tofu_check_known_host("other.com", "8443", pub);
        ASSERT_EQ(r, 0, "different host should return 0 (new)");

        tofu_server_cleanup();
        tofu_test_cleanup();
    } TEST_END;
}

void test_tofu_ecdhe_roundtrip(void) {
    TEST_BEGIN("TOFU ECDHE handshake roundtrip") {
        tofu_test_setup();

        int fds[2];
        ASSERT(make_socketpair(fds) == 0, "socketpair failed");

        obfs_set_mode(OBFS_TLS);
        g_tofu = 1;
        signal(SIGPIPE, SIG_IGN);

        /* Server init */
        ASSERT(tofu_server_init() == 0, "tofu server init failed");

        pid_t pid = fork();
        ASSERT(pid >= 0, "fork failed");

        if (pid == 0) {
            /* Client */
            close(fds[0]);
            if (obfs_tls_connect(fds[1]) < 0) _exit(1);
            if (farm9crypt_init_ecdhe_tofu(fds[1], "testpass", 8,
                                           0, "127.0.0.1", "9999") != 0)
                _exit(2);
            char msg[] = "tofu-hello";
            if (farm9crypt_write(fds[1], msg, 10) < 0) _exit(3);
            _exit(0);
        }

        /* Server */
        close(fds[1]);
        ASSERT(obfs_tls_accept(fds[0]) == 0, "TLS accept failed");

        int rc = farm9crypt_init_ecdhe_tofu(fds[0], "testpass", 8,
                                            1, NULL, NULL);
        ASSERT_EQ(rc, 0, "ECDHE+TOFU handshake failed");

        char buf[64];
        int n = farm9crypt_read(fds[0], buf, sizeof(buf));
        ASSERT_EQ(n, 10, "recv wrong length");
        ASSERT(memcmp(buf, "tofu-hello", 10) == 0, "data mismatch");

        int status;
        waitpid(pid, &status, 0);
        ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "client failed");

        close(fds[0]);
        farm9crypt_cleanup();
        tofu_server_cleanup();
        obfs_set_mode(OBFS_NONE);
        g_tofu = 0;
        tofu_test_cleanup();
    } TEST_END;
}

void test_tofu_fingerprint_format(void) {
    TEST_BEGIN("TOFU fingerprint hex formatting") {
        unsigned char pub[32];
        for (int i = 0; i < 32; i++) pub[i] = (unsigned char)i;

        char fp[65];
        tofu_format_fingerprint(pub, fp, sizeof(fp));

        ASSERT_EQ((int)strlen(fp), 64, "fingerprint should be 64 hex chars");
        ASSERT(strncmp(fp, "0001020304", 10) == 0, "hex prefix wrong");
    } TEST_END;
}
