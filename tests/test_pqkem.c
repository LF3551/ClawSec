/*
 * test_pqkem.c — Post-Quantum Hybrid KEM tests
 */
#define _POSIX_C_SOURCE 200809L
#include "test.h"
#include "pqkem.h"
#include "tofu.h"
#include "obfs.h"

#include <signal.h>
#include <stdio.h>
#include <sys/stat.h>

/* Helper: set HOME to a temp dir for isolated tests */
static char s_pq_tmpdir[256];

static void pq_test_setup(void) {
    snprintf(s_pq_tmpdir, sizeof(s_pq_tmpdir), "/tmp/clawsec_pq_test_%d", getpid());
    mkdir(s_pq_tmpdir, 0700);
    setenv("HOME", s_pq_tmpdir, 1);
}

static void pq_test_cleanup(void) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", s_pq_tmpdir);
    system(cmd);
}

/* Test 1: ML-KEM-768 availability check */
void test_pq_available(void) {
    TEST_BEGIN("ML-KEM-768 is available") {
        ASSERT(pq_available() == 1, "ML-KEM-768 not available in OpenSSL");
    } TEST_END;
}

/* Test 2: Keygen produces valid public key */
void test_pq_keygen(void) {
    TEST_BEGIN("ML-KEM-768 keygen produces 1184-byte pubkey") {
        unsigned char pubkey[PQ_KEM_PUBKEY_LEN];
        memset(pubkey, 0, sizeof(pubkey));

        void *handle = pq_keygen(pubkey);
        ASSERT(handle != NULL, "keygen returned NULL");

        /* Verify pubkey is non-zero */
        int nonzero = 0;
        for (int i = 0; i < PQ_KEM_PUBKEY_LEN; i++)
            if (pubkey[i] != 0) { nonzero = 1; break; }
        ASSERT(nonzero, "pubkey is all zeros");

        pq_free_key(handle);
    } TEST_END;
}

/* Test 3: Encapsulate/Decapsulate roundtrip */
void test_pq_encap_decap(void) {
    TEST_BEGIN("ML-KEM-768 encapsulate/decapsulate roundtrip") {
        unsigned char pubkey[PQ_KEM_PUBKEY_LEN];
        void *handle = pq_keygen(pubkey);
        ASSERT(handle != NULL, "keygen failed");

        unsigned char ct[PQ_KEM_CT_LEN];
        unsigned char ss_sender[PQ_KEM_SS_LEN];
        unsigned char ss_recv[PQ_KEM_SS_LEN];

        ASSERT(pq_encapsulate(pubkey, ct, ss_sender) == 0, "encapsulate failed");
        ASSERT(pq_decapsulate(handle, ct, ss_recv) == 0, "decapsulate failed");

        ASSERT(memcmp(ss_sender, ss_recv, PQ_KEM_SS_LEN) == 0,
               "shared secrets don't match");

        pq_free_key(handle);
    } TEST_END;
}

/* Test 4: Different encapsulations produce different shared secrets */
void test_pq_different_secrets(void) {
    TEST_BEGIN("ML-KEM-768 different encapsulations differ") {
        unsigned char pubkey[PQ_KEM_PUBKEY_LEN];
        void *handle = pq_keygen(pubkey);
        ASSERT(handle != NULL, "keygen failed");

        unsigned char ct1[PQ_KEM_CT_LEN], ct2[PQ_KEM_CT_LEN];
        unsigned char ss1[PQ_KEM_SS_LEN], ss2[PQ_KEM_SS_LEN];

        ASSERT(pq_encapsulate(pubkey, ct1, ss1) == 0, "encap 1 failed");
        ASSERT(pq_encapsulate(pubkey, ct2, ss2) == 0, "encap 2 failed");

        /* Different ciphertexts → different shared secrets */
        ASSERT(memcmp(ct1, ct2, PQ_KEM_CT_LEN) != 0, "ciphertexts should differ");
        ASSERT(memcmp(ss1, ss2, PQ_KEM_SS_LEN) != 0, "shared secrets should differ");

        pq_free_key(handle);
    } TEST_END;
}

/* Test 5: Tampered ciphertext produces different secret (implicit reject) */
void test_pq_tampered_ct(void) {
    TEST_BEGIN("ML-KEM-768 tampered ciphertext produces wrong secret") {
        unsigned char pubkey[PQ_KEM_PUBKEY_LEN];
        void *handle = pq_keygen(pubkey);
        ASSERT(handle != NULL, "keygen failed");

        unsigned char ct[PQ_KEM_CT_LEN];
        unsigned char ss_good[PQ_KEM_SS_LEN];
        unsigned char ss_bad[PQ_KEM_SS_LEN];

        ASSERT(pq_encapsulate(pubkey, ct, ss_good) == 0, "encap failed");

        /* Tamper with ciphertext */
        ct[0] ^= 0xFF;
        ct[100] ^= 0xFF;

        /* ML-KEM uses implicit rejection: decapsulate succeeds but gives wrong secret */
        int rc = pq_decapsulate(handle, ct, ss_bad);
        ASSERT(rc == 0, "decapsulate should succeed (implicit reject)");
        ASSERT(memcmp(ss_good, ss_bad, PQ_KEM_SS_LEN) != 0,
               "tampered ct should produce different secret");

        pq_free_key(handle);
    } TEST_END;
}

/* Test 6: Full hybrid ECDHE+PQ handshake over socketpair */
void test_pq_ecdhe_roundtrip(void) {
    TEST_BEGIN("Post-quantum hybrid ECDHE roundtrip") {
        pq_test_setup();

        int fds[2];
        ASSERT(make_socketpair(fds) == 0, "socketpair failed");

        obfs_set_mode(OBFS_TLS);
        g_pq = 1;
        g_tofu = 0;
        signal(SIGPIPE, SIG_IGN);

        pid_t pid = fork();
        ASSERT(pid >= 0, "fork failed");

        if (pid == 0) {
            /* Client */
            close(fds[0]);
            if (obfs_tls_connect(fds[1]) < 0) _exit(1);
            if (farm9crypt_init_ecdhe_pq(fds[1], "pqpass", 6,
                                          0, "127.0.0.1", "7777") != 0)
                _exit(2);
            char msg[] = "pq-hello!!";
            if (farm9crypt_write(fds[1], msg, 10) < 0) _exit(3);
            _exit(0);
        }

        /* Server */
        close(fds[1]);
        ASSERT(obfs_tls_accept(fds[0]) == 0, "TLS accept failed");

        int rc = farm9crypt_init_ecdhe_pq(fds[0], "pqpass", 6,
                                           1, NULL, NULL);
        ASSERT_EQ(rc, 0, "PQ hybrid handshake failed");

        char buf[64];
        int n = farm9crypt_read(fds[0], buf, sizeof(buf));
        ASSERT_EQ(n, 10, "recv wrong length");
        ASSERT(memcmp(buf, "pq-hello!!", 10) == 0, "data mismatch");

        int status;
        waitpid(pid, &status, 0);
        ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "client failed");

        close(fds[0]);
        farm9crypt_cleanup();
        obfs_set_mode(OBFS_NONE);
        g_pq = 0;
        pq_test_cleanup();
    } TEST_END;
}

/* Test 7: Full hybrid ECDHE+PQ+TOFU handshake */
void test_pq_tofu_ecdhe_roundtrip(void) {
    TEST_BEGIN("Post-quantum hybrid + TOFU ECDHE roundtrip") {
        pq_test_setup();

        int fds[2];
        ASSERT(make_socketpair(fds) == 0, "socketpair failed");

        obfs_set_mode(OBFS_TLS);
        g_pq = 1;
        g_tofu = 1;
        signal(SIGPIPE, SIG_IGN);

        ASSERT(tofu_server_init() == 0, "tofu server init failed");

        pid_t pid = fork();
        ASSERT(pid >= 0, "fork failed");

        if (pid == 0) {
            /* Client */
            close(fds[0]);
            if (obfs_tls_connect(fds[1]) < 0) _exit(1);
            if (farm9crypt_init_ecdhe_pq(fds[1], "pqtofu", 6,
                                          0, "127.0.0.1", "7778") != 0)
                _exit(2);
            char msg[] = "pqtofu-msg";
            if (farm9crypt_write(fds[1], msg, 10) < 0) _exit(3);
            _exit(0);
        }

        /* Server */
        close(fds[1]);
        ASSERT(obfs_tls_accept(fds[0]) == 0, "TLS accept failed");

        int rc = farm9crypt_init_ecdhe_pq(fds[0], "pqtofu", 6,
                                           1, NULL, NULL);
        ASSERT_EQ(rc, 0, "PQ+TOFU hybrid handshake failed");

        char buf[64];
        int n = farm9crypt_read(fds[0], buf, sizeof(buf));
        ASSERT_EQ(n, 10, "recv wrong length");
        ASSERT(memcmp(buf, "pqtofu-msg", 10) == 0, "data mismatch");

        int status;
        waitpid(pid, &status, 0);
        ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "client failed");

        close(fds[0]);
        farm9crypt_cleanup();
        tofu_server_cleanup();
        obfs_set_mode(OBFS_NONE);
        g_pq = 0;
        g_tofu = 0;
        pq_test_cleanup();
    } TEST_END;
}
