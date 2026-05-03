/*
 * test_fingerprint.c — TLS ClientHello fingerprint tests
 */
#define _POSIX_C_SOURCE 200809L
#include "test.h"
#include "fingerprint.h"
#include "obfs.h"

#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

void test_fp_flag(void) {
    TEST_BEGIN("fingerprint profile set/get") {
        ASSERT_EQ(fp_get_profile(), FP_NONE, "should be NONE by default");
        fp_set_profile(FP_CHROME);
        ASSERT_EQ(fp_get_profile(), FP_CHROME, "should be CHROME");
        fp_set_profile(FP_FIREFOX);
        ASSERT_EQ(fp_get_profile(), FP_FIREFOX, "should be FIREFOX");
        fp_set_profile(FP_SAFARI);
        ASSERT_EQ(fp_get_profile(), FP_SAFARI, "should be SAFARI");
        fp_set_profile(FP_NONE);
        ASSERT_EQ(fp_get_profile(), FP_NONE, "should be NONE after reset");
    } TEST_END;
}

void test_fp_chrome_tls_roundtrip(void) {
    TEST_BEGIN("Chrome fingerprint TLS handshake roundtrip") {
        int fds[2];
        ASSERT(make_socketpair(fds) == 0, "socketpair failed");

        obfs_set_mode(OBFS_TLS);
        fp_set_profile(FP_CHROME);
        signal(SIGPIPE, SIG_IGN);

        pid_t pid = fork();
        ASSERT(pid >= 0, "fork failed");

        if (pid == 0) {
            /* Client with Chrome fingerprint */
            close(fds[0]);
            if (obfs_tls_connect(fds[1]) < 0) _exit(1);
            if (obfs_send(fds[1], "chrome-hi", 9) < 0) _exit(2);
            char rbuf[64];
            if (obfs_recv(fds[1], rbuf, sizeof(rbuf)) <= 0) _exit(3);
            _exit(0);
        }

        close(fds[1]);
        ASSERT(obfs_tls_accept(fds[0]) == 0, "TLS accept failed");

        char buf[64];
        int n = obfs_recv(fds[0], buf, sizeof(buf));
        ASSERT_EQ(n, 9, "recv wrong length");
        ASSERT(memcmp(buf, "chrome-hi", 9) == 0, "data mismatch");
        ASSERT(obfs_send(fds[0], "ok", 2) == 2, "send back failed");

        int status;
        waitpid(pid, &status, 0);
        ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "client failed");

        close(fds[0]);
        fp_set_profile(FP_NONE);
        obfs_set_mode(OBFS_NONE);
    } TEST_END;
}

/* Verify ALPS extension (0x4469) is present in Chrome profile ClientHello */
static volatile int s_alps_ext_seen = 0;
static volatile size_t s_alps_ext_len = 0;

static int alps_server_parse_cb(SSL *s, unsigned int ext_type,
                                unsigned int context,
                                const unsigned char *in, size_t inlen,
                                X509 *x, size_t chainidx,
                                int *al, void *parse_arg) {
    (void)s; (void)ext_type; (void)context;
    (void)x; (void)chainidx; (void)al; (void)parse_arg;
    s_alps_ext_seen = 1;
    s_alps_ext_len = inlen;
    (void)in;
    return 1;
}

void test_fp_chrome_compress_cert(void) {
    TEST_BEGIN("Chrome sends ALPS extension 0x4469") {
        s_alps_ext_seen = 0;
        s_alps_ext_len = 0;

        int fds[2];
        ASSERT(make_socketpair(fds) == 0, "socketpair failed");

        obfs_set_mode(OBFS_TLS);
        fp_set_profile(FP_CHROME);
        signal(SIGPIPE, SIG_IGN);

        pid_t pid = fork();
        ASSERT(pid >= 0, "fork failed");

        if (pid == 0) {
            close(fds[0]);
            if (obfs_tls_connect(fds[1]) < 0) _exit(1);
            obfs_send(fds[1], "x", 1);
            _exit(0);
        }

        close(fds[1]);

        /* Manual server with parse callback for 0x4469 */
        SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
        ASSERT(ctx != NULL, "SSL_CTX_new failed");
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

        EVP_PKEY *pkey = EVP_EC_gen("P-256");
        ASSERT(pkey != NULL, "keygen failed");
        X509 *cert = X509_new();
        X509_set_pubkey(cert, pkey);
        X509_gmtime_adj(X509_getm_notBefore(cert), 0);
        X509_gmtime_adj(X509_getm_notAfter(cert), 86400);
        X509_NAME *name = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                    (unsigned char *)"test", -1, -1, 0);
        X509_set_issuer_name(cert, name);
        X509_sign(cert, pkey, EVP_sha256());
        SSL_CTX_use_certificate(ctx, cert);
        SSL_CTX_use_PrivateKey(ctx, pkey);

        /* Register parse callback for ALPS extension */
        SSL_CTX_add_custom_ext(ctx, 0x4469,
                               SSL_EXT_CLIENT_HELLO,
                               NULL, NULL, NULL,
                               alps_server_parse_cb, NULL);

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fds[0]);
        SSL_accept(ssl);

        ASSERT_EQ(s_alps_ext_seen, 1, "ALPS extension 0x4469 not seen");
        ASSERT_EQ((int)s_alps_ext_len, 5, "ALPS payload wrong size");

        int status;
        waitpid(pid, &status, 0);

        SSL_free(ssl);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        SSL_CTX_free(ctx);
        close(fds[0]);
        fp_set_profile(FP_NONE);
        obfs_set_mode(OBFS_NONE);
    } TEST_END;
}

void test_fp_auto_enables_tls(void) {
    TEST_BEGIN("fingerprint auto-enables TLS mode") {
        obfs_set_mode(OBFS_NONE);
        ASSERT_EQ(obfs_get_mode(), OBFS_NONE, "should start NONE");

        /* Simulate what clawsec.c does for --fingerprint */
        fp_set_profile(FP_CHROME);
        if (obfs_get_mode() == OBFS_NONE)
            obfs_set_mode(OBFS_TLS);

        ASSERT_EQ(obfs_get_mode(), OBFS_TLS, "should auto-enable TLS");

        fp_set_profile(FP_NONE);
        obfs_set_mode(OBFS_NONE);
    } TEST_END;
}
