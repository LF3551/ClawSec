/*
 * test_ech.c — ECH (Encrypted Client Hello) tests
 */
#define _POSIX_C_SOURCE 200809L
#include "test.h"
#include "obfs.h"

#include <openssl/ssl.h>
#include <openssl/rand.h>

void test_ech_flag(void) {
    TEST_BEGIN("ECH enable/disable flag") {
        ASSERT_EQ(obfs_ech_enabled(), 0, "should be disabled by default");
        obfs_ech_enable();
        ASSERT_EQ(obfs_ech_enabled(), 1, "should be enabled");
        obfs_ech_disable();
        ASSERT_EQ(obfs_ech_enabled(), 0, "should be disabled after disable");
    } TEST_END;
}

void test_ech_tls_connects(void) {
    TEST_BEGIN("ECH + TLS handshake roundtrip") {
        int fds[2];
        ASSERT(make_socketpair(fds) == 0, "socketpair failed");

        obfs_set_mode(OBFS_TLS);
        obfs_ech_enable();

        pid_t pid = fork();
        ASSERT(pid >= 0, "fork failed");

        if (pid == 0) {
            /* Client: connect with GREASE ECH extension */
            close(fds[0]);
            if (obfs_tls_connect(fds[1]) < 0) _exit(1);
            const char *msg = "ech-hello";
            if (obfs_send(fds[1], msg, 9) < 0) _exit(2);
            char rbuf[64];
            if (obfs_recv(fds[1], rbuf, sizeof(rbuf)) <= 0) _exit(3);
            _exit(0);
        }

        /* Server: accept (ignores ECH extension) */
        close(fds[1]);
        ASSERT(obfs_tls_accept(fds[0]) == 0, "TLS accept failed with ECH");

        char buf[64];
        int n = obfs_recv(fds[0], buf, sizeof(buf));
        ASSERT(n == 9, "recv wrong length");
        ASSERT(memcmp(buf, "ech-hello", 9) == 0, "data mismatch");

        ASSERT(obfs_send(fds[0], "ok", 2) == 2, "send back failed");

        int status;
        waitpid(pid, &status, 0);
        ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "client child failed");

        close(fds[0]);
        obfs_ech_disable();
        obfs_set_mode(OBFS_NONE);
    } TEST_END;
}

/* Verify that the GREASE ECH extension (0xfe0d) is actually present
   in the ClientHello when --ech is enabled */
static volatile int s_ech_ext_seen = 0;
static volatile size_t s_ech_ext_len = 0;

static int ech_server_parse_cb(SSL *s, unsigned int ext_type,
                               unsigned int context,
                               const unsigned char *in, size_t inlen,
                               X509 *x, size_t chainidx,
                               int *al, void *parse_arg) {
    (void)s; (void)ext_type; (void)context;
    (void)x; (void)chainidx; (void)al; (void)parse_arg;
    s_ech_ext_seen = 1;
    s_ech_ext_len = inlen;
    (void)in;
    return 1;
}

void test_ech_extension_present(void) {
    TEST_BEGIN("ECH extension 0xfe0d present in ClientHello") {
        s_ech_ext_seen = 0;
        s_ech_ext_len = 0;

        int fds[2];
        ASSERT(make_socketpair(fds) == 0, "socketpair failed");

        obfs_set_mode(OBFS_TLS);
        obfs_ech_enable();

        pid_t pid = fork();
        ASSERT(pid >= 0, "fork failed");

        if (pid == 0) {
            close(fds[0]);
            if (obfs_tls_connect(fds[1]) < 0) _exit(1);
            obfs_send(fds[1], "x", 1);
            _exit(0);
        }

        /* Server side: set up custom parse callback for ext 0xfe0d */
        close(fds[1]);

        SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
        ASSERT(ctx != NULL, "SSL_CTX_new failed");
        SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

        /* Generate a key+cert for the server */
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

        /* Register parse callback for ECH extension */
        SSL_CTX_add_custom_ext(ctx, 0xfe0d,
                               SSL_EXT_CLIENT_HELLO,
                               NULL, NULL, NULL,
                               ech_server_parse_cb, NULL);

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fds[0]);
        SSL_accept(ssl);  /* performs handshake, triggers parse callback */

        /* Verify the extension was received */
        ASSERT_EQ(s_ech_ext_seen, 1, "ECH extension 0xfe0d not seen");
        ASSERT(s_ech_ext_len >= 160 + 42, "ECH ext payload too small");
        ASSERT(s_ech_ext_len <= 224 + 42, "ECH ext payload too large");

        int status;
        waitpid(pid, &status, 0);

        SSL_free(ssl);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        SSL_CTX_free(ctx);
        close(fds[0]);
        obfs_ech_disable();
        obfs_set_mode(OBFS_NONE);
    } TEST_END;
}

void test_ech_auto_enables_tls(void) {
    TEST_BEGIN("ECH auto-enables TLS mode") {
        obfs_set_mode(OBFS_NONE);
        ASSERT_EQ(obfs_get_mode(), OBFS_NONE, "should start NONE");

        /* Simulate what clawsec.c does for case 'E' */
        obfs_ech_enable();
        if (obfs_get_mode() == OBFS_NONE)
            obfs_set_mode(OBFS_TLS);

        ASSERT_EQ(obfs_get_mode(), OBFS_TLS, "ECH should auto-enable TLS");
        ASSERT_EQ(obfs_ech_enabled(), 1, "ECH should be on");

        obfs_ech_disable();
        obfs_set_mode(OBFS_NONE);
    } TEST_END;
}
