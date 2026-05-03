/*
 * test_obfs.c — Tests for obfuscation layer and new features
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdlib.h>
#include <zlib.h>
#include <openssl/evp.h>

#include "test.h"
#include "obfs.h"

/* ---- obfs mode tests ---- */

void test_obfs_mode_default(void) {
    TEST_BEGIN("obfs mode defaults to NONE");
    obfs_set_mode(OBFS_NONE);
    ASSERT_EQ(obfs_get_mode(), OBFS_NONE, "mode should be NONE");
    TEST_END;
}

void test_obfs_mode_set_http(void) {
    TEST_BEGIN("obfs mode set to HTTP");
    obfs_set_mode(OBFS_HTTP);
    ASSERT_EQ(obfs_get_mode(), OBFS_HTTP, "mode should be HTTP");
    obfs_set_mode(OBFS_NONE);
    TEST_END;
}

/* ---- HTTP obfs send/recv roundtrip ---- */

void test_obfs_http_roundtrip(void) {
    TEST_BEGIN("obfs HTTP send/recv roundtrip via socketpair");

    int sv[2];
    int rc = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    ASSERT(rc == 0, "socketpair failed");

    obfs_set_mode(OBFS_HTTP);

    const char *payload = "Hello, obfuscated world!";
    int plen = (int)strlen(payload);

    pid_t pid = fork();
    ASSERT(pid >= 0, "fork failed");

    if (pid == 0) {
        close(sv[0]);
        int r = obfs_send(sv[1], payload, plen);
        close(sv[1]);
        _exit(r < 0 ? 1 : 0);
    }

    close(sv[1]);
    char buf[256];
    memset(buf, 0, sizeof(buf));
    int got = obfs_recv(sv[0], buf, sizeof(buf));
    close(sv[0]);

    int status;
    waitpid(pid, &status, 0);
    ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "child send failed");
    ASSERT(got == plen, "wrong received length");
    ASSERT(memcmp(buf, payload, plen) == 0, "payload mismatch");

    obfs_set_mode(OBFS_NONE);
    TEST_END;
}

void test_obfs_http_multiple_messages(void) {
    TEST_BEGIN("obfs HTTP multiple messages in sequence");

    int sv[2];
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair failed");
    obfs_set_mode(OBFS_HTTP);

    pid_t pid = fork();
    ASSERT(pid >= 0, "fork failed");

    if (pid == 0) {
        close(sv[0]);
        const char *msgs[] = {"msg1", "second message", "third"};
        for (int i = 0; i < 3; i++) {
            if (obfs_send(sv[1], msgs[i], (int)strlen(msgs[i])) < 0)
                _exit(1);
        }
        close(sv[1]);
        _exit(0);
    }

    close(sv[1]);
    char buf[256];
    const char *expected[] = {"msg1", "second message", "third"};

    for (int i = 0; i < 3; i++) {
        memset(buf, 0, sizeof(buf));
        int got = obfs_recv(sv[0], buf, sizeof(buf));
        ASSERT(got == (int)strlen(expected[i]), "wrong length for message");
        ASSERT(memcmp(buf, expected[i], got) == 0, "content mismatch");
    }
    close(sv[0]);

    int status;
    waitpid(pid, &status, 0);
    ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "child failed");

    obfs_set_mode(OBFS_NONE);
    TEST_END;
}

void test_obfs_http_large_payload(void) {
    TEST_BEGIN("obfs HTTP large payload (4096 bytes)");

    int sv[2];
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair failed");
    obfs_set_mode(OBFS_HTTP);

    char payload[4096];
    for (int i = 0; i < 4096; i++)
        payload[i] = (char)(i & 0xFF);

    pid_t pid = fork();
    ASSERT(pid >= 0, "fork failed");

    if (pid == 0) {
        close(sv[0]);
        int r = obfs_send(sv[1], payload, 4096);
        close(sv[1]);
        _exit(r < 0 ? 1 : 0);
    }

    close(sv[1]);
    char buf[8192];
    int got = obfs_recv(sv[0], buf, sizeof(buf));
    close(sv[0]);

    int status;
    waitpid(pid, &status, 0);
    ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "child failed");
    ASSERT(got == 4096, "wrong length");
    ASSERT(memcmp(buf, payload, 4096) == 0, "payload mismatch");

    obfs_set_mode(OBFS_NONE);
    TEST_END;
}

/* ---- parse_host_port tests ---- */

static int test_parse_host_port(const char *spec, char *host, size_t hlen,
                                char *port, size_t plen) {
    if (!spec) return -1;
    if (spec[0] == '[') {
        const char *bracket = strchr(spec, ']');
        if (!bracket) return -1;
        size_t hl = bracket - spec - 1;
        if (hl >= hlen) return -1;
        memcpy(host, spec + 1, hl);
        host[hl] = '\0';
        if (bracket[1] != ':') return -1;
        snprintf(port, plen, "%s", bracket + 2);
        return 0;
    }
    const char *colon = strrchr(spec, ':');
    if (!colon || colon == spec) return -1;
    size_t hl = colon - spec;
    if (hl >= hlen) return -1;
    memcpy(host, spec, hl);
    host[hl] = '\0';
    snprintf(port, plen, "%s", colon + 1);
    return 0;
}

void test_parse_forward_spec_ipv4(void) {
    TEST_BEGIN("parse host:port (IPv4)");
    char host[256], port[32];
    ASSERT(test_parse_host_port("192.168.1.1:8080", host, sizeof(host),
                                port, sizeof(port)) == 0, "parse failed");
    ASSERT_STR_EQ(host, "192.168.1.1", "host mismatch");
    ASSERT_STR_EQ(port, "8080", "port mismatch");
    TEST_END;
}

void test_parse_forward_spec_ipv6(void) {
    TEST_BEGIN("parse [IPv6]:port");
    char host[256], port[32];
    ASSERT(test_parse_host_port("[::1]:443", host, sizeof(host),
                                port, sizeof(port)) == 0, "parse failed");
    ASSERT_STR_EQ(host, "::1", "host mismatch");
    ASSERT_STR_EQ(port, "443", "port mismatch");
    TEST_END;
}

void test_parse_forward_spec_hostname(void) {
    TEST_BEGIN("parse hostname:port");
    char host[256], port[32];
    ASSERT(test_parse_host_port("example.com:22", host, sizeof(host),
                                port, sizeof(port)) == 0, "parse failed");
    ASSERT_STR_EQ(host, "example.com", "host mismatch");
    ASSERT_STR_EQ(port, "22", "port mismatch");
    TEST_END;
}

void test_parse_forward_spec_invalid(void) {
    TEST_BEGIN("parse invalid specs rejected");
    char host[256], port[32];
    ASSERT(test_parse_host_port(NULL, host, sizeof(host), port, sizeof(port)) == -1, "NULL not rejected");
    ASSERT(test_parse_host_port(":80", host, sizeof(host), port, sizeof(port)) == -1, ":80 not rejected");
    ASSERT(test_parse_host_port("[bad", host, sizeof(host), port, sizeof(port)) == -1, "[bad not rejected");
    TEST_END;
}

/* ---- zlib compress/decompress tests ---- */

void test_zlib_roundtrip(void) {
    TEST_BEGIN("zlib compress/decompress roundtrip");
    const char *data = "Hello, this is a test string for compression! "
                       "It should compress well because it has repetition. "
                       "Hello, this is a test string for compression!";
    size_t data_len = strlen(data);

    char compressed[4096];
    uLongf comp_len = sizeof(compressed);
    int rc = compress2((Bytef*)compressed, &comp_len,
                       (const Bytef*)data, (uLong)data_len,
                       Z_DEFAULT_COMPRESSION);
    ASSERT(rc == Z_OK, "compress2 failed");
    ASSERT(comp_len < data_len, "compressed should be smaller");

    char decompressed[4096];
    uLongf decomp_len = sizeof(decompressed);
    rc = uncompress((Bytef*)decompressed, &decomp_len,
                    (const Bytef*)compressed, comp_len);
    ASSERT(rc == Z_OK, "uncompress failed");
    ASSERT(decomp_len == data_len, "decompressed size mismatch");
    ASSERT(memcmp(decompressed, data, data_len) == 0, "data mismatch");
    TEST_END;
}

void test_zlib_binary_data(void) {
    TEST_BEGIN("zlib binary data roundtrip");
    char data[2048];
    for (int i = 0; i < 2048; i++)
        data[i] = (char)(i & 0xFF);

    char compressed[4096];
    uLongf comp_len = sizeof(compressed);
    int rc = compress2((Bytef*)compressed, &comp_len,
                       (const Bytef*)data, 2048, Z_DEFAULT_COMPRESSION);
    ASSERT(rc == Z_OK, "compress2 failed");

    char decompressed[4096];
    uLongf decomp_len = sizeof(decompressed);
    rc = uncompress((Bytef*)decompressed, &decomp_len,
                    (const Bytef*)compressed, comp_len);
    ASSERT(rc == Z_OK, "uncompress failed");
    ASSERT(decomp_len == 2048, "size mismatch");
    ASSERT(memcmp(decompressed, data, 2048) == 0, "data mismatch");
    TEST_END;
}

/* ---- SHA-256 verification tests ---- */

static void sha256_hex_test(const unsigned char *hash, char *hex) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        hex[i*2]   = hx[hash[i] >> 4];
        hex[i*2+1] = hx[hash[i] & 0x0f];
    }
    hex[64] = '\0';
}

void test_sha256_known_vector(void) {
    TEST_BEGIN("SHA-256 known test vector");
    /* SHA-256("abc") = ba7816bf... */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    ASSERT(ctx != NULL, "EVP_MD_CTX_new failed");
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, "abc", 3);
    unsigned char hash[32];
    unsigned int hlen = 32;
    EVP_DigestFinal_ex(ctx, hash, &hlen);
    EVP_MD_CTX_free(ctx);

    char hex[65];
    sha256_hex_test(hash, hex);
    ASSERT_STR_EQ(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                  "SHA-256(abc) mismatch");
    TEST_END;
}

void test_sha256_incremental(void) {
    TEST_BEGIN("SHA-256 incremental vs single-shot");
    const char *data = "Hello, World! This is a test of incremental hashing.";
    size_t len = strlen(data);

    /* Single shot */
    EVP_MD_CTX *ctx1 = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx1, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx1, data, len);
    unsigned char hash1[32];
    unsigned int hlen = 32;
    EVP_DigestFinal_ex(ctx1, hash1, &hlen);
    EVP_MD_CTX_free(ctx1);

    /* Incremental (byte by byte) */
    EVP_MD_CTX *ctx2 = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx2, EVP_sha256(), NULL);
    for (size_t i = 0; i < len; i++)
        EVP_DigestUpdate(ctx2, data + i, 1);
    unsigned char hash2[32];
    hlen = 32;
    EVP_DigestFinal_ex(ctx2, hash2, &hlen);
    EVP_MD_CTX_free(ctx2);

    ASSERT(memcmp(hash1, hash2, 32) == 0, "hashes should match");
    TEST_END;
}
