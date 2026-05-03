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
