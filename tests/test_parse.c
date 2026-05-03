/*
 * test_parse.c — Tests for host:port parsing
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "test.h"

/* Local helper mimicking parse_host_port from clawsec.c */
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
