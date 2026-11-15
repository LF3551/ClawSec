/*
 * test_parse.c — Tests for host:port / listen-spec parsing (src/net.c)
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "test.h"
#include "net.h"
#include <netinet/in.h>
#include <arpa/inet.h>

void test_parse_forward_spec_ipv4(void) {
    TEST_BEGIN("parse host:port (IPv4)");
    char host[256], port[32];
    ASSERT(net_parse_host_port("192.168.1.1:8080", host, sizeof(host),
                               port, sizeof(port)) == 0, "parse failed");
    ASSERT_STR_EQ(host, "192.168.1.1", "host mismatch");
    ASSERT_STR_EQ(port, "8080", "port mismatch");
    TEST_END;
}

void test_parse_forward_spec_ipv6(void) {
    TEST_BEGIN("parse [IPv6]:port");
    char host[256], port[32];
    ASSERT(net_parse_host_port("[::1]:443", host, sizeof(host),
                               port, sizeof(port)) == 0, "parse failed");
    ASSERT_STR_EQ(host, "::1", "host mismatch");
    ASSERT_STR_EQ(port, "443", "port mismatch");
    TEST_END;
}

void test_parse_forward_spec_hostname(void) {
    TEST_BEGIN("parse hostname:port");
    char host[256], port[32];
    ASSERT(net_parse_host_port("example.com:22", host, sizeof(host),
                               port, sizeof(port)) == 0, "parse failed");
    ASSERT_STR_EQ(host, "example.com", "host mismatch");
    ASSERT_STR_EQ(port, "22", "port mismatch");
    TEST_END;
}

void test_parse_forward_spec_invalid(void) {
    TEST_BEGIN("parse invalid specs rejected");
    char host[256], port[32];
    const char *bad[] = { ":80", "[bad", "[::1]80", "[]:80", "host:", "host:0",
                          "host:65536", "host:80x", "host:-1", "noport", NULL };
    ASSERT(net_parse_host_port(NULL, host, sizeof(host), port, sizeof(port)) == -1,
           "NULL not rejected");
    for (int i = 0; bad[i]; i++)
        ASSERT(net_parse_host_port(bad[i], host, sizeof(host), port, sizeof(port)) == -1,
               bad[i]);
    char tiny[4];
    ASSERT(net_parse_host_port("example.com:22", tiny, sizeof(tiny), port, sizeof(port)) == -1,
           "host longer than buffer not rejected");
    TEST_END;
}

void test_parse_listen_spec(void) {
    TEST_BEGIN("parse listen spec: port defaults to loopback");
    char host[256], port[8];
    ASSERT(net_parse_listen_spec("1080", "127.0.0.1", host, sizeof(host),
                                 port, sizeof(port)) == 0, "port only");
    ASSERT_STR_EQ(host, "127.0.0.1", "default host");
    ASSERT_STR_EQ(port, "1080", "port");
    ASSERT(net_parse_listen_spec("0.0.0.0:1080", "127.0.0.1", host, sizeof(host),
                                 port, sizeof(port)) == 0, "explicit host");
    ASSERT_STR_EQ(host, "0.0.0.0", "explicit host kept");
    ASSERT(net_parse_listen_spec("[::1]:9", "127.0.0.1", host, sizeof(host),
                                 port, sizeof(port)) == 0, "ipv6 host");
    ASSERT_STR_EQ(host, "::1", "ipv6 host kept");
    ASSERT(net_parse_listen_spec("abc", "127.0.0.1", host, sizeof(host),
                                 port, sizeof(port)) == -1, "non-numeric port rejected");
    ASSERT(net_parse_listen_spec("0", "127.0.0.1", host, sizeof(host),
                                 port, sizeof(port)) == -1, "port 0 rejected");
    TEST_END;
}

void test_listen_on_loopback_only(void) {
    TEST_BEGIN("net_listen_on binds the requested address only");
    int fd = net_listen_on("127.0.0.1", "0");   /* 0 = any free port */
    ASSERT(fd >= 0, "listen on 127.0.0.1 failed");
    struct sockaddr_in sa;
    socklen_t len = sizeof(sa);
    int rc = getsockname(fd, (struct sockaddr *)&sa, &len);
    close(fd);
    ASSERT(rc == 0, "getsockname");
    ASSERT(sa.sin_family == AF_INET, "family");
    ASSERT(ntohl(sa.sin_addr.s_addr) == INADDR_LOOPBACK, "must be bound to 127.0.0.1, not 0.0.0.0");
    TEST_END;
}
