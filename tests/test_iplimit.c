/*
 * test_iplimit.c — per-address limits for the -K server
 */
#define _POSIX_C_SOURCE 200809L
#include "test.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include "iplimit.h"

static int key4(const char *ip, char *out) {
    struct sockaddr_in a = { .sin_family = AF_INET };
    inet_pton(AF_INET, ip, &a.sin_addr);
    return iplimit_key((struct sockaddr *)&a, sizeof(a), out);
}

static int key6(const char *ip, char *out) {
    struct sockaddr_in6 a = { .sin6_family = AF_INET6 };
    inet_pton(AF_INET6, ip, &a.sin6_addr);
    return iplimit_key((struct sockaddr *)&a, sizeof(a), out);
}

void test_iplimit_keys(void) {
    TEST_BEGIN("iplimit: IPv4, IPv6 /64 grouping, v4-mapped") {
        char a[IPLIMIT_KEY_LEN], b[IPLIMIT_KEY_LEN];
        ASSERT(key4("192.0.2.7", a) == 0 && strcmp(a, "192.0.2.7") == 0, "ipv4");
        ASSERT(key6("2001:db8:1:2:aaaa::1", a) == 0 && key6("2001:db8:1:2:bbbb::9", b) == 0, "ipv6");
        ASSERT_STR_EQ(a, b, "same /64 must share a key");
        ASSERT_STR_EQ(a, "2001:db8:1:2::/64", "ipv6 key format");
        ASSERT(key6("2001:db8:1:3::1", b) == 0 && strcmp(a, b) != 0, "other /64 differs");
        ASSERT(key6("::ffff:198.51.100.4", a) == 0 && strcmp(a, "198.51.100.4") == 0,
               "v4-mapped counts as IPv4");
    } TEST_END;
}

void test_iplimit_concurrency(void) {
    TEST_BEGIN("iplimit: --max-per-ip bounds one address, not others") {
        iplimit_configure(2, 0, 600, 600);
        time_t t = 1000;
        ASSERT_EQ(iplimit_admit("10.0.0.1", t, NULL), IPLIMIT_OK, "first");
        iplimit_started("10.0.0.1", 101, t);
        iplimit_started("10.0.0.1", 102, t);
        ASSERT_EQ(iplimit_admit("10.0.0.1", t, NULL), IPLIMIT_TOO_MANY, "third must wait");
        ASSERT_EQ(iplimit_admit("10.0.0.2", t, NULL), IPLIMIT_OK, "other address unaffected");
        iplimit_finished(101, 0, t, NULL);
        ASSERT_EQ(iplimit_admit("10.0.0.1", t, NULL), IPLIMIT_OK, "slot freed by exit");
        iplimit_finished(102, 0, t, NULL);
        iplimit_finished(999, 1, t, NULL);           /* unknown pid: ignored */
    } TEST_END;
}

static void fail_once(const char *ip, pid_t pid, time_t t, int *fails) {
    iplimit_started(ip, pid, t);
    *fails = iplimit_finished(pid, 1, t, NULL);
}

void test_iplimit_auth_lockout(void) {
    TEST_BEGIN("iplimit: lockout after N failures, expiry, window") {
        iplimit_configure(0, 3, 600, 600);
        int f = 0;
        time_t t = 5000;
        fail_once("203.0.113.9", 201, t, &f);      ASSERT_EQ(f, 1, "1st failure");
        fail_once("203.0.113.9", 202, t + 1, &f);  ASSERT_EQ(f, 2, "2nd failure");
        ASSERT_EQ(iplimit_admit("203.0.113.9", t + 2, NULL), IPLIMIT_OK, "not yet blocked");
        fail_once("203.0.113.9", 203, t + 2, &f);  ASSERT_EQ(f, 3, "3rd failure");
        int retry = 0;
        ASSERT_EQ(iplimit_admit("203.0.113.9", t + 3, &retry), IPLIMIT_BLOCKED, "blocked");
        ASSERT(retry > 590 && retry <= 600, "retry-after");
        ASSERT_EQ(iplimit_admit("203.0.113.10", t + 3, NULL), IPLIMIT_OK, "neighbour not blocked");
        ASSERT_EQ(iplimit_admit("203.0.113.9", t + 2 + 600, NULL), IPLIMIT_OK, "block expires");

        /* failures spread wider than the window never add up to a block */
        iplimit_configure(0, 3, 600, 600);
        fail_once("198.51.100.1", 301, t, &f);
        fail_once("198.51.100.1", 302, t + 400, &f);
        fail_once("198.51.100.1", 303, t + 800, &f);
        ASSERT_EQ(f, 1, "a failure 800 s after the first starts a new window");
        ASSERT_EQ(iplimit_admit("198.51.100.1", t + 801, NULL), IPLIMIT_OK, "not blocked");

        /* successful sessions do not count */
        iplimit_configure(0, 2, 600, 600);
        iplimit_started("198.51.100.2", 401, t);
        ASSERT_EQ(iplimit_finished(401, 0, t, NULL), 0, "success is not a failure");
    } TEST_END;
}

void test_iplimit_eviction_keeps_blocks(void) {
    TEST_BEGIN("iplimit: address churn does not evict a block") {
        iplimit_configure(0, 1, 600, 600);
        int f;
        time_t t = 9000;
        fail_once("192.0.2.66", 501, t, &f);
        ASSERT_EQ(iplimit_admit("192.0.2.66", t, NULL), IPLIMIT_BLOCKED, "blocked");
        /* 10000 other addresses come and go (more than the table holds) */
        char ip[32];
        for (int i = 0; i < 10000; i++) {
            snprintf(ip, sizeof(ip), "10.%d.%d.%d", (i >> 16) & 255, (i >> 8) & 255, i & 255);
            iplimit_started(ip, 1000 + i, t + 1);
            iplimit_finished(1000 + i, 0, t + 1, NULL);
        }
        ASSERT_EQ(iplimit_admit("192.0.2.66", t + 2, NULL), IPLIMIT_BLOCKED, "block survives churn");
        ASSERT(iplimit_tracked() <= 8192, "table stays bounded");
    } TEST_END;
}
