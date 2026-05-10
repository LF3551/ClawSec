/*
 * test_tun.c — TUN VPN unit tests
 */
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L
#include "test.h"
#include "tun.h"
#include <string.h>
#include <arpa/inet.h>

/*
 * Test: CIDR parsing with prefix
 */
void test_tun_parse_cidr(void) {
    TEST_BEGIN("tun CIDR parse 10.0.0.1/24") {
        char ip[64];
        int prefix;
        int rc = tun_parse_cidr("10.0.0.1/24", ip, sizeof(ip), &prefix);
        ASSERT(rc == 0, "parse ok");
        ASSERT(strcmp(ip, "10.0.0.1") == 0, "ip correct");
        ASSERT(prefix == 24, "prefix 24");
    } TEST_END;
}

/*
 * Test: CIDR parsing without prefix defaults to /24
 */
void test_tun_parse_cidr_default(void) {
    TEST_BEGIN("tun CIDR parse default /24") {
        char ip[64];
        int prefix;
        int rc = tun_parse_cidr("192.168.1.1", ip, sizeof(ip), &prefix);
        ASSERT(rc == 0, "parse ok");
        ASSERT(strcmp(ip, "192.168.1.1") == 0, "ip correct");
        ASSERT(prefix == 24, "default prefix 24");
    } TEST_END;
}

/*
 * Test: CIDR parsing with /16 prefix
 */
void test_tun_parse_cidr_16(void) {
    TEST_BEGIN("tun CIDR parse 172.16.0.1/16") {
        char ip[64];
        int prefix;
        int rc = tun_parse_cidr("172.16.0.1/16", ip, sizeof(ip), &prefix);
        ASSERT(rc == 0, "parse ok");
        ASSERT(strcmp(ip, "172.16.0.1") == 0, "ip correct");
        ASSERT(prefix == 16, "prefix 16");
    } TEST_END;
}

/*
 * Test: CIDR rejects invalid prefix
 */
void test_tun_parse_cidr_invalid_prefix(void) {
    TEST_BEGIN("tun CIDR rejects invalid prefix") {
        char ip[64];
        int prefix;
        int rc1 = tun_parse_cidr("10.0.0.1/0", ip, sizeof(ip), &prefix);
        int rc2 = tun_parse_cidr("10.0.0.1/31", ip, sizeof(ip), &prefix);
        ASSERT(rc1 != 0, "rejects /0");
        ASSERT(rc2 != 0, "rejects /31");
    } TEST_END;
}

/*
 * Test: CIDR rejects NULL input
 */
void test_tun_parse_cidr_null(void) {
    TEST_BEGIN("tun CIDR rejects NULL") {
        char ip[64];
        int prefix;
        int rc = tun_parse_cidr(NULL, ip, sizeof(ip), &prefix);
        ASSERT(rc != 0, "rejects NULL");
    } TEST_END;
}

/*
 * Test: validate config with valid IP
 */
void test_tun_validate_config_ok(void) {
    TEST_BEGIN("tun validate config valid") {
        ASSERT(tun_validate_config("10.0.0.1", 24) == 0, "10.0.0.1/24 valid");
        ASSERT(tun_validate_config("192.168.1.1", 16) == 0, "192.168.1.1/16 valid");
        ASSERT(tun_validate_config("172.16.0.1", 8) == 0, "172.16.0.1/8 valid");
    } TEST_END;
}

/*
 * Test: validate config rejects bad IP
 */
void test_tun_validate_config_bad_ip(void) {
    TEST_BEGIN("tun validate config bad IP") {
        ASSERT(tun_validate_config("999.0.0.1", 24) != 0, "rejects 999.x");
        ASSERT(tun_validate_config("not-an-ip", 24) != 0, "rejects non-IP");
        ASSERT(tun_validate_config("", 24) != 0, "rejects empty");
    } TEST_END;
}

/*
 * Test: validate config rejects bad prefix
 */
void test_tun_validate_config_bad_prefix(void) {
    TEST_BEGIN("tun validate config bad prefix") {
        ASSERT(tun_validate_config("10.0.0.1", 0) != 0, "rejects /0");
        ASSERT(tun_validate_config("10.0.0.1", 33) != 0, "rejects /33");
        ASSERT(tun_validate_config("10.0.0.1", 31) != 0, "rejects /31");
    } TEST_END;
}

/*
 * Test: TUN wire format header structure
 */
void test_tun_wire_format(void) {
    TEST_BEGIN("tun VPN wire format header") {
        /* Simulate building a wire frame */
        char wire[TUN_BUF_SIZE];
        char payload[] = "Hello VPN";
        int pkt_len = (int)strlen(payload);

        memcpy(wire, "TVPN", 4);
        wire[4] = (pkt_len >> 8) & 0xFF;
        wire[5] = pkt_len & 0xFF;
        memcpy(wire + TUN_HDR_SIZE, payload, pkt_len);

        /* Verify header */
        ASSERT(memcmp(wire, "TVPN", 4) == 0, "magic correct");
        int decoded_len = ((unsigned char)wire[4] << 8) | (unsigned char)wire[5];
        ASSERT(decoded_len == pkt_len, "length correct");
        ASSERT(memcmp(wire + TUN_HDR_SIZE, payload, pkt_len) == 0, "payload correct");
    } TEST_END;
}

/*
 * Test: TUN constants are sane
 */
void test_tun_constants(void) {
    TEST_BEGIN("tun MTU and buffer constants") {
        ASSERT(TUN_MTU == 1400, "MTU is 1400");
        ASSERT(TUN_HDR_SIZE == 6, "header is 6 bytes");
        ASSERT(TUN_BUF_SIZE == TUN_HDR_SIZE + TUN_MTU, "buf = hdr + mtu");
    } TEST_END;
}
