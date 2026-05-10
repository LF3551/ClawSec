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
#include <openssl/rand.h>

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

/*
 * Test: UDP VPN encrypt/decrypt round-trip
 */
void test_tun_udp_encrypt_decrypt(void) {
    TEST_BEGIN("tun UDP VPN encrypt/decrypt round-trip") {
        unsigned char key[32];
        RAND_bytes(key, 32);

        const char *msg = "Hello UDP VPN!";
        int msg_len = (int)strlen(msg);

        unsigned char enc[TUN_UDP_OVERHEAD + 64];
        int enc_len = 0;

        int rc = tun_udp_encrypt(key, 42, (const unsigned char *)msg, msg_len,
                                  enc, &enc_len);
        ASSERT(rc == 0, "encrypt ok");
        ASSERT(enc_len == TUN_UDP_MAGIC_LEN + TUN_UDP_NONCE_LEN + msg_len + TUN_UDP_TAG_LEN,
               "encrypted length correct");

        unsigned char dec[64];
        int dec_len = 0;
        uint32_t seq = 0;

        rc = tun_udp_decrypt(key, enc, enc_len, dec, &dec_len, &seq);
        ASSERT(rc == 0, "decrypt ok");
        ASSERT(dec_len == msg_len, "decrypted length matches");
        ASSERT(memcmp(dec, msg, msg_len) == 0, "decrypted payload matches");
        ASSERT(seq == 42, "sequence number correct");
    } TEST_END;
}

/*
 * Test: UDP VPN decrypt rejects tampered data
 */
void test_tun_udp_tamper_detect(void) {
    TEST_BEGIN("tun UDP VPN detects tampered data") {
        unsigned char key[32];
        RAND_bytes(key, 32);

        const char *msg = "Secret VPN data";
        int msg_len = (int)strlen(msg);

        unsigned char enc[TUN_UDP_OVERHEAD + 64];
        int enc_len = 0;
        tun_udp_encrypt(key, 1, (const unsigned char *)msg, msg_len, enc, &enc_len);

        /* Tamper with ciphertext */
        enc[TUN_UDP_MAGIC_LEN + TUN_UDP_NONCE_LEN + 3] ^= 0xFF;

        unsigned char dec[64];
        int dec_len = 0;
        uint32_t seq = 0;
        int rc = tun_udp_decrypt(key, enc, enc_len, dec, &dec_len, &seq);
        ASSERT(rc != 0, "rejects tampered data");
    } TEST_END;
}

/*
 * Test: UDP VPN decrypt rejects wrong key
 */
void test_tun_udp_wrong_key(void) {
    TEST_BEGIN("tun UDP VPN rejects wrong key") {
        unsigned char key1[32], key2[32];
        RAND_bytes(key1, 32);
        RAND_bytes(key2, 32);

        const char *msg = "Key mismatch test";
        int msg_len = (int)strlen(msg);

        unsigned char enc[TUN_UDP_OVERHEAD + 64];
        int enc_len = 0;
        tun_udp_encrypt(key1, 1, (const unsigned char *)msg, msg_len, enc, &enc_len);

        unsigned char dec[64];
        int dec_len = 0;
        uint32_t seq = 0;
        int rc = tun_udp_decrypt(key2, enc, enc_len, dec, &dec_len, &seq);
        ASSERT(rc != 0, "rejects wrong key");
    } TEST_END;
}

/*
 * Test: UDP VPN wire format structure
 */
void test_tun_udp_wire_format(void) {
    TEST_BEGIN("tun UDP VPN wire format") {
        unsigned char key[32];
        RAND_bytes(key, 32);

        unsigned char payload[100];
        memset(payload, 0xAA, sizeof(payload));

        unsigned char enc[TUN_UDP_OVERHEAD + 200];
        int enc_len = 0;
        tun_udp_encrypt(key, 0x01020304, payload, 100, enc, &enc_len);

        /* Check magic */
        ASSERT(memcmp(enc, "CVPN", 4) == 0, "magic is CVPN");

        /* Check nonce embeds sequence */
        ASSERT(enc[4] == 0x01, "nonce[0] = seq byte 0");
        ASSERT(enc[5] == 0x02, "nonce[1] = seq byte 1");
        ASSERT(enc[6] == 0x03, "nonce[2] = seq byte 2");
        ASSERT(enc[7] == 0x04, "nonce[3] = seq byte 3");

        /* Total: magic(4) + nonce(12) + ct(100) + tag(16) = 132 */
        ASSERT(enc_len == 132, "total datagram size correct");
    } TEST_END;
}

/*
 * Test: UDP VPN constants
 */
void test_tun_udp_constants(void) {
    TEST_BEGIN("tun UDP VPN constants") {
        ASSERT(TUN_UDP_OVERHEAD == 32, "overhead is 32 bytes");
        ASSERT(TUN_UDP_NONCE_LEN == 12, "nonce is 12 bytes");
        ASSERT(TUN_UDP_TAG_LEN == 16, "tag is 16 bytes");
        ASSERT(TUN_UDP_MAGIC_LEN == 4, "magic is 4 bytes");
    } TEST_END;
}

/*
 * Test: UDP VPN rejects truncated packet
 */
void test_tun_udp_truncated(void) {
    TEST_BEGIN("tun UDP VPN rejects truncated packet") {
        unsigned char key[32];
        RAND_bytes(key, 32);

        /* Too short to even hold header + tag */
        unsigned char bad[20] = "CVPN";
        unsigned char dec[64];
        int dec_len = 0;
        uint32_t seq = 0;
        int rc = tun_udp_decrypt(key, bad, 20, dec, &dec_len, &seq);
        ASSERT(rc != 0, "rejects truncated packet");
    } TEST_END;
}

/*
 * Test: UDP VPN rejects bad magic
 */
void test_tun_udp_bad_magic(void) {
    TEST_BEGIN("tun UDP VPN rejects bad magic") {
        unsigned char key[32];
        RAND_bytes(key, 32);

        const char *msg = "test";
        unsigned char enc[TUN_UDP_OVERHEAD + 64];
        int enc_len = 0;
        tun_udp_encrypt(key, 1, (const unsigned char *)msg, 4, enc, &enc_len);

        /* Corrupt magic */
        enc[0] = 'X';

        unsigned char dec[64];
        int dec_len = 0;
        uint32_t seq = 0;
        int rc = tun_udp_decrypt(key, enc, enc_len, dec, &dec_len, &seq);
        ASSERT(rc != 0, "rejects bad magic");
    } TEST_END;
}
