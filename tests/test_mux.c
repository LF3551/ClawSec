/*
 * test_mux.c — Stream multiplexer tests
 */
#define _POSIX_C_SOURCE 200809L
#include "test.h"
#include "mux.h"

void test_mux_encode_decode(void) {
    TEST_BEGIN("mux header encode/decode roundtrip") {
        unsigned char buf[MUX_HDR_SIZE];
        mux_header_t hdr;

        mux_encode_header(buf, 7, MUX_DATA, 1234);
        ASSERT(mux_decode_header(buf, &hdr) == 0, "decode failed");
        ASSERT_EQ(hdr.stream_id, 7, "stream_id wrong");
        ASSERT_EQ(hdr.type, MUX_DATA, "type wrong");
        ASSERT_EQ(hdr.length, 1234, "length wrong");
    } TEST_END;
}

void test_mux_frame_types(void) {
    TEST_BEGIN("mux all frame types") {
        unsigned char buf[MUX_HDR_SIZE];
        mux_header_t hdr;

        /* OPEN */
        mux_encode_header(buf, 1, MUX_OPEN, 0);
        mux_decode_header(buf, &hdr);
        ASSERT_EQ(hdr.type, MUX_OPEN, "OPEN type wrong");
        ASSERT_EQ(hdr.length, 0, "OPEN length should be 0");

        /* CLOSE with max stream_id */
        mux_encode_header(buf, 63, MUX_CLOSE, 0);
        mux_decode_header(buf, &hdr);
        ASSERT_EQ(hdr.stream_id, 63, "max stream_id wrong");
        ASSERT_EQ(hdr.type, MUX_CLOSE, "CLOSE type wrong");
    } TEST_END;
}

void test_mux_max_payload(void) {
    TEST_BEGIN("mux reject oversized payload") {
        unsigned char buf[MUX_HDR_SIZE];
        mux_header_t hdr;

        /* Manually set length to 65535 (> MUX_MAX_PAYLOAD) */
        buf[0] = 1;
        buf[1] = MUX_DATA;
        buf[2] = 0xFF;
        buf[3] = 0xFF;

        ASSERT(mux_decode_header(buf, &hdr) == -1, "should reject > MUX_MAX_PAYLOAD");

        /* Boundary: MUX_MAX_PAYLOAD accepted, MUX_MAX_PAYLOAD + 1 rejected */
        mux_encode_header(buf, 1, MUX_DATA, MUX_MAX_PAYLOAD);
        ASSERT(mux_decode_header(buf, &hdr) == 0, "max payload should decode");
        mux_encode_header(buf, 1, MUX_DATA, MUX_MAX_PAYLOAD + 1);
        ASSERT(mux_decode_header(buf, &hdr) == -1, "max+1 should be rejected");
    } TEST_END;
}

void test_mux_max_frame_roundtrip(void) {
    TEST_BEGIN("mux max-size frame fits one encrypted message") {
        ASSERT(MUX_HDR_SIZE + MUX_MAX_PAYLOAD <= FARM9_MAX_MSG,
               "mux frame larger than FARM9_MAX_MSG");
        int fds[2];
        ASSERT(make_socketpair(fds) == 0, "socketpair");
        int bufsize = 65536;
        setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
        setsockopt(fds[1], SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));

        static unsigned char payload[MUX_MAX_PAYLOAD], got[MUX_MAX_PAYLOAD];
        for (int i = 0; i < MUX_MAX_PAYLOAD; i++) payload[i] = (unsigned char)(i * 7);

        ASSERT(farm9crypt_init_password("MuxFramePass1", 13, FARM9_ROLE_CLIENT) == 0, "init");
        int wn = mux_write_frame(fds[0], 9, MUX_DATA, payload, sizeof(payload));
        farm9crypt_cleanup();
        ASSERT_EQ(wn, MUX_MAX_PAYLOAD, "write max frame");

        ASSERT(farm9crypt_init_password("MuxFramePass1", 13, FARM9_ROLE_SERVER) == 0, "init peer");
        mux_header_t hdr;
        int rn = mux_read_frame(fds[1], &hdr, got, sizeof(got));
        farm9crypt_cleanup();
        close(fds[0]); close(fds[1]);
        ASSERT_EQ(rn, MUX_MAX_PAYLOAD, "read max frame");
        ASSERT_EQ(hdr.stream_id, 9, "stream id");
        ASSERT(memcmp(got, payload, sizeof(payload)) == 0, "payload mismatch");
    } TEST_END;
}

void test_mux_open_payload(void) {
    TEST_BEGIN("mux v2 OPEN payload encode/decode") {
        unsigned char b[300], fl;
        char host[256];
        uint16_t port = 0;
        int has;
        int n = mux_encode_open(b, sizeof(b), MUX_OPEN_FC, "example.org", 443);
        ASSERT(n == 1 + 1 + 11 + 2, "length");
        ASSERT(mux_decode_open(b, (size_t)n, &fl, host, sizeof(host), &port, &has) == 0, "decode");
        ASSERT(fl == MUX_OPEN_FC && has && port == 443 && strcmp(host, "example.org") == 0, "fields");
        ASSERT(mux_decode_open(b, 0, &fl, host, sizeof(host), &port, &has) == 0 && !has && fl == 0,
               "empty OPEN = v1");
        n = mux_encode_open(b, sizeof(b), MUX_OPEN_FC, NULL, 0);
        ASSERT(n == 1 && mux_decode_open(b, 1, &fl, host, sizeof(host), &port, &has) == 0 &&
               !has && fl == MUX_OPEN_FC, "flags only (-L)");
        b[1] = 200;                                   /* host length beyond the payload */
        ASSERT(mux_decode_open(b, 16, &fl, host, sizeof(host), &port, &has) == -1, "truncated");
        unsigned char nul[] = { 1, 3, 'a', 0, 'b', 0, 80 };
        ASSERT(mux_decode_open(nul, sizeof(nul), &fl, host, sizeof(host), &port, &has) == -1,
               "embedded NUL rejected");
    } TEST_END;
}

void test_mux_socks_parse(void) {
    TEST_BEGIN("mux SOCKS5 parser: partial input, address types, errors") {
        char host[256];
        uint16_t port;
        unsigned char code;
        const unsigned char g[] = { 5, 2, 2, 0 };
        ASSERT(mux_socks_parse_greeting(g, 1) == 0, "partial greeting");
        ASSERT(mux_socks_parse_greeting(g, 3) == 0, "methods incomplete");
        ASSERT(mux_socks_parse_greeting(g, 4) == 4, "no-auth offered");
        const unsigned char g_auth[] = { 5, 1, 2 };
        ASSERT(mux_socks_parse_greeting(g_auth, 3) == -1, "password auth only");
        const unsigned char g4[] = { 4, 1, 0 };
        ASSERT(mux_socks_parse_greeting(g4, 3) == -1, "SOCKS4");

        const unsigned char r4[] = { 5, 1, 0, 1, 192, 0, 2, 9, 0x1f, 0x90 };
        ASSERT(mux_socks_parse_request(r4, 9, host, sizeof(host), &port, &code) == 0, "partial");
        ASSERT(mux_socks_parse_request(r4, 10, host, sizeof(host), &port, &code) == 10 &&
               strcmp(host, "192.0.2.9") == 0 && port == 8080, "IPv4");
        const unsigned char rd[] = { 5, 1, 0, 3, 3, 'a', 'b', 'c', 0, 80, 0xAA };
        ASSERT(mux_socks_parse_request(rd, sizeof(rd), host, sizeof(host), &port, &code) == 10 &&
               strcmp(host, "abc") == 0 && port == 80, "domain (extra byte left over)");
        unsigned char r6[22] = { 5, 1, 0, 4 };
        r6[4] = 0x20; r6[5] = 0x01; r6[6] = 0x0d; r6[7] = 0xb8; r6[19] = 1; r6[21] = 22;
        ASSERT(mux_socks_parse_request(r6, 22, host, sizeof(host), &port, &code) == 22 &&
               strcmp(host, "2001:db8::1") == 0 && port == 22, "IPv6");
        const unsigned char bind[] = { 5, 2, 0, 1, 1, 2, 3, 4, 0, 1 };
        ASSERT(mux_socks_parse_request(bind, 10, host, sizeof(host), &port, &code) == -1 &&
               code == 0x07, "BIND -> command not supported");
        const unsigned char at[] = { 5, 1, 0, 9 };
        ASSERT(mux_socks_parse_request(at, 4, host, sizeof(host), &port, &code) == -1 &&
               code == 0x08, "unknown address type");
        const unsigned char dnul[] = { 5, 1, 0, 3, 2, 'a', 0, 0, 80 };
        ASSERT(mux_socks_parse_request(dnul, sizeof(dnul), host, sizeof(host), &port, &code) == -1,
               "NUL in domain rejected");
    } TEST_END;
}
