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
