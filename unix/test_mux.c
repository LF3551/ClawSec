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

        ASSERT(mux_decode_header(buf, &hdr) == -1, "should reject >8192 payload");
    } TEST_END;
}
