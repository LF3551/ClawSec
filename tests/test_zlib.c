/*
 * test_zlib.c — Tests for zlib compress/decompress
 */
#include <stdio.h>
#include <string.h>
#include <zlib.h>

#include "test.h"

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
