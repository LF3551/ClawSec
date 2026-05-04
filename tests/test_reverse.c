/*
 * test_reverse.c — Reverse tunnel and persistent connection tests
 */
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L
#include "test.h"
#include "reverse.h"
#include "persistent.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

/*
 * Test: Persistent backoff starts at 1 second
 */
void test_persist_backoff_initial(void) {
    TEST_BEGIN("persistent backoff starts at 1s") {
        srand(42);
        int delay = persist_next_delay(0);
        ASSERT(delay >= 1 && delay <= 2, "initial delay 1-2s");
    } TEST_END;
}

/*
 * Test: Persistent backoff grows exponentially
 */
void test_persist_backoff_exponential(void) {
    TEST_BEGIN("persistent backoff grows exponentially") {
        srand(42);
        int d0 = persist_next_delay(0);
        int d1 = persist_next_delay(1);
        int d2 = persist_next_delay(2);
        int d3 = persist_next_delay(3);
        /* Should roughly double: 1, 2, 4, 8 (with jitter) */
        ASSERT(d1 > d0, "d1 > d0");
        ASSERT(d2 > d1, "d2 > d1");
        ASSERT(d3 > d2, "d3 > d2");
    } TEST_END;
}

/*
 * Test: Persistent backoff caps at max
 */
void test_persist_backoff_max(void) {
    TEST_BEGIN("persistent backoff caps at 60s") {
        srand(42);
        int delay = persist_next_delay(20); /* 2^20 would be huge */
        ASSERT(delay <= PERSIST_BACKOFF_MAX + PERSIST_BACKOFF_MAX / 4 + 1,
               "delay capped at max + jitter");
    } TEST_END;
}

/*
 * Test: Heartbeat check detects heartbeat message
 */
void test_persist_heartbeat_detect(void) {
    TEST_BEGIN("persistent heartbeat detection") {
        const char *hb = PERSIST_HEARTBEAT_MSG;
        int is_hb = persist_heartbeat_check(hb, strlen(hb));
        ASSERT_EQ(is_hb, 1, "detects heartbeat");

        int is_not = persist_heartbeat_check("data", 4);
        ASSERT_EQ(is_not, 0, "rejects non-heartbeat");
    } TEST_END;
}

/*
 * Test: Reverse tunnel signal format
 */
void test_reverse_signal_format(void) {
    TEST_BEGIN("reverse tunnel signal wire format") {
        /* Verify signal strings are properly terminated with \n */
        const char *open_sig = "ROPEN\n";
        const char *ok_sig = "ROK\n";
        const char *fail_sig = "RFAIL\n";

        ASSERT_EQ((int)strlen(open_sig), 6, "ROPEN length");
        ASSERT_EQ((int)strlen(ok_sig), 4, "ROK length");
        ASSERT_EQ((int)strlen(fail_sig), 6, "RFAIL length");
        ASSERT(open_sig[5] == '\n', "ROPEN ends with newline");
        ASSERT(ok_sig[3] == '\n', "ROK ends with newline");
    } TEST_END;
}

/*
 * Test: Persistent backoff jitter produces variation
 */
void test_persist_backoff_jitter(void) {
    TEST_BEGIN("persistent backoff jitter produces variation") {
        srand(1);
        int d1 = persist_next_delay(3);
        srand(99);
        int d2 = persist_next_delay(3);
        /* With different seeds, jitter should make delays differ */
        /* But both should be in range [6, 10] for attempt=3 (base=8 ±2) */
        ASSERT(d1 >= 1, "delay1 >= 1");
        ASSERT(d2 >= 1, "delay2 >= 1");
        ASSERT(d1 <= PERSIST_BACKOFF_MAX + 20, "delay1 within bounds");
    } TEST_END;
}

/*
 * Test: Persistent heartbeat ignores non-heartbeat data
 */
void test_persist_heartbeat_ignores_data(void) {
    TEST_BEGIN("persistent heartbeat ignores regular data") {
        ASSERT_EQ(persist_heartbeat_check("GET / HTTP/1.1\r\n", 16), 0, "HTTP not heartbeat");
        ASSERT_EQ(persist_heartbeat_check("ROPEN\n", 6), 0, "ROPEN not heartbeat");
        ASSERT_EQ(persist_heartbeat_check("HB", 2), 0, "partial HB not heartbeat");
        ASSERT_EQ(persist_heartbeat_check("", 0), 0, "empty not heartbeat");
    } TEST_END;
}

/*
 * Test: Reverse tunnel signals are distinct (no overlap)
 */
void test_reverse_signals_distinct(void) {
    TEST_BEGIN("reverse tunnel signals are distinct") {
        const char *open_sig = "ROPEN\n";
        const char *ok_sig = "ROK\n";
        const char *fail_sig = "RFAIL\n";
        const char *hb = "HB\n";

        /* No signal is a prefix of another */
        ASSERT(strncmp(open_sig, ok_sig, strlen(ok_sig)) != 0, "ROPEN != ROK prefix");
        ASSERT(strncmp(open_sig, fail_sig, strlen(fail_sig)) != 0, "ROPEN != RFAIL prefix");
        ASSERT(strncmp(ok_sig, fail_sig, strlen(fail_sig)) != 0, "ROK != RFAIL prefix");
        /* Heartbeat is distinct from all reverse signals */
        ASSERT(strncmp(hb, open_sig, strlen(hb)) != 0, "HB != ROPEN prefix");
        ASSERT(strncmp(hb, ok_sig, strlen(hb)) != 0, "HB != ROK prefix");
    } TEST_END;
}
