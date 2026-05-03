/*
 * test.h — Minimal C test framework for ClawSec
 *
 * Usage:
 *   TEST_BEGIN("test name") {
 *       ASSERT(condition, "failure message");
 *       ...
 *   } TEST_END
 */
#ifndef CLAWSEC_TEST_H
#define CLAWSEC_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include "farm9crypt.h"

/* Counters (defined in test_main.c) */
extern int tests_run;
extern int tests_passed;

/* Start a test case */
#define TEST_BEGIN(name) do { \
    tests_run++; \
    const char *_test_name = (name); \
    int _test_failed = 0; \
    printf("  [TEST] %-50s ", _test_name); \
    fflush(stdout);

/* Assert condition; on failure mark and jump to cleanup */
#define ASSERT(cond, msg) \
    if (!(cond)) { \
        printf("FAIL: %s\n", (msg)); \
        _test_failed = 1; \
        goto _test_cleanup; \
    }

/* Assert equality for ints */
#define ASSERT_EQ(a, b, msg) ASSERT((a) == (b), msg)

/* Assert inequality */
#define ASSERT_NE(a, b, msg) ASSERT((a) != (b), msg)

/* Assert string equality */
#define ASSERT_STR_EQ(a, b, msg) ASSERT(strcmp((a), (b)) == 0, msg)

/* Skip test (counts as passed) */
#define TEST_SKIP(reason) do { \
    printf("SKIP (%s)\n", (reason)); \
    tests_passed++; \
    goto _test_cleanup; \
} while(0)

/* End test case (cleanup label + pass/fail reporting) */
#define TEST_END \
    if (!_test_failed) { tests_passed++; printf("PASS\n"); } \
    _test_cleanup: \
    (void)_test_name; \
    (void)_test_failed; \
} while(0)

/* Helper: create connected socket pair */
static inline int make_socketpair(int fds[2]) {
    return socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
}

/* Test function signature */
typedef void (*test_fn)(void);

/* Test suite registration */
typedef struct {
    const char *name;
    test_fn *tests;
    int count;
} test_suite_t;

#endif /* CLAWSEC_TEST_H */
