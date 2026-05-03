/*
 * test_clawsec.c — Test runner for ClawSec
 *
 * Build: make test
 * Run:   ./test_clawsec
 */
#define _POSIX_C_SOURCE 200809L
#include "test.h"

/* Global counters */
int tests_run = 0;
int tests_passed = 0;

/* test_crypto.c */
extern void test_basic_roundtrip(void);
extern void test_multiple_messages(void);
extern void test_salt_generation(void);
extern void test_salt_different_keys(void);
extern void test_wrong_password(void);
extern void test_large_message(void);
extern void test_null_password(void);
extern void test_invalid_salt(void);

/* test_protocol.c */
extern void test_replay_protection(void);
extern void test_bad_magic(void);

/* test_handshake.c */
extern void test_full_handshake(void);
extern void test_bidirectional(void);

/* test_obfs.c */
extern void test_obfs_mode_default(void);
extern void test_obfs_mode_set_http(void);
extern void test_obfs_http_roundtrip(void);
extern void test_obfs_http_multiple_messages(void);
extern void test_obfs_http_large_payload(void);
extern void test_parse_forward_spec_ipv4(void);
extern void test_parse_forward_spec_ipv6(void);
extern void test_parse_forward_spec_hostname(void);
extern void test_parse_forward_spec_invalid(void);

int main(void) {
    printf("\n=== ClawSec Test Suite ===\n\n");

    /* Crypto tests */
    test_basic_roundtrip();
    test_multiple_messages();
    test_salt_generation();
    test_salt_different_keys();
    test_wrong_password();
    test_large_message();
    test_null_password();
    test_invalid_salt();

    /* Protocol tests */
    test_replay_protection();
    test_bad_magic();

    /* Handshake tests */
    test_full_handshake();
    test_bidirectional();

    /* Obfuscation tests */
    test_obfs_mode_default();
    test_obfs_mode_set_http();
    test_obfs_http_roundtrip();
    test_obfs_http_multiple_messages();
    test_obfs_http_large_payload();

    /* Parse host:port tests */
    test_parse_forward_spec_ipv4();
    test_parse_forward_spec_ipv6();
    test_parse_forward_spec_hostname();
    test_parse_forward_spec_invalid();

    printf("\n=== Results: %d/%d passed ===\n\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
