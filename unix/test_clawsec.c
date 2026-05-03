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

/* Globals needed by util.o */
int g_verbose = 0;

/* Globals needed by mux.o and net.o */
int g_jitter = 0;
int g_udp_mode = 0;
int g_af_family = 0;

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

/* test_parse.c */
extern void test_parse_forward_spec_ipv4(void);
extern void test_parse_forward_spec_ipv6(void);
extern void test_parse_forward_spec_hostname(void);
extern void test_parse_forward_spec_invalid(void);

/* test_zlib.c */
extern void test_zlib_roundtrip(void);
extern void test_zlib_binary_data(void);

/* test_sha256.c */
extern void test_sha256_known_vector(void);
extern void test_sha256_incremental(void);

/* test_chat.c */
extern void test_fingerprint_deterministic(void);
extern void test_ctrl_msg_build(void);

/* test_util.c */
extern void test_initialized_flag(void);
extern void test_raw_key_init(void);
extern void test_fingerprint_uninitialized(void);
extern void test_write_all_basic(void);

/* test_stealth.c */
extern void test_obfs_mode_set_tls(void);
extern void test_tls_roundtrip(void);
extern void test_pad_roundtrip(void);
extern void test_pad_uniform_size(void);
extern void test_pad_too_large(void);
extern void test_jitter_applies_delay(void);
extern void test_jitter_zero_noop(void);

/* test_ech.c */
extern void test_ech_flag(void);
extern void test_ech_tls_connects(void);
extern void test_ech_extension_present(void);
extern void test_ech_auto_enables_tls(void);

/* test_mux.c */
extern void test_mux_encode_decode(void);
extern void test_mux_frame_types(void);
extern void test_mux_max_payload(void);

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

    /* Compression tests */
    test_zlib_roundtrip();
    test_zlib_binary_data();

    /* SHA-256 verification tests */
    test_sha256_known_vector();
    test_sha256_incremental();

    /* Chat features */
    test_fingerprint_deterministic();
    test_ctrl_msg_build();

    /* State & utility tests */
    test_initialized_flag();
    test_raw_key_init();
    test_fingerprint_uninitialized();
    test_write_all_basic();

    /* Stealth / anti-fingerprint tests */
    test_obfs_mode_set_tls();
    test_tls_roundtrip();
    test_pad_roundtrip();
    test_pad_uniform_size();
    test_pad_too_large();
    test_jitter_applies_delay();
    test_jitter_zero_noop();

    /* ECH tests */
    test_ech_flag();
    test_ech_tls_connects();
    test_ech_extension_present();
    test_ech_auto_enables_tls();

    /* Mux tests */
    test_mux_encode_decode();
    test_mux_frame_types();
    test_mux_max_payload();

    printf("\n=== Results: %d/%d passed ===\n\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
