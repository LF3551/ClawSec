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
int tests_skipped = 0;

/* Globals needed by util.o */
int g_verbose = 0;

/* Globals needed by mux.o and net.o */
int g_jitter = 0;
int g_udp_mode = 0;
int g_af_family = 0;
int g_pq = 0;

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

/* test_security.c — protocol v3 regression tests */
extern void test_sec_roles_roundtrip(void);
extern void test_sec_reflection_rejected(void);
extern void test_sec_edited_seq_replay_rejected(void);
extern void test_sec_header_flags_tamper_rejected(void);
extern void test_sec_version_mismatch_rejected(void);
extern void test_sec_forged_frame_leaves_buffer_untouched(void);
extern void test_sec_oversized_message_bounded(void);
extern void test_sec_large_caller_buffer_accepted(void);
extern void test_sec_write_rejects_oversize(void);
extern void test_sec_ecdhe_directional_keys(void);
extern void test_sec_wrong_password_detected(void);
extern void test_sec_old_server_detected(void);
extern void test_sec_old_client_detected(void);
extern void test_sec_udp_reorder_loss_replay(void);

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
extern void test_parse_listen_spec(void);
extern void test_listen_on_loopback_only(void);

/* test_zlib.c */

/* test_sha256.c */

/* test_chat.c */
extern void test_fingerprint_deterministic(void);

/* test_util.c */
extern void test_initialized_flag(void);
extern void test_password_roles_interop(void);
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
extern void test_mux_max_frame_roundtrip(void);
extern void test_mux_open_payload(void);
extern void test_mux_socks_parse(void);

/* test_fallback.c */
extern void test_fallback_knock_roundtrip(void);
extern void test_fallback_detects_probe(void);
extern void test_fallback_knock_magic(void);

/* test_fingerprint.c */
extern void test_fp_flag(void);
extern void test_fp_chrome_tls_roundtrip(void);
extern void test_fp_chrome_compress_cert(void);
extern void test_fp_auto_enables_tls(void);

/* test_tofu.c */
extern void test_tofu_server_init_generates_key(void);
extern void test_tofu_server_persistent_key(void);
extern void test_tofu_sign_verify(void);
extern void test_tofu_known_hosts(void);
extern void test_tofu_ecdhe_roundtrip(void);
extern void test_tofu_fingerprint_format(void);

/* test_pqkem.c */
extern void test_pq_available(void);
extern void test_pq_keygen(void);
extern void test_pq_encap_decap(void);
extern void test_pq_different_secrets(void);
extern void test_pq_tampered_ct(void);
extern void test_pq_ecdhe_roundtrip(void);
extern void test_pq_tofu_ecdhe_roundtrip(void);

/* test_argon2.c */
extern void test_argon2_available(void);
extern void test_argon2_known_answer(void);
extern void test_argon2_matches_openssl(void);
extern void test_argon2_derive(void);
extern void test_argon2_deterministic(void);
extern void test_argon2_different_passwords(void);
extern void test_argon2_different_salts(void);
extern void test_argon2_rejects_bad_input(void);
extern void test_argon2_roundtrip_encrypt(void);

/* test_portscan.c */
extern void test_portscan_finds_open_port(void);
extern void test_portscan_closed_port(void);
extern void test_portscan_range_validation(void);
extern void test_portscan_banner_grab(void);
extern void test_portscan_multiple_ports(void);

/* test_socks5.c */
extern void test_socks5_server_clean_exit(void);
extern void test_socks5_client_binds(void);

/* test_filetx.c */
extern void test_filetx_send_no_file(void);
extern void test_filetx_recv_bad_header(void);
extern void test_filetx_roundtrip_real(void);
extern void test_filetx_resume_real(void);

/* test_hardening.c */
extern void test_secret_from_arg_scrubs_argv(void);
extern void test_secret_from_file(void);
extern void test_secret_from_file_rejects_empty(void);
extern void test_secret_from_env_unsets(void);
extern void test_acl_default_policy(void);
extern void test_acl_allow_list(void);
extern void test_acl_rejects_bad_lists(void);
extern void test_filetx_sanitize_real(void);

/* test_spake2.c */
extern void test_spake2_rfc9382_vectors(void);
extern void test_spake2_properties(void);
extern void test_spake2_rejects_bad_points(void);

/* test_pake.c */
extern void test_pake_wrong_password_reported_on_server(void);
extern void test_pake_old_v3_server(void);
extern void test_pake_old_v3_client(void);
extern void test_pake_option_mismatch(void);
extern void test_pake_pq_roundtrip(void);
extern void test_pake_mitm_transcript_tamper(void);
extern void test_pake_mitm_passthrough(void);
extern void test_pake_udp_retransmit(void);

/* test_iplimit.c */
extern void test_iplimit_keys(void);
extern void test_iplimit_concurrency(void);
extern void test_iplimit_auth_lockout(void);
extern void test_iplimit_eviction_keeps_blocks(void);

/* test_pad.c */
extern void test_pad_record_sizes(void);
extern void test_pad_mismatch_rejected(void);
extern void test_pad_handshake_mismatch(void);
extern void test_pad_handshake_both(void);

/* test_users.c */
extern void test_users_names_and_scalars(void);
extern void test_users_file(void);
extern void test_users_handshake(void);

/* test_reverse.c */
extern void test_persist_backoff_initial(void);
extern void test_persist_backoff_exponential(void);
extern void test_persist_backoff_max(void);
extern void test_persist_heartbeat_detect(void);
extern void test_persist_backoff_jitter(void);
extern void test_persist_heartbeat_ignores_data(void);

/* test_tun.c */
extern void test_tun_parse_cidr(void);
extern void test_tun_parse_cidr_default(void);
extern void test_tun_parse_cidr_16(void);
extern void test_tun_parse_cidr_invalid_prefix(void);
extern void test_tun_parse_cidr_null(void);
extern void test_tun_validate_config_ok(void);
extern void test_tun_validate_config_bad_ip(void);
extern void test_tun_validate_config_bad_prefix(void);
extern void test_tun_constants(void);
extern void test_tun_udp_encrypt_decrypt(void);
extern void test_tun_udp_tamper_detect(void);
extern void test_tun_udp_wrong_key(void);
extern void test_tun_udp_wire_format(void);
extern void test_tun_udp_constants(void);
extern void test_tun_udp_truncated(void);
extern void test_tun_udp_bad_magic(void);
extern void test_tun_udp_replay_window(void);
extern void test_tun_parse_cidr_rejects_injection(void);
extern void test_tun_valid_ifname(void);

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

    /* Protocol v3 security regressions */
    test_sec_roles_roundtrip();
    test_sec_reflection_rejected();
    test_sec_edited_seq_replay_rejected();
    test_sec_header_flags_tamper_rejected();
    test_sec_version_mismatch_rejected();
    test_sec_forged_frame_leaves_buffer_untouched();
    test_sec_oversized_message_bounded();
    test_sec_large_caller_buffer_accepted();
    test_sec_write_rejects_oversize();
    test_sec_ecdhe_directional_keys();
    test_sec_wrong_password_detected();
    test_sec_old_server_detected();
    test_sec_old_client_detected();
    test_sec_udp_reorder_loss_replay();

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
    test_parse_listen_spec();
    test_listen_on_loopback_only();

    /* Compression tests */

    /* SHA-256 verification tests */

    /* Chat features */
    test_fingerprint_deterministic();

    /* State & utility tests */
    test_initialized_flag();
    test_password_roles_interop();
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
    test_mux_max_frame_roundtrip();
    test_mux_open_payload();
    test_mux_socks_parse();

    /* Fallback tests */
    test_fallback_knock_roundtrip();
    test_fallback_detects_probe();
    test_fallback_knock_magic();

    /* Fingerprint tests */
    test_fp_flag();
    test_fp_chrome_tls_roundtrip();
    test_fp_chrome_compress_cert();
    test_fp_auto_enables_tls();

    /* TOFU tests */
    test_tofu_server_init_generates_key();
    test_tofu_server_persistent_key();
    test_tofu_sign_verify();
    test_tofu_known_hosts();
    test_tofu_ecdhe_roundtrip();
    test_tofu_fingerprint_format();

    /* Post-Quantum KEM tests */
    test_pq_available();
    test_pq_keygen();
    test_pq_encap_decap();
    test_pq_different_secrets();
    test_pq_tampered_ct();
    test_pq_ecdhe_roundtrip();
    test_pq_tofu_ecdhe_roundtrip();

    /* Argon2id KDF tests */
    test_argon2_available();
    test_argon2_known_answer();
    test_argon2_matches_openssl();
    test_argon2_derive();
    test_argon2_deterministic();
    test_argon2_different_passwords();
    test_argon2_different_salts();
    test_argon2_rejects_bad_input();
    test_argon2_roundtrip_encrypt();

    /* Port scanner tests */
    test_portscan_finds_open_port();
    test_portscan_closed_port();
    test_portscan_range_validation();
    test_portscan_banner_grab();
    test_portscan_multiple_ports();

    /* SOCKS5 proxy tests */
    test_socks5_server_clean_exit();
    test_socks5_client_binds();

    /* File transfer tests */
    test_filetx_send_no_file();
    test_filetx_recv_bad_header();
    test_filetx_roundtrip_real();
    test_filetx_resume_real();

    /* Hardening: password sources, SOCKS policy, file names */
    test_secret_from_arg_scrubs_argv();
    test_secret_from_file();
    test_secret_from_file_rejects_empty();
    test_secret_from_env_unsets();
    test_acl_default_policy();
    test_acl_allow_list();
    test_acl_rejects_bad_lists();
    test_filetx_sanitize_real();

    /* SPAKE2 (RFC 9382) */
    test_spake2_rfc9382_vectors();
    test_spake2_properties();
    test_spake2_rejects_bad_points();

    /* Protocol v4 handshake */
    test_pake_wrong_password_reported_on_server();
    test_pake_old_v3_server();
    test_pake_old_v3_client();
    test_pake_option_mismatch();
    test_pake_pq_roundtrip();
    test_pake_mitm_transcript_tamper();
    test_pake_mitm_passthrough();
    test_pake_udp_retransmit();

    /* -K per-address limits */
    test_iplimit_keys();
    test_iplimit_concurrency();
    test_iplimit_auth_lockout();
    test_iplimit_eviction_keeps_blocks();

    /* --pad record padding */
    test_pad_record_sizes();
    test_pad_mismatch_rejected();
    test_pad_handshake_mismatch();
    test_pad_handshake_both();

    /* Per-user login */
    test_users_names_and_scalars();
    test_users_file();
    test_users_handshake();

    /* Reverse tunnel + persistent tests */
    test_persist_backoff_initial();
    test_persist_backoff_exponential();
    test_persist_backoff_max();
    test_persist_heartbeat_detect();
    test_persist_backoff_jitter();
    test_persist_heartbeat_ignores_data();

    /* TUN VPN tests */
    test_tun_parse_cidr();
    test_tun_parse_cidr_default();
    test_tun_parse_cidr_16();
    test_tun_parse_cidr_invalid_prefix();
    test_tun_parse_cidr_null();
    test_tun_validate_config_ok();
    test_tun_validate_config_bad_ip();
    test_tun_validate_config_bad_prefix();
    test_tun_constants();

    /* UDP VPN tests */
    test_tun_udp_encrypt_decrypt();
    test_tun_udp_tamper_detect();
    test_tun_udp_wrong_key();
    test_tun_udp_wire_format();
    test_tun_udp_constants();
    test_tun_udp_truncated();
    test_tun_udp_bad_magic();
    test_tun_udp_replay_window();
    test_tun_parse_cidr_rejects_injection();
    test_tun_valid_ifname();

    printf("\n=== Results: %d/%d passed", tests_passed, tests_run);
    if (tests_skipped) printf(" (%d skipped)", tests_skipped);
    printf(" ===\n\n");
    return (tests_passed == tests_run) ? 0 : 1;
}
