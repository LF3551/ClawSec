/*
 *  farm9crypt.h
 *
 *  C interface between netcat and AES-GCM encryption.
 *
 *  Wire protocol v4 (ClawSec 4.x):
 *  - Handshake: SPAKE2 PAKE (RFC 9382) with mutual key confirmation over the
 *    whole transcript; optional Ed25519 server identity and ML-KEM-768 hybrid
 *  - AES-256-GCM authenticated encryption; the 16-byte frame header
 *    (magic, version, flags, sequence, length) is authenticated as AAD
 *  - Independent keys per direction (client->server / server->client),
 *    derived with HKDF-SHA256 from the handshake session key
 *  - Strict in-order sequence numbers (replay / reorder / reflection rejected)
 *  - Plaintext is released to the caller only after the tag is verified
 *
 *  NOTE: This file must be included within "extern C {...}" when included in C++
 */

/* Endpoint roles. Each side must use the opposite role of its peer; the role
 * selects which directional key is used for sending and which for receiving. */
#define FARM9_ROLE_CLIENT 0
#define FARM9_ROLE_SERVER 1

/* Initialize from a password and a fixed built-in salt.
 * Intended for tests/local use only: production sessions use ECDHE below. */
int farm9crypt_init_password(const char* password, size_t pass_len, int server_mode);

/* Initialize from a password + explicit salt (salt_len >= FARM9_SALT_LEN). */
int farm9crypt_init_password_with_salt(const char* password, size_t pass_len,
                                       const unsigned char* salt, size_t salt_len,
                                       int server_mode);

/* Password-authenticated handshake (SPAKE2, forward secrecy).
 * Returns 0 on success, -1 on error (see farm9crypt_last_failure()).
 * server_mode selects the handshake role and the session role (FARM9_ROLE_*). */
int farm9crypt_init_ecdhe(int sockfd, const char* password, size_t pass_len, int server_mode);

/* With TOFU: same as above plus server identity verification.
 * Server: signs the handshake transcript with its Ed25519 identity key.
 * Client: verifies signature and checks known_hosts for host:port.
 * peer_host/peer_port: remote address (used by client for known_hosts lookup). */
int farm9crypt_init_ecdhe_tofu(int sockfd, const char* password, size_t pass_len,
                                int server_mode, const char *peer_host, const char *peer_port);

/* Post-quantum hybrid: SPAKE2 + ML-KEM-768 (+ TOFU if g_tofu is set).
 * The session key depends on both the SPAKE2 secret and the ML-KEM shared
 * secret, so recorded traffic stays confidential against a future quantum
 * adversary as long as ML-KEM holds. */
int farm9crypt_init_ecdhe_pq(int sockfd, const char* password, size_t pass_len,
                              int server_mode, const char *peer_host, const char *peer_port);

/* Derive and cache the password scalar once (Argon2id) before serving
 * connections; handshakes then skip the expensive KDF. Returns 0 or -1. */
int farm9crypt_prepare_password(const char* password, size_t pass_len);

/* Record padding (--pad). Set before the handshake: it is announced in the
 * hello and both ends must agree. farm9crypt_max_payload() is the largest
 * message that still fits one FARM9_PAD_UNIT record when padding is on
 * (FARM9_MAX_MSG otherwise); modes that chunk data use it so that records
 * have a uniform size. */
void farm9crypt_set_padding(int enabled);
int  farm9crypt_padding(void);
int  farm9crypt_max_payload(void);

/* --rekey: update the stream keys every `seconds` and/or every `records`
 * sent records (0 = off; at least one must be set to enable). Set before
 * the handshake: it is announced there and both ends must use it. */
void farm9crypt_set_rekey(int seconds, unsigned long long records);
int  farm9crypt_rekey(void);
/* Number of key updates sent / received in this session (tests, logs) */
void farm9crypt_key_updates(unsigned long *sent, unsigned long *received);

/* Set UDP datagram mode (must be called before read/write) */
void farm9crypt_set_udp_mode(int enabled);

/* Generate random salt for session handshake */
int farm9crypt_generate_salt(unsigned char* salt_out, size_t len);

/* Enable debug output */
void farm9crypt_debug();

/* Check if encryption is initialized */
int farm9crypt_initialized();

/* Encrypted read.
 * Returns plaintext length, 0 on orderly close, -1 on error (errno set):
 *   EBADMSG          authentication failed (tampered/forged/reflected frame)
 *   EPROTO           bad magic, unexpected sequence number or malformed frame
 *   EPROTONOSUPPORT  peer uses a different protocol version
 *   EMSGSIZE         authenticated message larger than `size` (nothing copied)
 *   EOVERFLOW        sequence space exhausted; the session must be re-established
 *   EAGAIN           (UDP mode only) every queued datagram was invalid and was
 *                    dropped; nothing to deliver right now, try again later
 * In UDP mode (farm9crypt_set_udp_mode) lost and reordered datagrams are
 * tolerated: a 64-entry sliding window rejects duplicates and stale ones, and
 * forged/corrupted datagrams are dropped instead of ending the session.
 * The caller's buffer is written only with authenticated plaintext and never
 * beyond `size` bytes. Buffers larger than FARM9_MAX_MSG are accepted. */
int farm9crypt_read(int sockfd, char* buf, int size);

/* Encrypted write of 1..FARM9_MAX_MSG bytes.
 * Returns bytes written or -1 on error (EINVAL, EOVERFLOW, or socket errors). */
int farm9crypt_write(int sockfd, char* buf, int size);

/* Clean up and free resources */
void farm9crypt_cleanup();

/* Export this endpoint's 32-byte UDP VPN data-channel keys:
 * tx_key encrypts datagrams we send, rx_key decrypts datagrams we receive.
 * They are derived independently of the TCP keys and of each other.
 * Returns 0 on success, -1 if not initialized or bad params. */
int farm9crypt_export_udp_keys(unsigned char tx_key[32], unsigned char rx_key[32]);

/* Why the last handshake failed, for callers that must tell permanent
 * failures (no point in retrying) from network errors. */
#define FARM9_FAIL_NONE    0   /* success, or a transport/network error */
#define FARM9_FAIL_AUTH    1   /* key confirmation failed: wrong password or tampering */
#define FARM9_FAIL_VERSION 2   /* peer speaks another protocol version / not ClawSec */
#define FARM9_FAIL_CONFIG  3   /* peer uses different --tofu / --pq settings */
int  farm9crypt_last_failure(void);
void farm9crypt_set_failure(int reason);   /* used by the handshake code */

/* Get session fingerprint (identical on both ends of a session) */
/* Returns bytes written, or -1 on error */
int farm9crypt_get_fingerprint(unsigned char *out, size_t len);

/* Protocol constants */
#define FARM9_MAGIC 0x434C4157     /* "CLAW" */
#define FARM9_VERSION 0x0004       /* Protocol version 4 (ClawSec 4.x: SPAKE2 handshake) */
#define FARM9_IV_LEN 12            /* AES-GCM IV length */
#define FARM9_TAG_LEN 16           /* AES-GCM auth tag length */
#define FARM9_SALT_LEN 16          /* KDF salt length */
#define FARM9_KEY_LEN 32           /* AES-256 key length */
#define FARM9_HEADER_LEN 16        /* magic(4) version(2) flags(2) seq(4) length(4) */
#define FARM9_MAX_MSG 8192         /* Maximum plaintext size per message */

/* --pad: record padding. The plaintext of every record becomes
 * [u16 BE length][data][random bytes], padded to a multiple of
 * FARM9_PAD_UNIT; the header carries FARM9_FLAG_PADDED (authenticated).
 * Negotiated in the handshake, so both ends always agree. */
#define FARM9_PAD_UNIT 1400
#define FARM9_FLAG_PADDED 0x0001
/* --rekey: a record with this flag carries one byte 0x01; after it the
 * sender's stream key becomes HKDF(key, "ClawSec v4 key update") and its
 * sequence number restarts at 0 (one-way ratchet, like TLS 1.3 KeyUpdate).
 * Negotiated in the handshake; never used in UDP mode. */
#define FARM9_FLAG_KEYUPDATE 0x0002
#define FARM9_MAX_WIRE (((FARM9_MAX_MSG + 2 + FARM9_PAD_UNIT - 1) / FARM9_PAD_UNIT) * FARM9_PAD_UNIT)
