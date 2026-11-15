/*
 *  farm9crypt.h
 *
 *  C interface between netcat and AES-GCM encryption.
 *
 *  Wire protocol v3 (ClawSec 3.x):
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

/* Initialize with ECDHE + password (Perfect Forward Secrecy) */
/* Returns: 0 on success, -1 on error */
/* server_mode: 1 = generate keypair and write pubkey to sockfd, read peer pubkey */
/*              0 = read peer pubkey from sockfd, generate keypair and write pubkey */
/* server_mode is also the session role (FARM9_ROLE_*) for directional keys. */
int farm9crypt_init_ecdhe(int sockfd, const char* password, size_t pass_len, int server_mode);

/* ECDHE with TOFU: same as above but with server identity verification.
 * Server: signs ephemeral pubkey with Ed25519 identity key.
 * Client: verifies signature and checks known_hosts for host:port.
 * peer_host/peer_port: remote address (used by client for known_hosts lookup). */
int farm9crypt_init_ecdhe_tofu(int sockfd, const char* password, size_t pass_len,
                                int server_mode, const char *peer_host, const char *peer_port);

/* Post-Quantum Hybrid ECDHE: X25519 + ML-KEM-768 (+ optional TOFU).
 * Uses both classical ECDHE and quantum-resistant KEM so the session key
 * is secure against both classical and quantum adversaries.
 * If g_tofu is set, X25519 phase includes Ed25519 identity signing. */
int farm9crypt_init_ecdhe_pq(int sockfd, const char* password, size_t pass_len,
                              int server_mode, const char *peer_host, const char *peer_port);

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

/* Get session fingerprint (identical on both ends of a session) */
/* Returns bytes written, or -1 on error */
int farm9crypt_get_fingerprint(unsigned char *out, size_t len);

/* Protocol constants */
#define FARM9_MAGIC 0x434C4157     /* "CLAW" */
#define FARM9_VERSION 0x0003       /* Protocol version 3 (ClawSec 3.x: authenticated header, directional keys) */
#define FARM9_IV_LEN 12            /* AES-GCM IV length */
#define FARM9_TAG_LEN 16           /* AES-GCM auth tag length */
#define FARM9_SALT_LEN 16          /* KDF salt length */
#define FARM9_KEY_LEN 32           /* AES-256 key length */
#define FARM9_HEADER_LEN 16        /* magic(4) version(2) flags(2) seq(4) length(4) */
#define FARM9_MAX_MSG 8192         /* Maximum plaintext size per message */
