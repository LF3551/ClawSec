#ifndef CLAWSEC_TOFU_H
#define CLAWSEC_TOFU_H

#include <stddef.h>

/*
 * TOFU (Trust On First Use) — SSH-like server identity verification.
 *
 * Server has a persistent Ed25519 identity keypair.
 * During handshake, server signs its ephemeral X25519 pubkey.
 * Client verifies signature and checks known_hosts:
 *   - First connection: save identity pubkey, show fingerprint
 *   - Reconnection: verify identity matches saved pubkey
 *   - Mismatch: WARNING and abort (possible MITM)
 *
 * Files:
 *   ~/.clawsec/identity     — server Ed25519 private key (PEM)
 *   ~/.clawsec/identity.pub — server Ed25519 public key (raw 32 bytes hex)
 *   ~/.clawsec/known_hosts  — client: "host:port <hex_pubkey>\n"
 */

#define TOFU_ED25519_PUBKEY_LEN 32
#define TOFU_ED25519_SIGLEN     64

/* Global TOFU state */
extern int g_tofu;

/*
 * Server: load or generate persistent Ed25519 identity keypair.
 * Stores in ~/.clawsec/identity (PEM) and ~/.clawsec/identity.pub.
 * Returns 0 on success, -1 on error.
 */
int tofu_server_init(void);

/*
 * Server: sign data (ephemeral X25519 pubkey) with identity key.
 * out must be at least TOFU_ED25519_SIGLEN bytes.
 * Returns 0 on success, -1 on error.
 */
int tofu_server_sign(const unsigned char *data, size_t data_len,
                     unsigned char *sig_out);

/*
 * Server: get identity public key (32 bytes).
 * Returns pointer to internal buffer (valid until tofu_server_cleanup).
 */
const unsigned char *tofu_server_get_pubkey(void);

/*
 * Server: cleanup identity key resources.
 */
void tofu_server_cleanup(void);

/*
 * Client: verify Ed25519 signature.
 * Returns 1 if valid, 0 if invalid.
 */
int tofu_verify_signature(const unsigned char *pubkey,
                          const unsigned char *data, size_t data_len,
                          const unsigned char *sig, size_t sig_len);

/*
 * Client: check/store server identity in known_hosts.
 *   host, port: server address
 *   pubkey: server Ed25519 public key (32 bytes)
 *
 * Returns:
 *    1 = known host, identity matches (OK)
 *    0 = new host, saved to known_hosts (first contact)
 *   -1 = KNOWN HOST, IDENTITY CHANGED (possible MITM!)
 *   -2 = error (file I/O, etc.)
 */
int tofu_check_known_host(const char *host, const char *port,
                          const unsigned char *pubkey);

/*
 * Format Ed25519 public key as hex fingerprint string.
 * out must be at least 65 bytes (32*2 + null).
 */
void tofu_format_fingerprint(const unsigned char *pubkey, char *out, size_t out_len);

#endif
