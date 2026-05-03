#ifndef CLAWSEC_FINGERPRINT_H
#define CLAWSEC_FINGERPRINT_H

#include <openssl/ssl.h>

/*
 * TLS ClientHello fingerprint profiles.
 *
 * Shapes the TLS handshake to mimic a specific browser:
 *   - Cipher suite order (TLS 1.3 + 1.2)
 *   - Supported groups / curves
 *   - Signature algorithms
 *   - ALPN (h2, http/1.1)
 *   - Custom extensions (compress_certificate for Chrome)
 *
 * DPI systems match JA3/JA4 fingerprints against known browser
 * databases.  Without fingerprinting, OpenSSL's default ClientHello
 * stands out as a non-browser TLS client.
 */

#define FP_NONE    0
#define FP_CHROME  1
#define FP_FIREFOX 2
#define FP_SAFARI  3

void fp_set_profile(int profile);
int  fp_get_profile(void);

/*
 * Apply fingerprint settings to an SSL_CTX (client side).
 * Must be called after SSL_CTX_new, before SSL_new.
 * Returns 0 on success.
 */
int fp_apply_ctx(SSL_CTX *ctx);

#endif
