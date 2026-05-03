/*
 * obfs.c — Traffic obfuscation layer
 *
 * Three anti-DPI modes:
 *
 * OBFS_HTTP: wraps each encrypted packet as an HTTP POST/response.
 * OBFS_TLS:  wraps the entire connection in a real TLS 1.3 session.
 *            From the outside, traffic is indistinguishable from HTTPS.
 *
 * Additional anti-fingerprint features:
 * - Packet padding (obfs_pad/obfs_unpad): all packets become uniform size
 * - Timing jitter (obfs_jitter): random delays defeat timing correlation
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "obfs.h"

static int g_obfs_mode = OBFS_NONE;
static SSL_CTX *g_ssl_ctx = NULL;
static SSL     *g_ssl     = NULL;

void obfs_set_mode(int mode) {
    g_obfs_mode = mode;
}

int obfs_get_mode(void) {
    return g_obfs_mode;
}

/* Read exactly len bytes from fd */
static int obfs_read_exact(int fd, void *buf, size_t len) {
    unsigned char *p = (unsigned char *)buf;
    size_t total = 0;
    while (total < len) {
        ssize_t n = recv(fd, p + total, len - total, 0);
        if (n <= 0) {
            if (n == 0) return 0;
            if (errno == EINTR) continue;
            return -1;
        }
        total += (size_t)n;
    }
    return (int)total;
}

/* Write exactly len bytes to fd */
static int obfs_write_exact(int fd, const void *buf, size_t len) {
    const unsigned char *p = (const unsigned char *)buf;
    size_t total = 0;
    while (total < len) {
        ssize_t n = send(fd, p + total, len - total, 0);
        if (n <= 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        total += (size_t)n;
    }
    return (int)total;
}

/* Read one byte at a time until \r\n\r\n found. Returns header length or -1. */
static int obfs_read_http_header(int fd, char *hdr, size_t hdr_size) {
    size_t pos = 0;
    while (pos < hdr_size - 1) {
        ssize_t n = recv(fd, hdr + pos, 1, 0);
        if (n <= 0) {
            if (n == 0) return 0;
            if (errno == EINTR) continue;
            return -1;
        }
        pos++;
        hdr[pos] = '\0';
        if (pos >= 4 &&
            hdr[pos-4] == '\r' && hdr[pos-3] == '\n' &&
            hdr[pos-2] == '\r' && hdr[pos-1] == '\n') {
            return (int)pos;
        }
    }
    return -1; /* header too large */
}

/* Extract Content-Length from HTTP header */
static int obfs_parse_content_length(const char *hdr) {
    /* Case-insensitive search without strcasestr (portability) */
    const char *p = hdr;
    while (*p) {
        if ((p[0] == 'C' || p[0] == 'c') &&
            strncasecmp(p, "Content-Length:", 15) == 0) {
            p += 15;
            while (*p == ' ') p++;
            int len = atoi(p);
            if (len <= 0 || len > 65536) return -1;
            return len;
        }
        p++;
    }
    return -1;
}

/*
 * HTTP request paths — rotated to look like real traffic
 */
static const char *http_paths[] = {
    "/api/v1/sync",
    "/api/v2/data",
    "/cdn/assets/check",
    "/health",
    "/api/v1/telemetry",
};
#define NUM_PATHS 5
static int path_idx = 0;

int obfs_send(int fd, const void *data, size_t len) {
    if (g_obfs_mode == OBFS_NONE) {
        return obfs_write_exact(fd, data, len);
    }

    if (g_obfs_mode == OBFS_TLS) {
        /* TLS mode: write through SSL */
        if (!g_ssl) return -1;
        int ret = SSL_write(g_ssl, data, (int)len);
        return (ret > 0) ? ret : -1;
    }

    /* HTTP mode: wrap as POST request */
    char header[512];
    int hlen = snprintf(header, sizeof(header),
        "POST %s HTTP/1.1\r\n"
        "Host: cdn.cloudflare-dns.com\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %zu\r\n"
        "Connection: keep-alive\r\n"
        "\r\n",
        http_paths[path_idx % NUM_PATHS], len);
    path_idx++;

    if (obfs_write_exact(fd, header, (size_t)hlen) < 0) return -1;
    if (obfs_write_exact(fd, data, len) < 0) return -1;
    return (int)len;
}

int obfs_recv(int fd, void *buf, size_t buflen) {
    if (g_obfs_mode == OBFS_NONE) {
        ssize_t n = recv(fd, buf, buflen, 0);
        return (int)n;
    }

    if (g_obfs_mode == OBFS_TLS) {
        /* TLS mode: read through SSL */
        if (!g_ssl) return -1;
        int ret = SSL_read(g_ssl, buf, (int)buflen);
        if (ret <= 0) {
            int err = SSL_get_error(g_ssl, ret);
            if (err == SSL_ERROR_ZERO_RETURN) return 0;
            return -1;
        }
        return ret;
    }

    /* HTTP mode: read header, extract Content-Length, read payload */
    char hdr[2048];
    int hlen = obfs_read_http_header(fd, hdr, sizeof(hdr));
    if (hlen <= 0) return hlen;

    int content_len = obfs_parse_content_length(hdr);
    if (content_len < 0) return -1;
    if ((size_t)content_len > buflen) return -1;

    return obfs_read_exact(fd, buf, (size_t)content_len);
}

/* ──────────── TLS Camouflage ──────────── */

/*
 * Generate a self-signed EC (P-256) certificate at runtime.
 * The cert has a random CN that looks like a CDN domain.
 */
static const char *fake_cns[] = {
    "cdn.cloudflare.com", "edge.fastly.net", "d1.awsstatic.com",
    "assets.akamaized.net", "cdn.jsdelivr.net", "static.cloudflareinsights.com",
};
#define NUM_CNS 6

static int tls_generate_self_signed(SSL_CTX *ctx) {
    EVP_PKEY *pkey = EVP_EC_gen("P-256");
    if (!pkey) return -1;

    X509 *x509 = X509_new();
    if (!x509) { EVP_PKEY_free(pkey); return -1; }

    /* Serial = random 8 bytes */
    unsigned char serial_bytes[8];
    RAND_bytes(serial_bytes, 8);
    BIGNUM *bn_serial = BN_bin2bn(serial_bytes, 8, NULL);
    BN_to_ASN1_INTEGER(bn_serial, X509_get_serialNumber(x509));
    BN_free(bn_serial);

    /* Valid: now → now + 365 days */
    X509_gmtime_adj(X509_getm_notBefore(x509), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509), 365L * 24 * 3600);

    X509_set_pubkey(x509, pkey);

    /* Random CDN-like CN */
    unsigned char rnd;
    RAND_bytes(&rnd, 1);
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (const unsigned char *)fake_cns[rnd % NUM_CNS], -1, -1, 0);
    X509_set_issuer_name(x509, name);

    /* Sign */
    X509_sign(x509, pkey, EVP_sha256());

    SSL_CTX_use_certificate(ctx, x509);
    SSL_CTX_use_PrivateKey(ctx, pkey);

    X509_free(x509);
    EVP_PKEY_free(pkey);
    return 0;
}

int obfs_tls_accept(int fd) {
    /* Server side: wrap fd in TLS with auto-generated cert */
    g_ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!g_ssl_ctx) return -1;

    /* Force TLS 1.3 only — most modern, hardest to fingerprint */
    SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_3_VERSION);

    if (tls_generate_self_signed(g_ssl_ctx) < 0) {
        SSL_CTX_free(g_ssl_ctx); g_ssl_ctx = NULL;
        return -1;
    }

    g_ssl = SSL_new(g_ssl_ctx);
    if (!g_ssl) {
        SSL_CTX_free(g_ssl_ctx); g_ssl_ctx = NULL;
        return -1;
    }

    SSL_set_fd(g_ssl, fd);
    if (SSL_accept(g_ssl) <= 0) {
        SSL_free(g_ssl); g_ssl = NULL;
        SSL_CTX_free(g_ssl_ctx); g_ssl_ctx = NULL;
        return -1;
    }
    return 0;
}

int obfs_tls_connect(int fd) {
    /* Client side: connect to TLS server, skip cert verification
       (we have our own crypto layer inside — cert is just camouflage) */
    g_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_ssl_ctx) return -1;

    SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_3_VERSION);
    /* No cert verification — the inner ECDHE+PBKDF2 layer provides authentication */
    SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, NULL);

    g_ssl = SSL_new(g_ssl_ctx);
    if (!g_ssl) {
        SSL_CTX_free(g_ssl_ctx); g_ssl_ctx = NULL;
        return -1;
    }

    /* Set a realistic SNI hostname */
    unsigned char rnd;
    RAND_bytes(&rnd, 1);
    SSL_set_tlsext_host_name(g_ssl, fake_cns[rnd % NUM_CNS]);

    SSL_set_fd(g_ssl, fd);
    if (SSL_connect(g_ssl) <= 0) {
        SSL_free(g_ssl); g_ssl = NULL;
        SSL_CTX_free(g_ssl_ctx); g_ssl_ctx = NULL;
        return -1;
    }
    return 0;
}

/* ──────────── Packet Padding ──────────── */

int obfs_pad(const void *data, size_t len, void *out, size_t out_max) {
    if (len > OBFS_PAD_SIZE - 2 || out_max < OBFS_PAD_SIZE) return -1;

    unsigned char *p = (unsigned char *)out;
    /* 2-byte big-endian real length */
    p[0] = (unsigned char)((len >> 8) & 0xFF);
    p[1] = (unsigned char)(len & 0xFF);
    memcpy(p + 2, data, len);

    /* Fill remainder with random bytes (not zeros — defeats entropy analysis) */
    size_t pad_len = OBFS_PAD_SIZE - 2 - len;
    if (pad_len > 0)
        RAND_bytes(p + 2 + len, (int)pad_len);

    return OBFS_PAD_SIZE;
}

int obfs_unpad(const void *data, size_t len, void *out, size_t out_max) {
    if (len < 2) return -1;
    const unsigned char *p = (const unsigned char *)data;
    size_t real_len = ((size_t)p[0] << 8) | p[1];
    if (real_len > len - 2 || real_len > out_max) return -1;
    memcpy(out, p + 2, real_len);
    return (int)real_len;
}

/* ──────────── Timing Jitter ──────────── */

void obfs_jitter(int max_ms) {
    if (max_ms <= 0) return;
    unsigned int rnd;
    RAND_bytes((unsigned char *)&rnd, sizeof(rnd));
    int delay_us = (int)((rnd % (unsigned int)max_ms) * 1000);
    usleep((useconds_t)delay_us);
}
