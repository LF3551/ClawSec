/*
 * tofu.c — Trust On First Use (SSH-like server identity)
 *
 * Server: persistent Ed25519 identity key in ~/.clawsec/identity
 * Client: known_hosts verification in ~/.clawsec/known_hosts
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include "tofu.h"

int g_tofu = 0;

static EVP_PKEY *s_identity_key = NULL;
static unsigned char s_identity_pubkey[TOFU_ED25519_PUBKEY_LEN];

/* ──────── Path helpers ──────── */

static int tofu_get_dir(char *buf, size_t buflen) {
    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        if (!pw) return -1;
        home = pw->pw_dir;
    }
    int n = snprintf(buf, buflen, "%s/.clawsec", home);
    return (n > 0 && (size_t)n < buflen) ? 0 : -1;
}

static int tofu_ensure_dir(void) {
    char dir[512];
    if (tofu_get_dir(dir, sizeof(dir)) < 0) return -1;
    if (mkdir(dir, 0700) < 0 && errno != EEXIST) return -1;
    return 0;
}

/* ──────── Server: identity key management ──────── */

int tofu_server_init(void) {
    if (tofu_ensure_dir() < 0) return -1;

    char dir[512];
    if (tofu_get_dir(dir, sizeof(dir)) < 0) return -1;

    char keypath[576];
    snprintf(keypath, sizeof(keypath), "%s/identity", dir);

    /* Try to load existing key */
    FILE *fp = fopen(keypath, "r");
    if (fp) {
        s_identity_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
        fclose(fp);
        if (!s_identity_key) {
            fprintf(stderr, "ERROR: Failed to read identity key from %s\n", keypath);
            return -1;
        }
    } else {
        /* Generate new Ed25519 keypair */
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
        if (!pctx) return -1;
        if (EVP_PKEY_keygen_init(pctx) <= 0 ||
            EVP_PKEY_keygen(pctx, &s_identity_key) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            return -1;
        }
        EVP_PKEY_CTX_free(pctx);

        /* Save private key (0600) */
        int fd = open(keypath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) {
            EVP_PKEY_free(s_identity_key);
            s_identity_key = NULL;
            return -1;
        }
        fp = fdopen(fd, "w");
        if (!fp || !PEM_write_PrivateKey(fp, s_identity_key, NULL, NULL, 0, NULL, NULL)) {
            if (fp) fclose(fp); else close(fd);
            EVP_PKEY_free(s_identity_key);
            s_identity_key = NULL;
            return -1;
        }
        fclose(fp);

        char fpstr[65];
        size_t pk_len = TOFU_ED25519_PUBKEY_LEN;
        EVP_PKEY_get_raw_public_key(s_identity_key, s_identity_pubkey, &pk_len);
        tofu_format_fingerprint(s_identity_pubkey, fpstr, sizeof(fpstr));
        fprintf(stderr, "TOFU: Generated new server identity key\n");
        fprintf(stderr, "TOFU: Fingerprint: %s\n", fpstr);
    }

    /* Extract public key */
    size_t pk_len = TOFU_ED25519_PUBKEY_LEN;
    if (EVP_PKEY_get_raw_public_key(s_identity_key, s_identity_pubkey, &pk_len) != 1) {
        EVP_PKEY_free(s_identity_key);
        s_identity_key = NULL;
        return -1;
    }

    return 0;
}

int tofu_server_sign(const unsigned char *data, size_t data_len,
                     unsigned char *sig_out) {
    if (!s_identity_key) return -1;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return -1;

    if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, s_identity_key) <= 0) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    size_t sig_len = TOFU_ED25519_SIGLEN;
    if (EVP_DigestSign(mdctx, sig_out, &sig_len, data, data_len) <= 0) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);
    return 0;
}

const unsigned char *tofu_server_get_pubkey(void) {
    return s_identity_key ? s_identity_pubkey : NULL;
}

void tofu_server_cleanup(void) {
    if (s_identity_key) {
        EVP_PKEY_free(s_identity_key);
        s_identity_key = NULL;
    }
    memset(s_identity_pubkey, 0, sizeof(s_identity_pubkey));
}

/* ──────── Client: signature verification ──────── */

int tofu_verify_signature(const unsigned char *pubkey,
                          const unsigned char *data, size_t data_len,
                          const unsigned char *sig, size_t sig_len) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                                  pubkey, TOFU_ED25519_PUBKEY_LEN);
    if (!pkey) return 0;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) { EVP_PKEY_free(pkey); return 0; }

    int ok = 0;
    if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pkey) > 0) {
        ok = (EVP_DigestVerify(mdctx, sig, sig_len, data, data_len) == 1);
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return ok;
}

/* ──────── Client: known_hosts management ──────── */

int tofu_check_known_host(const char *host, const char *port,
                          const unsigned char *pubkey) {
    if (tofu_ensure_dir() < 0) return -2;

    char dir[512];
    if (tofu_get_dir(dir, sizeof(dir)) < 0) return -2;

    char path[576];
    snprintf(path, sizeof(path), "%s/known_hosts", dir);

    char new_fp[65];
    tofu_format_fingerprint(pubkey, new_fp, sizeof(new_fp));

    /* Search for existing entry */
    FILE *fp = fopen(path, "r");
    if (fp) {
        char line[512];
        char needle[320];
        snprintf(needle, sizeof(needle), "%s:%s ", host, port);
        size_t needle_len = strlen(needle);

        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, needle, needle_len) == 0) {
                fclose(fp);
                /* Found entry — compare pubkey */
                const char *saved_fp = line + needle_len;
                if (strncmp(saved_fp, new_fp, 64) == 0) {
                    return 1;  /* Match */
                }
                /* MISMATCH — possible MITM */
                fprintf(stderr,
                    "\n"
                    "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
                    "@ WARNING: SERVER IDENTITY HAS CHANGED!              @\n"
                    "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
                    "Someone may be performing a man-in-the-middle attack.\n"
                    "The server identity key for %s:%s has changed.\n\n"
                    "Expected: %.64s\n"
                    "Received: %s\n\n"
                    "If this is expected (server reinstalled), remove the\n"
                    "old entry from ~/.clawsec/known_hosts and reconnect.\n"
                    "Connection aborted.\n",
                    host, port, saved_fp, new_fp);
                return -1;
            }
        }
        fclose(fp);
    }

    /* New host — save and display fingerprint */
    fp = fopen(path, "a");
    if (!fp) return -2;
    fprintf(fp, "%s:%s %s\n", host, port, new_fp);
    fclose(fp);

    fprintf(stderr,
        "TOFU: New server identity for %s:%s\n"
        "TOFU: Fingerprint: %s\n"
        "TOFU: Saved to ~/.clawsec/known_hosts\n",
        host, port, new_fp);

    return 0;
}

/* ──────── Utility ──────── */

void tofu_format_fingerprint(const unsigned char *pubkey, char *out, size_t out_len) {
    if (out_len < 65) { out[0] = '\0'; return; }
    for (int i = 0; i < TOFU_ED25519_PUBKEY_LEN; i++) {
        snprintf(out + i * 2, 3, "%02x", pubkey[i]);
    }
    out[64] = '\0';
}
