/*
 * ecdhe.cc — ClawSec v4 handshake: SPAKE2 (RFC 9382) PAKE, optional
 * Ed25519 server identity (TOFU) and optional ML-KEM-768 hybrid.
 *
 * Wire protocol 4 (all messages are sent as one unit; fixed layouts):
 *
 *   hello = "CS" || u16 version (=4) || u16 flags      flags: 1 = TOFU, 2 = PQ
 *
 *   1  S->C  hello || pB (65) || [server Ed25519 pubkey (32)] || [ML-KEM pubkey (1184)]
 *   2  C->S  hello || pA (65) || [ML-KEM ciphertext (1088)]
 *   3  S->C  cB (32) || [Ed25519 signature (64)]
 *   4  C->S  cA (32)
 *
 *   AAD     = SHA-256(msg1 || msg2)                    (whole transcript)
 *   SPAKE2  : A = client, B = server, identities "ClawSec v4 client/server",
 *             confirmation keys bound to AAD (RFC 9382 section 4)
 *   sig     = Ed25519(identity, "ClawSec v4 server signature" || Hash(TT) || AAD)
 *   session = HKDF-SHA256(Ke || [ML-KEM shared secret],
 *                         info = "ClawSec v4 session" || AAD)
 *
 * The password is never used as a plain DH key: a man-in-the-middle can test
 * one password guess per connection and cannot run an offline dictionary
 * attack against a captured or interfered handshake. Both confirmation MACs
 * and the signature cover the complete transcript (versions, flags, identity
 * key, KEM data), so any modification is detected.
 *
 * w = Argon2id(password) is computed once per process and cached.
 */

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <sys/time.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

extern "C"
{
#include "ecdhe.h"
#include "obfs.h"
#include "tofu.h"
#include "pqkem.h"
#include "spake2.h"
#include "farm9crypt.h"
#include "version.h"
#include "users.h"
}

/* Secure memory cleanup */
static void secure_zero(void *ptr, size_t len) {
    OPENSSL_cleanse(ptr, len);
}

/* ---------- obfs-aware I/O ---------- */

extern "C" int ecdhe_send(int sockfd, const void *buf, size_t len) {
    if (obfs_get_mode() != OBFS_NONE)
        return obfs_send(sockfd, buf, len) < 0 ? -1 : 0;
    size_t total = 0;
    const unsigned char *ptr = (const unsigned char *)buf;
    while (total < len) {
        ssize_t n = send(sockfd, ptr + total, len - total, 0);
        if (n <= 0) { if (errno == EINTR) continue; return -1; }
        total += n;
    }
    return 0;
}

extern "C" int ecdhe_recv(int sockfd, void *buf, size_t len) {
    size_t total = 0;
    unsigned char *ptr = (unsigned char *)buf;
    if (obfs_get_mode() == OBFS_HTTP) {
        /* One HTTP body per handshake message: it must be exactly len bytes */
        return obfs_recv(sockfd, buf, len) == (int)len ? 0 : -1;
    }
    if (obfs_get_mode() == OBFS_TLS) {
        /* A TLS read may return less than requested: keep reading */
        while (total < len) {
            int n = obfs_recv(sockfd, ptr + total, len - total);
            if (n <= 0) return -1;
            total += (size_t)n;
        }
        return 0;
    }
    while (total < len) {
        ssize_t n = recv(sockfd, ptr + total, len - total, 0);
        if (n <= 0) { if (n == 0) return -1; if (errno == EINTR) continue; return -1; }
        total += n;
    }
    return 0;
}

/* ---------- Password scalar cache ---------- */

#define W_SALT "ClawSec v4 SPAKE2 password scalar"
static unsigned char cached_pw_hash[32];
static unsigned char cached_w[SPAKE2_SCALAR_LEN];
static int cached_valid = 0;

static char s_user[USER_NAME_MAX + 1];          /* client: --user */
static const char *s_users_file = NULL;          /* server: --users */
static char s_peer_user[USER_NAME_MAX + 1];      /* server: name sent by the client */

extern "C" int ecdhe_set_user(const char *name) {
    if (name && !user_name_valid(name)) return -1;
    snprintf(s_user, sizeof(s_user), "%s", name ? name : "");
    cached_valid = 0;
    return 0;
}

extern "C" void ecdhe_set_users_file(const char *path) { s_users_file = path; }

extern "C" const char *ecdhe_peer_user(void) { return s_peer_user[0] ? s_peer_user : NULL; }

extern "C" int ecdhe_prepare_password(const char *password, size_t pass_len) {
    unsigned char h[32];
    if (!password || pass_len == 0) return -1;
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    int ok = md && EVP_DigestInit_ex(md, EVP_sha256(), NULL) &&
             EVP_DigestUpdate(md, s_user, strlen(s_user) + 1) &&   /* user, NUL, password */
             EVP_DigestUpdate(md, password, pass_len) && EVP_DigestFinal_ex(md, h, NULL);
    EVP_MD_CTX_free(md);
    if (!ok) return -1;
    if (cached_valid && CRYPTO_memcmp(h, cached_pw_hash, 32) == 0) return 0;
    int rc = s_user[0]
        ? user_password_to_w(s_user, password, pass_len, cached_w)
        : spake2_password_to_w(password, pass_len, (const unsigned char *)W_SALT,
                               sizeof(W_SALT) - 1, cached_w);
    if (rc != 0) {
        secure_zero(h, sizeof(h));
        return -1;
    }
    memcpy(cached_pw_hash, h, 32);
    cached_valid = 1;
    secure_zero(h, sizeof(h));
    return 0;
}

extern "C" void ecdhe_forget_password(void) {
    secure_zero(cached_w, sizeof(cached_w));
    secure_zero(cached_pw_hash, sizeof(cached_pw_hash));
    cached_valid = 0;
}

/* ---------- Message framing ---------- */

#define HELLO_LEN   6
#define FLAG_TOFU   0x0001
#define FLAG_PQ     0x0002
#define FLAG_PAD    0x0004
#define FLAG_USER   0x0008      /* per-user passwords (--users / --user) */
#define ID_CLIENT   "ClawSec v4 client"
#define ID_SERVER   "ClawSec v4 server"
#define SIG_LABEL   "ClawSec v4 server signature"
#define KEY_LABEL   "ClawSec v4 session"
#define SIG_LEN     64
#define ID_PUB_LEN  32

#define MSG1_MAX (HELLO_LEN + SPAKE2_POINT_LEN + ID_PUB_LEN + PQ_KEM_PUBKEY_LEN)
#define MSG2_MAX (HELLO_LEN + 1 + USER_NAME_MAX + SPAKE2_POINT_LEN + PQ_KEM_CT_LEN)
#define MSG3_MAX (SPAKE2_POINT_LEN + SPAKE2_CONF_LEN + SIG_LEN)

/* With FLAG_USER the server cannot compute pB before it knows the user:
 * pB moves from message 1 to message 3, and message 2 carries the name. */
static size_t msg1_len(unsigned flags) {
    return HELLO_LEN + ((flags & FLAG_USER) ? 0 : SPAKE2_POINT_LEN) +
           ((flags & FLAG_TOFU) ? ID_PUB_LEN : 0) + ((flags & FLAG_PQ) ? PQ_KEM_PUBKEY_LEN : 0);
}
static size_t msg2_len(unsigned flags, size_t user_len) {
    return HELLO_LEN + ((flags & FLAG_USER) ? 1 + user_len : 0) + SPAKE2_POINT_LEN +
           ((flags & FLAG_PQ) ? PQ_KEM_CT_LEN : 0);
}
static size_t msg3_len(unsigned flags) {
    return ((flags & FLAG_USER) ? SPAKE2_POINT_LEN : 0) + SPAKE2_CONF_LEN +
           ((flags & FLAG_TOFU) ? SIG_LEN : 0);
}

static void hello_build(unsigned char out[HELLO_LEN], unsigned flags) {
    out[0] = 'C';
    out[1] = 'S';
    out[2] = (unsigned char)(FARM9_VERSION >> 8);
    out[3] = (unsigned char)(FARM9_VERSION & 0xff);
    out[4] = (unsigned char)(flags >> 8);
    out[5] = (unsigned char)(flags & 0xff);
}

static const char *flag_names(unsigned f, char *buf, size_t len) {
    buf[0] = '\0';
    if (f & FLAG_TOFU) strncat(buf, " --tofu", len - strlen(buf) - 1);
    if (f & FLAG_PQ)   strncat(buf, " --pq", len - strlen(buf) - 1);
    if (f & FLAG_PAD)  strncat(buf, " --pad", len - strlen(buf) - 1);
    if (f & FLAG_USER) strncat(buf, " per-user login (--users/--user)", len - strlen(buf) - 1);
    if (f & ~(unsigned)(FLAG_TOFU | FLAG_PQ | FLAG_PAD | FLAG_USER))
        strncat(buf, " (options unknown to this version)", len - strlen(buf) - 1);
    if (!buf[0]) strncat(buf, " none of --tofu/--pq/--pad/--user", len - 1);
    return buf + 1;
}

/* Validate the first 4 bytes (magic + version). len = bytes available.
 * (In UDP mode the connecting side takes the server role, so messages say
 * "the other end" rather than client/server.) */
static int hello_version_ok(const unsigned char *buf, size_t len) {
    const char *who = "other end";
    if (len < 4 || buf[0] != 'C' || buf[1] != 'S') {
        farm9crypt_set_failure(FARM9_FAIL_VERSION);
        fprintf(stderr, "[ClawSec] Error: the %s does not speak the ClawSec protocol "
                        "(or uses different --obfs / -u settings)\n", who);
        return -1;
    }
    unsigned v = ((unsigned)buf[2] << 8) | buf[3];
    if (v != FARM9_VERSION) {
        farm9crypt_set_failure(FARM9_FAIL_VERSION);
        fprintf(stderr, "[ClawSec] Error: the %s speaks protocol v%u (ClawSec %u.x); this is "
                        "ClawSec " CLAWSEC_VERSION " (protocol v%u). Use the same major "
                        "version on both ends.\n", who, v, v, FARM9_VERSION);
        return -1;
    }
    return 0;
}

static int hello_flags_ok(const unsigned char *buf, unsigned mine) {
    unsigned theirs = ((unsigned)buf[4] << 8) | buf[5];
    if (theirs != mine) {
        farm9crypt_set_failure(FARM9_FAIL_CONFIG);
        char a[128], b[128];
        fprintf(stderr, "[ClawSec] Error: option mismatch: this side uses %s, the other end "
                        "uses %s.\n", flag_names(mine, a, sizeof(a)), flag_names(theirs, b, sizeof(b)));
        if ((mine ^ theirs) & FLAG_USER)
            fprintf(stderr, "[ClawSec] The server has per-user login (--users): connect with "
                            "--user <name>; a server without --users takes no --user.\n");
        if ((mine ^ theirs) & (FLAG_TOFU | FLAG_PQ | FLAG_PAD))
            fprintf(stderr, "[ClawSec] --tofu, --pq and --pad must be set identically on both "
                            "ends (--pad also needs ClawSec 4.2+ on both).\n");
        return -1;
    }
    return 0;
}

static int is_datagram_transport(int fd) {
    int type = 0;
    socklen_t l = sizeof(type);
    if (obfs_get_mode() == OBFS_HTTP) return 1;
    return getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &l) == 0 && type == SOCK_DGRAM;
}

/*
 * Receive a message that starts with a hello (msg1 or msg2). The expected
 * total length follows from the flags, which must equal ours.
 * Stream transports: read the hello first, so a peer with another version or
 * other options is reported instead of waiting for bytes that never come.
 * Datagram transports (UDP, HTTP bodies): one unit holds the whole message.
 */
/* The side that has not sent anything yet answers a foreign version with its
 * own hello, so that an older peer reports the mismatch instead of waiting
 * for a timeout (notably in UDP mode). */
static void courtesy_hello(int fd, unsigned my_flags, int server_mode) {
    if (server_mode) return;                /* role B already sent message 1 */
    unsigned char h[HELLO_LEN];
    hello_build(h, my_flags);
    (void)ecdhe_send(fd, h, sizeof(h));
}

/* ---------- UDP: loss-tolerant message exchange ---------- */

static int is_udp(int fd) {
    int type = 0;
    socklen_t l = sizeof(type);
    return obfs_get_mode() == OBFS_NONE &&
           getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &l) == 0 && type == SOCK_DGRAM;
}

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/*
 * Wait for the peer's next handshake datagram. While waiting, our last
 * message (resend) is retransmitted with exponential backoff (0.5 s .. 4 s)
 * and immediately whenever the peer repeats its previous message (prev),
 * which means our answer was lost. Datagrams of an unexpected length are
 * ignored (want_len 0 = any datagram of at least 4 bytes, for hellos).
 * The overall limit is the socket's receive timeout (--handshake-timeout).
 * Returns the datagram length, or -1 (errno ETIMEDOUT on timeout).
 */
static int udp_wait(int fd, const unsigned char *resend, size_t resend_len,
                    const unsigned char *prev, size_t prev_len,
                    unsigned char *in, size_t in_max, size_t want_len) {
    struct timeval tv = { 0, 0 };
    socklen_t tl = sizeof(tv);
    long long limit_ms = 0;
    if (getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, &tl) == 0)
        limit_ms = (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
    long long deadline = limit_ms > 0 ? now_ms() + limit_ms : 0;
    int interval = 500;
    long long next_resend = now_ms() + interval;

    for (;;) {
        long long now = now_ms();
        if (deadline && now >= deadline) {
            errno = ETIMEDOUT;
            return -1;
        }
        long long wait = resend ? next_resend - now : 1000;
        if (deadline && deadline - now < wait) wait = deadline - now;
        if (wait < 0) wait = 0;
        struct pollfd p = { fd, POLLIN, 0 };
        int rc = poll(&p, 1, (int)wait);
        if (rc < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (rc == 0) {
            if (resend && now_ms() >= next_resend) {
                (void)send(fd, resend, resend_len, 0);
                if (interval < 4000) interval *= 2;
                next_resend = now_ms() + interval;
            }
            continue;
        }
        /* Receive into a scratch buffer larger than any handshake message,
         * with MSG_TRUNC for the real size: a longer datagram must never be
         * mistaken for a shorter message by truncation. */
        unsigned char dg[MSG1_MAX + 64];
        ssize_t n = recv(fd, dg, sizeof(dg), MSG_DONTWAIT | MSG_TRUNC);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (errno == ECONNREFUSED) continue;    /* ICMP from a peer not yet listening */
            return -1;
        }
        if ((size_t)n > sizeof(dg)) continue;      /* oversized: not ours */
        if (prev && (size_t)n == prev_len && memcmp(dg, prev, prev_len) == 0) {
            if (resend) (void)send(fd, resend, resend_len, 0);   /* our answer was lost */
            continue;
        }
        if (want_len ? (size_t)n != want_len : n < 4) continue;   /* noise / stale */
        if ((size_t)n > in_max) continue;
        memcpy(in, dg, (size_t)n);
        return (int)n;
    }
}

static int recv_hello_msg(int fd, unsigned char *buf, size_t max, size_t expected,
                          unsigned my_flags, int server_mode,
                          const unsigned char *resend, size_t resend_len) {
    if (is_datagram_transport(fd)) {
        int n;
        if (obfs_get_mode() == OBFS_HTTP) {
            n = obfs_recv(fd, buf, max);
        } else {
            n = udp_wait(fd, resend, resend_len, NULL, 0, buf, max, 0);
        }
        if (n <= 0) return -1;
        if (hello_version_ok(buf, (size_t)n) != 0) {
            courtesy_hello(fd, my_flags, server_mode);
            return -1;
        }
        if ((size_t)n < HELLO_LEN) return -1;
        if (hello_flags_ok(buf, my_flags) != 0) return -1;
        if (expected && (size_t)n != expected) {
            fprintf(stderr, "[ClawSec] Error: malformed handshake message\n");
            return -1;
        }
        return n;
    }
    if (ecdhe_recv(fd, buf, HELLO_LEN) < 0) return -1;
    if (hello_version_ok(buf, HELLO_LEN) != 0) {
        courtesy_hello(fd, my_flags, server_mode);
        return -1;
    }
    if (hello_flags_ok(buf, my_flags) != 0) return -1;
    if (expected > HELLO_LEN && ecdhe_recv(fd, buf + HELLO_LEN, expected - HELLO_LEN) < 0)
        return -1;
    return (int)expected;
}

static int hkdf_session(const unsigned char *ikm, size_t ikm_len,
                        const unsigned char aad[32], unsigned char out[32]) {
    unsigned char info[sizeof(KEY_LABEL) - 1 + 32];
    memcpy(info, KEY_LABEL, sizeof(KEY_LABEL) - 1);
    memcpy(info + sizeof(KEY_LABEL) - 1, aad, 32);
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) return -1;
    EVP_KDF_CTX *kc = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kc) return -1;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)"SHA256", 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)ikm, ikm_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, sizeof(info)),
        OSSL_PARAM_construct_end()
    };
    int rc = EVP_KDF_derive(kc, out, 32, params) == 1 ? 0 : -1;
    EVP_KDF_CTX_free(kc);
    return rc;
}

/* Data signed by the server identity key */
static void sig_input(unsigned char out[sizeof(SIG_LABEL) - 1 + 64],
                      const unsigned char tt_hash[32], const unsigned char aad[32]) {
    memcpy(out, SIG_LABEL, sizeof(SIG_LABEL) - 1);
    memcpy(out + sizeof(SIG_LABEL) - 1, tt_hash, 32);
    memcpy(out + sizeof(SIG_LABEL) - 1 + 32, aad, 32);
}

/* ---------- The handshake ---------- */

static int transcript_aad(const unsigned char *m1, size_t l1, const unsigned char *m2,
                          size_t l2, unsigned char aad[32]) {
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    int ok = md && EVP_DigestInit_ex(md, EVP_sha256(), NULL) &&
             EVP_DigestUpdate(md, m1, l1) && EVP_DigestUpdate(md, m2, l2) &&
             EVP_DigestFinal_ex(md, aad, NULL);
    EVP_MD_CTX_free(md);
    return ok ? 0 : -1;
}

/* Server, per-user mode: the password scalar of `name`. Unknown users get a
 * stable fake scalar (keyed hash of the name with a per-process random key),
 * so a failed login looks the same whether or not the user exists. */
static void user_scalar(const char *name, unsigned char w[SPAKE2_SCALAR_LEN]) {
    static unsigned char fake_key[32];
    static int have_key = 0;
    user_entry_t e;
    int r = s_users_file ? users_lookup(s_users_file, name, &e) : -1;
    if (r == 1 && !e.disabled) {                    /* disabled = like unknown */
        memcpy(w, e.w, SPAKE2_SCALAR_LEN);
        OPENSSL_cleanse(&e, sizeof(e));
        return;
    }
    OPENSSL_cleanse(&e, sizeof(e));
    if (r < 0) fprintf(stderr, "[ClawSec] Error: cannot read the users file\n");
    if (!have_key) {
        RAND_bytes(fake_key, sizeof(fake_key));
        have_key = 1;
    }
    unsigned int len = 0;
    HMAC(EVP_sha256(), fake_key, sizeof(fake_key), (const unsigned char *)name, strlen(name),
         w, &len);
    w[0] &= 0x7f;                                   /* below the group order */
}

static int handshake(int fd, const char *password, size_t pass_len, int server_mode,
                     unsigned flags, const char *peer_host, const char *peer_port,
                     unsigned char key_out[32]) {
    unsigned char m1[MSG1_MAX], m2[MSG2_MAX], m3[MSG3_MAX], m4[SPAKE2_CONF_LEN];
    unsigned char aad[32], ke[SPAKE2_KEY_LEN], my_conf[SPAKE2_CONF_LEN];
    unsigned char peer_conf[SPAKE2_CONF_LEN], tt_hash[32], w[SPAKE2_SCALAR_LEN];
    unsigned char kem_pk[PQ_KEM_PUBKEY_LEN], kem_ss[PQ_KEM_SS_LEN];
    unsigned char ikm[SPAKE2_KEY_LEN + PQ_KEM_SS_LEN];
    unsigned char sig_msg[sizeof(SIG_LABEL) - 1 + 64];
    spake2_ctx *sp = NULL;
    void *kem = NULL;
    int rc = -1;

    if (farm9crypt_padding()) flags |= FLAG_PAD;
    if (server_mode ? s_users_file != NULL : s_user[0] != '\0') flags |= FLAG_USER;
    const int tofu = (flags & FLAG_TOFU) != 0, pq = (flags & FLAG_PQ) != 0;
    const int user = (flags & FLAG_USER) != 0;
    const size_t l1 = msg1_len(flags), l3 = msg3_len(flags);
    size_t l2 = msg2_len(flags, strlen(s_user));
    const int udp = is_udp(fd);
    s_peer_user[0] = '\0';

    if (user && udp) {
        fprintf(stderr, "[ClawSec] Error: per-user login is not available with -u\n");
        return -1;
    }
    if (!(server_mode && user) && (!password || pass_len == 0)) return -1;
    if (pq && !pq_available()) {
        fprintf(stderr, "[ClawSec] Error: --pq needs OpenSSL 3.5+ with ML-KEM-768\n");
        return -1;
    }
    if (!(server_mode && user)) {
        if (ecdhe_prepare_password(password, pass_len) != 0) {
            fprintf(stderr, "[ClawSec] Error: password key derivation failed\n");
            return -1;
        }
        memcpy(w, cached_w, sizeof(w));
    }

    if (server_mode) {
        /* 1: hello || [pB] || [identity] || [KEM pubkey] */
        size_t off = HELLO_LEN;
        hello_build(m1, flags);
        if (!user) {
            sp = spake2_new(SPAKE2_ROLE_B, w, (const unsigned char *)ID_CLIENT,
                            sizeof(ID_CLIENT) - 1, (const unsigned char *)ID_SERVER,
                            sizeof(ID_SERVER) - 1);
            if (!sp || spake2_message(sp, m1 + off) != 0) goto out;
            off += SPAKE2_POINT_LEN;
        }
        if (tofu) {
            const unsigned char *id = tofu_server_get_pubkey();
            if (!id) {
                fprintf(stderr, "[ClawSec] Error: TOFU identity key not loaded\n");
                goto out;
            }
            memcpy(m1 + off, id, ID_PUB_LEN);
            off += ID_PUB_LEN;
        }
        if (pq) {
            kem = pq_keygen(kem_pk);
            if (!kem) goto out;
            memcpy(m1 + off, kem_pk, PQ_KEM_PUBKEY_LEN);
        }
        if (ecdhe_send(fd, m1, l1) < 0) goto out;

        /* 2: hello || [len || name] || pA || [KEM ciphertext] */
        const unsigned char *pA;
        if (user) {
            int n = recv_hello_msg(fd, m2, sizeof(m2),
                                   is_datagram_transport(fd) ? 0 : HELLO_LEN + 1, flags, 1,
                                   NULL, 0);
            if (n < HELLO_LEN + 1) goto out;
            size_t ul = m2[HELLO_LEN];
            if (ul < 1 || ul > USER_NAME_MAX) {
                fprintf(stderr, "[ClawSec] Error: invalid user name length\n");
                goto out;
            }
            l2 = msg2_len(flags, ul);
            if (is_datagram_transport(fd) ? (size_t)n != l2
                                          : ecdhe_recv(fd, m2 + HELLO_LEN + 1, l2 - HELLO_LEN - 1) < 0)
                goto out;
            memcpy(s_peer_user, m2 + HELLO_LEN + 1, ul);
            s_peer_user[ul] = '\0';
            if (!user_name_valid(s_peer_user)) {
                fprintf(stderr, "[ClawSec] Error: invalid user name\n");
                s_peer_user[0] = '\0';
                goto out;
            }
            pA = m2 + HELLO_LEN + 1 + ul;
            user_scalar(s_peer_user, w);
            sp = spake2_new(SPAKE2_ROLE_B, w, (const unsigned char *)ID_CLIENT,
                            sizeof(ID_CLIENT) - 1, (const unsigned char *)ID_SERVER,
                            sizeof(ID_SERVER) - 1);
            if (!sp || spake2_message(sp, m3) != 0) goto out;     /* pB leads message 3 */
        } else {
            if (recv_hello_msg(fd, m2, sizeof(m2), l2, flags, 1, udp ? m1 : NULL, l1) < 0)
                goto out;
            pA = m2 + HELLO_LEN;
        }

        if (transcript_aad(m1, l1, m2, l2, aad) != 0) goto out;
        if (spake2_finish(sp, pA, aad, sizeof(aad), ke, my_conf, peer_conf, tt_hash) != 0) {
            fprintf(stderr, "[ClawSec] Error: invalid handshake message from client\n");
            goto out;
        }
        if (pq && pq_decapsulate(kem, pA + SPAKE2_POINT_LEN, kem_ss) != 0) {
            fprintf(stderr, "[ClawSec] Error: ML-KEM decapsulation failed\n");
            goto out;
        }

        /* 3: [pB] || cB || [signature] */
        size_t c3 = user ? SPAKE2_POINT_LEN : 0;
        memcpy(m3 + c3, my_conf, SPAKE2_CONF_LEN);
        if (tofu) {
            sig_input(sig_msg, tt_hash, aad);
            if (tofu_server_sign(sig_msg, sizeof(sig_msg), m3 + c3 + SPAKE2_CONF_LEN) != 0) {
                fprintf(stderr, "[ClawSec] Error: TOFU signing failed\n");
                goto out;
            }
        }
        if (ecdhe_send(fd, m3, l3) < 0) goto out;

        /* 4: cA. Anything but a valid cA here is a failed password attempt. */
        int got4 = udp ? (udp_wait(fd, m3, l3, m2, l2, m4, sizeof(m4), sizeof(m4)) < 0 ? -1 : 0)
                       : ecdhe_recv(fd, m4, sizeof(m4));
        if (got4 < 0 ||
            CRYPTO_memcmp(m4, peer_conf, SPAKE2_CONF_LEN) != 0) {
            farm9crypt_set_failure(FARM9_FAIL_AUTH);
            if (user)
                fprintf(stderr, "[ClawSec] Error: authentication failed for user '%s' "
                                "(unknown user, wrong password or tampering)\n", s_peer_user);
            else
                fprintf(stderr, "[ClawSec] Error: authentication failed - the client did not "
                                "prove the password (wrong password or tampering)\n");
            goto out;
        }
    } else {
        sp = spake2_new(SPAKE2_ROLE_A, w, (const unsigned char *)ID_CLIENT, sizeof(ID_CLIENT) - 1,
                        (const unsigned char *)ID_SERVER, sizeof(ID_SERVER) - 1);
        if (!sp) goto out;

        /* 1 */
        if (recv_hello_msg(fd, m1, sizeof(m1), l1, flags, 0, NULL, 0) < 0) goto out;
        const unsigned char *after = m1 + HELLO_LEN + (user ? 0 : SPAKE2_POINT_LEN);
        const unsigned char *id_pub = tofu ? after : NULL;
        const unsigned char *peer_kem = pq ? after + (tofu ? ID_PUB_LEN : 0) : NULL;

        /* 2 */
        size_t off = HELLO_LEN;
        hello_build(m2, flags);
        if (user) {
            size_t ul = strlen(s_user);
            m2[off++] = (unsigned char)ul;
            memcpy(m2 + off, s_user, ul);
            off += ul;
        }
        unsigned char *pA = m2 + off;
        if (spake2_message(sp, pA) != 0) goto out;
        if (pq && pq_encapsulate(peer_kem, pA + SPAKE2_POINT_LEN, kem_ss) != 0) {
            fprintf(stderr, "[ClawSec] Error: ML-KEM encapsulation failed\n");
            goto out;
        }
        if (ecdhe_send(fd, m2, l2) < 0) goto out;
        if (transcript_aad(m1, l1, m2, l2, aad) != 0) goto out;

        /* 3: the server proves the password (and its identity) first */
        int got3 = udp ? (udp_wait(fd, m2, l2, m1, l1, m3, sizeof(m3), l3) < 0 ? -1 : 0)
                       : ecdhe_recv(fd, m3, l3);
        if (got3 < 0) {
            fprintf(stderr, "[ClawSec] Error: connection closed during the handshake\n");
            goto out;
        }
        const unsigned char *pB = user ? m3 : m1 + HELLO_LEN;
        const unsigned char *cB = m3 + (user ? SPAKE2_POINT_LEN : 0);
        if (spake2_finish(sp, pB, aad, sizeof(aad), ke, my_conf, peer_conf, tt_hash) != 0) {
            fprintf(stderr, "[ClawSec] Error: invalid handshake message from server\n");
            goto out;
        }
        if (CRYPTO_memcmp(cB, peer_conf, SPAKE2_CONF_LEN) != 0) {
            farm9crypt_set_failure(FARM9_FAIL_AUTH);
            fprintf(stderr, "[ClawSec] Error: authentication failed - wrong %spassword "
                            "(or the handshake was tampered with)\n", user ? "user name or " : "");
            goto out;
        }
        if (tofu) {
            sig_input(sig_msg, tt_hash, aad);
            if (tofu_verify_signature(id_pub, sig_msg, sizeof(sig_msg),
                                      cB + SPAKE2_CONF_LEN, SIG_LEN) != 1) {
                farm9crypt_set_failure(FARM9_FAIL_AUTH);
                fprintf(stderr, "[ClawSec] Error: server identity signature is invalid\n");
                goto out;
            }
            if (peer_host && peer_port) {
                int known = tofu_check_known_host(peer_host, peer_port, id_pub);
                if (known == -1) {          /* identity changed: warning already printed */
                    farm9crypt_set_failure(FARM9_FAIL_AUTH);
                    goto out;
                }
                if (known == -2)
                    fprintf(stderr, "[ClawSec] Warning: could not access known_hosts\n");
            }
        }

        /* 4 */
        if (ecdhe_send(fd, my_conf, SPAKE2_CONF_LEN) < 0) goto out;
        if (udp) {                  /* nothing acknowledges message 4: send it 3 times */
            (void)send(fd, my_conf, SPAKE2_CONF_LEN, 0);
            (void)send(fd, my_conf, SPAKE2_CONF_LEN, 0);
        }
    }

    /* session key */
    {
        size_t ikm_len = SPAKE2_KEY_LEN;
        memcpy(ikm, ke, SPAKE2_KEY_LEN);
        if (pq) {
            memcpy(ikm + SPAKE2_KEY_LEN, kem_ss, PQ_KEM_SS_LEN);
            ikm_len += PQ_KEM_SS_LEN;
        }
        if (hkdf_session(ikm, ikm_len, aad, key_out) != 0) goto out;
    }
    rc = 0;

out:
    spake2_free(sp);
    if (kem) pq_free_key(kem);
    if (rc != 0 && !(server_mode && user && farm9crypt_last_failure() == FARM9_FAIL_AUTH))
        s_peer_user[0] = '\0';                      /* keep the name for failure logs */
    secure_zero(w, sizeof(w));
    secure_zero(ke, sizeof(ke));
    secure_zero(my_conf, sizeof(my_conf));
    secure_zero(peer_conf, sizeof(peer_conf));
    secure_zero(tt_hash, sizeof(tt_hash));
    secure_zero(kem_ss, sizeof(kem_ss));
    secure_zero(ikm, sizeof(ikm));
    return rc;
}

/* ---------- Public handshake functions ---------- */

extern "C" int ecdhe_handshake(int sockfd, const char *password, size_t pass_len,
                               int server_mode, unsigned char *key_out) {
    return handshake(sockfd, password, pass_len, server_mode, 0, NULL, NULL, key_out);
}

extern "C" int ecdhe_handshake_tofu(int sockfd, const char *password, size_t pass_len,
                                    int server_mode, const char *peer_host,
                                    const char *peer_port, unsigned char *key_out) {
    return handshake(sockfd, password, pass_len, server_mode, FLAG_TOFU,
                     peer_host, peer_port, key_out);
}

extern "C" int ecdhe_handshake_pq(int sockfd, const char *password, size_t pass_len,
                                  int server_mode, const char *peer_host,
                                  const char *peer_port, unsigned char *key_out) {
    return handshake(sockfd, password, pass_len, server_mode,
                     FLAG_PQ | (g_tofu ? FLAG_TOFU : 0), peer_host, peer_port, key_out);
}
