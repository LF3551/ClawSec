#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <zlib.h>
#include <openssl/evp.h>

#include "relay.h"
#include "util.h"
#include "farm9crypt.h"

#define COLOR_RESET   "\033[0m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_CYAN    "\033[36m"

#define BUFSIZE 8192

/* Feature flags — set from clawsec.c */
int g_compress = 0;
int g_progress = 0;
int g_verify   = 0;

/* ── Progress bar helper ── */
static void print_progress(size_t bytes, struct timeval *start, int is_send) {
    struct timeval now;
    gettimeofday(&now, NULL);
    double elapsed = (now.tv_sec - start->tv_sec) +
                     (now.tv_usec - start->tv_usec) / 1e6;
    if (elapsed < 0.1) return;  /* throttle updates */

    double rate = (elapsed > 0) ? bytes / elapsed : 0;
    const char *unit = "B/s";
    double display_rate = rate;
    if (display_rate > 1024*1024) { display_rate /= 1024*1024; unit = "MB/s"; }
    else if (display_rate > 1024) { display_rate /= 1024; unit = "KB/s"; }

    const char *label = is_send ? "Sent" : "Recv";
    if (bytes > 1024*1024)
        fprintf(stderr, "\r[%s] %.1f MB  (%.1f %s)   ",
                label, bytes / (1024.0*1024.0), display_rate, unit);
    else if (bytes > 1024)
        fprintf(stderr, "\r[%s] %.1f KB  (%.1f %s)   ",
                label, bytes / 1024.0, display_rate, unit);
    else
        fprintf(stderr, "\r[%s] %zu B  (%.1f %s)   ",
                label, bytes, display_rate, unit);
    fflush(stderr);
}

/* ── Compress buffer with zlib ── */
static int zlib_compress(const char *in, size_t in_len,
                         char *out, size_t out_max) {
    uLongf out_len = (uLongf)out_max;
    int rc = compress2((Bytef*)out, &out_len, (const Bytef*)in, (uLong)in_len,
                       Z_DEFAULT_COMPRESSION);
    return (rc == Z_OK) ? (int)out_len : -1;
}

/* ── Decompress buffer with zlib ── */
static int zlib_decompress(const char *in, size_t in_len,
                           char *out, size_t out_max) {
    uLongf out_len = (uLongf)out_max;
    int rc = uncompress((Bytef*)out, &out_len, (const Bytef*)in, (uLong)in_len);
    return (rc == Z_OK) ? (int)out_len : -1;
}

/* SHA-256 verification magic sent after all data */
#define VERIFY_MAGIC "CLAW_SHA256:"
#define VERIFY_MSG_LEN (12 + 64 + 1)  /* magic + hex + newline */

static void sha256_hex(const unsigned char *hash, char *hex) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        hex[i*2]   = hx[hash[i] >> 4];
        hex[i*2+1] = hx[hash[i] & 0x0f];
    }
    hex[64] = '\0';
}

static void print_chat_message(const char *sender_label,
                               const char *color,
                               const char *msg,
                               size_t len) {
    time_t now = time(NULL);
    struct tm tm_info;
    char timestamp[16];
    localtime_r(&now, &tm_info);
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", &tm_info);
    fprintf(stdout, "%s[%s %s]%s ", color, timestamp, sender_label, COLOR_RESET);
    for (size_t i = 0; i < len; ++i) {
        fputc((unsigned char)msg[i], stdout);
        if (msg[i] == '\n' && i + 1 < len) {
            fprintf(stdout, "%s[%s %s]%s ", color, timestamp, sender_label, COLOR_RESET);
        }
    }
    if (len > 0 && msg[len - 1] != '\n') fputc('\n', stdout);
    fflush(stdout);
}

int relay_socket_stdio(int sockfd, int is_server, int chat_enabled) {
    char inbuf[BUFSIZE];
    char netbuf[BUFSIZE];
    char zbuf[BUFSIZE + 256]; /* extra space for zlib overhead */
    ssize_t n;
    size_t sent = 0, received = 0;
    size_t sent_raw = 0, recv_raw = 0; /* uncompressed counters */
    const char *local_label = is_server ? "Server" : "Client";
    const char *remote_label = is_server ? "Client" : "Server";
    int interactive = isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
    int chat_mode = chat_enabled && interactive;
    int stdin_closed = 0;

    /* SHA-256 contexts for verify mode */
    EVP_MD_CTX *sha_send = NULL, *sha_recv = NULL;
    if (g_verify) {
        sha_send = EVP_MD_CTX_new();
        sha_recv = EVP_MD_CTX_new();
        EVP_DigestInit_ex(sha_send, EVP_sha256(), NULL);
        EVP_DigestInit_ex(sha_recv, EVP_sha256(), NULL);
    }

    struct timeval start;
    if (g_progress) gettimeofday(&start, NULL);

    if (chat_mode) {
        fprintf(stdout,
                "%s[Secure chat established] local=%s remote=%s%s\n",
                COLOR_CYAN, local_label, remote_label, COLOR_RESET);
        fflush(stdout);
    }

    for (;;) {
        fd_set rfds;
        int nfds = sockfd;

        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);
        if (!stdin_closed) {
            FD_SET(STDIN_FILENO, &rfds);
            if (STDIN_FILENO > nfds) nfds = STDIN_FILENO;
        }

        int ret = select(nfds + 1, &rfds, NULL, NULL, NULL);
        if (ret < 0) {
            if (errno == EINTR) continue;
            fatal("select failed");
        }

        if (FD_ISSET(sockfd, &rfds)) {
            n = farm9crypt_read(sockfd, netbuf, sizeof(netbuf));
            if (n < 0) fatal("read from network failed");
            if (n == 0) break;

            char *outdata = netbuf;
            int outlen = (int)n;

            /* Decompress if enabled */
            if (g_compress) {
                outlen = zlib_decompress(netbuf, (size_t)n, zbuf, sizeof(zbuf));
                if (outlen < 0) fatal("zlib decompress failed");
                outdata = zbuf;
                recv_raw += (size_t)outlen;
            }

            received += (size_t)n;

            /* Check for SHA-256 verify message at end of stream */
            if (g_verify && outlen >= (int)VERIFY_MSG_LEN &&
                memcmp(outdata, VERIFY_MAGIC, 12) == 0) {
                /* This is the hash message, verify it */
                unsigned char hash[32];
                char hex[65];
                unsigned int hlen = 32;
                EVP_DigestFinal_ex(sha_recv, hash, &hlen);
                sha256_hex(hash, hex);
                char peer_hex[65];
                memcpy(peer_hex, outdata + 12, 64);
                peer_hex[64] = '\0';
                if (strcmp(hex, peer_hex) == 0)
                    fprintf(stderr, "[Verify] SHA-256 OK: %s\n", hex);
                else
                    fprintf(stderr, "[Verify] SHA-256 MISMATCH! local=%s remote=%s\n",
                            hex, peer_hex);
                continue;
            }

            if (g_verify)
                EVP_DigestUpdate(sha_recv, outdata, outlen);

            if (chat_mode) {
                print_chat_message(remote_label, COLOR_CYAN, outdata, (size_t)outlen);
            } else {
                if (write_all(STDOUT_FILENO, outdata, (size_t)outlen) < 0)
                    fatal("write to stdout failed");
            }

            if (g_progress && !chat_mode)
                print_progress(g_compress ? recv_raw : received, &start, 0);
        }

        if (!stdin_closed && FD_ISSET(STDIN_FILENO, &rfds)) {
            n = read(STDIN_FILENO, inbuf, sizeof(inbuf));
            if (n < 0) fatal("read from stdin failed");
            if (n == 0) {
                /* EOF on stdin — send verify hash if enabled, then shutdown */
                if (g_verify) {
                    unsigned char hash[32];
                    char hex[65], msg[VERIFY_MSG_LEN];
                    unsigned int hlen = 32;
                    EVP_DigestFinal_ex(sha_send, hash, &hlen);
                    sha256_hex(hash, hex);
                    memcpy(msg, VERIFY_MAGIC, 12);
                    memcpy(msg + 12, hex, 64);
                    msg[76] = '\n';

                    char *send_data = msg;
                    int send_len = VERIFY_MSG_LEN;
                    if (g_compress) {
                        send_len = zlib_compress(msg, VERIFY_MSG_LEN, zbuf, sizeof(zbuf));
                        if (send_len < 0) fatal("zlib compress failed");
                        send_data = zbuf;
                    }
                    farm9crypt_write(sockfd, send_data, send_len);
                }
                shutdown(sockfd, SHUT_WR);
                stdin_closed = 1;
            } else {
                if (g_verify)
                    EVP_DigestUpdate(sha_send, inbuf, n);

                sent_raw += (size_t)n;

                char *send_data = inbuf;
                int send_len = (int)n;

                /* Compress if enabled */
                if (g_compress) {
                    send_len = zlib_compress(inbuf, (size_t)n, zbuf, sizeof(zbuf));
                    if (send_len < 0) fatal("zlib compress failed");
                    send_data = zbuf;
                }

                sent += (size_t)send_len;

                if (chat_mode) {
                    print_chat_message(local_label, COLOR_GREEN, inbuf, (size_t)n);
                }
                ssize_t wn = farm9crypt_write(sockfd, send_data, send_len);
                if (wn != send_len) fatal("write to network failed");

                if (g_progress && !chat_mode)
                    print_progress(g_compress ? sent_raw : sent, &start, 1);
            }
        }
    }

    if (g_verify) {
        EVP_MD_CTX_free(sha_send);
        EVP_MD_CTX_free(sha_recv);
    }

    if (g_progress && !chat_mode)
        fprintf(stderr, "\n");  /* newline after progress bar */

    if (!chat_mode && g_verbose) {
        if (g_compress)
            fprintf(stderr,
                    "\n[Transfer complete] Sent %zu→%zu bytes, received %zu→%zu bytes (compressed)\n",
                    sent_raw, sent, recv_raw, received);
        else
            fprintf(stderr,
                    "\n[Transfer complete] Sent %zu bytes, received %zu bytes\n",
                    sent, received);
    }
    return 0;
}

int relay_encrypted_plain(int enc_fd, int plain_fd) {
    char buf[BUFSIZE];
    ssize_t n;
    size_t sent = 0, received = 0;

    for (;;) {
        fd_set rfds;
        int nfds = enc_fd > plain_fd ? enc_fd : plain_fd;

        FD_ZERO(&rfds);
        FD_SET(enc_fd, &rfds);
        FD_SET(plain_fd, &rfds);

        int ret = select(nfds + 1, &rfds, NULL, NULL, NULL);
        if (ret < 0) {
            if (errno == EINTR) continue;
            return -1;
        }

        /* Encrypted -> plaintext */
        if (FD_ISSET(enc_fd, &rfds)) {
            n = farm9crypt_read(enc_fd, buf, sizeof(buf));
            if (n <= 0) break;
            received += (size_t)n;
            if (write_all(plain_fd, buf, (size_t)n) < 0) break;
        }

        /* Plaintext -> encrypted */
        if (FD_ISSET(plain_fd, &rfds)) {
            n = read(plain_fd, buf, sizeof(buf));
            if (n <= 0) break;
            sent += (size_t)n;
            if (farm9crypt_write(enc_fd, buf, (size_t)n) != n) break;
        }
    }

    if (g_verbose)
        log_msg(1, "[Forwarding done] sent=%zu recv=%zu", sent, received);
    return 0;
}
