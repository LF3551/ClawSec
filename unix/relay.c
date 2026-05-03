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
#include <sys/stat.h>
#include <fcntl.h>
#include <zlib.h>
#include <openssl/evp.h>

#include "relay.h"
#include "util.h"
#include "farm9crypt.h"

#define COLOR_RESET   "\033[0m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_DIM     "\033[2m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_BOLD    "\033[1m"

#define BUFSIZE 8192
#define MAX_FILE_SIZE (4 * 1024 * 1024) /* 4MB inline file limit */

/* Feature flags — set from clawsec.c */
int g_compress = 0;
int g_progress = 0;
int g_verify   = 0;
char *g_nickname = NULL;

/* ── Control message protocol ── */
#define CTRL_SOH      '\x01'  /* control message prefix */
#define CTRL_RECEIPT  'R'     /* read receipt */
#define CTRL_NICKNAME 'N'     /* nickname announcement */
#define CTRL_FILE     'F'     /* file transfer header+data */
#define CTRL_PING     'P'     /* ping (payload=timestamp_ms) */
#define CTRL_PONG     'Q'     /* pong (payload=timestamp_ms) */

/* ── Emoji fingerprint ── */
static const char *fp_emojis[] = {
    "🔒", "🔑", "🛡️",  "⚡", "🌟", "💎", "🎯", "🔥",
    "🌊", "🍀", "🎭", "🚀", "🌈", "🎵", "🎨", "🔔",
    "🎲", "🌺", "🍎", "🍊", "🍋", "🍇", "🍓", "🍑",
    "🥝", "🌻", "🌸", "💜", "💙", "💚", "❤️",  "🧡"
};

static void print_fingerprint(void) {
    unsigned char fp[8];
    if (farm9crypt_get_fingerprint(fp, 8) < 0) return;
    fprintf(stdout, "%s  🔐 Session: %s", COLOR_YELLOW, COLOR_BOLD);
    for (int i = 0; i < 4; i++)
        fprintf(stdout, "%02x%02x%s", fp[i*2], fp[i*2+1], i < 3 ? "-" : "");
    fprintf(stdout, "%s  ", COLOR_RESET);
    for (int i = 0; i < 6; i++)
        fprintf(stdout, "%s", fp_emojis[fp[i] & 0x1f]);
    fprintf(stdout, "\n%s  Verify this matches on both sides to confirm no MITM.%s\n",
            COLOR_DIM, COLOR_RESET);
    fflush(stdout);
}

/* ── Progress bar helper ── */
static void print_progress(size_t bytes, struct timeval *start, int is_send) {
    struct timeval now;
    gettimeofday(&now, NULL);
    double elapsed = (now.tv_sec - start->tv_sec) +
                     (now.tv_usec - start->tv_usec) / 1e6;
    if (elapsed < 0.1) return;

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

/* ── Compress/decompress ── */
static int zlib_compress_buf(const char *in, size_t in_len,
                             char *out, size_t out_max) {
    uLongf out_len = (uLongf)out_max;
    int rc = compress2((Bytef*)out, &out_len, (const Bytef*)in, (uLong)in_len,
                       Z_DEFAULT_COMPRESSION);
    return (rc == Z_OK) ? (int)out_len : -1;
}

static int zlib_decompress_buf(const char *in, size_t in_len,
                               char *out, size_t out_max) {
    uLongf out_len = (uLongf)out_max;
    int rc = uncompress((Bytef*)out, &out_len, (const Bytef*)in, (uLong)in_len);
    return (rc == Z_OK) ? (int)out_len : -1;
}

/* ── SHA-256 verify helpers ── */
#define VERIFY_MAGIC "CLAW_SHA256:"
#define VERIFY_MSG_LEN (12 + 64 + 1)

static void sha256_hex(const unsigned char *hash, char *hex) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        hex[i*2]   = hx[hash[i] >> 4];
        hex[i*2+1] = hx[hash[i] & 0x0f];
    }
    hex[64] = '\0';
}

/* ── Format file size for display ── */
static void fmt_size(size_t bytes, char *buf, size_t buflen) {
    if (bytes >= 1024*1024)
        snprintf(buf, buflen, "%.1f MB", bytes / (1024.0*1024.0));
    else if (bytes >= 1024)
        snprintf(buf, buflen, "%.1f KB", bytes / 1024.0);
    else
        snprintf(buf, buflen, "%zu B", bytes);
}

/* ── Get current time in milliseconds ── */
static uint64_t now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/* ── Build control message ── */
static int build_ctrl(char *buf, size_t buflen, char type,
                      const void *payload, size_t plen) {
    if (2 + plen > buflen) return -1;
    buf[0] = CTRL_SOH;
    buf[1] = type;
    if (plen > 0) memcpy(buf + 2, payload, plen);
    return (int)(2 + plen);
}

/* ── Send a control message ── */
static int send_ctrl(int sockfd, char type, const void *payload, size_t plen,
                     int compress, char *zbuf, size_t zbuflen) {
    char ctrl[256];
    int clen = build_ctrl(ctrl, sizeof(ctrl), type, payload, plen);
    if (clen < 0) return -1;

    char *send_data = ctrl;
    int send_len = clen;
    if (compress) {
        send_len = zlib_compress_buf(ctrl, clen, zbuf, zbuflen);
        if (send_len < 0) return -1;
        send_data = zbuf;
    }
    return farm9crypt_write(sockfd, send_data, send_len) == send_len ? 0 : -1;
}

/* ── Chat message display ── */
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
        if (msg[i] == '\n' && i + 1 < len)
            fprintf(stdout, "%s[%s %s]%s ", color, timestamp, sender_label, COLOR_RESET);
    }
    if (len > 0 && msg[len - 1] != '\n') fputc('\n', stdout);
    fflush(stdout);
}

/* ── Slash command: /file ── */
static int cmd_file(int sockfd, const char *path, const char *local_label,
                    int compress, char *zbuf, size_t zbuflen) {
    struct stat st;
    if (stat(path, &st) < 0 || !S_ISREG(st.st_mode)) {
        fprintf(stdout, "%s  ⚠ File not found: %s%s\n", COLOR_YELLOW, path, COLOR_RESET);
        return -1;
    }
    if ((size_t)st.st_size > MAX_FILE_SIZE) {
        fprintf(stdout, "%s  ⚠ File too large (max 4MB for inline). Use file transfer mode.%s\n",
                COLOR_YELLOW, COLOR_RESET);
        return -1;
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stdout, "%s  ⚠ Cannot open: %s%s\n", COLOR_YELLOW, path, COLOR_RESET);
        return -1;
    }
    size_t fsize = (size_t)st.st_size;
    /* Extract basename */
    const char *basename = strrchr(path, '/');
    basename = basename ? basename + 1 : path;

    /* Build: \x01F + "size:filename\n" + raw data */
    size_t hdr_len = snprintf(NULL, 0, "%zu:%s\n", fsize, basename);
    size_t total = 2 + hdr_len + fsize;
    char *msg = malloc(total);
    if (!msg) { close(fd); return -1; }
    msg[0] = CTRL_SOH;
    msg[1] = CTRL_FILE;
    snprintf(msg + 2, hdr_len + 1, "%zu:%s\n", fsize, basename);
    ssize_t rd = read(fd, msg + 2 + hdr_len, fsize);
    close(fd);
    if (rd != (ssize_t)fsize) { free(msg); return -1; }

    char *send_data = msg;
    int send_len = (int)total;
    char *zbig = NULL;
    if (compress) {
        zbig = malloc(total + 256);
        if (!zbig) { free(msg); return -1; }
        send_len = zlib_compress_buf(msg, total, zbig, total + 256);
        if (send_len < 0) { free(msg); free(zbig); return -1; }
        send_data = zbig;
    }
    int rc = (farm9crypt_write(sockfd, send_data, send_len) == send_len) ? 0 : -1;
    free(msg);
    if (zbig) free(zbig);

    if (rc == 0) {
        char sz[32];
        fmt_size(fsize, sz, sizeof(sz));
        time_t now = time(NULL);
        struct tm tm_info;
        char ts[16];
        localtime_r(&now, &tm_info);
        strftime(ts, sizeof(ts), "%H:%M:%S", &tm_info);
        fprintf(stdout, "%s[%s %s]%s 📎 Sent file: %s%s%s (%s)\n",
                COLOR_GREEN, ts, local_label, COLOR_RESET,
                COLOR_BOLD, basename, COLOR_RESET, sz);
        fflush(stdout);
    }
    return rc;
}

/* ── Handle received control message ── */
static void handle_ctrl(int sockfd, const char *data, int len,
                        const char *remote_label, char *peer_nick, size_t pnlen,
                        int compress, char *zbuf, size_t zbuflen) {
    if (len < 2) return;
    char type = data[1];

    switch (type) {
    case CTRL_RECEIPT:
        fprintf(stdout, "%s  ✓✓ delivered%s\n", COLOR_DIM, COLOR_RESET);
        fflush(stdout);
        break;

    case CTRL_NICKNAME: {
        size_t nlen = (size_t)(len - 2);
        if (nlen >= pnlen) nlen = pnlen - 1;
        memcpy(peer_nick, data + 2, nlen);
        peer_nick[nlen] = '\0';
        /* Strip trailing newline */
        if (nlen > 0 && peer_nick[nlen-1] == '\n') peer_nick[nlen-1] = '\0';
        fprintf(stdout, "%s  📛 Peer identified as: %s%s%s\n",
                COLOR_YELLOW, COLOR_BOLD, peer_nick, COLOR_RESET);
        fflush(stdout);
        break;
    }

    case CTRL_FILE: {
        /* Parse "size:filename\n" then raw data */
        const char *hdr = data + 2;
        int hdr_avail = len - 2;
        const char *nl = memchr(hdr, '\n', hdr_avail);
        if (!nl) break;
        size_t hdr_len = nl - hdr + 1;
        size_t fsize = 0;
        const char *colon = memchr(hdr, ':', hdr_avail);
        if (!colon || colon > nl) break;
        fsize = (size_t)atol(hdr);
        char fname[256];
        size_t fname_len = nl - colon - 1;
        if (fname_len >= sizeof(fname)) fname_len = sizeof(fname) - 1;
        memcpy(fname, colon + 1, fname_len);
        fname[fname_len] = '\0';

        const char *file_data = nl + 1;
        size_t data_avail = len - (file_data - data);
        if (data_avail < fsize) {
            fprintf(stdout, "%s  ⚠ Incomplete file received%s\n", COLOR_YELLOW, COLOR_RESET);
            break;
        }

        /* Sanitize filename: strip path separators */
        for (char *p = fname; *p; p++)
            if (*p == '/' || *p == '\\') *p = '_';

        /* Write to current directory */
        int fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            fprintf(stdout, "%s  ⚠ Cannot create: %s%s\n", COLOR_YELLOW, fname, COLOR_RESET);
            break;
        }
        write_all(fd, file_data, fsize);
        close(fd);

        char sz[32];
        fmt_size(fsize, sz, sizeof(sz));
        time_t now = time(NULL);
        struct tm tm_info;
        char ts[16];
        localtime_r(&now, &tm_info);
        strftime(ts, sizeof(ts), "%H:%M:%S", &tm_info);
        fprintf(stdout, "%s[%s %s]%s 📎 Received file: %s%s%s (%s) → saved\n",
                COLOR_CYAN, ts, remote_label, COLOR_RESET,
                COLOR_BOLD, fname, COLOR_RESET, sz);
        fflush(stdout);

        /* Send receipt for file */
        send_ctrl(sockfd, CTRL_RECEIPT, NULL, 0, compress, zbuf, zbuflen);
        break;
    }

    case CTRL_PING: {
        /* Echo back as pong */
        send_ctrl(sockfd, CTRL_PONG, data + 2, len - 2, compress, zbuf, zbuflen);
        break;
    }

    case CTRL_PONG: {
        /* Calculate RTT */
        if (len >= 2 + (int)sizeof(uint64_t)) {
            uint64_t t0;
            memcpy(&t0, data + 2, sizeof(t0));
            uint64_t rtt = now_ms() - t0;
            fprintf(stdout, "%s  🏓 Pong: %llu ms RTT%s\n",
                    COLOR_YELLOW, (unsigned long long)rtt, COLOR_RESET);
            fflush(stdout);
        }
        break;
    }
    }
}

/* ── Handle slash commands typed by user ── */
static int handle_slash_cmd(int sockfd, const char *line, size_t len,
                            const char *local_label,
                            int compress, char *zbuf, size_t zbuflen) {
    /* Strip trailing newline */
    char cmd[512];
    size_t clen = len;
    if (clen >= sizeof(cmd)) clen = sizeof(cmd) - 1;
    memcpy(cmd, line, clen);
    cmd[clen] = '\0';
    if (clen > 0 && cmd[clen-1] == '\n') cmd[--clen] = '\0';
    if (clen > 0 && cmd[clen-1] == '\r') cmd[--clen] = '\0';

    if (strcmp(cmd, "/help") == 0) {
        fprintf(stdout,
                "%s╭──── Chat Commands ────╮%s\n"
                "%s│ /file <path>  Send file (up to 4MB)  │%s\n"
                "%s│ /ping         Encrypted RTT test     │%s\n"
                "%s│ /clear        Clear screen            │%s\n"
                "%s│ /whoami       Show session info       │%s\n"
                "%s│ /help         This help               │%s\n"
                "%s╰───────────────────────╯%s\n",
                COLOR_YELLOW, COLOR_RESET,
                COLOR_YELLOW, COLOR_RESET,
                COLOR_YELLOW, COLOR_RESET,
                COLOR_YELLOW, COLOR_RESET,
                COLOR_YELLOW, COLOR_RESET,
                COLOR_YELLOW, COLOR_RESET,
                COLOR_YELLOW, COLOR_RESET);
        fflush(stdout);
        return 1;
    }

    if (strcmp(cmd, "/clear") == 0) {
        fprintf(stdout, "\033[2J\033[H");
        fflush(stdout);
        return 1;
    }

    if (strcmp(cmd, "/whoami") == 0) {
        fprintf(stdout, "%s  📋 You are: %s%s%s\n", COLOR_YELLOW,
                COLOR_BOLD, g_nickname ? g_nickname : local_label, COLOR_RESET);
        print_fingerprint();
        return 1;
    }

    if (strcmp(cmd, "/ping") == 0) {
        uint64_t t = now_ms();
        send_ctrl(sockfd, CTRL_PING, &t, sizeof(t), compress, zbuf, zbuflen);
        fprintf(stdout, "%s  🏓 Ping sent...%s\n", COLOR_DIM, COLOR_RESET);
        fflush(stdout);
        return 1;
    }

    if (strncmp(cmd, "/file ", 6) == 0) {
        const char *path = cmd + 6;
        while (*path == ' ') path++;
        if (*path)
            cmd_file(sockfd, path, local_label, compress, zbuf, zbuflen);
        else
            fprintf(stdout, "%s  Usage: /file <path>%s\n", COLOR_YELLOW, COLOR_RESET);
        fflush(stdout);
        return 1;
    }

    return 0; /* not a slash command */
}

/* ── Print chat banner ── */
static void print_chat_banner(const char *local_label, const char *remote_label,
                              time_t connect_time) {
    struct tm tm_info;
    char ts[16];
    localtime_r(&connect_time, &tm_info);
    strftime(ts, sizeof(ts), "%H:%M:%S", &tm_info);

    fprintf(stdout,
            "\n%s╔══════════════════════════════════════╗%s\n"
            "%s║    🔐 ClawSec Encrypted Chat         ║%s\n"
            "%s╚══════════════════════════════════════╝%s\n",
            COLOR_CYAN, COLOR_RESET,
            COLOR_CYAN, COLOR_RESET,
            COLOR_CYAN, COLOR_RESET);
    print_fingerprint();
    fprintf(stdout, "%s  Connected at %s | local=%s%s%s | remote=%s%s%s%s\n",
            COLOR_DIM, ts,
            COLOR_RESET COLOR_GREEN, local_label, COLOR_RESET COLOR_DIM,
            COLOR_RESET COLOR_CYAN, remote_label, COLOR_RESET COLOR_DIM,
            COLOR_RESET);
    fprintf(stdout, "%s  Type /help for commands%s\n\n",
            COLOR_DIM, COLOR_RESET);
    fflush(stdout);
}

/* ═══════════════════ MAIN RELAY ═══════════════════ */

int relay_socket_stdio(int sockfd, int is_server, int chat_enabled) {
    char inbuf[BUFSIZE];
    char netbuf[BUFSIZE];
    char zbuf[BUFSIZE + 256];
    ssize_t n;
    size_t sent = 0, received = 0;
    size_t sent_raw = 0, recv_raw = 0;
    const char *local_label = g_nickname ? g_nickname : (is_server ? "Server" : "Client");
    const char *remote_label = is_server ? "Client" : "Server";
    char peer_nick[64] = {0};
    int interactive = isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
    int chat_mode = chat_enabled && interactive;
    int stdin_closed = 0;
    time_t connect_time = time(NULL);

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
        print_chat_banner(local_label, remote_label, connect_time);

        /* Send nickname to peer if set */
        if (g_nickname)
            send_ctrl(sockfd, CTRL_NICKNAME, g_nickname, strlen(g_nickname),
                      g_compress, zbuf, sizeof(zbuf));
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

        /* ── Network → stdout ── */
        if (FD_ISSET(sockfd, &rfds)) {
            n = farm9crypt_read(sockfd, netbuf, sizeof(netbuf));
            if (n < 0) fatal("read from network failed");
            if (n == 0) {
                if (chat_mode) {
                    const char *who = peer_nick[0] ? peer_nick : remote_label;
                    fprintf(stdout, "\n%s  ⚡ %s disconnected%s\n",
                            COLOR_YELLOW, who, COLOR_RESET);
                    /* Show session duration */
                    int dur = (int)(time(NULL) - connect_time);
                    fprintf(stdout, "%s  ⏱ Session duration: %d:%02d:%02d%s\n",
                            COLOR_DIM, dur/3600, (dur%3600)/60, dur%60, COLOR_RESET);
                    fflush(stdout);
                }
                break;
            }

            char *outdata = netbuf;
            int outlen = (int)n;

            if (g_compress) {
                outlen = zlib_decompress_buf(netbuf, (size_t)n, zbuf, sizeof(zbuf));
                if (outlen < 0) fatal("zlib decompress failed");
                outdata = zbuf;
                recv_raw += (size_t)outlen;
            }

            received += (size_t)n;

            /* Check for SHA-256 verify message */
            if (g_verify && outlen >= (int)VERIFY_MSG_LEN &&
                memcmp(outdata, VERIFY_MAGIC, 12) == 0) {
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

            /* Check for control message */
            if (outlen >= 2 && outdata[0] == CTRL_SOH) {
                handle_ctrl(sockfd, outdata, outlen,
                            peer_nick[0] ? peer_nick : remote_label,
                            peer_nick, sizeof(peer_nick),
                            g_compress, zbuf, sizeof(zbuf));
                continue;
            }

            if (g_verify)
                EVP_DigestUpdate(sha_recv, outdata, outlen);

            if (chat_mode) {
                const char *who = peer_nick[0] ? peer_nick : remote_label;
                print_chat_message(who, COLOR_CYAN, outdata, (size_t)outlen);
                /* Send read receipt */
                send_ctrl(sockfd, CTRL_RECEIPT, NULL, 0,
                          g_compress, zbuf, sizeof(zbuf));
            } else {
                if (write_all(STDOUT_FILENO, outdata, (size_t)outlen) < 0)
                    fatal("write to stdout failed");
            }

            if (g_progress && !chat_mode)
                print_progress(g_compress ? recv_raw : received, &start, 0);
        }

        /* ── stdin → Network ── */
        if (!stdin_closed && FD_ISSET(STDIN_FILENO, &rfds)) {
            n = read(STDIN_FILENO, inbuf, sizeof(inbuf));
            if (n < 0) fatal("read from stdin failed");
            if (n == 0) {
                if (g_verify) {
                    unsigned char hash[32];
                    char hex[65], msg[VERIFY_MSG_LEN];
                    unsigned int hlen = 32;
                    EVP_DigestFinal_ex(sha_send, hash, &hlen);
                    sha256_hex(hash, hex);
                    memcpy(msg, VERIFY_MAGIC, 12);
                    memcpy(msg + 12, hex, 64);
                    msg[76] = '\n';
                    char *sd = msg; int sl = VERIFY_MSG_LEN;
                    if (g_compress) {
                        sl = zlib_compress_buf(msg, VERIFY_MSG_LEN, zbuf, sizeof(zbuf));
                        if (sl < 0) fatal("zlib compress failed");
                        sd = zbuf;
                    }
                    farm9crypt_write(sockfd, sd, sl);
                }
                shutdown(sockfd, SHUT_WR);
                stdin_closed = 1;
            } else {
                /* Check for slash commands in chat mode */
                if (chat_mode && n > 1 && inbuf[0] == '/') {
                    if (handle_slash_cmd(sockfd, inbuf, (size_t)n, local_label,
                                         g_compress, zbuf, sizeof(zbuf)))
                        continue;
                }

                if (g_verify)
                    EVP_DigestUpdate(sha_send, inbuf, n);

                sent_raw += (size_t)n;
                char *send_data = inbuf;
                int send_len = (int)n;

                if (g_compress) {
                    send_len = zlib_compress_buf(inbuf, (size_t)n, zbuf, sizeof(zbuf));
                    if (send_len < 0) fatal("zlib compress failed");
                    send_data = zbuf;
                }

                sent += (size_t)send_len;

                if (chat_mode)
                    print_chat_message(local_label, COLOR_GREEN, inbuf, (size_t)n);

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
        fprintf(stderr, "\n");

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

        if (FD_ISSET(enc_fd, &rfds)) {
            n = farm9crypt_read(enc_fd, buf, sizeof(buf));
            if (n <= 0) break;
            received += (size_t)n;
            if (write_all(plain_fd, buf, (size_t)n) < 0) break;
        }

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
