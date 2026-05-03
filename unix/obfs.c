/*
 * obfs.c — Traffic obfuscation layer
 *
 * OBFS_HTTP mode wraps each encrypted packet as an HTTP POST/response
 * to make traffic look like normal web requests to DPI/firewalls.
 *
 * Wire format (HTTP mode):
 *   Send: "POST /api/v1/data HTTP/1.1\r\nHost: cdn.example.com\r\n"
 *         "Content-Length: <len>\r\nContent-Type: application/octet-stream\r\n\r\n"
 *         <raw_payload>
 *
 *   Recv: "HTTP/1.1 200 OK\r\nContent-Length: <len>\r\n"
 *         "Content-Type: application/octet-stream\r\n\r\n"
 *         <raw_payload>
 *
 * Both sides use the same framing — the important thing is the Content-Length
 * header for precise payload extraction.
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>

#include "obfs.h"

static int g_obfs_mode = OBFS_NONE;

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

    /* HTTP mode: read header, extract Content-Length, read payload */
    char hdr[2048];
    int hlen = obfs_read_http_header(fd, hdr, sizeof(hdr));
    if (hlen <= 0) return hlen;

    int content_len = obfs_parse_content_length(hdr);
    if (content_len < 0) return -1;
    if ((size_t)content_len > buflen) return -1;

    return obfs_read_exact(fd, buf, (size_t)content_len);
}
