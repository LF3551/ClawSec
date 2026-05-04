#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>

#include <openssl/evp.h>

#include "filetx.h"
#include "farm9crypt.h"
#include "util.h"

/* ── Helpers ── */

static void put_be64(unsigned char *buf, uint64_t v) {
    for (int i = 7; i >= 0; i--) {
        buf[i] = v & 0xFF;
        v >>= 8;
    }
}

static uint64_t get_be64(const unsigned char *buf) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v = (v << 8) | buf[i];
    return v;
}

static void put_be16(unsigned char *buf, uint16_t v) {
    buf[0] = (v >> 8) & 0xFF;
    buf[1] = v & 0xFF;
}

static uint16_t get_be16(const unsigned char *buf) {
    return (buf[0] << 8) | buf[1];
}

/* Compute SHA-256 of a file (from offset 0 to end). */
static int sha256_file(const char *path, uint64_t size, unsigned char out[32]) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

    char buf[FILETX_CHUNK_SIZE];
    uint64_t remaining = size;
    while (remaining > 0) {
        size_t toread = remaining < sizeof(buf) ? (size_t)remaining : sizeof(buf);
        ssize_t n = read(fd, buf, toread);
        if (n <= 0) break;
        EVP_DigestUpdate(ctx, buf, n);
        remaining -= n;
    }
    close(fd);

    unsigned int hlen = 32;
    EVP_DigestFinal_ex(ctx, out, &hlen);
    EVP_MD_CTX_free(ctx);
    return (remaining == 0) ? 0 : -1;
}

/* Progress bar with percentage */
static void print_progress(uint64_t transferred, uint64_t total,
                           struct timeval *start, const char *label) {
    struct timeval now;
    gettimeofday(&now, NULL);
    double elapsed = (now.tv_sec - start->tv_sec) +
                     (now.tv_usec - start->tv_usec) / 1e6;
    if (elapsed < 0.1) return;

    double rate = (elapsed > 0) ? transferred / elapsed : 0;
    int pct = total > 0 ? (int)(transferred * 100 / total) : 0;

    const char *unit = "B/s";
    double drate = rate;
    if (drate > 1024*1024) { drate /= 1024*1024; unit = "MB/s"; }
    else if (drate > 1024) { drate /= 1024; unit = "KB/s"; }

    /* Size display */
    char size_str[32];
    if (total > 1024*1024*1024ULL)
        snprintf(size_str, sizeof(size_str), "%.1f/%.1f GB",
                 transferred/(1024.0*1024*1024), total/(1024.0*1024*1024));
    else if (total > 1024*1024)
        snprintf(size_str, sizeof(size_str), "%.1f/%.1f MB",
                 transferred/(1024.0*1024), total/(1024.0*1024));
    else
        snprintf(size_str, sizeof(size_str), "%.1f/%.1f KB",
                 transferred/1024.0, total/1024.0);

    /* Bar */
    int bar_width = 30;
    int filled = pct * bar_width / 100;
    fprintf(stderr, "\r%s [", label);
    for (int i = 0; i < bar_width; i++)
        fputc(i < filled ? '#' : '.', stderr);
    fprintf(stderr, "] %3d%%  %s  %.1f %s   ", pct, size_str, drate, unit);
    fflush(stderr);
}

/* ──────────────────────────────────────────────────────────────── */

int filetx_send(int tunnel_fd, const char *filepath) {
    /* Open and stat file */
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "ERROR: Cannot open file '%s': %s\n", filepath, strerror(errno));
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "ERROR: Not a regular file: %s\n", filepath);
        close(fd);
        return -1;
    }

    uint64_t file_size = (uint64_t)st.st_size;

    /* Extract basename */
    const char *basename = strrchr(filepath, '/');
    basename = basename ? basename + 1 : filepath;
    int name_len = strlen(basename);
    if (name_len > 255) name_len = 255;

    /* Compute SHA-256 */
    unsigned char file_hash[32];
    fprintf(stderr, "Computing SHA-256...\n");
    if (sha256_file(filepath, file_size, file_hash) < 0) {
        fprintf(stderr, "ERROR: Failed to compute SHA-256\n");
        close(fd);
        return -1;
    }

    /* Build header: [8:size][32:sha256][2:name_len][N:name] */
    int hdr_len = FILETX_HDR_SIZE + name_len;
    char hdr[FILETX_HDR_SIZE + 256];
    put_be64((unsigned char *)hdr, file_size);
    memcpy(hdr + 8, file_hash, 32);
    put_be16((unsigned char *)hdr + 40, (uint16_t)name_len);
    memcpy(hdr + 42, basename, name_len);

    /* Send header */
    if (farm9crypt_write(tunnel_fd, hdr, hdr_len) < 0) {
        fprintf(stderr, "ERROR: Failed to send file header\n");
        close(fd);
        return -1;
    }

    log_msg(1, "Sending: %s (%llu bytes)", basename, (unsigned long long)file_size);

    /* Read resume offset from receiver */
    char offset_buf[8];
    int rlen = farm9crypt_read(tunnel_fd, offset_buf, sizeof(offset_buf));
    if (rlen < 8) {
        fprintf(stderr, "ERROR: Failed to read resume offset\n");
        close(fd);
        return -1;
    }
    uint64_t offset = get_be64((unsigned char *)offset_buf);

    if (offset > 0 && offset < file_size) {
        fprintf(stderr, "Resuming from offset %llu (%.1f%%)\n",
                (unsigned long long)offset, offset * 100.0 / file_size);
        lseek(fd, (off_t)offset, SEEK_SET);
    } else if (offset >= file_size) {
        fprintf(stderr, "File already fully transferred.\n");
        close(fd);
        /* Read verify status */
        char vbuf[1];
        farm9crypt_read(tunnel_fd, vbuf, 1);
        return 0;
    }

    /* Stream file data */
    uint64_t sent = 0;
    uint64_t to_send = file_size - offset;
    struct timeval start;
    gettimeofday(&start, NULL);

    char chunk[FILETX_CHUNK_SIZE];
    while (sent < to_send) {
        size_t want = (to_send - sent) < FILETX_CHUNK_SIZE ?
                      (size_t)(to_send - sent) : FILETX_CHUNK_SIZE;
        ssize_t rd = read(fd, chunk, want);
        if (rd <= 0) {
            fprintf(stderr, "\nERROR: Read error at offset %llu\n",
                    (unsigned long long)(offset + sent));
            close(fd);
            return -1;
        }

        if (farm9crypt_write(tunnel_fd, chunk, (int)rd) < 0) {
            fprintf(stderr, "\nERROR: Tunnel write failed\n");
            close(fd);
            return -1;
        }

        sent += rd;
        print_progress(sent, to_send, &start, "TX");
    }
    close(fd);
    fprintf(stderr, "\n");

    /* Read verification result */
    char verify_buf[1];
    rlen = farm9crypt_read(tunnel_fd, verify_buf, sizeof(verify_buf));
    if (rlen < 1) {
        fprintf(stderr, "WARNING: No verification response\n");
        return 0;
    }

    if (verify_buf[0] == 0) {
        fprintf(stderr, "✓ SHA-256 verified — transfer complete\n");
        return 0;
    } else {
        fprintf(stderr, "✗ SHA-256 MISMATCH — file may be corrupted!\n");
        return -1;
    }
}

/* ──────────────────────────────────────────────────────────────── */

int filetx_recv(int tunnel_fd, const char *output_dir) {
    /* Read header */
    char hdr_buf[FILETX_HDR_SIZE + 256];
    int rlen = farm9crypt_read(tunnel_fd, hdr_buf, sizeof(hdr_buf));
    if (rlen < FILETX_HDR_SIZE) {
        fprintf(stderr, "ERROR: Invalid file transfer header\n");
        return -1;
    }

    uint64_t file_size = get_be64((unsigned char *)hdr_buf);
    unsigned char expected_hash[32];
    memcpy(expected_hash, hdr_buf + 8, 32);
    uint16_t name_len = get_be16((unsigned char *)hdr_buf + 40);

    if (name_len > 255 || (int)name_len > rlen - FILETX_HDR_SIZE) {
        fprintf(stderr, "ERROR: Invalid filename in header\n");
        return -1;
    }

    char filename[256];
    memcpy(filename, hdr_buf + 42, name_len);
    filename[name_len] = '\0';

    /* Sanitize filename — no path traversal */
    for (int i = 0; i < name_len; i++) {
        if (filename[i] == '/' || filename[i] == '\\')
            filename[i] = '_';
    }
    if (filename[0] == '.')
        filename[0] = '_';

    /* Build output path */
    char outpath[512];
    if (output_dir && output_dir[0]) {
        snprintf(outpath, sizeof(outpath), "%s/%s", output_dir, filename);
    } else {
        snprintf(outpath, sizeof(outpath), "%s", filename);
    }

    log_msg(1, "Receiving: %s (%llu bytes)", filename, (unsigned long long)file_size);
    fprintf(stderr, "Receiving: %s (%llu bytes)\n", filename,
            (unsigned long long)file_size);

    /* Check for partial file (resume support) */
    uint64_t offset = 0;
    struct stat st;
    if (stat(outpath, &st) == 0 && S_ISREG(st.st_mode)) {
        /* Partial file exists — offer to resume */
        if ((uint64_t)st.st_size < file_size) {
            offset = (uint64_t)st.st_size;
            fprintf(stderr, "Partial file found (%llu bytes), resuming...\n",
                    (unsigned long long)offset);
        } else if ((uint64_t)st.st_size == file_size) {
            /* Check if hash matches — already complete */
            unsigned char existing_hash[32];
            if (sha256_file(outpath, file_size, existing_hash) == 0 &&
                memcmp(existing_hash, expected_hash, 32) == 0) {
                fprintf(stderr, "File already exists and verified.\n");
                offset = file_size;
            } else {
                /* Hash mismatch — re-download */
                offset = 0;
            }
        }
    }

    /* Send resume offset */
    char offset_buf[8];
    put_be64((unsigned char *)offset_buf, offset);
    if (farm9crypt_write(tunnel_fd, offset_buf, 8) < 0) {
        fprintf(stderr, "ERROR: Failed to send resume offset\n");
        return -1;
    }

    if (offset >= file_size) {
        /* Already complete — send verify */
        char ok = 0;
        farm9crypt_write(tunnel_fd, &ok, 1);
        return 0;
    }

    /* Open file for writing (append if resuming) */
    int flags = O_WRONLY | O_CREAT;
    if (offset > 0) {
        flags |= O_APPEND;
    } else {
        flags |= O_TRUNC;
    }
    int fd = open(outpath, flags, 0644);
    if (fd < 0) {
        fprintf(stderr, "ERROR: Cannot create file '%s': %s\n", outpath, strerror(errno));
        return -1;
    }

    /* Receive data chunks */
    uint64_t received = 0;
    uint64_t to_recv = file_size - offset;
    struct timeval start;
    gettimeofday(&start, NULL);

    /* SHA-256 of received data (for the entire file) */
    EVP_MD_CTX *sha_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(sha_ctx, EVP_sha256(), NULL);

    /* If resuming, hash the existing part first */
    if (offset > 0) {
        int rfd = open(outpath, O_RDONLY);
        if (rfd >= 0) {
            char hbuf[FILETX_CHUNK_SIZE];
            uint64_t hashed = 0;
            while (hashed < offset) {
                size_t want = (offset - hashed) < sizeof(hbuf) ?
                              (size_t)(offset - hashed) : sizeof(hbuf);
                ssize_t n = read(rfd, hbuf, want);
                if (n <= 0) break;
                EVP_DigestUpdate(sha_ctx, hbuf, n);
                hashed += n;
            }
            close(rfd);
        }
    }

    char chunk[FILETX_CHUNK_SIZE];
    while (received < to_recv) {
        rlen = farm9crypt_read(tunnel_fd, chunk, sizeof(chunk));
        if (rlen <= 0) {
            fprintf(stderr, "\nERROR: Tunnel read failed at %llu/%llu\n",
                    (unsigned long long)(offset + received),
                    (unsigned long long)file_size);
            close(fd);
            EVP_MD_CTX_free(sha_ctx);
            return -1;
        }

        /* Don't write more than expected */
        size_t to_write = (size_t)rlen;
        if (received + to_write > to_recv)
            to_write = (size_t)(to_recv - received);

        ssize_t wr = write(fd, chunk, to_write);
        if (wr != (ssize_t)to_write) {
            fprintf(stderr, "\nERROR: Write failed: %s\n", strerror(errno));
            close(fd);
            EVP_MD_CTX_free(sha_ctx);
            return -1;
        }

        EVP_DigestUpdate(sha_ctx, chunk, to_write);
        received += to_write;
        print_progress(received, to_recv, &start, "RX");
    }
    close(fd);
    fprintf(stderr, "\n");

    /* Compute final hash */
    unsigned char computed_hash[32];
    unsigned int hlen = 32;
    EVP_DigestFinal_ex(sha_ctx, computed_hash, &hlen);
    EVP_MD_CTX_free(sha_ctx);

    /* Verify */
    int match = (memcmp(computed_hash, expected_hash, 32) == 0);
    char verify = match ? 0 : 1;
    farm9crypt_write(tunnel_fd, &verify, 1);

    if (match) {
        fprintf(stderr, "✓ SHA-256 verified — saved to %s\n", outpath);
        return 0;
    } else {
        fprintf(stderr, "✗ SHA-256 MISMATCH — file may be corrupted!\n");
        /* Remove corrupted file */
        unlink(outpath);
        return -1;
    }
}
