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

void filetx_sanitize_name(char *name) {
    if (!name) return;
    for (char *c = name; *c; c++) {
        unsigned char u = (unsigned char)*c;
        if (*c == '/' || *c == '\\' || u < 0x20 || u == 0x7f)
            *c = '_';
    }
    if (name[0] == '.')
        name[0] = '_';
    if (name[0] == '\0')
        strcpy(name, "received.bin");
}

/* Hash the first len bytes of an open file (pread, offset 0) into ctx. */
static int hash_prefix(int fd, uint64_t len, EVP_MD_CTX *ctx) {
    char buf[FILETX_CHUNK_SIZE];
    uint64_t done = 0;
    while (done < len) {
        size_t want = (len - done) < sizeof(buf) ? (size_t)(len - done) : sizeof(buf);
        ssize_t n = pread(fd, buf, want, (off_t)done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        EVP_DigestUpdate(ctx, buf, (size_t)n);
        done += (uint64_t)n;
    }
    return 0;
}

/* Is the existing destination already this exact file? (never follows links) */
static int final_matches(const char *path, uint64_t size, const unsigned char hash[32]) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NOCTTY);
    if (fd < 0) return 0;
    struct stat st;
    int match = 0;
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && (uint64_t)st.st_size == size) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        unsigned char h[32];
        unsigned int hl = 32;
        if (ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
            hash_prefix(fd, size, ctx) == 0 &&
            EVP_DigestFinal_ex(ctx, h, &hl) == 1)
            match = memcmp(h, hash, 32) == 0;
        EVP_MD_CTX_free(ctx);
    }
    close(fd);
    return match;
}

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
    filetx_sanitize_name(filename);            /* also stops at an embedded NUL */

    const char *dir = (output_dir && output_dir[0]) ? output_dir : ".";
    char outpath[4096], partpath[4096 + sizeof(FILETX_PART_SUFFIX)];
    int n1 = snprintf(outpath, sizeof(outpath), "%s/%s", dir, filename);
    int n2 = snprintf(partpath, sizeof(partpath), "%s%s", outpath, FILETX_PART_SUFFIX);
    if (n1 < 0 || (size_t)n1 >= sizeof(outpath) || n2 < 0 || (size_t)n2 >= sizeof(partpath)) {
        fprintf(stderr, "ERROR: Output path too long\n");
        return -1;
    }

    log_msg(1, "Receiving: %s (%llu bytes)", filename, (unsigned long long)file_size);
    fprintf(stderr, "Receiving: %s (%llu bytes)\n", filename,
            (unsigned long long)file_size);

    /* Already received? (identical regular file at the destination) */
    if (final_matches(outpath, file_size, expected_hash)) {
        fprintf(stderr, "File already exists and verified.\n");
        char offset_buf[8];
        put_be64((unsigned char *)offset_buf, file_size);
        if (farm9crypt_write(tunnel_fd, offset_buf, 8) < 0) return -1;
        char ok = 0;
        farm9crypt_write(tunnel_fd, &ok, 1);
        return 0;
    }

    /* Partial data lives in our own "<name>.clawsec-part": never follow a
     * symlink, never write into a file that is not ours or has other links. */
    int fd = open(partpath, O_RDWR | O_CREAT | O_NOFOLLOW | O_NOCTTY, 0644);
    if (fd < 0) {
        fprintf(stderr, "ERROR: Cannot create '%s': %s\n", partpath, strerror(errno));
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
        st.st_uid != geteuid()) {
        fprintf(stderr, "ERROR: Refusing to use '%s' (not a private regular file)\n", partpath);
        close(fd);
        return -1;
    }

    uint64_t offset = (uint64_t)st.st_size;
    if (offset > file_size) {                   /* stale partial of another file */
        if (ftruncate(fd, 0) < 0) { close(fd); return -1; }
        offset = 0;
    }
    if (offset > 0)
        fprintf(stderr, "Partial file found (%llu bytes), resuming...\n",
                (unsigned long long)offset);

    /* Hash what we already have, then append */
    EVP_MD_CTX *sha_ctx = EVP_MD_CTX_new();
    if (!sha_ctx || EVP_DigestInit_ex(sha_ctx, EVP_sha256(), NULL) != 1 ||
        (offset > 0 && hash_prefix(fd, offset, sha_ctx) != 0) ||
        lseek(fd, (off_t)offset, SEEK_SET) < 0) {
        fprintf(stderr, "ERROR: Cannot read partial file '%s'\n", partpath);
        EVP_MD_CTX_free(sha_ctx);
        close(fd);
        return -1;
    }

    /* Send resume offset */
    char offset_buf[8];
    put_be64((unsigned char *)offset_buf, offset);
    if (farm9crypt_write(tunnel_fd, offset_buf, 8) < 0) {
        fprintf(stderr, "ERROR: Failed to send resume offset\n");
        EVP_MD_CTX_free(sha_ctx);
        close(fd);
        return -1;
    }

    /* Receive data chunks */
    uint64_t received = 0;
    uint64_t to_recv = file_size - offset;
    struct timeval start;
    gettimeofday(&start, NULL);

    char chunk[FILETX_CHUNK_SIZE];
    while (received < to_recv) {
        rlen = farm9crypt_read(tunnel_fd, chunk, sizeof(chunk));
        if (rlen <= 0) {
            fprintf(stderr, "\nERROR: Tunnel read failed at %llu/%llu "
                            "(partial data kept in %s for resume)\n",
                    (unsigned long long)(offset + received),
                    (unsigned long long)file_size, partpath);
            close(fd);
            EVP_MD_CTX_free(sha_ctx);
            return -1;
        }

        /* Don't write more than expected */
        size_t to_write = (size_t)rlen;
        if (received + to_write > to_recv)
            to_write = (size_t)(to_recv - received);

        if (write_all(fd, chunk, to_write) < 0) {
            fprintf(stderr, "\nERROR: Write failed: %s\n", strerror(errno));
            close(fd);
            EVP_MD_CTX_free(sha_ctx);
            return -1;
        }

        EVP_DigestUpdate(sha_ctx, chunk, to_write);
        received += to_write;
        print_progress(received, to_recv, &start, "RX");
    }
    fprintf(stderr, "\n");

    /* Compute final hash */
    unsigned char computed_hash[32];
    unsigned int hlen = 32;
    EVP_DigestFinal_ex(sha_ctx, computed_hash, &hlen);
    EVP_MD_CTX_free(sha_ctx);

    int match = (memcmp(computed_hash, expected_hash, 32) == 0);
    if (match && (fsync(fd) < 0 || rename(partpath, outpath) < 0)) {
        fprintf(stderr, "ERROR: Cannot move '%s' into place: %s\n", partpath, strerror(errno));
        match = 0;
    }
    close(fd);

    char verify = match ? 0 : 1;
    farm9crypt_write(tunnel_fd, &verify, 1);

    if (match) {
        fprintf(stderr, "✓ SHA-256 verified — saved to %s\n", outpath);
        return 0;
    }
    fprintf(stderr, "✗ SHA-256 MISMATCH — file may be corrupted, discarded\n");
    unlink(partpath);                           /* only ever our own partial file */
    return -1;
}
