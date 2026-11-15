/*
 * fuzz_frame.c — libFuzzer harness for the encrypted record layer.
 *
 * Feeds arbitrary bytes to farm9crypt_read() as a TCP byte stream and as UDP
 * datagrams: exactly what an on-path attacker without the password controls
 * (header, lengths, magic, version, sequence, the failed-tag path, buffer
 * bounds). The first input byte selects the mode and the caller buffer size.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>

#include "farm9crypt.h"
#include "fuzz_common.h"

static void read_all(int fd, int size) {
    char *buf = malloc((size_t)size);
    if (!buf) return;
    for (int i = 0; i < 64; i++) {
        int n = farm9crypt_read(fd, buf, size);
        if (n <= 0) break;
        if (n > size) abort();                 /* must never exceed the buffer */
    }
    free(buf);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    /* Fixed test key (Argon2id once, not per input) */
    if (farm9crypt_init_password("fuzz-password", 13, FARM9_ROLE_SERVER) != 0) abort();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len) {
    if (len < 1 || len > 65536) return 0;
    int udp = data[0] & 1;
    static const int sizes[] = { 1, 7, 64, 1500, 8192, 20000 };
    int size = sizes[(data[0] >> 1) % 6];
    data++; len--;

    int fds[2];
    if (socketpair(AF_UNIX, udp ? SOCK_DGRAM : SOCK_STREAM, 0, fds) != 0) return 0;
    farm9crypt_set_udp_mode(udp);

    if (udp) {
        /* Split the input into datagrams at 0xFF 0xFE markers */
        size_t start = 0;
        for (size_t i = 0; i + 1 <= len; i++) {
            if (i + 1 == len || (data[i] == 0xFF && data[i + 1] == 0xFE)) {
                size_t end = (i + 1 == len) ? len : i;
                /* Never block: the datagram queue of a socketpair is small
                 * (net.unix.max_dgram_qlen) and nobody reads until later */
                if (end > start && send(fds[0], data + start, end - start, MSG_DONTWAIT) < 0)
                    break;
                start = i + 2;
                i++;
            }
        }
        close(fds[0]);
        /* Datagram sockets have no EOF: read only what is queued */
        fcntl(fds[1], F_SETFL, fcntl(fds[1], F_GETFL, 0) | O_NONBLOCK);
        char *buf = malloc((size_t)size);
        if (buf) {
            for (int i = 0; i < 64; i++) {
                int n = farm9crypt_read(fds[1], buf, size);
                if (n > size) abort();
                if (n <= 0) break;
            }
            free(buf);
        }
    } else {
        size_t off = 0;
        while (off < len) {
            ssize_t w = send(fds[0], data + off, len - off, MSG_DONTWAIT);
            if (w <= 0) break;
            off += (size_t)w;
        }
        shutdown(fds[0], SHUT_WR);
        read_all(fds[1], size);
        close(fds[0]);
    }
    close(fds[1]);
    farm9crypt_set_udp_mode(0);
    return 0;
}
