/*
 * mux.c — Stream multiplexer for ClawSec
 *
 * Multiplexes multiple logical streams over a single encrypted tunnel.
 * Used with -L port forwarding: multiple clients share one tunnel.
 *
 * Frame format: [stream_id(1)][type(1)][length(2 BE)][payload(N)]
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/select.h>

#include "mux.h"
#include "farm9crypt.h"
#include "util.h"
#include "net.h"
#include "obfs.h"
#include "relay.h"

int g_mux = 0;

int mux_encode_header(unsigned char *buf, unsigned char stream_id,
                      unsigned char type, unsigned short length) {
    buf[0] = stream_id;
    buf[1] = type;
    buf[2] = (length >> 8) & 0xFF;
    buf[3] = length & 0xFF;
    return MUX_HDR_SIZE;
}

int mux_decode_header(const unsigned char *buf, mux_header_t *hdr) {
    hdr->stream_id = buf[0];
    hdr->type = buf[1];
    hdr->length = ((unsigned short)buf[2] << 8) | buf[3];
    if (hdr->length > MUX_MAX_PAYLOAD) return -1;
    return 0;
}

int mux_write_frame(int sockfd, unsigned char stream_id,
                    unsigned char type, const void *data, size_t len) {
    if (len > MUX_MAX_PAYLOAD) return -1;

    char frame[MUX_HDR_SIZE + MUX_MAX_PAYLOAD];
    mux_encode_header((unsigned char *)frame, stream_id, type, (unsigned short)len);
    if (len > 0)
        memcpy(frame + MUX_HDR_SIZE, data, len);

    int total = MUX_HDR_SIZE + (int)len;

    if (g_jitter > 0) obfs_jitter(g_jitter);

    return farm9crypt_write(sockfd, frame, total) == total ? (int)len : -1;
}

int mux_read_frame(int sockfd, mux_header_t *hdr, void *buf, size_t buflen) {
    memset(hdr, 0, sizeof(*hdr));

    char raw[MUX_HDR_SIZE + MUX_MAX_PAYLOAD];
    int got = farm9crypt_read(sockfd, raw, sizeof(raw));
    if (got <= 0) return got;

    if (got < MUX_HDR_SIZE) return -1;

    if (mux_decode_header((unsigned char *)raw, hdr) < 0) return -1;
    if ((int)hdr->length > got - MUX_HDR_SIZE) return -1;
    if (hdr->length > buflen) return -1;

    if (hdr->length > 0)
        memcpy(buf, raw + MUX_HDR_SIZE, hdr->length);

    return (int)hdr->length;
}

/* ──────────── Server-side mux relay ──────────── */

int mux_relay_server(int enc_fd, const char *fwd_host, const char *fwd_port) {
    int streams[MUX_MAX_STREAMS];
    memset(streams, -1, sizeof(streams));

    char buf[MUX_MAX_PAYLOAD];

    log_msg(1, "mux: server relay -> %s:%s", fwd_host, fwd_port);

    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(enc_fd, &rfds);
        int nfds = enc_fd;

        for (int i = 0; i < MUX_MAX_STREAMS; i++) {
            if (streams[i] >= 0) {
                FD_SET(streams[i], &rfds);
                if (streams[i] > nfds) nfds = streams[i];
            }
        }

        int ret = select(nfds + 1, &rfds, NULL, NULL, NULL);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* Encrypted side → demux */
        if (FD_ISSET(enc_fd, &rfds)) {
            mux_header_t hdr;
            int n = mux_read_frame(enc_fd, &hdr, buf, sizeof(buf));

            if (n < 0 || (n == 0 && hdr.type == 0)) break;

            switch (hdr.type) {
            case MUX_OPEN: {
                if (hdr.stream_id >= MUX_MAX_STREAMS) break;
                if (streams[hdr.stream_id] >= 0)
                    close(streams[hdr.stream_id]);
                int tfd = net_try_connect(fwd_host, fwd_port, 5);
                if (tfd < 0) {
                    mux_write_frame(enc_fd, hdr.stream_id, MUX_CLOSE, NULL, 0);
                    log_msg(1, "mux: stream %d connect failed", hdr.stream_id);
                } else {
                    streams[hdr.stream_id] = tfd;
                    log_msg(1, "mux: stream %d -> %s:%s",
                            hdr.stream_id, fwd_host, fwd_port);
                }
                break;
            }
            case MUX_DATA:
                if (hdr.stream_id >= MUX_MAX_STREAMS ||
                    streams[hdr.stream_id] < 0) break;
                if (write_all(streams[hdr.stream_id], buf, (size_t)n) < 0) {
                    close(streams[hdr.stream_id]);
                    streams[hdr.stream_id] = -1;
                    mux_write_frame(enc_fd, hdr.stream_id, MUX_CLOSE, NULL, 0);
                }
                break;

            case MUX_CLOSE:
                if (hdr.stream_id >= MUX_MAX_STREAMS) break;
                if (streams[hdr.stream_id] >= 0) {
                    close(streams[hdr.stream_id]);
                    streams[hdr.stream_id] = -1;
                    log_msg(1, "mux: stream %d closed", hdr.stream_id);
                }
                break;
            }
        }

        /* Target connections → mux frames */
        for (int i = 0; i < MUX_MAX_STREAMS; i++) {
            if (streams[i] >= 0 && FD_ISSET(streams[i], &rfds)) {
                ssize_t n = read(streams[i], buf, sizeof(buf));
                if (n <= 0) {
                    close(streams[i]);
                    streams[i] = -1;
                    mux_write_frame(enc_fd, (unsigned char)i, MUX_CLOSE, NULL, 0);
                    log_msg(1, "mux: stream %d target EOF", i);
                } else {
                    if (mux_write_frame(enc_fd, (unsigned char)i,
                                        MUX_DATA, buf, (size_t)n) < 0)
                        goto done;
                }
            }
        }
    }

done:
    for (int i = 0; i < MUX_MAX_STREAMS; i++) {
        if (streams[i] >= 0) close(streams[i]);
    }
    return 0;
}

/* ──────────── Client-side mux relay ──────────── */

int mux_relay_client(int enc_fd, const char *local_port) {
    int listen_fd = net_listen(local_port);

    int streams[MUX_MAX_STREAMS];
    memset(streams, -1, sizeof(streams));
    int next_id = 1;

    char buf[MUX_MAX_PAYLOAD];

    log_msg(1, "mux: client relay on *:%s", local_port);

    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(enc_fd, &rfds);
        FD_SET(listen_fd, &rfds);

        int nfds = enc_fd > listen_fd ? enc_fd : listen_fd;

        for (int i = 0; i < MUX_MAX_STREAMS; i++) {
            if (streams[i] >= 0) {
                FD_SET(streams[i], &rfds);
                if (streams[i] > nfds) nfds = streams[i];
            }
        }

        int ret = select(nfds + 1, &rfds, NULL, NULL, NULL);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* New local connection */
        if (FD_ISSET(listen_fd, &rfds)) {
            int client_fd = net_accept(listen_fd);
            if (client_fd >= 0 && next_id < MUX_MAX_STREAMS) {
                int sid = next_id++;
                streams[sid] = client_fd;
                mux_write_frame(enc_fd, (unsigned char)sid, MUX_OPEN, NULL, 0);
                log_msg(1, "mux: stream %d opened (local)", sid);
            } else if (client_fd >= 0) {
                close(client_fd);
                fprintf(stderr, "mux: max streams reached\n");
            }
        }

        /* Encrypted side → demux */
        if (FD_ISSET(enc_fd, &rfds)) {
            mux_header_t hdr;
            int n = mux_read_frame(enc_fd, &hdr, buf, sizeof(buf));

            if (n < 0 || (n == 0 && hdr.type == 0)) break;

            switch (hdr.type) {
            case MUX_DATA:
                if (hdr.stream_id < MUX_MAX_STREAMS &&
                    streams[hdr.stream_id] >= 0) {
                    if (write_all(streams[hdr.stream_id], buf, (size_t)n) < 0) {
                        close(streams[hdr.stream_id]);
                        streams[hdr.stream_id] = -1;
                        mux_write_frame(enc_fd, hdr.stream_id, MUX_CLOSE, NULL, 0);
                    }
                }
                break;

            case MUX_CLOSE:
                if (hdr.stream_id < MUX_MAX_STREAMS &&
                    streams[hdr.stream_id] >= 0) {
                    close(streams[hdr.stream_id]);
                    streams[hdr.stream_id] = -1;
                    log_msg(1, "mux: stream %d closed by remote", hdr.stream_id);
                }
                break;
            }
        }

        /* Local connections → mux frames */
        for (int i = 0; i < MUX_MAX_STREAMS; i++) {
            if (streams[i] >= 0 && FD_ISSET(streams[i], &rfds)) {
                ssize_t n = read(streams[i], buf, sizeof(buf));
                if (n <= 0) {
                    close(streams[i]);
                    streams[i] = -1;
                    mux_write_frame(enc_fd, (unsigned char)i, MUX_CLOSE, NULL, 0);
                    log_msg(1, "mux: stream %d local EOF", i);
                } else {
                    if (mux_write_frame(enc_fd, (unsigned char)i,
                                        MUX_DATA, buf, (size_t)n) < 0)
                        goto done;
                }
            }
        }
    }

done:
    close(listen_fd);
    for (int i = 0; i < MUX_MAX_STREAMS; i++) {
        if (streams[i] >= 0) close(streams[i]);
    }
    return 0;
}
