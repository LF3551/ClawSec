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
#include <poll.h>

#include "mux.h"
#include "farm9crypt.h"
#include "util.h"
#include "net.h"
#include "obfs.h"
#include "relay.h"

int g_mux = 0;

_Static_assert(MUX_HDR_SIZE + MUX_MAX_PAYLOAD <= FARM9_MAX_MSG,
               "a mux frame must fit into one encrypted message");

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

/* ──────────── Stream table (shared by both sides) ────────────
 *
 * A stream id is reused only after both sides agree it is closed:
 *   OPEN    -- local fd open, data flows
 *   CLOSING -- we closed our fd and sent CLOSE; waiting for the peer's CLOSE
 *              (data still in flight for the old stream is dropped)
 *   FREE    -- id may be (re)used
 * Receiving CLOSE for an OPEN stream closes it and answers with CLOSE (ack);
 * receiving CLOSE for a CLOSING stream completes the close. Ordering of the
 * encrypted channel guarantees that every frame of the old stream arrives
 * before the ack, so a reused id never receives stale data.
 * (A 3.0.0 peer does not send the ack; with it ids are not reused.)
 */

enum { ST_FREE = 0, ST_OPEN, ST_CLOSING };

typedef struct {
    int fd[MUX_MAX_STREAMS];
    unsigned char state[MUX_MAX_STREAMS];
} mux_table_t;

static void table_init(mux_table_t *t) {
    for (int i = 0; i < MUX_MAX_STREAMS; i++) {
        t->fd[i] = -1;
        t->state[i] = ST_FREE;
    }
}

static void table_close_all(mux_table_t *t) {
    for (int i = 0; i < MUX_MAX_STREAMS; i++)
        if (t->fd[i] >= 0) close(t->fd[i]);
    table_init(t);
}

/* Local side of stream id finished (EOF/error): close and tell the peer */
static int local_close(int enc_fd, mux_table_t *t, int id) {
    if (t->fd[id] >= 0) close(t->fd[id]);
    t->fd[id] = -1;
    t->state[id] = ST_CLOSING;
    return mux_write_frame(enc_fd, (unsigned char)id, MUX_CLOSE, NULL, 0);
}

/* Peer sent CLOSE for id */
static int peer_close(int enc_fd, mux_table_t *t, int id) {
    if (t->state[id] == ST_OPEN) {
        if (t->fd[id] >= 0) close(t->fd[id]);
        t->fd[id] = -1;
        t->state[id] = ST_FREE;
        return mux_write_frame(enc_fd, (unsigned char)id, MUX_CLOSE, NULL, 0); /* ack */
    }
    t->state[id] = ST_FREE;     /* CLOSING -> FREE, or a stray CLOSE */
    return 0;
}

/* Peer sent DATA for id */
static int peer_data(int enc_fd, mux_table_t *t, int id, const char *buf, size_t n) {
    if (t->state[id] != ST_OPEN || t->fd[id] < 0) return 0;   /* stale: drop */
    if (write_all(t->fd[id], buf, n) < 0)
        return local_close(enc_fd, t, id);
    return 0;
}

/* Build the poll set: [enc_fd][extra_fd?][open streams...] */
static int build_pollset(struct pollfd *pfd, int *ids, int enc_fd, int extra_fd,
                         const mux_table_t *t) {
    int n = 0;
    pfd[n].fd = enc_fd; pfd[n].events = POLLIN; pfd[n].revents = 0; ids[n++] = -1;
    if (extra_fd >= 0) {
        pfd[n].fd = extra_fd; pfd[n].events = POLLIN; pfd[n].revents = 0; ids[n++] = -2;
    }
    for (int i = 0; i < MUX_MAX_STREAMS; i++) {
        if (t->state[i] == ST_OPEN && t->fd[i] >= 0) {
            pfd[n].fd = t->fd[i]; pfd[n].events = POLLIN; pfd[n].revents = 0;
            ids[n++] = i;
        }
    }
    return n;
}

/* Forward readable local streams into the tunnel. Returns -1 if the
 * tunnel failed. */
static int pump_streams(int enc_fd, mux_table_t *t, struct pollfd *pfd,
                        const int *ids, int n, char *buf) {
    for (int k = 0; k < n; k++) {
        int id = ids[k];
        if (id < 0 || !(pfd[k].revents & (POLLIN | POLLHUP | POLLERR))) continue;
        /* The id may have been closed or reused while handling a tunnel frame
         * in this iteration: only read the very fd that poll() reported. */
        if (t->state[id] != ST_OPEN || t->fd[id] != pfd[k].fd) continue;
        ssize_t r = read(t->fd[id], buf, MUX_MAX_PAYLOAD);
        if (r <= 0) {
            log_msg(1, "mux: stream %d local EOF", id);
            if (local_close(enc_fd, t, id) < 0) return -1;
        } else if (mux_write_frame(enc_fd, (unsigned char)id, MUX_DATA, buf, (size_t)r) < 0) {
            return -1;
        }
    }
    return 0;
}

/* ──────────── Server-side mux relay ──────────── */

int mux_relay_server(int enc_fd, const char *fwd_host, const char *fwd_port) {
    mux_table_t t;
    table_init(&t);
    char buf[MUX_MAX_PAYLOAD];
    struct pollfd pfd[MUX_MAX_STREAMS + 2];
    int ids[MUX_MAX_STREAMS + 2];

    log_msg(1, "mux: server relay -> %s:%s", fwd_host, fwd_port);

    for (;;) {
        int n = build_pollset(pfd, ids, enc_fd, -1, &t);
        int ret = poll(pfd, (nfds_t)n, -1);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* Encrypted side -> demux */
        if (pfd[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            mux_header_t hdr;
            int got = mux_read_frame(enc_fd, &hdr, buf, sizeof(buf));
            if (got < 0 || (got == 0 && hdr.type == 0)) break;
            if (hdr.stream_id >= MUX_MAX_STREAMS) continue;
            int id = hdr.stream_id;

            switch (hdr.type) {
            case MUX_OPEN: {
                if (t.fd[id] >= 0) close(t.fd[id]);       /* peer reused the id */
                t.fd[id] = -1;
                int tfd = net_try_connect(fwd_host, fwd_port, 5);
                if (tfd < 0) {
                    log_msg(1, "mux: stream %d connect failed", id);
                    t.state[id] = ST_CLOSING;
                    if (mux_write_frame(enc_fd, (unsigned char)id, MUX_CLOSE, NULL, 0) < 0)
                        goto done;
                } else {
                    t.fd[id] = tfd;
                    t.state[id] = ST_OPEN;
                    log_msg(1, "mux: stream %d -> %s:%s", id, fwd_host, fwd_port);
                }
                break;
            }
            case MUX_DATA:
                if (peer_data(enc_fd, &t, id, buf, (size_t)got) < 0) goto done;
                break;
            case MUX_CLOSE:
                if (peer_close(enc_fd, &t, id) < 0) goto done;
                log_msg(1, "mux: stream %d closed", id);
                break;
            }
        }

        if (pump_streams(enc_fd, &t, pfd, ids, n, buf) < 0) break;
    }

done:
    table_close_all(&t);
    return 0;
}

/* ──────────── Client-side mux relay ──────────── */

int mux_relay_client(int enc_fd, const char *listen_host, const char *local_port) {
    int listen_fd = net_listen_on(listen_host, local_port);
    if (listen_fd < 0) return -1;

    mux_table_t t;
    table_init(&t);
    char buf[MUX_MAX_PAYLOAD];
    struct pollfd pfd[MUX_MAX_STREAMS + 2];
    int ids[MUX_MAX_STREAMS + 2];

    log_msg(1, "mux: client relay on %s:%s", listen_host ? listen_host : "*", local_port);

    for (;;) {
        int n = build_pollset(pfd, ids, enc_fd, listen_fd, &t);
        int ret = poll(pfd, (nfds_t)n, -1);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* New local connection: lowest free id (0 is never used) */
        if (pfd[1].revents & POLLIN) {
            int client_fd = accept(listen_fd, NULL, NULL);
            if (client_fd >= 0) {
                int sid = -1;
                for (int i = 1; i < MUX_MAX_STREAMS; i++)
                    if (t.state[i] == ST_FREE) { sid = i; break; }
                if (sid < 0) {
                    close(client_fd);
                    fprintf(stderr, "mux: all %d streams busy, connection refused\n",
                            MUX_MAX_STREAMS - 1);
                } else {
                    t.fd[sid] = client_fd;
                    t.state[sid] = ST_OPEN;
                    if (mux_write_frame(enc_fd, (unsigned char)sid, MUX_OPEN, NULL, 0) < 0)
                        goto done;
                    log_msg(1, "mux: stream %d opened (local)", sid);
                }
            }
        }

        /* Encrypted side -> demux */
        if (pfd[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            mux_header_t hdr;
            int got = mux_read_frame(enc_fd, &hdr, buf, sizeof(buf));
            if (got < 0 || (got == 0 && hdr.type == 0)) break;
            if (hdr.stream_id >= MUX_MAX_STREAMS) continue;
            int id = hdr.stream_id;

            if (hdr.type == MUX_DATA) {
                if (peer_data(enc_fd, &t, id, buf, (size_t)got) < 0) goto done;
            } else if (hdr.type == MUX_CLOSE) {
                if (peer_close(enc_fd, &t, id) < 0) goto done;
                log_msg(1, "mux: stream %d closed by remote", id);
            }
        }

        if (pump_streams(enc_fd, &t, pfd, ids, n, buf) < 0) break;
    }

done:
    close(listen_fd);
    table_close_all(&t);
    return 0;
}
