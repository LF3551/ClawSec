/*
 * mux.c — stream multiplexer for ClawSec (see mux.h for the frame format)
 *
 * Event loop design (one thread; helper threads only for outbound connects):
 *  - The tunnel is read whenever it is readable; it is written only from a
 *    queue when poll() reports POLLOUT, so the two ends never deadlock with
 *    both sides blocked in a tunnel write.
 *  - Local sockets are written from per-stream queues on POLLOUT; a slow
 *    local consumer only stalls its own stream. With a v2 peer each stream
 *    has a receive window (MUX_WINDOW_SIZE): the sender stops reading its
 *    local socket when the window is used up, so memory stays bounded.
 *  - Local reads pause while the tunnel queue is above TUNQ_HIGH.
 *  - Outbound connects (and DNS) of the server run in detached helper
 *    threads and report through a pipe, so a slow destination never stalls
 *    the other streams.
 *
 * Stream ids are reused only after both sides agree the stream is closed:
 * CLOSE closes a stream; the receiver of a CLOSE for a stream it still has
 * open first delivers pending data to its local socket, then closes and
 * answers with CLOSE (ack). v2 streams half-close with FIN and send CLOSE
 * once both directions are finished.
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "mux.h"
#include "farm9crypt.h"
#include "util.h"
#include "net.h"
#include "obfs.h"
#include "acl.h"
#include "relay.h"

int g_mux = 0;

_Static_assert(MUX_HDR_SIZE + MUX_MAX_PAYLOAD <= FARM9_MAX_MSG,
               "a mux frame must fit into one encrypted message");

#define TUNQ_HIGH        (1024 * 1024)        /* pause local reads above this */
#define LEGACY_QUEUE_MAX (4 * 1024 * 1024)    /* v1 streams: no flow control */
#define SOCKS_BUF        600
#define SOCKS_TIMEOUT_S  10
#define CONNECT_TIMEOUT  10

/* ──────────── Frame encoding ──────────── */

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
    if ((int)hdr->length != got - MUX_HDR_SIZE) return -1;
    if (hdr->length > buflen) return -1;

    if (hdr->length > 0)
        memcpy(buf, raw + MUX_HDR_SIZE, hdr->length);

    return (int)hdr->length;
}

int mux_encode_open(unsigned char *buf, size_t buflen, unsigned char flags,
                    const char *host, uint16_t port) {
    size_t hl = host ? strlen(host) : 0;
    if (hl > 255 || buflen < 1 + (host ? 3 + hl : 0)) return -1;
    buf[0] = flags;
    if (!host) return 1;
    buf[1] = (unsigned char)hl;
    memcpy(buf + 2, host, hl);
    buf[2 + hl] = (unsigned char)(port >> 8);
    buf[3 + hl] = (unsigned char)(port & 0xff);
    return (int)(4 + hl);
}

int mux_decode_open(const unsigned char *buf, size_t len, unsigned char *flags,
                    char *host, size_t hostlen, uint16_t *port, int *has_target) {
    *flags = 0;
    *has_target = 0;
    if (len == 0) return 0;                       /* v1 OPEN */
    *flags = buf[0];
    if (len == 1) return 0;
    size_t hl = buf[1];
    if (len != 4 + hl || hl == 0 || !host || hostlen <= hl) return -1;
    memcpy(host, buf + 2, hl);
    host[hl] = '\0';
    if (memchr(host, '\0', hl)) return -1;        /* embedded NUL */
    *port = (uint16_t)((buf[2 + hl] << 8) | buf[3 + hl]);
    *has_target = 1;
    return 0;
}

/* ──────────── SOCKS5 parsing (client side, local application) ──────────── */

int mux_socks_parse_greeting(const unsigned char *buf, size_t len) {
    if (len < 2) return 0;
    if (buf[0] != 0x05) return -1;
    size_t need = 2 + (size_t)buf[1];
    if (len < need) return 0;
    for (size_t i = 2; i < need; i++)
        if (buf[i] == 0x00) return (int)need;     /* "no authentication" offered */
    return -1;
}

int mux_socks_parse_request(const unsigned char *buf, size_t len, char *host,
                            size_t hostlen, uint16_t *port, unsigned char *reply_code) {
    *reply_code = 0x01;
    if (len < 4) return 0;
    if (buf[0] != 0x05) return -1;
    if (buf[1] != 0x01) { *reply_code = 0x07; return -1; }   /* only CONNECT */
    size_t need;
    switch (buf[3]) {
    case 0x01: need = 4 + 4 + 2; break;
    case 0x04: need = 4 + 16 + 2; break;
    case 0x03:
        if (len < 5) return 0;
        if (buf[4] == 0) return -1;
        need = 5 + (size_t)buf[4] + 2;
        break;
    default:
        *reply_code = 0x08;                        /* address type not supported */
        return -1;
    }
    if (len < need) return 0;
    if (buf[3] == 0x01) {
        if (!inet_ntop(AF_INET, buf + 4, host, (socklen_t)hostlen)) return -1;
    } else if (buf[3] == 0x04) {
        if (!inet_ntop(AF_INET6, buf + 4, host, (socklen_t)hostlen)) return -1;
    } else {
        size_t hl = buf[4];
        if (hl >= hostlen || memchr(buf + 5, '\0', hl)) return -1;
        memcpy(host, buf + 5, hl);
        host[hl] = '\0';
    }
    *port = (uint16_t)((buf[need - 2] << 8) | buf[need - 1]);
    return (int)need;
}

/* ──────────── Byte queues ──────────── */

typedef struct chunk {
    struct chunk *next;
    size_t len, off;
    unsigned char data[];
} chunk_t;

typedef struct {
    chunk_t *head, *tail;
    size_t bytes;
} queue_t;

static int q_push(queue_t *q, const void *data, size_t len) {
    if (len == 0) return 0;
    chunk_t *c = malloc(sizeof(*c) + len);
    if (!c) return -1;
    c->next = NULL;
    c->len = len;
    c->off = 0;
    memcpy(c->data, data, len);
    if (q->tail) q->tail->next = c; else q->head = c;
    q->tail = c;
    q->bytes += len;
    return 0;
}

static void q_drop(queue_t *q, size_t n) {
    while (n && q->head) {
        chunk_t *c = q->head;
        size_t avail = c->len - c->off;
        size_t k = n < avail ? n : avail;
        c->off += k;
        q->bytes -= k;
        n -= k;
        if (c->off == c->len) {
            q->head = c->next;
            if (!q->head) q->tail = NULL;
            free(c);
        }
    }
}

static void q_clear(queue_t *q) {
    q_drop(q, q->bytes);
    q->head = q->tail = NULL;
    q->bytes = 0;
}

/* ──────────── Streams and session ──────────── */

enum {
    ST_FREE = 0,
    ST_SOCKS,        /* client: SOCKS5 negotiation with the local application */
    ST_WAIT_REPLY,   /* client: OPEN sent, waiting for REPLY */
    ST_CONNECTING,   /* server: outbound connect in progress */
    ST_OPEN,
    ST_DRAINING,     /* peer sent CLOSE: deliver queued data, then close + ack */
    ST_LINGER,       /* local-only close after flushing (SOCKS errors) */
    ST_CLOSING       /* we sent CLOSE, waiting for the peer's CLOSE */
};

typedef struct {
    int fd;
    unsigned char state;
    unsigned char fc;          /* v2 stream: flow control + FIN */
    unsigned char rd_eof;      /* local read side finished (FIN sent) */
    unsigned char peer_fin;    /* peer sent FIN */
    unsigned char wr_shut;     /* local write side shut down */
    uint32_t gen;              /* generation, for connect results */
    uint32_t credit;           /* bytes we may still send (v2) */
    uint32_t consumed;         /* bytes delivered locally since the last WINDOW */
    uint32_t local_only;       /* queued bytes that did not come from the peer
                                  (SOCKS replies): not part of the window */
    queue_t out;               /* data waiting for the local socket */
    time_t since;              /* ST_SOCKS start */
    int greeted;
    size_t slen;
    unsigned char sbuf[SOCKS_BUF];
} stream_t;

typedef enum { MODE_FWD_SERVER, MODE_FWD_CLIENT, MODE_SOCKS_SERVER, MODE_SOCKS_CLIENT } mux_mode_t;

typedef struct {
    int enc;
    mux_mode_t mode;
    int peer_v2;
    int listen_fd;
    const char *fwd_host, *fwd_port;
    queue_t tunq;
    int dead;                  /* tunnel failed */
    stream_t s[MUX_MAX_STREAMS];
} mux_t;

static int is_server(const mux_t *m) {
    return m->mode == MODE_FWD_SERVER || m->mode == MODE_SOCKS_SERVER;
}

/* Queue a frame for the tunnel */
static void send_frame(mux_t *m, int id, int type, const void *data, size_t len) {
    unsigned char f[MUX_HDR_SIZE + MUX_MAX_PAYLOAD];
    if (len > MUX_MAX_PAYLOAD) { m->dead = 1; return; }
    mux_encode_header(f, (unsigned char)id, (unsigned char)type, (unsigned short)len);
    if (len) memcpy(f + MUX_HDR_SIZE, data, len);
    if (q_push(&m->tunq, f, MUX_HDR_SIZE + len) != 0) m->dead = 1;
}

static void send_u32(mux_t *m, int id, int type, uint32_t v) {
    unsigned char b[4] = { (unsigned char)(v >> 24), (unsigned char)(v >> 16),
                           (unsigned char)(v >> 8), (unsigned char)v };
    send_frame(m, id, type, b, 4);
}

static void stream_reset(stream_t *s) {
    if (s->fd >= 0) close(s->fd);
    q_clear(&s->out);
    uint32_t gen = s->gen + 1;
    memset(s, 0, sizeof(*s));
    s->fd = -1;
    s->gen = gen;
}

/* Our side is finished with id (or aborts it): close locally, tell the peer */
static void close_and_notify(mux_t *m, int id) {
    stream_t *s = &m->s[id];
    if (s->fd >= 0) close(s->fd);
    s->fd = -1;
    q_clear(&s->out);
    s->state = ST_CLOSING;
    send_frame(m, id, MUX_CLOSE, NULL, 0);
}

/* Both directions of a v2 stream done? Then close it. */
static void maybe_finish(mux_t *m, int id) {
    stream_t *s = &m->s[id];
    if (s->state == ST_OPEN && s->fc && s->rd_eof && s->peer_fin && s->out.bytes == 0)
        close_and_notify(m, id);
}

static int set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL);
    return fl < 0 ? -1 : fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* ──────────── Asynchronous connects (server) ──────────── */

typedef struct {
    int id;
    uint32_t gen;
    int fd;
    int status;
} connect_result_t;

typedef struct {
    int id;
    uint32_t gen;
    int filtered;
    char host[256];
    char port[8];
} connect_job_t;

static int s_notify[2] = { -1, -1 };      /* never closed: helpers may still write */

static void *connect_worker(void *arg) {
    connect_job_t *job = arg;
    connect_result_t r = { job->id, job->gen, -1, MUX_REPLY_FAIL };
    int denied = 0;
    if (job->filtered)
        r.fd = net_try_connect_filtered(job->host, job->port, CONNECT_TIMEOUT, acl_allowed, &denied);
    else
        r.fd = net_try_connect(job->host, job->port, CONNECT_TIMEOUT);
    if (r.fd >= 0) r.status = MUX_REPLY_OK;
    else if (denied) r.status = MUX_REPLY_DENIED;
    if (r.status == MUX_REPLY_DENIED)
        log_msg(1, "mux: stream %d: %s:%s denied by destination policy (see --socks-allow)",
                job->id, job->host, job->port);
    else if (r.status != MUX_REPLY_OK)
        log_msg(1, "mux: stream %d: connect to %s:%s failed", job->id, job->host, job->port);
    if (write(s_notify[1], &r, sizeof(r)) != (ssize_t)sizeof(r) && r.fd >= 0)
        close(r.fd);
    free(job);
    return NULL;
}

static int start_connect(int id, uint32_t gen, const char *host, const char *port, int filtered) {
    if (s_notify[0] < 0) {
        if (pipe(s_notify) != 0) return -1;
        fcntl(s_notify[0], F_SETFD, FD_CLOEXEC);
        fcntl(s_notify[1], F_SETFD, FD_CLOEXEC);
    }
    connect_job_t *job = calloc(1, sizeof(*job));
    if (!job) return -1;
    job->id = id;
    job->gen = gen;
    job->filtered = filtered;
    snprintf(job->host, sizeof(job->host), "%s", host);
    snprintf(job->port, sizeof(job->port), "%s", port);
    pthread_t t;
    pthread_attr_t a;
    pthread_attr_init(&a);
    pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
    int rc = pthread_create(&t, &a, connect_worker, job);
    pthread_attr_destroy(&a);
    if (rc != 0) {
        free(job);
        return -1;
    }
    return 0;
}

static void on_connect_result(mux_t *m, const connect_result_t *r) {
    stream_t *s = (r->id > 0 && r->id < MUX_MAX_STREAMS) ? &m->s[r->id] : NULL;
    if (!s || s->gen != r->gen || s->state != ST_CONNECTING) {
        if (r->fd >= 0) close(r->fd);              /* stream gone meanwhile */
        return;
    }
    if (s->fc) {
        unsigned char st = (unsigned char)r->status;
        send_frame(m, r->id, MUX_REPLY, &st, 1);
    }
    if (r->fd < 0) {
        close_and_notify(m, r->id);
        return;
    }
    set_nonblock(r->fd);
    s->fd = r->fd;
    s->state = ST_OPEN;
    log_msg(1, "mux: stream %d connected", r->id);
    if (s->peer_fin && s->out.bytes == 0) {    /* FIN arrived while connecting */
        shutdown(s->fd, SHUT_WR);
        s->wr_shut = 1;
    }
}

/* ──────────── Frames from the peer ──────────── */

static void handle_open(mux_t *m, int id, const unsigned char *p, size_t len) {
    stream_t *s = &m->s[id];
    unsigned char flags;
    char host[256];
    uint16_t port = 0;
    int has_target;

    if (s->state != ST_FREE) stream_reset(s);   /* v1 peer reused the id */
    if (mux_decode_open(p, len, &flags, host, sizeof(host), &port, &has_target) != 0) {
        send_frame(m, id, MUX_CLOSE, NULL, 0);
        s->state = ST_CLOSING;
        return;
    }
    s->fc = (flags & MUX_OPEN_FC) != 0;
    s->credit = MUX_WINDOW_SIZE;
    s->state = ST_CONNECTING;

    const char *h, *pt;
    char port_str[8];
    int filtered = 0;
    if (m->mode == MODE_SOCKS_SERVER) {
        if (!has_target) {
            unsigned char st = MUX_REPLY_FAIL;
            if (s->fc) send_frame(m, id, MUX_REPLY, &st, 1);
            close_and_notify(m, id);
            return;
        }
        snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
        h = host;
        pt = port_str;
        filtered = 1;
        log_msg(1, "mux: stream %d SOCKS CONNECT %s:%s", id, h, pt);
    } else {
        h = m->fwd_host;
        pt = m->fwd_port;
        log_msg(1, "mux: stream %d -> %s:%s", id, h, pt);
    }
    if (start_connect(id, s->gen, h, pt, filtered) != 0) {
        connect_result_t r = { id, s->gen, -1, MUX_REPLY_FAIL };
        on_connect_result(m, &r);
    }
}

static void handle_data(mux_t *m, int id, const unsigned char *p, size_t len) {
    stream_t *s = &m->s[id];
    if (s->state != ST_OPEN && s->state != ST_CONNECTING && s->state != ST_WAIT_REPLY)
        return;                                       /* stale: drop */
    if (s->peer_fin) return;                          /* data after FIN: ignore */
    if (s->fc && s->out.bytes - s->local_only + len > MUX_WINDOW_SIZE) {
        log_msg(1, "mux: stream %d: peer exceeded the flow-control window, closing it", id);
        close_and_notify(m, id);
        return;
    }
    if (q_push(&s->out, p, len) != 0) close_and_notify(m, id);
}

static void handle_close(mux_t *m, int id) {
    stream_t *s = &m->s[id];
    switch (s->state) {
    case ST_CLOSING:
    case ST_FREE:
        stream_reset(s);                              /* ack, or stray CLOSE */
        break;
    case ST_OPEN:
        if (s->fd >= 0 && s->out.bytes > 0) {
            s->state = ST_DRAINING;                   /* deliver, then ack */
            break;
        }
        /* fall through */
    case ST_DRAINING:                                 /* (duplicate CLOSE) */
    default:
        stream_reset(s);
        send_frame(m, id, MUX_CLOSE, NULL, 0);
        break;
    }
}

static void handle_reply(mux_t *m, int id, const unsigned char *p, size_t len) {
    stream_t *s = &m->s[id];
    if (s->state != ST_WAIT_REPLY || len != 1) return;
    unsigned char rep[10] = { 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
    if (p[0] == MUX_REPLY_OK) {
        q_push(&s->out, rep, sizeof(rep));
        s->local_only += sizeof(rep);
        s->state = ST_OPEN;
        if (s->slen) {                                /* data sent before the reply */
            size_t n = s->slen;
            send_frame(m, id, MUX_DATA, s->sbuf, n);
            s->credit -= (uint32_t)n;
            s->slen = 0;
        }
    } else {
        rep[1] = p[0] == MUX_REPLY_DENIED ? 0x02 : 0x04;
        q_push(&s->out, rep, sizeof(rep));
        s->local_only += sizeof(rep);
        s->state = ST_OPEN;          /* deliver the error; the server's CLOSE follows */
        s->rd_eof = 1;               /* (and is answered by handle_close) */
        s->slen = 0;
    }
}

static void handle_frame(mux_t *m, const mux_header_t *h, const unsigned char *p, size_t len) {
    int id = h->stream_id;
    if (h->type == MUX_HELLO) {
        if (id == 0 && len >= 1 && p[0] >= 2 && !m->peer_v2) {
            m->peer_v2 = 1;
            log_msg(1, "mux: peer speaks mux v%u", p[0]);
        }
        return;
    }
    if (id == 0) return;
    if (!m->peer_v2 && id >= MUX_V1_STREAMS) return;
    switch (h->type) {
    case MUX_OPEN:
        if (is_server(m)) handle_open(m, id, p, len);
        break;
    case MUX_DATA:
        handle_data(m, id, p, len);
        break;
    case MUX_CLOSE:
        handle_close(m, id);
        log_msg(1, "mux: stream %d closed by peer", id);
        break;
    case MUX_REPLY:
        if (!is_server(m)) handle_reply(m, id, p, len);
        break;
    case MUX_FIN: {
        stream_t *s = &m->s[id];
        if (!s->fc || s->peer_fin) break;
        if (s->state != ST_OPEN && s->state != ST_CONNECTING && s->state != ST_WAIT_REPLY) break;
        s->peer_fin = 1;
        if (s->state == ST_OPEN && s->out.bytes == 0 && s->fd >= 0) {
            shutdown(s->fd, SHUT_WR);
            s->wr_shut = 1;
            maybe_finish(m, id);
        }
        break;
    }
    case MUX_WINDOW:
        if (len == 4 && m->s[id].fc && m->s[id].state != ST_FREE) {
            uint32_t inc = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                           ((uint32_t)p[2] << 8) | p[3];
            uint64_t c = (uint64_t)m->s[id].credit + inc;
            m->s[id].credit = c > MUX_WINDOW_SIZE ? MUX_WINDOW_SIZE : (uint32_t)c;
        }
        break;
    default:
        break;                                        /* unknown type: ignore */
    }
}

/* ──────────── Local sockets ──────────── */

/* Deliver queued data to the local socket */
static void flush_local(mux_t *m, int id) {
    stream_t *s = &m->s[id];
    while (s->out.bytes > 0 && s->fd >= 0) {
        chunk_t *c = s->out.head;
        ssize_t w = write(s->fd, c->data + c->off, c->len - c->off);
        if (w < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            log_msg(1, "mux: stream %d local write failed", id);
            if (s->state == ST_SOCKS || s->state == ST_LINGER) {
                stream_reset(s);                     /* the peer never saw this id */
            } else if (s->state == ST_DRAINING) {
                stream_reset(s);
                send_frame(m, id, MUX_CLOSE, NULL, 0);   /* ack */
            } else {
                close_and_notify(m, id);
            }
            return;
        }
        q_drop(&s->out, (size_t)w);
        uint32_t counted = (uint32_t)w;
        if (s->local_only) {
            uint32_t k = s->local_only < counted ? s->local_only : counted;
            s->local_only -= k;
            counted -= k;
        }
        if (s->fc && s->state == ST_OPEN && counted) {
            s->consumed += counted;
            if (s->consumed >= MUX_WINDOW_SIZE / 4) {
                send_u32(m, id, MUX_WINDOW, s->consumed);
                s->consumed = 0;
            }
        }
    }
    if (s->out.bytes) return;
    if (s->state == ST_DRAINING) {
        stream_reset(s);
        send_frame(m, id, MUX_CLOSE, NULL, 0);
    } else if (s->state == ST_LINGER) {
        stream_reset(s);
    } else if (s->state == ST_OPEN && s->peer_fin && !s->wr_shut && s->fd >= 0) {
        shutdown(s->fd, SHUT_WR);
        s->wr_shut = 1;
        maybe_finish(m, id);
    }
}

static void socks_fail_local(stream_t *s, unsigned char code) {
    unsigned char rep[10] = { 0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
    q_push(&s->out, rep, sizeof(rep));
    s->state = ST_LINGER;
}

/* Client: SOCKS5 negotiation bytes from the local application */
static void socks_input(mux_t *m, int id) {
    stream_t *s = &m->s[id];
    ssize_t r = read(s->fd, s->sbuf + s->slen, sizeof(s->sbuf) - s->slen);
    if (r == 0 || (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
        stream_reset(s);
        return;
    }
    if (r < 0) return;
    s->slen += (size_t)r;

    if (!s->greeted) {
        int n = mux_socks_parse_greeting(s->sbuf, s->slen);
        if (n < 0) {
            static const unsigned char no[2] = { 0x05, 0xFF };
            q_push(&s->out, no, 2);
            s->state = ST_LINGER;
            return;
        }
        if (n == 0) goto check_full;
        static const unsigned char yes[2] = { 0x05, 0x00 };
        q_push(&s->out, yes, 2);
        s->local_only += 2;
        s->greeted = 1;
        memmove(s->sbuf, s->sbuf + n, s->slen - (size_t)n);
        s->slen -= (size_t)n;
    }
    {
        char host[256];
        uint16_t port;
        unsigned char code;
        int n = mux_socks_parse_request(s->sbuf, s->slen, host, sizeof(host), &port, &code);
        if (n < 0) {
            socks_fail_local(s, code);
            return;
        }
        if (n == 0) goto check_full;
        unsigned char open[1 + 3 + 255];
        int ol = mux_encode_open(open, sizeof(open), MUX_OPEN_FC, host, port);
        if (ol < 0) {
            socks_fail_local(s, 0x01);
            return;
        }
        memmove(s->sbuf, s->sbuf + n, s->slen - (size_t)n);   /* early application data */
        s->slen -= (size_t)n;
        s->fc = 1;
        s->credit = MUX_WINDOW_SIZE;
        s->state = ST_WAIT_REPLY;
        send_frame(m, id, MUX_OPEN, open, (size_t)ol);
        log_msg(1, "mux: stream %d SOCKS CONNECT %s:%u", id, host, (unsigned)port);
        return;
    }
check_full:
    if (s->slen == sizeof(s->sbuf)) socks_fail_local(s, 0x01);
}

/* Local data -> tunnel */
static void pump_local(mux_t *m, int id) {
    stream_t *s = &m->s[id];
    unsigned char buf[MUX_MAX_PAYLOAD];
    size_t want = sizeof(buf);
    if (s->fc && s->credit < want) want = s->credit;
    if (want == 0) return;
    ssize_t r = read(s->fd, buf, want);
    if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return;
        log_msg(1, "mux: stream %d local read error", id);
        close_and_notify(m, id);
        return;
    }
    if (r == 0) {
        log_msg(1, "mux: stream %d local EOF", id);
        if (s->fc) {
            s->rd_eof = 1;
            send_frame(m, id, MUX_FIN, NULL, 0);
            maybe_finish(m, id);
        } else {
            close_and_notify(m, id);
        }
        return;
    }
    send_frame(m, id, MUX_DATA, buf, (size_t)r);
    if (s->fc) s->credit -= (uint32_t)r;
}

/* Client: a new local connection */
static void accept_local(mux_t *m) {
    int fd = accept(m->listen_fd, NULL, NULL);
    if (fd < 0) return;
    int max = m->peer_v2 ? MUX_MAX_STREAMS : MUX_V1_STREAMS;
    int id = -1;
    for (int i = 1; i < max; i++)
        if (m->s[i].state == ST_FREE) { id = i; break; }
    if (id < 0) {
        close(fd);
        fprintf(stderr, "mux: all %d streams busy, connection refused\n", max - 1);
        return;
    }
    set_nonblock(fd);
    stream_t *s = &m->s[id];
    s->fd = fd;
    if (m->mode == MODE_SOCKS_CLIENT) {
        s->state = ST_SOCKS;
        s->since = time(NULL);
        return;
    }
    s->state = ST_OPEN;
    if (m->peer_v2) {
        unsigned char fl = MUX_OPEN_FC;
        s->fc = 1;
        s->credit = MUX_WINDOW_SIZE;
        send_frame(m, id, MUX_OPEN, &fl, 1);
    } else {
        send_frame(m, id, MUX_OPEN, NULL, 0);
    }
    log_msg(1, "mux: stream %d opened (local)%s", id, s->fc ? "" : " [v1 peer]");
}

/* ──────────── Tunnel ──────────── */

static int tunnel_writable(int fd) {
    struct pollfd p = { fd, POLLOUT, 0 };
    return poll(&p, 1, 0) == 1 && (p.revents & POLLOUT);
}

static int tunnel_readable(int fd) {
    struct pollfd p = { fd, POLLIN, 0 };
    return poll(&p, 1, 0) == 1 && (p.revents & (POLLIN | POLLHUP | POLLERR));
}

/* Send queued frames while the tunnel accepts them */
static void flush_tunnel(mux_t *m) {
    int first = 1;
    while (m->tunq.head && !m->dead) {
        if (!first && !tunnel_writable(m->enc)) return;
        first = 0;
        chunk_t *c = m->tunq.head;
        if (g_jitter > 0) obfs_jitter(g_jitter);
        int n = (int)(c->len - c->off);
        if (farm9crypt_write(m->enc, (char *)c->data + c->off, n) != n) {
            m->dead = 1;
            return;
        }
        q_drop(&m->tunq, (size_t)n);
    }
}

/* ──────────── Main loop ──────────── */

#define NOTIFY_SLOT (-3)
#define LISTEN_SLOT (-2)
#define TUNNEL_SLOT (-1)

static int mux_run(mux_t *m) {
    struct pollfd pfd[MUX_MAX_STREAMS + 3];
    int ids[MUX_MAX_STREAMS + 3];
    unsigned char buf[MUX_MAX_PAYLOAD];

    for (int i = 0; i < MUX_MAX_STREAMS; i++) {
        m->s[i].fd = -1;
        m->s[i].state = ST_FREE;
    }
    unsigned char ver = MUX_VERSION;
    send_frame(m, 0, MUX_HELLO, &ver, 1);

    while (!m->dead) {
        int n = 0;
        /* A v1 peer has no flow control: when one of its streams has a large
         * backlog for a slow local consumer, stop reading the tunnel (as 4.0
         * did by blocking) until the backlog shrinks. */
        int tunnel_in = POLLIN;
        for (int i = 1; i < MUX_MAX_STREAMS; i++)
            if (!m->s[i].fc && m->s[i].out.bytes > LEGACY_QUEUE_MAX) { tunnel_in = 0; break; }
        pfd[n] = (struct pollfd){ m->enc, (short)(tunnel_in | (m->tunq.head ? POLLOUT : 0)), 0 };
        ids[n++] = TUNNEL_SLOT;
        if (m->listen_fd >= 0) {
            pfd[n] = (struct pollfd){ m->listen_fd, POLLIN, 0 };
            ids[n++] = LISTEN_SLOT;
        }
        if (is_server(m) && s_notify[0] >= 0) {
            pfd[n] = (struct pollfd){ s_notify[0], POLLIN, 0 };
            ids[n++] = NOTIFY_SLOT;
        }
        int timeout = -1;
        time_t now = time(NULL);
        for (int i = 1; i < MUX_MAX_STREAMS; i++) {
            stream_t *s = &m->s[i];
            if (s->fd < 0) continue;
            short ev = 0;
            if (s->state == ST_SOCKS) {
                if (now - s->since >= SOCKS_TIMEOUT_S) {
                    stream_reset(s);                  /* silent local client */
                    continue;
                }
                ev |= POLLIN;
                timeout = 1000;
            } else if (s->state == ST_OPEN && !s->rd_eof &&
                       m->tunq.bytes < TUNQ_HIGH && (!s->fc || s->credit > 0)) {
                ev |= POLLIN;
            }
            if (s->out.bytes) ev |= POLLOUT;
            if (!ev) continue;
            pfd[n] = (struct pollfd){ s->fd, ev, 0 };
            ids[n++] = i;
        }

        int rc = poll(pfd, (nfds_t)n, timeout);
        if (rc < 0) {
            if (errno == EINTR) continue;
            break;
        }

        for (int k = 0; k < n && !m->dead; k++) {
            short re = pfd[k].revents;
            if (!re) continue;
            int id = ids[k];
            if (id == TUNNEL_SLOT) {
                if (re & POLLOUT) flush_tunnel(m);
                if (re & (POLLIN | POLLHUP | POLLERR)) {
                    /* a few frames per round, without starving local sockets */
                    for (int f = 0; f < 16 && !m->dead; f++) {
                        mux_header_t h;
                        int got = mux_read_frame(m->enc, &h, buf, sizeof(buf));
                        if (got < 0 || (got == 0 && h.type == 0)) {
                            m->dead = 1;
                            break;
                        }
                        handle_frame(m, &h, buf, (size_t)got);
                        if (!tunnel_readable(m->enc)) break;
                    }
                }
            } else if (id == LISTEN_SLOT) {
                if (re & POLLIN) accept_local(m);
            } else if (id == NOTIFY_SLOT) {
                connect_result_t r;
                while (read(s_notify[0], &r, sizeof(r)) == (ssize_t)sizeof(r)) {
                    on_connect_result(m, &r);
                    if (!tunnel_readable(s_notify[0])) break;
                }
            } else {
                stream_t *s = &m->s[id];
                if (s->fd != pfd[k].fd) continue;     /* closed/reused this round */
                if (re & POLLOUT) flush_local(m, id);
                if (s->fd != pfd[k].fd) continue;
                if (re & (POLLIN | POLLHUP | POLLERR)) {
                    if (s->state == ST_SOCKS) socks_input(m, id);
                    else if (s->state == ST_OPEN && !s->rd_eof) pump_local(m, id);
                }
            }
        }
        /* deliver data that arrived for streams whose socket is idle */
        for (int i = 1; i < MUX_MAX_STREAMS && !m->dead; i++)
            if (m->s[i].out.bytes && m->s[i].fd >= 0 &&
                (m->s[i].state == ST_OPEN || m->s[i].state == ST_DRAINING ||
                 m->s[i].state == ST_LINGER))
                flush_local(m, i);
        if (m->tunq.head && tunnel_writable(m->enc)) flush_tunnel(m);
    }

    /* Tunnel gone: give local sockets up to 2 s to take what already arrived */
    time_t end = time(NULL) + 2;
    for (int i = 1; i < MUX_MAX_STREAMS; i++) {
        stream_t *s = &m->s[i];
        while (s->fd >= 0 && s->out.bytes && time(NULL) < end) {
            struct pollfd p = { s->fd, POLLOUT, 0 };
            if (poll(&p, 1, 200) <= 0) continue;
            chunk_t *c = s->out.head;
            ssize_t w = write(s->fd, c->data + c->off, c->len - c->off);
            if (w <= 0 && errno != EAGAIN && errno != EINTR) break;
            if (w > 0) q_drop(&s->out, (size_t)w);
        }
    }
    for (int i = 0; i < MUX_MAX_STREAMS; i++) stream_reset(&m->s[i]);
    q_clear(&m->tunq);
    return 0;
}

static mux_t *mux_new(int enc_fd, mux_mode_t mode) {
    mux_t *m = calloc(1, sizeof(*m));
    if (!m) return NULL;
    m->enc = enc_fd;
    m->mode = mode;
    m->listen_fd = -1;
    if (mode == MODE_FWD_SERVER || mode == MODE_SOCKS_SERVER) {
        if (s_notify[0] < 0 && pipe(s_notify) == 0) {
            fcntl(s_notify[0], F_SETFD, FD_CLOEXEC);
            fcntl(s_notify[1], F_SETFD, FD_CLOEXEC);
        }
        if (s_notify[0] < 0) { free(m); return NULL; }
    }
    return m;
}

int mux_relay_server(int enc_fd, const char *fwd_host, const char *fwd_port) {
    mux_t *m = mux_new(enc_fd, MODE_FWD_SERVER);
    if (!m) return -1;
    m->fwd_host = fwd_host;
    m->fwd_port = fwd_port;
    log_msg(1, "mux: server relay -> %s:%s", fwd_host, fwd_port);
    mux_run(m);
    free(m);
    return 0;
}

int mux_relay_client(int enc_fd, const char *listen_host, const char *local_port) {
    int lfd = net_listen_on(listen_host, local_port);
    if (lfd < 0) return -1;
    mux_t *m = mux_new(enc_fd, MODE_FWD_CLIENT);
    if (!m) { close(lfd); return -1; }
    m->listen_fd = lfd;
    log_msg(1, "mux: client relay on %s:%s", listen_host ? listen_host : "*", local_port);
    mux_run(m);
    close(lfd);
    free(m);
    return 0;
}

int mux_socks_server(int enc_fd) {
    mux_t *m = mux_new(enc_fd, MODE_SOCKS_SERVER);
    if (!m) return -1;
    m->peer_v2 = 1;              /* only v2 clients switch SOCKS to mux */
    log_msg(1, "SOCKS5 server: multiplexed mode");
    mux_run(m);
    free(m);
    return 0;
}

int mux_socks_client(int enc_fd, int listen_fd) {
    mux_t *m = mux_new(enc_fd, MODE_SOCKS_CLIENT);
    if (!m) return -1;
    m->listen_fd = listen_fd;
    m->peer_v2 = 1;              /* the server confirmed mux SOCKS */
    log_msg(1, "SOCKS5 proxy: multiplexed mode");
    mux_run(m);
    free(m);
    return 0;
}
