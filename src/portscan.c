#ifdef __linux__
#define _GNU_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "portscan.h"
#include "util.h"
#include "net.h"

#include <openssl/rand.h>
#include <openssl/sha.h>

int g_scan_rate = SCAN_RATE_DEFAULT;

/* Fisher-Yates shuffle */
static void shuffle_ports(int *arr, int n) {
    for (int i = n - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
    }
}

static void jitter_delay(int jitter_ms) {
    if (jitter_ms <= 0) return;
    int delay = rand() % (jitter_ms + 1);
    if (delay > 0) {
        struct timespec ts;
        ts.tv_sec = delay / 1000;
        ts.tv_nsec = (delay % 1000) * 1000000L;
        nanosleep(&ts, NULL);
    }
}

/* Banner grabbing: connect to port, read initial response.
 * For services that wait for client input (HTTP, etc.) — send a probe. */
#define BANNER_BUF 256
#define BANNER_TIMEOUT_MS 2000

static void grab_banner(const char *host, int port, int af,
                        struct sockaddr_storage *addr, socklen_t addrlen) {
    int sock = socket(af, SOCK_STREAM, 0);
    if (sock < 0) return;

    struct sockaddr_storage sa;
    memcpy(&sa, addr, addrlen);
    if (af == AF_INET)
        ((struct sockaddr_in *)&sa)->sin_port = htons(port);
    else
        ((struct sockaddr_in6 *)&sa)->sin6_port = htons(port);

    /* Blocking connect with short timeout */
    struct timeval tv = {BANNER_TIMEOUT_MS / 1000, (BANNER_TIMEOUT_MS % 1000) * 1000};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct linger lg = {1, 0};
    setsockopt(sock, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));

    if (connect(sock, (struct sockaddr *)&sa, addrlen) < 0) {
        close(sock);
        return;
    }

    char buf[BANNER_BUF];
    ssize_t n = 0;

    /* Try reading first — many services send banner immediately (SSH, FTP, SMTP, MySQL) */
    n = recv(sock, buf, sizeof(buf) - 1, 0);

    /* If nothing received, try HTTP probe */
    if (n <= 0) {
        const char *http_probe = "HEAD / HTTP/1.0\r\nHost: ";
        send(sock, http_probe, strlen(http_probe), 0);
        send(sock, host, strlen(host), 0);
        send(sock, "\r\n\r\n", 4, 0);
        n = recv(sock, buf, sizeof(buf) - 1, 0);
    }

    close(sock);

    if (n > 0) {
        buf[n] = '\0';
        /* Sanitize: replace control chars with dots, truncate at first newline */
        for (int i = 0; i < n; i++) {
            if (buf[i] == '\r' || buf[i] == '\n') {
                buf[i] = '\0';
                break;
            }
            if ((unsigned char)buf[i] < 0x20 && buf[i] != '\t')
                buf[i] = '.';
        }
        if (buf[0] != '\0')
            printf("         └─ %s\n", buf);
    }

    (void)host;
}

/*
 * SYN (half-open) scan with a raw socket: Linux only, needs root or
 * CAP_NET_RAW. Returns 1 if it ran, 0 if unavailable (caller falls back to
 * the connect scan). No TCP connection is completed, so services do not see
 * an accepted connection; the kernel answers the SYN-ACK with RST.
 */
#ifdef __linux__
/* RFC 1071 one's-complement sum */
static uint32_t csum_add(uint32_t sum, const void *data, size_t len) {
    const unsigned char *p = (const unsigned char *)data;
    while (len > 1) { sum += (uint32_t)((p[0] << 8) | p[1]); p += 2; len -= 2; }
    if (len) sum += (uint32_t)(p[0] << 8);
    return sum;
}

static uint16_t csum_fold(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

/* TCP checksum over the IPv4 pseudo-header + segment */
static uint16_t tcp_checksum(struct in_addr src, struct in_addr dst,
                             const unsigned char *seg, size_t len) {
    unsigned char pseudo[12];
    memcpy(pseudo, &src.s_addr, 4);
    memcpy(pseudo + 4, &dst.s_addr, 4);
    pseudo[8] = 0;
    pseudo[9] = IPPROTO_TCP;
    pseudo[10] = (unsigned char)(len >> 8);
    pseudo[11] = (unsigned char)(len & 0xFF);
    uint32_t sum = csum_add(0, pseudo, sizeof(pseudo));
    sum = csum_add(sum, seg, len);
    return htons(csum_fold(sum));
}

static int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Initial sequence number for a probe: keyed hash of the target port, so a
 * SYN-ACK is accepted only if it acknowledges exactly our probe. */
static uint32_t syn_cookie(const unsigned char key[16], int port) {
    unsigned char in[18], md[SHA256_DIGEST_LENGTH];
    memcpy(in, key, 16);
    in[16] = (unsigned char)(port >> 8);
    in[17] = (unsigned char)port;
    SHA256(in, sizeof(in), md);
    return ((uint32_t)md[0] << 24) | ((uint32_t)md[1] << 16) | ((uint32_t)md[2] << 8) | md[3];
}

enum { SYN_UNKNOWN = 0, SYN_OPEN, SYN_CLOSED };

typedef struct {
    int fd, af;
    struct sockaddr_storage target, local;
    socklen_t tlen;
    uint16_t sport;
    unsigned char key[16];
    unsigned char *state;          /* indexed by port */
    int answered, open;
} syn_ctx_t;

static int syn_send(syn_ctx_t *c, int port) {
    unsigned char seg[20];
    memset(seg, 0, sizeof(seg));
    uint32_t seq = syn_cookie(c->key, port);
    seg[0] = (unsigned char)(c->sport >> 8); seg[1] = (unsigned char)c->sport;
    seg[2] = (unsigned char)(port >> 8);     seg[3] = (unsigned char)port;
    seg[4] = (unsigned char)(seq >> 24); seg[5] = (unsigned char)(seq >> 16);
    seg[6] = (unsigned char)(seq >> 8);  seg[7] = (unsigned char)seq;
    seg[12] = 5 << 4;                        /* data offset: 5 words */
    seg[13] = 0x02;                          /* SYN */
    seg[14] = 0x04; seg[15] = 0x00;          /* window 1024 */
    struct sockaddr_storage to = c->target;
    if (c->af == AF_INET) {
        struct sockaddr_in *t4 = (struct sockaddr_in *)&to;
        uint16_t ck = tcp_checksum(((struct sockaddr_in *)&c->local)->sin_addr,
                                   t4->sin_addr, seg, sizeof(seg));
        memcpy(seg + 16, &ck, 2);
        t4->sin_port = 0;                    /* raw IPv4: must be 0 or the protocol */
    } else {
        ((struct sockaddr_in6 *)&to)->sin6_port = 0;   /* kernel fills the checksum */
    }
    for (;;) {
        if (sendto(c->fd, seg, sizeof(seg), 0, (struct sockaddr *)&to, c->tlen) >= 0) return 0;
        if (errno == EINTR) continue;
        if (errno == ENOBUFS || errno == EAGAIN) {   /* local queue full: back off */
            struct timespec ts = { 0, 1000000 };
            nanosleep(&ts, NULL);
            continue;
        }
        return -1;
    }
}

/* Process every queued reply */
static void syn_drain(syn_ctx_t *c) {
    unsigned char buf[256];
    for (;;) {
        struct sockaddr_storage from;
        socklen_t flen = sizeof(from);
        ssize_t n = recvfrom(c->fd, buf, sizeof(buf), MSG_DONTWAIT,
                             (struct sockaddr *)&from, &flen);
        if (n < 0) {
            if (errno == EINTR) continue;
            return;                                  /* EAGAIN: nothing queued */
        }
        const unsigned char *t;
        if (c->af == AF_INET) {                      /* IPv4 raw: IP header included */
            if (n < 20) continue;
            size_t ihl = (size_t)(buf[0] & 0x0F) * 4;
            if (ihl < 20 || (size_t)n < ihl + 20) continue;
            if (memcmp(buf + 12, &((struct sockaddr_in *)&c->target)->sin_addr, 4) != 0)
                continue;
            t = buf + ihl;
        } else {                                     /* IPv6 raw: TCP segment only */
            if (n < 20 || from.ss_family != AF_INET6 ||
                memcmp(&((struct sockaddr_in6 *)&from)->sin6_addr,
                       &((struct sockaddr_in6 *)&c->target)->sin6_addr, 16) != 0)
                continue;
            t = buf;
        }
        int port = (t[0] << 8) | t[1], dport = (t[2] << 8) | t[3];
        if (dport != c->sport || port < 1 || c->state[port] != SYN_UNKNOWN) continue;
        uint32_t ack = ((uint32_t)t[8] << 24) | ((uint32_t)t[9] << 16) |
                       ((uint32_t)t[10] << 8) | t[11];
        if (ack != syn_cookie(c->key, port) + 1) continue;      /* not our probe */
        if ((t[13] & 0x12) == 0x12) {                           /* SYN+ACK: open */
            c->state[port] = SYN_OPEN;
            c->open++;
            printf("  %5d/tcp  open\n", port);
            fflush(stdout);
        } else if (t[13] & 0x04) {                              /* RST: closed */
            c->state[port] = SYN_CLOSED;
        } else {
            continue;
        }
        c->answered++;
    }
}

/* Wait until `until` (ms), processing replies as they arrive */
static void syn_wait(syn_ctx_t *c, int64_t until) {
    for (;;) {
        syn_drain(c);
        int64_t left = until - now_ms();
        if (left <= 0) return;
        struct pollfd p = { c->fd, POLLIN, 0 };
        if (poll(&p, 1, (int)left) < 0 && errno != EINTR) return;
    }
}

/*
 * Pipelined SYN scan: probes are sent at --scan-rate packets per second
 * while replies are collected; ports that did not answer are probed once
 * more, then reported as filtered. Replies are matched by address, ports
 * and a keyed ISN (syn_cookie), so stray or spoofed packets are ignored.
 */
static int try_syn_scan(const char *host, int *ports, int nports,
                        int jitter_ms, int timeout_ms, int *open_count) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = g_af_family;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0) return 0;

    syn_ctx_t c;
    memset(&c, 0, sizeof(c));
    c.af = res->ai_family;
    c.tlen = res->ai_addrlen;
    memcpy(&c.target, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    if (c.af != AF_INET && c.af != AF_INET6) return 0;

    c.fd = socket(c.af, SOCK_RAW, IPPROTO_TCP);
    if (c.fd < 0) return 0;                          /* not root: fall back */
    if (c.af == AF_INET6) {
        int off = 16;                                /* TCP checksum offset */
        if (setsockopt(c.fd, IPPROTO_IPV6, IPV6_CHECKSUM, &off, sizeof(off)) < 0) {
            close(c.fd);
            return 0;
        }
    }
    int rcvbuf = 4 * 1024 * 1024;
    setsockopt(c.fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    /* Source address the kernel would use towards the target */
    int probe = socket(c.af, SOCK_DGRAM, 0);
    struct sockaddr_storage to = c.target;
    if (c.af == AF_INET) ((struct sockaddr_in *)&to)->sin_port = htons(80);
    else ((struct sockaddr_in6 *)&to)->sin6_port = htons(80);
    socklen_t llen = sizeof(c.local);
    if (probe < 0 || connect(probe, (struct sockaddr *)&to, c.tlen) < 0 ||
        getsockname(probe, (struct sockaddr *)&c.local, &llen) < 0) {
        if (probe >= 0) close(probe);
        close(c.fd);
        return 0;
    }
    close(probe);

    c.state = calloc(65536, 1);
    if (!c.state || RAND_bytes(c.key, sizeof(c.key)) != 1) {
        free(c.state);
        close(c.fd);
        return 0;
    }
    uint16_t r16;
    RAND_bytes((unsigned char *)&r16, sizeof(r16));
    c.sport = (uint16_t)(40000 + r16 % 20000);

    int rate = g_scan_rate > 0 ? g_scan_rate : SCAN_RATE_DEFAULT;
    int64_t gap_us = 1000000 / rate;
    int64_t t0 = now_ms();

    for (int round = 0; round < 2 && c.answered < nports; round++) {
        struct timespec start;
        clock_gettime(CLOCK_MONOTONIC, &start);
        int64_t sent = 0;
        for (int i = 0; i < nports; i++) {
            if (c.state[ports[i]] != SYN_UNKNOWN) continue;
            /* pace: the k-th probe of the round leaves at k * gap */
            int64_t due_ms = (int64_t)start.tv_sec * 1000 + start.tv_nsec / 1000000 +
                             sent * gap_us / 1000;
            syn_wait(&c, due_ms);
            if (syn_send(&c, ports[i]) < 0) {
                free(c.state);
                close(c.fd);
                return 0;
            }
            sent++;
            if (jitter_ms > 0) {
                jitter_delay(jitter_ms);             /* jitter replaces pacing */
                clock_gettime(CLOCK_MONOTONIC, &start);
                sent = 0;
            }
        }
        syn_wait(&c, now_ms() + timeout_ms);         /* late replies */
    }

    int filtered = nports - c.answered;
    if (g_verbose)
        log_msg(1, "SYN scan: %d ports in %lld ms (%d open, %d closed, %d filtered/no reply)",
                nports, (long long)(now_ms() - t0), c.open, c.answered - c.open, filtered);
    *open_count = c.open;
    free(c.state);
    close(c.fd);
    return 1;
}
#else
/* BSD/macOS raw sockets do not deliver TCP replies: use the connect scan */
static int try_syn_scan(const char *host, int *ports, int nports,
                        int jitter_ms, int timeout_ms, int *open_count) {
    (void)host; (void)ports; (void)nports; (void)jitter_ms;
    (void)timeout_ms; (void)open_count;
    return 0;
}
#endif

/*
 * Parallel connect scan — up to BATCH_SIZE simultaneous non-blocking connects.
 * Uses poll() to wait for a batch. SO_LINGER=0 sends RST immediately.
 */
#define BATCH_SIZE 128

static void connect_scan(const char *host, int *ports, int nports,
                         int jitter_ms, int timeout_ms, int *open_count,
                         int banner_grab) {
    *open_count = 0;

    /* Raise fd limit for parallel sockets */
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < 4096) {
        rl.rlim_cur = 4096;
        setrlimit(RLIMIT_NOFILE, &rl);
    }

    /* Resolve host once */
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = g_af_family;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0)
        return;

    struct sockaddr_storage addr;
    socklen_t addrlen = res->ai_addrlen;
    memcpy(&addr, res->ai_addr, addrlen);
    int af = res->ai_family;
    freeaddrinfo(res);

    struct pollfd *pfds = malloc(BATCH_SIZE * sizeof(struct pollfd));
    int *batch_ports = malloc(BATCH_SIZE * sizeof(int));
    if (!pfds || !batch_ports) {
        free(pfds); free(batch_ports);
        return;
    }

    for (int offset = 0; offset < nports; offset += BATCH_SIZE) {
        int batch = nports - offset;
        if (batch > BATCH_SIZE) batch = BATCH_SIZE;

        int active = 0;
        for (int i = 0; i < batch; i++) {
            int port = ports[offset + i];
            int sock = socket(af, SOCK_STREAM, 0);
            if (sock < 0) {
                pfds[i].fd = -1;
                continue;
            }

            /* Non-blocking + immediate RST on close */
            int flags = fcntl(sock, F_GETFL, 0);
            fcntl(sock, F_SETFL, flags | O_NONBLOCK);
            struct linger lg = {1, 0};
            setsockopt(sock, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));

            /* Set port in address */
            struct sockaddr_storage sa;
            memcpy(&sa, &addr, addrlen);
            if (af == AF_INET)
                ((struct sockaddr_in *)&sa)->sin_port = htons(port);
            else
                ((struct sockaddr_in6 *)&sa)->sin6_port = htons(port);

            int ret = connect(sock, (struct sockaddr *)&sa, addrlen);
            if (ret == 0) {
                /* Immediately connected (localhost) */
                printf("  %5d/tcp  open\n", port);
                (*open_count)++;
                close(sock);
                pfds[i].fd = -1;
                if (banner_grab)
                    grab_banner(host, port, af, &addr, addrlen);
            } else if (errno == EINPROGRESS) {
                pfds[i].fd = sock;
                pfds[i].events = POLLOUT;
                batch_ports[i] = port;
                active++;
            } else {
                close(sock);
                pfds[i].fd = -1;
            }
        }

        /* Poll loop: keep polling until all fds respond or timeout */
        if (active > 0) {
            int remaining = timeout_ms;
            while (active > 0 && remaining > 0) {
                struct timespec t0, t1;
                clock_gettime(CLOCK_MONOTONIC, &t0);

                int ret = poll(pfds, batch, remaining);
                if (ret <= 0) break;

                for (int i = 0; i < batch; i++) {
                    if (pfds[i].fd < 0) continue;
                    if (pfds[i].revents) {
                        int err = 0;
                        socklen_t slen = sizeof(err);
                        getsockopt(pfds[i].fd, SOL_SOCKET, SO_ERROR, &err, &slen);
                        if (err == 0) {
                            printf("  %5d/tcp  open\n", batch_ports[i]);
                            (*open_count)++;
                            if (banner_grab)
                                grab_banner(host, batch_ports[i], af, &addr, addrlen);
                        }
                        close(pfds[i].fd);
                        pfds[i].fd = -1;
                        active--;
                    }
                }

                clock_gettime(CLOCK_MONOTONIC, &t1);
                int elapsed = (int)((t1.tv_sec - t0.tv_sec) * 1000 +
                                    (t1.tv_nsec - t0.tv_nsec) / 1000000);
                remaining -= elapsed;
                if (remaining < 0) remaining = 0;
            }
        }

        /* Close any remaining sockets (filtered/no response) */
        for (int i = 0; i < batch; i++) {
            if (pfds[i].fd >= 0)
                close(pfds[i].fd);
        }

        if (jitter_ms > 0)
            jitter_delay(jitter_ms);
    }

    free(pfds);
    free(batch_ports);
}

int portscan_run(const char *host, int start_port, int end_port,
                 int jitter_ms, int timeout_ms, int banner_grab) {
    if (start_port < SCAN_PORT_MIN) start_port = SCAN_PORT_MIN;
    if (end_port > SCAN_PORT_MAX) end_port = SCAN_PORT_MAX;
    if (start_port > end_port) return 0;
    if (timeout_ms <= 0) timeout_ms = 200;

    int nports = end_port - start_port + 1;
    int *ports = malloc(nports * sizeof(int));
    if (!ports) {
        fprintf(stderr, "ERROR: out of memory for port list\n");
        return -1;
    }

    for (int i = 0; i < nports; i++)
        ports[i] = start_port + i;

    /* Randomize port order — defeats sequential scan detection */
    srand((unsigned)time(NULL) ^ getpid());
    shuffle_ports(ports, nports);

    printf("Scanning %s [%d-%d] (%d ports)...\n", host, start_port, end_port, nports);
    if (jitter_ms > 0)
        printf("  jitter: 0-%d ms between probes\n", jitter_ms);

    int open_count = 0;

    /* Try SYN scan first (stealth, needs root) — no banner grab with SYN */
    int syn_ok = 0;
    if (!banner_grab)
        syn_ok = try_syn_scan(host, ports, nports, jitter_ms, timeout_ms, &open_count);

    if (!syn_ok) {
        if (g_verbose)
            log_msg(1, "SYN scan unavailable (need root), using stealth connect scan");
        connect_scan(host, ports, nports, jitter_ms, timeout_ms, &open_count, banner_grab);
    } else {
        if (g_verbose)
            log_msg(1, "SYN (half-open) scan via raw socket: no TCP connection is completed");
    }

    printf("\n%d open port(s) on %s\n", open_count, host);

    free(ports);
    return open_count;
}
