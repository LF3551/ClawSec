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

static int try_syn_scan(const char *host, int *ports, int nports,
                        int jitter_ms, int timeout_ms, int *open_count) {
    if (g_af_family == AF_INET6) return 0;          /* IPv4 only */
    int rawfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (rawfd < 0) return 0;                        /* not root: fall back */

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0) {
        close(rawfd);
        return 0;
    }
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
    freeaddrinfo(res);

    /* Source address the kernel would use towards the target */
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    int probe = socket(AF_INET, SOCK_DGRAM, 0);
    if (probe < 0) { close(rawfd); return 0; }
    struct sockaddr_in to = target;
    to.sin_port = htons(80);
    socklen_t slen = sizeof(local);
    if (connect(probe, (struct sockaddr *)&to, sizeof(to)) < 0 ||
        getsockname(probe, (struct sockaddr *)&local, &slen) < 0) {
        close(probe); close(rawfd);
        return 0;
    }
    close(probe);

    uint16_t src_port = (uint16_t)(40000 + (rand() % 20000));
    *open_count = 0;

    for (int i = 0; i < nports; i++) {
        target.sin_port = htons((uint16_t)ports[i]);

        /* 20-byte TCP header with SYN */
        unsigned char seg[20];
        memset(seg, 0, sizeof(seg));
        uint32_t seq = (uint32_t)rand();
        seg[0] = (unsigned char)(src_port >> 8); seg[1] = (unsigned char)src_port;
        seg[2] = (unsigned char)(ports[i] >> 8); seg[3] = (unsigned char)ports[i];
        seg[4] = (unsigned char)(seq >> 24); seg[5] = (unsigned char)(seq >> 16);
        seg[6] = (unsigned char)(seq >> 8);  seg[7] = (unsigned char)seq;
        seg[12] = 5 << 4;                    /* data offset: 5 words */
        seg[13] = 0x02;                      /* SYN */
        seg[14] = 0x04; seg[15] = 0x00;      /* window 1024 */
        uint16_t ck = tcp_checksum(local.sin_addr, target.sin_addr, seg, sizeof(seg));
        memcpy(seg + 16, &ck, 2);

        if (sendto(rawfd, seg, sizeof(seg), 0, (struct sockaddr *)&target, sizeof(target)) < 0) {
            close(rawfd);
            return 0;
        }

        /* Collect packets until the reply for this probe or the deadline */
        int64_t deadline = now_ms() + timeout_ms;
        for (;;) {
            int left = (int)(deadline - now_ms());
            if (left <= 0) break;
            int rfd[1] = { rawfd }, rdy[1];
            if (wait_readable(rfd, rdy, 1, left) <= 0) break;
            unsigned char buf[128];
            ssize_t n = recv(rawfd, buf, sizeof(buf), 0);
            if (n < 20) continue;
            size_t ihl = (size_t)(buf[0] & 0x0F) * 4;   /* IP header length */
            if (ihl < 20 || (size_t)n < ihl + 20) continue;
            struct in_addr from;
            memcpy(&from.s_addr, buf + 12, 4);
            const unsigned char *t = buf + ihl;
            int sport = (t[0] << 8) | t[1], dport = (t[2] << 8) | t[3];
            if (from.s_addr != target.sin_addr.s_addr || sport != ports[i] || dport != src_port)
                continue;                               /* someone else's packet */
            if ((t[13] & 0x12) == 0x12) {               /* SYN+ACK: open */
                printf("  %5d/tcp  open\n", ports[i]);
                (*open_count)++;
            }
            break;                                      /* RST etc.: closed */
        }

        src_port++;
        if (src_port > 60000) src_port = 40000;
        jitter_delay(jitter_ms);
    }

    close(rawfd);
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
