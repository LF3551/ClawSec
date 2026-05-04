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
#include <sys/select.h>
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
 * SYN scan using raw socket (requires root/CAP_NET_RAW).
 * Returns 1 if raw socket available, 0 if not (fallback needed).
 */
static int try_syn_scan(const char *host, int *ports, int nports,
                        int jitter_ms, int timeout_ms, int *open_count) {
    (void)timeout_ms;

    /* Try to create raw socket */
    int rawfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (rawfd < 0) return 0;  /* Not root — fallback to connect scan */

    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0) {
        close(rawfd);
        return 0;
    }
    target.sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
    freeaddrinfo(res);

    /* Get local address for source IP */
    int probe_sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(80);
    local_addr.sin_addr = target.sin_addr;
    connect(probe_sock, (struct sockaddr *)&local_addr, sizeof(local_addr));
    socklen_t slen = sizeof(local_addr);
    getsockname(probe_sock, (struct sockaddr *)&local_addr, &slen);
    close(probe_sock);

    uint16_t src_port = 40000 + (rand() % 20000);

    *open_count = 0;

    for (int i = 0; i < nports; i++) {
        target.sin_port = htons(ports[i]);

        /* Build SYN packet */
        unsigned char pkt[40];
        memset(pkt, 0, sizeof(pkt));
        struct tcphdr *tcp = (struct tcphdr *)pkt;

#ifdef __APPLE__
        tcp->th_sport = htons(src_port);
        tcp->th_dport = htons(ports[i]);
        tcp->th_seq = htonl(rand());
        tcp->th_off = 5;
        tcp->th_flags = TH_SYN;
        tcp->th_win = htons(1024);
#else
        tcp->source = htons(src_port);
        tcp->dest = htons(ports[i]);
        tcp->seq = htonl(rand());
        tcp->doff = 5;
        tcp->syn = 1;
        tcp->window = htons(1024);
#endif

        sendto(rawfd, pkt, 20, 0, (struct sockaddr *)&target, sizeof(target));

        /* Wait for response with short timeout */
        fd_set rfds;
        struct timeval tv;
        FD_ZERO(&rfds);
        FD_SET(rawfd, &rfds);
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        int ret = select(rawfd + 1, &rfds, NULL, NULL, &tv);
        if (ret > 0) {
            unsigned char buf[128];
            ssize_t n = recv(rawfd, buf, sizeof(buf), 0);
            if (n >= 40) {
                /* IP header (20 bytes) + TCP header */
                struct tcphdr *resp = (struct tcphdr *)(buf + 20);
                uint16_t resp_sport, resp_flags;
#ifdef __APPLE__
                resp_sport = ntohs(resp->th_sport);
                resp_flags = resp->th_flags;
#else
                resp_sport = ntohs(resp->source);
                resp_flags = (resp->syn << 1) | resp->ack;
#endif
                if ((int)resp_sport == ports[i]) {
#ifdef __APPLE__
                    if (resp_flags & TH_SYN && resp_flags & TH_ACK) {
#else
                    if (resp->syn && resp->ack) {
#endif
                        printf("  %5d/tcp  open\n", ports[i]);
                        (*open_count)++;
                        /* Send RST to not complete handshake */
                    }
                }
            }
        }

        src_port++;
        if (src_port > 60000) src_port = 40000;
        jitter_delay(jitter_ms);
    }

    close(rawfd);
    return 1;
}

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
            log_msg(1, "SYN scan (raw socket) — server will not log connections");
    }

    printf("\n%d open port(s) on %s\n", open_count, host);

    free(ports);
    return open_count;
}
