#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "socks5.h"
#include "util.h"
#include "net.h"
#include "farm9crypt.h"

/*
 * SOCKS5 protocol constants
 */
#define SOCKS_VERSION   0x05
#define SOCKS_AUTH_NONE 0x00
#define SOCKS_CMD_CONNECT 0x01
#define SOCKS_ATYP_IPV4   0x01
#define SOCKS_ATYP_DOMAIN 0x03
#define SOCKS_ATYP_IPV6   0x04
#define SOCKS_REP_OK       0x00
#define SOCKS_REP_FAIL     0x01
#define SOCKS_REP_DENIED   0x02
#define SOCKS_REP_NETUNREACH 0x03
#define SOCKS_REP_HOSTUNREACH 0x04
#define SOCKS_REP_CONNREFUSED 0x05

#define RELAY_BUF 8192

/* Read exactly n bytes */
static int read_exact(int fd, void *buf, size_t n) {
    size_t done = 0;
    while (done < n) {
        ssize_t r = read(fd, (char *)buf + done, n - done);
        if (r <= 0) return -1;
        done += r;
    }
    return 0;
}

/*
 * Handle one SOCKS5 client connection.
 * Does SOCKS5 handshake, extracts target, sends through tunnel,
 * then relays bidirectionally.
 */
static void handle_socks_client(int client_fd, int tunnel_fd) {
    unsigned char buf[512];

    /* 1. Version/auth negotiation */
    if (read_exact(client_fd, buf, 2) < 0) goto fail;
    if (buf[0] != SOCKS_VERSION) goto fail;

    int nmethods = buf[1];
    if (nmethods > 0 && nmethods < 256) {
        if (read_exact(client_fd, buf, nmethods) < 0) goto fail;
    }

    /* Reply: no auth required */
    buf[0] = SOCKS_VERSION;
    buf[1] = SOCKS_AUTH_NONE;
    if (write(client_fd, buf, 2) != 2) goto fail;

    /* 2. CONNECT request */
    if (read_exact(client_fd, buf, 4) < 0) goto fail;
    if (buf[0] != SOCKS_VERSION || buf[1] != SOCKS_CMD_CONNECT) goto fail;

    char host[256];
    uint16_t port;
    int host_len = 0;

    switch (buf[3]) {
    case SOCKS_ATYP_IPV4: {
        unsigned char ipv4[4];
        if (read_exact(client_fd, ipv4, 4) < 0) goto fail;
        snprintf(host, sizeof(host), "%d.%d.%d.%d",
                 ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
        host_len = strlen(host);
        break;
    }
    case SOCKS_ATYP_DOMAIN: {
        unsigned char dlen;
        if (read_exact(client_fd, &dlen, 1) < 0) goto fail;
        if (read_exact(client_fd, host, dlen) < 0) goto fail;
        host[dlen] = '\0';
        host_len = dlen;
        break;
    }
    case SOCKS_ATYP_IPV6: {
        unsigned char ipv6[16];
        if (read_exact(client_fd, ipv6, 16) < 0) goto fail;
        inet_ntop(AF_INET6, ipv6, host, sizeof(host));
        host_len = strlen(host);
        break;
    }
    default:
        goto fail;
    }

    /* Read port (2 bytes, network order) */
    unsigned char port_buf[2];
    if (read_exact(client_fd, port_buf, 2) < 0) goto fail;
    port = (port_buf[0] << 8) | port_buf[1];

    log_msg(1, "SOCKS5 CONNECT %s:%d", host, port);

    /* 3. Send connect request through encrypted tunnel:
     *    [1: host_len][N: host][2: port_be] */
    char req[260];
    req[0] = (char)host_len;
    memcpy(req + 1, host, host_len);
    req[1 + host_len] = port_buf[0];
    req[2 + host_len] = port_buf[1];

    int req_len = 3 + host_len;
    if (farm9crypt_write(tunnel_fd, req, req_len) < 0) goto fail;

    /* 4. Read server response: [1: status] */
    char status_buf[1];
    int rlen = farm9crypt_read(tunnel_fd, status_buf, sizeof(status_buf));
    if (rlen < 1 || status_buf[0] != 0) {
        /* Connection failed — send SOCKS5 error */
        unsigned char reply[10] = {SOCKS_VERSION, SOCKS_REP_HOSTUNREACH,
                                   0, SOCKS_ATYP_IPV4, 0,0,0,0, 0,0};
        write(client_fd, reply, 10);
        goto fail;
    }

    /* 5. Send SOCKS5 success reply */
    unsigned char reply[10] = {SOCKS_VERSION, SOCKS_REP_OK,
                               0, SOCKS_ATYP_IPV4, 0,0,0,0, 0,0};
    if (write(client_fd, reply, 10) != 10) goto fail;

    /* 6. Relay: client_fd <-> tunnel_fd (encrypted) */
    fd_set rfds;
    int maxfd = (client_fd > tunnel_fd) ? client_fd : tunnel_fd;
    char relay_buf[RELAY_BUF];

    for (;;) {
        FD_ZERO(&rfds);
        FD_SET(client_fd, &rfds);
        FD_SET(tunnel_fd, &rfds);

        int ret = select(maxfd + 1, &rfds, NULL, NULL, NULL);
        if (ret <= 0) break;

        if (FD_ISSET(client_fd, &rfds)) {
            ssize_t n = read(client_fd, relay_buf, sizeof(relay_buf));
            if (n <= 0) break;
            if (farm9crypt_write(tunnel_fd, relay_buf, n) < 0) break;
        }

        if (FD_ISSET(tunnel_fd, &rfds)) {
            int n = farm9crypt_read(tunnel_fd, relay_buf, sizeof(relay_buf));
            if (n <= 0) break;
            ssize_t w = write(client_fd, relay_buf, n);
            if (w <= 0) break;
        }
    }

fail:
    close(client_fd);
}

/*
 * Client-side SOCKS5: listen on local_port, for each connection
 * do SOCKS5 handshake and forward through tunnel.
 *
 * Note: single-threaded sequential — one SOCKS connection at a time
 * through the tunnel. For concurrent, use --mux + --socks together.
 */
void socks5_client(int tunnel_fd, const char *local_port) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(NULL, local_port, &hints, &res) != 0) {
        fprintf(stderr, "ERROR: SOCKS5 cannot bind to port %s\n", local_port);
        return;
    }

    int listen_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (listen_fd < 0) {
        freeaddrinfo(res);
        fprintf(stderr, "ERROR: SOCKS5 socket failed\n");
        return;
    }

    int yes = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    if (bind(listen_fd, res->ai_addr, res->ai_addrlen) < 0) {
        freeaddrinfo(res);
        close(listen_fd);
        fprintf(stderr, "ERROR: SOCKS5 bind to port %s failed: %s\n",
                local_port, strerror(errno));
        return;
    }
    freeaddrinfo(res);

    if (listen(listen_fd, 5) < 0) {
        close(listen_fd);
        fprintf(stderr, "ERROR: SOCKS5 listen failed\n");
        return;
    }

    log_msg(1, "SOCKS5 proxy listening on 127.0.0.1:%s", local_port);

    for (;;) {
        int client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        handle_socks_client(client_fd, tunnel_fd);
    }

    close(listen_fd);
}

/*
 * Server-side SOCKS5: receive connect requests from tunnel,
 * make outbound connections, relay data back.
 */
void socks5_server(int tunnel_fd) {
    for (;;) {
        /* Read connect request: [1: host_len][N: host][2: port_be] */
        char buf[512];
        int rlen = farm9crypt_read(tunnel_fd, buf, sizeof(buf));
        if (rlen <= 0) break;

        if (rlen < 4) {
            char fail = 1;
            farm9crypt_write(tunnel_fd, &fail, 1);
            continue;
        }

        int host_len = (unsigned char)buf[0];
        if (host_len + 3 > rlen) {
            char fail = 1;
            farm9crypt_write(tunnel_fd, &fail, 1);
            continue;
        }

        char host[256];
        memcpy(host, buf + 1, host_len);
        host[host_len] = '\0';

        uint16_t port = ((unsigned char)buf[1 + host_len] << 8) | (unsigned char)buf[2 + host_len];
        char port_str[8];
        snprintf(port_str, sizeof(port_str), "%d", port);

        log_msg(1, "SOCKS5 server: connecting to %s:%s", host, port_str);

        /* Connect to target */
        int target_fd = net_try_connect(host, port_str, 10);
        if (target_fd < 0) {
            log_msg(1, "SOCKS5 server: connect to %s:%s failed", host, port_str);
            char fail = 1;
            farm9crypt_write(tunnel_fd, &fail, 1);
            continue;
        }

        /* Send success */
        char ok = 0;
        if (farm9crypt_write(tunnel_fd, &ok, 1) < 0) {
            close(target_fd);
            break;
        }

        /* Relay: target_fd <-> tunnel_fd (encrypted) */
        fd_set rfds;
        int maxfd = (target_fd > tunnel_fd) ? target_fd : tunnel_fd;
        char relay_buf[RELAY_BUF];

        for (;;) {
            FD_ZERO(&rfds);
            FD_SET(target_fd, &rfds);
            FD_SET(tunnel_fd, &rfds);

            int ret = select(maxfd + 1, &rfds, NULL, NULL, NULL);
            if (ret <= 0) break;

            if (FD_ISSET(target_fd, &rfds)) {
                ssize_t n = read(target_fd, relay_buf, sizeof(relay_buf));
                if (n <= 0) break;
                if (farm9crypt_write(tunnel_fd, relay_buf, n) < 0) break;
            }

            if (FD_ISSET(tunnel_fd, &rfds)) {
                int n = farm9crypt_read(tunnel_fd, relay_buf, sizeof(relay_buf));
                if (n <= 0) break;
                ssize_t w = write(target_fd, relay_buf, n);
                if (w <= 0) break;
            }
        }

        close(target_fd);
    }
}
