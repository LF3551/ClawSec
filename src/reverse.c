/*
 * reverse.c — Reverse tunnel implementation (-R)
 *
 * Server: listens on extra port, when connection comes in, signals client
 * through encrypted tunnel, then relays data bidirectionally.
 *
 * Client: waits for signal from server, connects to local target,
 * then relays data back through tunnel.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>

#include "reverse.h"
#include "farm9crypt.h"
#include "net.h"
#include "util.h"

#define REVERSE_SIG_OPEN  "ROPEN\n"
#define REVERSE_SIG_OK    "ROK\n"
#define REVERSE_SIG_FAIL  "RFAIL\n"
#define REVERSE_BUF_SIZE  8000

/* Cast helper for farm9crypt which takes char* */
static inline int rev_write(int fd, const char *msg, int len) {
    return farm9crypt_write(fd, (char *)msg, len);
}

/*
 * Relay bidirectional data between encrypted tunnel and plain socket.
 * Stops when either side closes.
 */
static int reverse_relay(int tunnel_fd, int plain_fd) {
    char buf[REVERSE_BUF_SIZE];
    int fds[2] = { tunnel_fd, plain_fd }, rdy[2];

    for (;;) {
        int rc = wait_readable(fds, rdy, 2, -1);
        if (rc < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* Encrypted tunnel → plain socket */
        if (rdy[0]) {
            int n = farm9crypt_read(tunnel_fd, buf, sizeof(buf));
            if (n <= 0) break;
            if (write_all(plain_fd, buf, n) < 0) break;
        }

        /* Plain socket → encrypted tunnel */
        if (rdy[1]) {
            size_t want = sizeof(buf) < (size_t)farm9crypt_max_payload()
                              ? sizeof(buf) : (size_t)farm9crypt_max_payload();
            int n = read(plain_fd, buf, want);
            if (n <= 0) break;
            if (farm9crypt_write(tunnel_fd, buf, n) < 0) break;
        }
    }

    return 0;
}

/*
 * Server side of reverse tunnel:
 * 1. Listen on rev_port for incoming connections
 * 2. When a client connects to rev_port, send ROPEN through tunnel
 * 3. Wait for ROK from tunnel client
 * 4. Relay data between incoming connection and tunnel
 */
int reverse_server(int tunnel_fd, const char *rev_host, const char *rev_port) {
    int listen_fd = net_listen_on(rev_host, rev_port);
    if (listen_fd < 0) return -1;
    log_msg(1, "reverse: listening on %s:%s (forwarding through tunnel)", rev_host, rev_port);

    for (;;) {
        int client_fd = net_accept(listen_fd);
        log_msg(1, "reverse: incoming connection on :%s, signaling tunnel client", rev_port);

        /* Signal the tunnel client */
        if (rev_write(tunnel_fd, REVERSE_SIG_OPEN, strlen(REVERSE_SIG_OPEN)) < 0) {
            close(client_fd);
            break;
        }

        /* Wait for acknowledgment */
        char ack[32];
        int n = farm9crypt_read(tunnel_fd, ack, sizeof(ack) - 1);
        if (n <= 0) {
            close(client_fd);
            break;
        }
        ack[n] = '\0';

        if (strncmp(ack, REVERSE_SIG_OK, strlen(REVERSE_SIG_OK)) != 0) {
            log_msg(1, "reverse: client failed to connect to target");
            close(client_fd);
            continue;
        }

        log_msg(1, "reverse: tunnel client ready, relaying");
        reverse_relay(tunnel_fd, client_fd);
        close(client_fd);
        log_msg(1, "reverse: connection closed");
    }

    close(listen_fd);
    return 0;
}

/*
 * Client side of reverse tunnel:
 * 1. Wait for ROPEN signal from server through encrypted tunnel
 * 2. Connect to local target_host:target_port
 * 3. Send ROK back through tunnel
 * 4. Relay data between tunnel and local target
 */
int reverse_client(int tunnel_fd, const char *target_host, const char *target_port) {
    log_msg(1, "reverse: waiting for connections (forwarding to %s:%s)",
            target_host, target_port);

    for (;;) {
        char sig[32];
        int n = farm9crypt_read(tunnel_fd, sig, sizeof(sig) - 1);
        if (n <= 0) break; /* tunnel closed */
        sig[n] = '\0';

        if (strncmp(sig, REVERSE_SIG_OPEN, strlen(REVERSE_SIG_OPEN)) != 0) {
            /* Not a reverse signal, ignore (could be heartbeat) */
            continue;
        }

        log_msg(1, "reverse: server has incoming connection, connecting to %s:%s",
                target_host, target_port);

        int target_fd = net_try_connect(target_host, target_port, 5);
        if (target_fd < 0) {
            log_msg(1, "reverse: cannot connect to %s:%s", target_host, target_port);
            rev_write(tunnel_fd, REVERSE_SIG_FAIL, strlen(REVERSE_SIG_FAIL));
            continue;
        }

        /* Acknowledge */
        if (rev_write(tunnel_fd, REVERSE_SIG_OK, strlen(REVERSE_SIG_OK)) < 0) {
            close(target_fd);
            break;
        }

        log_msg(1, "reverse: connected, relaying");
        reverse_relay(tunnel_fd, target_fd);
        close(target_fd);
        log_msg(1, "reverse: session ended");
    }

    return 0;
}
