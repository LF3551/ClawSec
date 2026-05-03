#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/select.h>
#include <sys/socket.h>

#include "relay.h"
#include "util.h"
#include "farm9crypt.h"

#define COLOR_RESET   "\033[0m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_CYAN    "\033[36m"

#define BUFSIZE 8192

static void print_chat_message(const char *sender_label,
                               const char *color,
                               const char *msg,
                               size_t len) {
    time_t now = time(NULL);
    struct tm tm_info;
    char timestamp[16];
    localtime_r(&now, &tm_info);
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", &tm_info);
    fprintf(stdout, "%s[%s %s]%s ", color, timestamp, sender_label, COLOR_RESET);
    for (size_t i = 0; i < len; ++i) {
        fputc((unsigned char)msg[i], stdout);
        if (msg[i] == '\n' && i + 1 < len) {
            fprintf(stdout, "%s[%s %s]%s ", color, timestamp, sender_label, COLOR_RESET);
        }
    }
    if (len > 0 && msg[len - 1] != '\n') fputc('\n', stdout);
    fflush(stdout);
}

int relay_socket_stdio(int sockfd, int is_server, int chat_enabled) {
    char inbuf[BUFSIZE];
    char netbuf[BUFSIZE];
    ssize_t n;
    size_t sent = 0, received = 0;
    const char *local_label = is_server ? "Server" : "Client";
    const char *remote_label = is_server ? "Client" : "Server";
    int interactive = isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
    int chat_mode = chat_enabled && interactive;
    int stdin_closed = 0;

    if (chat_mode) {
        fprintf(stdout,
                "%s[Secure chat established] local=%s remote=%s%s\n",
                COLOR_CYAN, local_label, remote_label, COLOR_RESET);
        fflush(stdout);
    }

    for (;;) {
        fd_set rfds;
        int nfds = sockfd;

        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);
        if (!stdin_closed) {
            FD_SET(STDIN_FILENO, &rfds);
            if (STDIN_FILENO > nfds) nfds = STDIN_FILENO;
        }

        int ret = select(nfds + 1, &rfds, NULL, NULL, NULL);
        if (ret < 0) {
            if (errno == EINTR) continue;
            fatal("select failed");
        }

        if (FD_ISSET(sockfd, &rfds)) {
            n = farm9crypt_read(sockfd, netbuf, sizeof(netbuf));
            if (n < 0) fatal("read from network failed");
            if (n == 0) break;
            received += (size_t)n;
            if (chat_mode) {
                print_chat_message(remote_label, COLOR_CYAN, netbuf, (size_t)n);
            } else {
                if (write_all(STDOUT_FILENO, netbuf, (size_t)n) < 0)
                    fatal("write to stdout failed");
            }
        }

        if (!stdin_closed && FD_ISSET(STDIN_FILENO, &rfds)) {
            n = read(STDIN_FILENO, inbuf, sizeof(inbuf));
            if (n < 0) fatal("read from stdin failed");
            if (n == 0) {
                shutdown(sockfd, SHUT_WR);
                stdin_closed = 1;
            } else {
                sent += (size_t)n;
                if (chat_mode) {
                    print_chat_message(local_label, COLOR_GREEN, inbuf, (size_t)n);
                }
                ssize_t wn = farm9crypt_write(sockfd, inbuf, (size_t)n);
                if (wn != n) fatal("write to network failed");
            }
        }
    }

    if (!chat_mode && g_verbose) {
        fprintf(stderr,
                "\n[Transfer complete] Sent %zu bytes, received %zu bytes\n",
                sent, received);
    }
    return 0;
}
