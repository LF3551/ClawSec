/*
 * children.c — -K handler processes (see children.h)
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <openssl/crypto.h>

#include "children.h"
#include "options.h"
#include "net.h"
#include "util.h"

/* -K: live handler processes (decremented by the SIGCHLD handler) */
volatile sig_atomic_t g_active_children = 0;
void (*g_child_exit_hook)(pid_t pid) = NULL;

/* Exited handlers, recorded by the SIGCHLD handler and consumed by the accept
 * loop (iplimit accounting). Live handlers <= 4096, so the ring cannot
 * overflow between two drains. */
#define EXIT_RING 4096
static volatile pid_t s_exit_pid[EXIT_RING];
static volatile int s_exit_status[EXIT_RING];
static volatile sig_atomic_t s_exit_head = 0;   /* written by the handler only */
static sig_atomic_t s_exit_tail = 0;            /* read side: SIGCHLD blocked */
static void sigchld_handler(int sig) {
    (void)sig;
    int saved_errno = errno;
    pid_t pid;
    int status;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (g_active_children > 0) g_active_children--;
        s_exit_pid[s_exit_head % EXIT_RING] = pid;
        s_exit_status[s_exit_head % EXIT_RING] = status;
        s_exit_head++;
    }
    errno = saved_errno;
}

/* -K: account for finished handlers (call with SIGCHLD blocked) */
void reap_handler_exits(void) {
    while (s_exit_tail != s_exit_head) {
        int i = s_exit_tail % EXIT_RING;
        pid_t pid = s_exit_pid[i];
        int st = s_exit_status[i];
        s_exit_tail++;
        if (g_child_exit_hook) g_child_exit_hook(pid);
        int auth_failed = WIFEXITED(st) && WEXITSTATUS(st) == CHILD_AUTH_FAILED;
        char key[IPLIMIT_KEY_LEN];
        int fails = iplimit_finished(pid, auth_failed, time(NULL), key);
        if (auth_failed && key[0]) {
            if (g_opt.auth_fail_limit && fails >= g_opt.auth_fail_limit)
                log_msg(0, "authentication failure from %s (%d/%d): blocking it for %d s",
                        key, fails, g_opt.auth_fail_limit, AUTH_BLOCK_TIME);
            else if (g_opt.auth_fail_limit)
                log_msg(1, "authentication failure from %s (%d/%d)", key, fails,
                        g_opt.auth_fail_limit);
            else
                log_msg(1, "authentication failure from %s", key);
        }
    }
}

/* -K: accept one connection and apply the per-address limits.
 * Returns the client fd (ipkey/have_key filled) or -1 if it was refused. */
int accept_admitted(int listen_fd, char ipkey[IPLIMIT_KEY_LEN], int *have_key) {
    struct sockaddr_storage peer;
    socklen_t peer_len = sizeof(peer);
    int client_fd = net_accept_peer(listen_fd, &peer, &peer_len);
    *have_key = iplimit_key((struct sockaddr *)&peer, peer_len, ipkey) == 0;

    sigset_t chld, prev;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    sigprocmask(SIG_BLOCK, &chld, &prev);
    reap_handler_exits();
    int verdict = IPLIMIT_OK, retry = 0;
    if (*have_key) verdict = iplimit_admit(ipkey, time(NULL), &retry);
    sigprocmask(SIG_SETMASK, &prev, NULL);
    if (verdict == IPLIMIT_OK) return client_fd;
    if (verdict == IPLIMIT_BLOCKED)
        log_msg(1, "refused %s: blocked for %d s after repeated authentication failures",
                ipkey, retry);
    else
        log_msg(1, "refused %s: %d handlers already running for this address (--max-per-ip)",
                ipkey, g_opt.max_per_ip);
    close(client_fd);
    return -1;
}

void install_sigchld(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld_handler;
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);
}

