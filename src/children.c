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
#include "users.h"
#include "version.h"
#include <stdint.h>

static void untrack(pid_t pid);

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
        untrack(pid);
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


/* ── Session registry ── */

typedef struct {
    pid_t pid;
    char peer[IPLIMIT_KEY_LEN];
    char user[USER_NAME_MAX + 1];
    time_t since;
} child_info_t;

static child_info_t *s_info;
static int s_ninfo, s_capinfo;
static int s_report[2] = { -1, -1 };
static time_t s_started;

static child_info_t *find_info(pid_t pid) {
    for (int i = 0; i < s_ninfo; i++)
        if (s_info[i].pid == pid) return &s_info[i];
    return NULL;
}

void children_track(pid_t pid, const char *peer) {
    if (s_ninfo == s_capinfo) {
        int nc = s_capinfo ? s_capinfo * 2 : 32;
        child_info_t *n = realloc(s_info, (size_t)nc * sizeof(*n));
        if (!n) return;
        s_info = n;
        s_capinfo = nc;
    }
    child_info_t *c = &s_info[s_ninfo++];
    memset(c, 0, sizeof(*c));
    c->pid = pid;
    snprintf(c->peer, sizeof(c->peer), "%s", peer && *peer ? peer : "-");
    c->since = time(NULL);
}

static void untrack(pid_t pid) {
    for (int i = 0; i < s_ninfo; i++)
        if (s_info[i].pid == pid) {
            s_info[i] = s_info[--s_ninfo];
            return;
        }
}

const char *children_user(pid_t pid) {
    child_info_t *c = find_info(pid);
    return c && c->user[0] ? c->user : NULL;
}

const char *children_peer(pid_t pid) {
    child_info_t *c = find_info(pid);
    return c ? c->peer : NULL;
}

long children_since(pid_t pid) {
    child_info_t *c = find_info(pid);
    return c ? (long)c->since : 0;
}

int children_reports_init(void) {
    if (s_report[0] >= 0) return 0;
    if (pipe(s_report) != 0) return -1;
    for (int i = 0; i < 2; i++) fcntl(s_report[i], F_SETFD, FD_CLOEXEC);
    fcntl(s_report[0], F_SETFL, fcntl(s_report[0], F_GETFL) | O_NONBLOCK);
    s_started = time(NULL);
    return 0;
}

int children_reports_fd(void) { return s_report[0]; }

/* report: pid(4) user(n) — one write, shorter than PIPE_BUF: atomic */
void children_report_user(const char *user) {
    if (s_report[1] < 0 || !user) return;
    char msg[4 + USER_NAME_MAX];
    int32_t pid = (int32_t)getpid();
    size_t n = strlen(user);
    if (n > USER_NAME_MAX) n = USER_NAME_MAX;
    memcpy(msg, &pid, 4);
    memcpy(msg + 4, user, n);
    (void)!write(s_report[1], msg, 4 + n);
}

void children_reports_read(void) {
    char msg[4 + USER_NAME_MAX];
    ssize_t r;
    while ((r = read(s_report[0], msg, sizeof(msg))) > 4) {
        int32_t pid;
        memcpy(&pid, msg, 4);
        child_info_t *c = find_info((pid_t)pid);
        if (!c) continue;
        size_t n = (size_t)r - 4;
        memcpy(c->user, msg + 4, n);
        c->user[n] = '\0';
    }
}

static void fmt_age(char *out, size_t len, long secs) {
    if (secs < 0) secs = 0;
    if (secs < 3600) snprintf(out, len, "%ldm%02lds", secs / 60, secs % 60);
    else snprintf(out, len, "%ldh%02ldm", secs / 3600, (secs % 3600) / 60);
}

void children_status(FILE *out, void *ctx) {
    (void)ctx;
    char age[32];
    time_t now = time(NULL);
    children_reports_read();
    fmt_age(age, sizeof(age), (long)(now - s_started));
    fprintf(out, "ClawSec %s, pid %d, up %s, %d of %d sessions\n", CLAWSEC_VERSION,
            (int)getpid(), age, s_ninfo, g_opt.max_clients);
    if (!s_ninfo) return;
    fprintf(out, "%-8s %-40s %-16s %s\n", "PID", "PEER", "USER", "AGE");
    for (int i = 0; i < s_ninfo; i++) {
        fmt_age(age, sizeof(age), (long)(now - s_info[i].since));
        fprintf(out, "%-8d %-40s %-16s %s\n", (int)s_info[i].pid, s_info[i].peer,
                s_info[i].user[0] ? s_info[i].user : "-", age);
    }
}
