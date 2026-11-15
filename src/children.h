/*
 * children.h — -K handler processes: SIGCHLD accounting and admission
 *
 * The SIGCHLD handler reaps handlers and records their exit status in a
 * ring; the accept loop (or the VPN hub) consumes it with SIGCHLD blocked to
 * update the per-address limits (iplimit).
 */
#ifndef CLAWSEC_CHILDREN_H
#define CLAWSEC_CHILDREN_H

#include <signal.h>
#include <sys/types.h>
#include "iplimit.h"

#define AUTH_FAIL_WINDOW 600       /* seconds */
#define AUTH_BLOCK_TIME  600       /* seconds */

/* Handler exit codes (-K) */
#define CHILD_OK          0
#define CHILD_ERROR       1
#define CHILD_AUTH_FAILED 3

/* Live handler processes (decremented by the SIGCHLD handler) */
extern volatile sig_atomic_t g_active_children;

/* Called by reap_handler_exits() for every finished handler (not from the
 * signal handler), e.g. so the VPN hub can drop that client's slot. */
extern void (*g_child_exit_hook)(pid_t pid);

void install_sigchld(void);
/* Account for finished handlers; call with SIGCHLD blocked. */
void reap_handler_exits(void);
/* Accept one connection and apply the per-address limits. Returns the
 * client fd (ipkey/have_key filled) or -1 if it was refused. */
int accept_admitted(int listen_fd, char ipkey[IPLIMIT_KEY_LEN], int *have_key);

/* ── Session registry for --control / --status ── */
#include <stdio.h>

/* Parent: create the report pipe (call once, before forking sessions) */
int children_reports_init(void);
/* Parent: read end, to poll; children_reports_read() consumes reports */
int children_reports_fd(void);
void children_reports_read(void);
/* Session process: tell the parent the logged-in user name (no-op without
 * a report pipe) */
void children_report_user(const char *user);

/* Parent: a session process started for peer (ipkey) */
void children_track(pid_t pid, const char *peer);
/* Look up a tracked session (NULL if unknown) */
const char *children_user(pid_t pid);
const char *children_peer(pid_t pid);
long children_since(pid_t pid);
/* Plain-text table of the running sessions */
void children_status(FILE *out, void *ctx);

#endif
