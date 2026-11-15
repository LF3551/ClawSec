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
#include "iplimit.h"

#define AUTH_FAIL_WINDOW 600       /* seconds */
#define AUTH_BLOCK_TIME  600       /* seconds */

/* Handler exit codes (-K) */
#define CHILD_OK          0
#define CHILD_ERROR       1
#define CHILD_AUTH_FAILED 3

/* Live handler processes (decremented by the SIGCHLD handler) */
extern volatile sig_atomic_t g_active_children;

void install_sigchld(void);
/* Account for finished handlers; call with SIGCHLD blocked. */
void reap_handler_exits(void);
/* Accept one connection and apply the per-address limits. Returns the
 * client fd (ipkey/have_key filled) or -1 if it was refused. */
int accept_admitted(int listen_fd, char ipkey[IPLIMIT_KEY_LEN], int *have_key);

#endif
