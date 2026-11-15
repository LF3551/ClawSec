#ifndef CLAWSEC_UTIL_H
#define CLAWSEC_UTIL_H

#include <stddef.h>
#include <stdarg.h>

/* Logging */
void log_msg(int level, const char *fmt, ...);
void fatal(const char *fmt, ...);

/* I/O helpers */
int write_all(int fd, const void *buf, size_t len);

/* poll()-based waiting (no FD_SETSIZE limit, unlike select()).
 * wait_readable: fds[i] < 0 are ignored; ready[i] = 1 if fds[i] is readable,
 * hung up or in error. timeout_ms < 0 waits forever. Returns poll()'s result
 * (0 = timeout, -1 = error with errno, e.g. EINTR). */
int wait_readable(const int *fds, int *ready, int n, int timeout_ms);

/* Wait until fd is writable (e.g. non-blocking connect finished).
 * Returns 1 if writable, 0 on timeout, -1 on error. */
int wait_writable(int fd, int timeout_ms);

/* Globals */
extern int g_verbose;

#endif
