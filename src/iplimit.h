/*
 * iplimit.h — per-source-address limits for the multi-client server (-K)
 *
 *  - at most max_per_ip concurrent handlers per address;
 *  - an address that fails password authentication fail_limit times within
 *    window seconds is refused for block seconds (online guessing is the
 *    only attack left against the SPAKE2 handshake, so it is rate-limited).
 *
 * IPv6 addresses are grouped by /64 (one customer network), IPv4-mapped IPv6
 * addresses count as the IPv4 address. Not thread-safe: used by the accept
 * loop only.
 */
#ifndef CLAWSEC_IPLIMIT_H
#define CLAWSEC_IPLIMIT_H

#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>

#define IPLIMIT_KEY_LEN 64

#define IPLIMIT_OK        0
#define IPLIMIT_TOO_MANY  1     /* max_per_ip handlers already running */
#define IPLIMIT_BLOCKED   2     /* too many authentication failures */

/* 0 disables the respective limit. Resets all state. */
void iplimit_configure(int max_per_ip, int fail_limit, int window_s, int block_s);

/* Canonical key for an address ("192.0.2.1", "2001:db8:1:2::/64").
 * Returns 0, or -1 for an unsupported address family. */
int iplimit_key(const struct sockaddr *sa, socklen_t len, char key[IPLIMIT_KEY_LEN]);

/* May a new connection from `key` be served now? On IPLIMIT_BLOCKED,
 * *retry_after receives the remaining block time in seconds. */
int iplimit_admit(const char *key, time_t now, int *retry_after);

/* A handler process for `key` was started / has finished. */
void iplimit_started(const char *key, pid_t pid, time_t now);
/* Returns the key's failure count after this event (0 if auth_failed == 0).
 * key_out (may be NULL) receives the address the pid belonged to. */
int iplimit_finished(pid_t pid, int auth_failed, time_t now, char key_out[IPLIMIT_KEY_LEN]);

/* Number of tracked addresses (tests). */
int iplimit_tracked(void);

#endif
