#ifndef CLAWSEC_PERSISTENT_H
#define CLAWSEC_PERSISTENT_H

/*
 * Persistent connection: auto-reconnect with heartbeat + exponential backoff.
 *
 * Client keeps reconnecting until killed (Ctrl+C).
 * Heartbeat every N seconds detects dead tunnels.
 */

#define PERSIST_HEARTBEAT_INTERVAL  15   /* seconds between heartbeats */
#define PERSIST_HEARTBEAT_TIMEOUT   45   /* seconds before declaring dead */
#define PERSIST_BACKOFF_INITIAL     1    /* initial reconnect delay (seconds) */
#define PERSIST_BACKOFF_MAX         60   /* max reconnect delay (seconds) */
#define PERSIST_HEARTBEAT_MSG       "HB\n"

/* Send periodic heartbeats. Returns -1 if tunnel is dead. */
int persist_heartbeat_send(int tunnel_fd);

/* Check for heartbeat. Returns -1 if timed out. */
int persist_heartbeat_check(const char *buf, int len);

/* Calculate next backoff delay (exponential with jitter) */
int persist_next_delay(int attempt);

#endif
