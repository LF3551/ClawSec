/*
 * persistent.c — Auto-reconnect with heartbeat + exponential backoff
 *
 * Maintains a stable encrypted tunnel that automatically reconnects
 * on disconnect. Heartbeat packets detect dead connections quickly.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "persistent.h"
#include "farm9crypt.h"
#include "util.h"

/*
 * Send heartbeat through encrypted tunnel.
 * Returns 0 on success, -1 on failure (tunnel dead).
 */
int persist_heartbeat_send(int tunnel_fd) {
    return farm9crypt_write(tunnel_fd, (char *)PERSIST_HEARTBEAT_MSG, strlen(PERSIST_HEARTBEAT_MSG));
}

/*
 * Check if received data is a heartbeat.
 * Returns 1 if heartbeat, 0 if regular data.
 */
int persist_heartbeat_check(const char *buf, int len) {
    if (len == (int)strlen(PERSIST_HEARTBEAT_MSG) &&
        memcmp(buf, PERSIST_HEARTBEAT_MSG, len) == 0)
        return 1;
    return 0;
}

/*
 * Calculate next reconnect delay using exponential backoff with jitter.
 * attempt: 0-based attempt counter.
 * Returns delay in seconds.
 */
int persist_next_delay(int attempt) {
    int base = PERSIST_BACKOFF_INITIAL;
    for (int i = 0; i < attempt && base < PERSIST_BACKOFF_MAX; i++)
        base *= 2;
    if (base > PERSIST_BACKOFF_MAX)
        base = PERSIST_BACKOFF_MAX;

    /* Add ±25% jitter */
    int jitter = base / 4;
    if (jitter > 0) {
        base += (rand() % (jitter * 2 + 1)) - jitter;
    }
    if (base < 1) base = 1;
    return base;
}
