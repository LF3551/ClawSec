/*
 * iplimit.c — per-source-address limits for the multi-client server (-K)
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

#include "iplimit.h"

#define TABLE_SIZE 8192           /* tracked addresses (oldest idle evicted) */
#define PID_SLOTS  4096           /* >= the --max-clients limit */

struct entry {
    char key[IPLIMIT_KEY_LEN];    /* "" = free */
    int active;
    int fails;
    time_t first_fail;
    time_t blocked_until;
    time_t last_seen;
};

static struct entry table[TABLE_SIZE];
static struct { pid_t pid; int idx; } pids[PID_SLOTS];
static int cfg_max_per_ip, cfg_fail_limit, cfg_window, cfg_block;

void iplimit_configure(int max_per_ip, int fail_limit, int window_s, int block_s) {
    cfg_max_per_ip = max_per_ip > 0 ? max_per_ip : 0;
    cfg_fail_limit = fail_limit > 0 ? fail_limit : 0;
    cfg_window = window_s > 0 ? window_s : 600;
    cfg_block = block_s > 0 ? block_s : 600;
    memset(table, 0, sizeof(table));
    memset(pids, 0, sizeof(pids));
}

int iplimit_key(const struct sockaddr *sa, socklen_t len, char key[IPLIMIT_KEY_LEN]) {
    if (sa->sa_family == AF_INET && len >= (socklen_t)sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)sa;
        return inet_ntop(AF_INET, &s4->sin_addr, key, IPLIMIT_KEY_LEN) ? 0 : -1;
    }
    if (sa->sa_family == AF_INET6 && len >= (socklen_t)sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)sa;
        struct in6_addr a = s6->sin6_addr;
        if (IN6_IS_ADDR_V4MAPPED(&a))
            return inet_ntop(AF_INET, &a.s6_addr[12], key, IPLIMIT_KEY_LEN) ? 0 : -1;
        memset(&a.s6_addr[8], 0, 8);                     /* group by /64 */
        if (!inet_ntop(AF_INET6, &a, key, IPLIMIT_KEY_LEN - 4)) return -1;
        strcat(key, "/64");
        return 0;
    }
    return -1;
}

static int find(const char *key) {
    for (int i = 0; i < TABLE_SIZE; i++)
        if (table[i].key[0] && strcmp(table[i].key, key) == 0) return i;
    return -1;
}

/* An entry that carries no state worth keeping */
static int idle(const struct entry *e, time_t now) {
    return e->active == 0 && e->blocked_until <= now &&
           (e->fails == 0 || now - e->first_fail >= cfg_window);
}

static int find_or_add(const char *key, time_t now) {
    int i = find(key), victim = -1;
    if (i >= 0) return i;
    for (i = 0; i < TABLE_SIZE; i++) {
        if (!table[i].key[0]) { victim = i; break; }
        if (idle(&table[i], now) &&
            (victim < 0 || table[i].last_seen < table[victim].last_seen))
            victim = i;
    }
    if (victim < 0) return -1;                       /* everything busy or blocked */
    memset(&table[victim], 0, sizeof(table[victim]));
    strncpy(table[victim].key, key, IPLIMIT_KEY_LEN - 1);
    table[victim].last_seen = now;
    return victim;
}

int iplimit_admit(const char *key, time_t now, int *retry_after) {
    int i = find(key);
    if (i < 0) return IPLIMIT_OK;
    struct entry *e = &table[i];
    if (e->blocked_until > now) {
        if (retry_after) *retry_after = (int)(e->blocked_until - now);
        return IPLIMIT_BLOCKED;
    }
    if (cfg_max_per_ip && e->active >= cfg_max_per_ip) return IPLIMIT_TOO_MANY;
    return IPLIMIT_OK;
}

void iplimit_started(const char *key, pid_t pid, time_t now) {
    int i = find_or_add(key, now);
    if (i < 0) return;                               /* table full: not tracked */
    table[i].active++;
    table[i].last_seen = now;
    for (int s = 0; s < PID_SLOTS; s++) {
        if (pids[s].pid == 0) {
            pids[s].pid = pid;
            pids[s].idx = i;
            return;
        }
    }
    table[i].active--;                               /* cannot happen with max-clients <= PID_SLOTS */
}

int iplimit_finished(pid_t pid, int auth_failed, time_t now, char key_out[IPLIMIT_KEY_LEN]) {
    for (int s = 0; s < PID_SLOTS; s++) {
        if (pids[s].pid != pid) continue;
        struct entry *e = &table[pids[s].idx];
        pids[s].pid = 0;
        if (e->active > 0) e->active--;
        e->last_seen = now;
        if (key_out) memcpy(key_out, e->key, IPLIMIT_KEY_LEN);
        if (!auth_failed) return 0;
        if (e->fails == 0 || now - e->first_fail >= cfg_window) {
            e->fails = 0;
            e->first_fail = now;
        }
        e->fails++;
        if (cfg_fail_limit && e->fails >= cfg_fail_limit) {
            e->blocked_until = now + cfg_block;
            int n = e->fails;
            e->fails = 0;                            /* a fresh budget after the block */
            return n;
        }
        return e->fails;
    }
    if (key_out) key_out[0] = '\0';
    return 0;
}

int iplimit_tracked(void) {
    int n = 0;
    for (int i = 0; i < TABLE_SIZE; i++)
        if (table[i].key[0]) n++;
    return n;
}
