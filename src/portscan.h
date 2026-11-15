#ifndef CLAWSEC_PORTSCAN_H
#define CLAWSEC_PORTSCAN_H

#define SCAN_PORT_MIN 1
#define SCAN_PORT_MAX 65535

/* SYN scan probes per second (--scan-rate) */
#define SCAN_RATE_DEFAULT 1000
#define SCAN_RATE_MAX     100000
extern int g_scan_rate;

/* Scan result for one port */
#define PORT_OPEN     1
#define PORT_CLOSED   0
#define PORT_FILTERED 2

typedef struct {
    int port;
    int state;  /* PORT_OPEN / PORT_CLOSED / PORT_FILTERED */
} scan_result_t;

/*
 * Stealth port scan.
 *   host       — target hostname or IP
 *   start_port — first port in range (1-65535)
 *   end_port   — last port in range (1-65535)
 *   jitter_ms  — random delay 0-N ms between probes (0 = no delay)
 *   timeout_ms — per-port connect timeout in ms
 *
 * Techniques:
 *   - SYN scan (raw socket, IPv4/IPv6, Linux) if running as root: pipelined at
 *     g_scan_rate probes/s, replies matched by a keyed ISN, unanswered ports
 *     retried once and then counted as filtered; no handshake is completed
 *   - Randomized port order — defeats sequential scan detection (IDS evasion)
 *   - Jitter between probes — anti-rate-limit / anti-threshold detection
 *   - Immediate RST after SYN-ACK — no application-layer interaction
 *
 * Returns number of open ports found, prints results to stdout.
 */
int portscan_run(const char *host, int start_port, int end_port,
                 int jitter_ms, int timeout_ms, int banner_grab);

#endif
