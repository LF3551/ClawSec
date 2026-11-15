/*
 * options.h — run-time settings from the command line (one place instead of
 * file-scope globals spread over clawsec.c)
 */
#ifndef CLAWSEC_OPTIONS_H
#define CLAWSEC_OPTIONS_H

struct clawsec_options {
    /* modes */
    int socks;                     /* --socks */
    const char *socks_port;        /* --socks [host:]port as given */
    char socks_host[256];          /* client listener address (resolved) */
    char socks_lport[8];
    const char *mux_port;          /* -p [host:]port with --mux (client) */
    char mux_host[256];
    char mux_lport[8];
    const char *send_file;         /* --send */
    const char *recv_dir;          /* --recv */
    const char *reverse_spec;      /* -R host:port */
    int persistent;                /* --persistent */
    const char *bind_port;         /* -p <port> (also the --tun-udp server port) */

    /* VPN */
    const char *tun_cidr;          /* --tun 10.0.0.1/24, client: or "auto" */
    const char *tun6_cidr;         /* --tun6 fd00::1/64 (server) */
    int masquerade;                /* --masquerade */
    int default_route;             /* --default-route */
    int tun_udp;                   /* --tun-udp */
    int hub_fd;                    /* -K --tun session process: socket to the hub */

    /* server limits */
    int max_clients;               /* --max-clients */
    int max_per_ip;                /* --max-per-ip (0 = unlimited) */
    int auth_fail_limit;           /* --auth-fail-limit per 10 min (0 = off) */
    int handshake_timeout;         /* --handshake-timeout (s, 0 = off) */
};

extern struct clawsec_options g_opt;

#endif
