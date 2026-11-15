#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <poll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <time.h>
#include <openssl/crypto.h>

#include "farm9crypt.h"
#include "util.h"
#include "net.h"
#include "relay.h"
#include "exec.h"
#include "obfs.h"
#include "mux.h"
#include "fallback.h"
#include "fingerprint.h"
#include "tofu.h"
#include "pqkem.h"
#include "portscan.h"
#include "socks5.h"
#include "filetx.h"
#include "reverse.h"
#include "persistent.h"
#include "tun.h"
#include "version.h"
#include "secret.h"
#include "acl.h"
#include "iplimit.h"
#include "users.h"
#include "vpn.h"
#include "hub.h"
#include "options.h"
#include "children.h"
#include "session.h"
#include "vpnrun.h"
#include "config.h"
#include "control.h"
#include "ecdhe.h"

/* Global config */
int g_verbose = 0;
int g_chat_mode = 0;
int g_udp_mode = 0;
int g_af_family; /* AF_UNSPEC */
int g_pq = 0;    /* --pq: post-quantum hybrid */

static char s_password[SECRET_MAX + 1];     /* session password (never in argv) */

static void ignore_sigpipe(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
}

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s [password] [-u] [-4|-6] [-c] [-v] [-w sec] host port\n"
            "  %s -l [password] -p port [-K] [-u] [-4|-6] [-c] [-v]", prog, prog);
#ifdef GAPING_SECURITY_HOLE
    fprintf(stderr, " [-e prog]");
#endif
    fprintf(stderr, "\n"
            "  %s -l [password] -p port -L host:port  (port forwarding)\n"
            "  [password] = --key-file <file> | -k <password>, or CLAWSEC_PASSWORD, or prompt\n\n", prog);
    fprintf(stderr,
            "Options:\n"
            "  -k <password>     Encryption password (visible in ps; prefer the next two)\n"
            "  --key-file <f>    Read the password from the first line of a file (0600)\n"
            "  --user <name>     Client: log in as <name> (server uses --users)\n"
            "  --users <file>    Server: per-user passwords instead of a shared one\n"
            "  --add-user <name> With --users: add a user / change its password, exit\n"
            "  --set-user <name> With --users: change a user's options, exit\n"
            "  --del-user <name> With --users: remove a user, exit\n"
            "  --user-option <o> ip=A.B.C.D | socks-allow=CIDR;CIDR | disabled | none\n"
            "                    (or set CLAWSEC_PASSWORD; without either you are prompted)\n"
            "  -l                Listen mode (server)\n"
            "  -p <port>         Local port in listen mode\n"
            "                    (with --mux on the client: [host:]port, default 127.0.0.1)\n"
            "  -K                Keep-open: accept multiple clients (fork per client)\n"
            "  --max-clients <n> With -K: concurrent handlers (default 16)\n"
            "  --control <path>  With -K: status socket (mode 0600); read it with\n"
            "                    clawsec --status <path>\n"
            "  --config <file>   Read options from a file (key = value; see the man page)\n"
            "  --max-per-ip <n>  With -K: concurrent handlers per address, IPv6 per /64\n"
            "                    (default 8, 0=unlimited)\n"
            "  --auth-fail-limit <n>  With -K: refuse an address for 10 min after n wrong\n"
            "                    passwords within 10 min (default 5, 0=off)\n"
            "  --handshake-timeout <s>  Abort session setup after s seconds (default 15, 0=off)\n"
            "  -L <host:port>    Port forwarding: forward decrypted traffic to host:port\n"
            "  -R <host:port>    Reverse tunnel. Server: address to listen on (127.0.0.1,\n"
            "                    or 0.0.0.0 to expose publicly). Client: target to connect to\n"
            "  --tun <ip/mask>   TUN VPN mode: create encrypted VPN tunnel\n"
            "                    (client: --tun auto = address from the server;\n"
            "                    server with -K: one device, many clients)\n"
            "  --tun6 <ip6/pfx>  Server: IPv6 inside the tunnel (e.g. fd00:c1a5::1/64)\n"
            "  --tun-udp         Use UDP data channel for VPN (avoids TCP-over-TCP)\n"
            "  --masquerade      Enable NAT (use with --tun on server for internet access)\n"
            "  --default-route   Route ALL traffic through VPN (client-side full tunnel)\n"
            "  --persistent      Auto-reconnect with exponential backoff (client mode)\n"
            "  --obfs http       Obfuscate traffic as HTTP requests (anti-DPI)\n"
            "  --obfs tls        Run inside TLS 1.3 (self-signed certificate)\n"
            "  --ech             Add a GREASE Encrypted Client Hello extension\n"
            "  --mux             Multiplex streams over one tunnel (with -L)\n"
            "  --fallback <h:p>  Proxy clients without the ClawSec knock to h:p\n"
            "  --fingerprint <p> Browser-like TLS ClientHello (chrome, firefox, safari)\n"
            "  --tofu            Trust On First Use (SSH-like server identity)\n"
            "  --pq              Post-quantum hybrid (SPAKE2 + ML-KEM-768)\n"
            "  --scan <range>    Port scan (SYN as root on Linux, else connect; random order)\n"
            "  --scan-rate <pps> SYN scan probes per second (default 1000)\n"
            "                    range: 1-1024, 22-443, all (default: 1-1024)\n"
            "  -b                Banner grab (show service version on open ports)\n"
            "  --socks-allow <l> SOCKS server: only allow destinations in l (CIDR list);\n"
            "                    default: all except loopback/link-local/cloud metadata\n"
            "  --socks [h:]port  SOCKS5 proxy through encrypted tunnel (client listens on\n"
            "                    127.0.0.1 by default; the proxy has no authentication)\n"
            "  --send <file>     Send file (encrypted, with SHA-256 verify + resume)\n"
            "  --recv <dir>      Receive file (save to dir, with resume support)\n"
            "  --pad             Pad all packets to uniform 1400 bytes (anti-analysis)\n"
            "  --jitter <ms>     Add random 0-N ms delay between packets (anti-timing)\n"
            "  -z                Compress data with zlib before encryption\n"
            "  -P                Show transfer progress bar\n"
            "  -V                SHA-256 end-to-end file verification\n"
            "  -n <name>         Chat nickname (default: Server/Client)\n"
            "  -u                UDP mode (default: TCP)\n"
            "  -4                Force IPv4 only\n"
            "  -6                Force IPv6 only\n"
            "  -c                Chat mode (timestamps, roles)\n"
            "  -w <sec>          Connect timeout in seconds\n"
            "  -v                Verbose output\n"
            "  --version         Print version and wire protocol, then exit\n");
#ifdef GAPING_SECURITY_HOLE
    fprintf(stderr,
            "  -e <program>      Execute program after connect (encrypted)\n");
#endif
}

/* Long-only options */
enum {
    OPT_KEY_FILE = 256,
    OPT_USER,
    OPT_USERS,
    OPT_ADD_USER,
    OPT_SET_USER,
    OPT_DEL_USER,
    OPT_USER_OPTION,
    OPT_MAX_CLIENTS,
    OPT_MAX_PER_IP,
    OPT_SCAN_RATE,
    OPT_TUN6,
    OPT_AUTH_FAIL_LIMIT,
    OPT_HANDSHAKE_TIMEOUT,
    OPT_SOCKS_ALLOW,
    OPT_CONFIG,
    OPT_CONTROL,
    OPT_STATUS,
};

/* Parse a non-negative decimal integer option. Returns -1 if invalid. */
static long parse_count(const char *s, long max) {
    char *end;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || end == s || *end != '\0' || v < 0 || v > max) return -1;
    return v;
}

int main(int argc, char **argv) {
    const char *password = NULL;
    const char *bind_port = NULL;  /* set to g_opt.bind_port below after parsing */
    const char *fwd_spec = NULL;
    const char *scan_range = NULL;
    int listen_mode = 0;
    const char *login_user = NULL;    /* --user (client) */
    const char *users_file = NULL;    /* --users (server) */
    const char *add_user = NULL;      /* --add-user (with --users) */
    const char *set_user = NULL;      /* --set-user (with --users) */
    const char *del_user = NULL;      /* --del-user (with --users) */
    char user_opts[USER_OPTS_MAX] = "";   /* --user-option, comma-joined */
    int have_user_opts = 0;
    int keep_open = 0;
    int timeout_sec = 0;
    int scan_mode = 0;
    int banner_grab = 0;
    int password_from_argv = 0;
    const char *key_file = NULL;
#ifdef GAPING_SECURITY_HOLE
    const char *exec_prog = NULL;
#endif

    static struct option long_opts[] = {
        {"obfs",        required_argument, NULL, 'O'},
        {"pad",         no_argument,       NULL, 'D'},
        {"jitter",      required_argument, NULL, 'J'},
        {"ech",         no_argument,       NULL, 'E'},
        {"mux",         no_argument,       NULL, 'M'},
        {"fallback",    required_argument, NULL, 'F'},
        {"fingerprint", required_argument, NULL, 'T'},
        {"tofu",        no_argument,       NULL, 'U'},
        {"pq",          no_argument,       NULL, 'Q'},
        {"scan",        required_argument, NULL, 'S'},
        {"socks",       required_argument, NULL, 'X'},
        {"send",        required_argument, NULL, 'W'},
        {"recv",        required_argument, NULL, 'Y'},
        {"persistent",  no_argument,       NULL, 'Z'},
        {"tun",         required_argument, NULL, 'N'},
        {"masquerade",  no_argument,       NULL, 'A'},
        {"default-route", no_argument,     NULL, 'G'},
        {"tun-udp",     no_argument,       NULL, 'B'},
        {"help",        no_argument,       NULL, 'h'},
        {"version",     no_argument,       NULL, 'I'},
        {"key-file",    required_argument, NULL, OPT_KEY_FILE},
        {"user",        required_argument, NULL, OPT_USER},
        {"users",       required_argument, NULL, OPT_USERS},
        {"add-user",    required_argument, NULL, OPT_ADD_USER},
        {"set-user",    required_argument, NULL, OPT_SET_USER},
        {"del-user",    required_argument, NULL, OPT_DEL_USER},
        {"user-option", required_argument, NULL, OPT_USER_OPTION},
        {"max-clients", required_argument, NULL, OPT_MAX_CLIENTS},
        {"max-per-ip", required_argument, NULL, OPT_MAX_PER_IP},
        {"scan-rate", required_argument, NULL, OPT_SCAN_RATE},
        {"tun6", required_argument, NULL, OPT_TUN6},
        {"auth-fail-limit", required_argument, NULL, OPT_AUTH_FAIL_LIMIT},
        {"handshake-timeout", required_argument, NULL, OPT_HANDSHAKE_TIMEOUT},
        {"socks-allow", required_argument, NULL, OPT_SOCKS_ALLOW},
        {"config", required_argument, NULL, OPT_CONFIG},
        {"control", required_argument, NULL, OPT_CONTROL},
        {"status", required_argument, NULL, OPT_STATUS},
        {NULL, 0, NULL, 0}
    };

#ifdef GAPING_SECURITY_HOLE
    const char *optstring = "hblKu46ck:p:w:ve:L:R:zPVn:";
#else
    /* -e is recognised only to explain how to enable it */
    const char *optstring = "hblKu46ck:p:w:ve:L:R:zPVn:";
#endif

    int opt;
    if (config_expand(&argc, &argv, long_opts) != 0) return 1;
    while ((opt = getopt_long(argc, argv, optstring, long_opts, NULL)) != -1) {
        switch (opt) {
        case 'h': usage(argv[0]); return 0;
        case 'I':
            printf("ClawSec %s (wire protocol %d)\n", CLAWSEC_VERSION, FARM9_VERSION);
            return 0;
        case 'b': banner_grab = 1; break;
        case 'l': listen_mode = 1; break;
        case 'K': keep_open = 1; break;
        case 'u': g_udp_mode = 1; break;
        case '4': g_af_family = AF_INET; break;
        case '6': g_af_family = AF_INET6; break;
        case 'c': g_chat_mode = 1; break;
        case 'k':
            if (secret_from_arg(optarg, s_password, sizeof(s_password)) != 0)
                return 1;
            password = s_password;
            password_from_argv = 1;
            break;
        case OPT_KEY_FILE: key_file = optarg; break;
        case OPT_CONFIG: break;              /* expanded by config_expand() */
        case OPT_CONTROL: g_opt.control_path = optarg; break;
        case OPT_STATUS: return control_status(optarg);
        case OPT_USER: login_user = optarg; break;
        case OPT_USERS: users_file = optarg; break;
        case OPT_ADD_USER: add_user = optarg; break;
        case OPT_SET_USER: set_user = optarg; break;
        case OPT_DEL_USER: del_user = optarg; break;
        case OPT_USER_OPTION: {
            size_t used = strlen(user_opts);
            if (used + strlen(optarg) + 2 > sizeof(user_opts)) {
                fprintf(stderr, "ERROR: too many --user-option values\n");
                return 1;
            }
            if (used) strcat(user_opts, ",");
            strcat(user_opts, optarg);
            have_user_opts = 1;
            break;
        }
        case OPT_MAX_CLIENTS: {
            long v = parse_count(optarg, 4096);
            if (v < 1) {
                fprintf(stderr, "ERROR: --max-clients must be 1-4096\n");
                return 1;
            }
            g_opt.max_clients = (int)v;
            break;
        }
        case OPT_TUN6: {
            struct in6_addr a6;
            int p6;
            if (vpn_parse_cidr6(optarg, &a6, &p6) != 0) {
                fprintf(stderr, "ERROR: Invalid --tun6 '%s' (use IPv6/prefix, prefix 64-120, "
                                "e.g. fd00:c1a5::1/64)\n", optarg);
                return 1;
            }
            g_opt.tun6_cidr = optarg;
            break;
        }
        case OPT_SCAN_RATE: {
            long v = parse_count(optarg, SCAN_RATE_MAX);
            if (v < 1) {
                fprintf(stderr, "ERROR: --scan-rate must be 1-%d probes per second\n", SCAN_RATE_MAX);
                return 1;
            }
            g_scan_rate = (int)v;
            break;
        }
        case OPT_MAX_PER_IP: {
            long v = parse_count(optarg, 4096);
            if (v < 0) {
                fprintf(stderr, "ERROR: --max-per-ip must be 0-4096\n");
                return 1;
            }
            g_opt.max_per_ip = (int)v;
            break;
        }
        case OPT_AUTH_FAIL_LIMIT: {
            long v = parse_count(optarg, 1000);
            if (v < 0) {
                fprintf(stderr, "ERROR: --auth-fail-limit must be 0-1000\n");
                return 1;
            }
            g_opt.auth_fail_limit = (int)v;
            break;
        }
        case OPT_HANDSHAKE_TIMEOUT: {
            long v = parse_count(optarg, 3600);
            if (v < 0) {
                fprintf(stderr, "ERROR: --handshake-timeout must be 0-3600 seconds\n");
                return 1;
            }
            g_opt.handshake_timeout = (int)v;
            break;
        }
        case OPT_SOCKS_ALLOW:
            if (acl_set_allow_list(optarg) != 0) return 1;
            break;
        case 'p': bind_port = optarg; break;
        case 'L': fwd_spec = optarg; break;
        case 'R': g_opt.reverse_spec = optarg; break;
        case 'O':
            if (strcmp(optarg, "http") == 0) {
                obfs_set_mode(OBFS_HTTP);
            } else if (strcmp(optarg, "tls") == 0) {
                obfs_set_mode(OBFS_TLS);
            } else {
                fprintf(stderr, "ERROR: Unknown obfuscation mode '%s' (supported: http, tls)\n", optarg);
                return 1;
            }
            break;
        case 'w':
            timeout_sec = atoi(optarg);
            if (timeout_sec < 0) timeout_sec = 0;
            break;
        case 'v': g_verbose++; break;
        case 'z': g_compress = 1; break;
        case 'P': g_progress = 1; break;
        case 'V': g_verify = 1; break;
        case 'n': g_nickname = optarg; break;
        case 'D': g_pad = 1; farm9crypt_set_padding(1); break;
        case 'J':
            g_jitter = atoi(optarg);
            if (g_jitter < 0) g_jitter = 0;
            break;
        case 'E':
            obfs_ech_enable();
            /* ECH implies TLS mode */
            if (obfs_get_mode() == OBFS_NONE)
                obfs_set_mode(OBFS_TLS);
            break;
        case 'M':
            g_mux = 1;
            break;
        case 'F':
            g_fallback = 1;
            if (net_parse_host_port(optarg, g_fallback_host, sizeof(g_fallback_host),
                                g_fallback_port, sizeof(g_fallback_port)) < 0) {
                fprintf(stderr, "ERROR: Invalid fallback target '%s' (use host:port)\n", optarg);
                return 1;
            }
            /* Fallback implies TLS mode */
            if (obfs_get_mode() == OBFS_NONE)
                obfs_set_mode(OBFS_TLS);
            break;
        case 'T':
            if (strcmp(optarg, "chrome") == 0) {
                fp_set_profile(FP_CHROME);
            } else if (strcmp(optarg, "firefox") == 0) {
                fp_set_profile(FP_FIREFOX);
            } else if (strcmp(optarg, "safari") == 0) {
                fp_set_profile(FP_SAFARI);
            } else {
                fprintf(stderr, "ERROR: Unknown fingerprint profile '%s' (supported: chrome, firefox, safari)\n", optarg);
                return 1;
            }
            /* Fingerprint implies TLS mode */
            if (obfs_get_mode() == OBFS_NONE)
                obfs_set_mode(OBFS_TLS);
            break;
        case 'U':
            g_tofu = 1;
            break;
        case 'Q':
            g_pq = 1;
            break;
        case 'S':
            scan_mode = 1;
            scan_range = optarg;
            break;
        case 'X':
            g_opt.socks = 1;
            g_opt.socks_port = optarg;
            break;
        case 'W':
            g_opt.send_file = optarg;
            break;
        case 'Y':
            g_opt.recv_dir = optarg;
            break;
        case 'Z':
            g_opt.persistent = 1;
            break;
        case 'N': {
            char ip[64]; int pfx;
            if (strcmp(optarg, "auto") == 0) {           /* client: server assigns */
                g_opt.tun_cidr = optarg;
                break;
            }
            if (tun_parse_cidr(optarg, ip, sizeof(ip), &pfx) != 0) {
                fprintf(stderr, "ERROR: Invalid --tun '%s' (use IPv4/prefix, e.g. 10.0.0.1/24, prefix 8-30)\n",
                        optarg);
                return 1;
            }
            g_opt.tun_cidr = optarg;
            break;
        }
        case 'A':
            g_opt.masquerade = 1;
            break;
        case 'G':
            g_opt.default_route = 1;
            break;
        case 'B':
            g_opt.tun_udp = 1;
            break;
#ifdef GAPING_SECURITY_HOLE
        case 'e': exec_prog = optarg; break;
#else
        case 'e':
            fprintf(stderr, "ERROR: -e (execute program) is not built into this binary.\n"
                            "Rebuild with: make <target> DFLAGS=-DGAPING_SECURITY_HOLE\n");
            return 1;
#endif
        default: usage(argv[0]); return 1;
        }
    }

    int exit_status = 0;
#ifdef GAPING_SECURITY_HOLE
    const char *exec_arg = exec_prog;
#else
    const char *exec_arg = NULL;
#endif

    /* Port scan mode — doesn't need password */
    g_opt.bind_port = bind_port;  /* expose to handle_client for --tun-udp */

    if (scan_mode) {
        if (optind >= argc) {
            fprintf(stderr, "ERROR: --scan requires target host\n");
            fprintf(stderr, "Usage: %s --scan <range> [--jitter N] [-v] host\n", argv[0]);
            fprintf(stderr, "  range: 1-1024, 80, 22-443 (default: 1-1024)\n");
            return 1;
        }
        const char *scan_host = argv[optind];
        int sp = 1, ep = 1024;
        if (scan_range && strcmp(scan_range, "all") == 0) {
            sp = 1; ep = 65535;
        } else if (scan_range) {
            if (strchr(scan_range, '-')) {
                sscanf(scan_range, "%d-%d", &sp, &ep);
            } else {
                sp = ep = atoi(scan_range);
            }
        }
        int scan_timeout = timeout_sec > 0 ? timeout_sec * 1000 : 1500;
        int ret = portscan_run(scan_host, sp, ep, g_jitter, scan_timeout, banner_grab);
        return (ret >= 0) ? 0 : 1;
    }

    /* VPN option checks */
    if (g_opt.tun_cidr && listen_mode && strcmp(g_opt.tun_cidr, "auto") == 0) {
        fprintf(stderr, "ERROR: --tun auto is a client option; the server needs --tun <ip/prefix>\n");
        return 1;
    }
    if (g_opt.tun6_cidr && (!g_opt.tun_cidr || !listen_mode)) {
        fprintf(stderr, "ERROR: --tun6 is a server option (with --tun); clients get their "
                        "IPv6 address from the server\n");
        return 1;
    }
    if (g_opt.tun_cidr && listen_mode && keep_open && g_opt.tun_udp) {
        fprintf(stderr, "ERROR: --tun-udp is not available with -K yet (multi-client VPN "
                        "uses the TCP channel)\n");
        return 1;
    }

    /* Per-user login: option checks */
    if ((add_user || set_user || del_user) && !users_file) {
        fprintf(stderr, "ERROR: --add-user/--set-user/--del-user need --users <file>\n");
        return 1;
    }
    if (have_user_opts && !add_user && !set_user) {
        fprintf(stderr, "ERROR: --user-option goes with --add-user or --set-user\n");
        return 1;
    }
    if (have_user_opts && users_parse_options(user_opts, NULL) != 0) return 1;
    if ((set_user && !user_name_valid(set_user)) || (del_user && !user_name_valid(del_user))) {
        fprintf(stderr, "ERROR: user names are 1-%d characters from A-Z a-z 0-9 . _ -\n",
                USER_NAME_MAX);
        return 1;
    }
    if (set_user) {                   /* options only, the password stays */
        if (!have_user_opts) {
            fprintf(stderr, "ERROR: --set-user needs --user-option KEY=VALUE "
                            "(or --user-option none)\n");
            return 1;
        }
        if (users_set(users_file, set_user, NULL, user_opts) != 0) {
            fprintf(stderr, "ERROR: cannot update '%s' in %s: %s\n", set_user, users_file,
                    errno == ENOENT ? "no such user (create it with --add-user)" : strerror(errno));
            return 1;
        }
        printf("user '%s' updated in %s\n", set_user, users_file);
        return 0;
    }
    if (del_user) {
        int r = users_delete(users_file, del_user);
        if (r < 0) {
            fprintf(stderr, "ERROR: cannot update %s: %s\n", users_file, strerror(errno));
            return 1;
        }
        printf(r ? "user '%s' removed from %s\n" : "no user '%s' in %s\n", del_user, users_file);
        return r ? 0 : 1;
    }
    if (login_user && (listen_mode || users_file)) {
        fprintf(stderr, "ERROR: --user is a client option (the server uses --users <file>)\n");
        return 1;
    }
    if (users_file && !listen_mode && !add_user && !set_user && !del_user) {
        fprintf(stderr, "ERROR: --users is a server option (-l); clients use --user <name>\n");
        return 1;
    }
    if ((login_user || users_file) && g_udp_mode && !add_user) {
        fprintf(stderr, "ERROR: per-user login (--user/--users) is not available with -u\n");
        return 1;
    }
    if ((login_user && !user_name_valid(login_user)) || (add_user && !user_name_valid(add_user))) {
        fprintf(stderr, "ERROR: user names are 1-%d characters from A-Z a-z 0-9 . _ -\n",
                USER_NAME_MAX);
        return 1;
    }

    /* --add-user: store the user's password scalar and exit */
    if (add_user) {
        char pw1[SECRET_MAX + 1], pw2[SECRET_MAX + 1];
        int rc;
        if (password_from_argv) {
            snprintf(pw1, sizeof(pw1), "%s", s_password);
            rc = 0;
        } else if (key_file) {
            rc = secret_from_file(key_file, pw1, sizeof(pw1));
        } else if ((rc = secret_from_env(pw1, sizeof(pw1))) == 1) {
            rc = secret_prompt("New password: ", pw1, sizeof(pw1));
            if (rc == 0 && (secret_prompt("Repeat password: ", pw2, sizeof(pw2)) != 0 ||
                            strcmp(pw1, pw2) != 0)) {
                fprintf(stderr, "ERROR: passwords do not match\n");
                rc = -1;
            }
            secret_wipe(pw2, sizeof(pw2));
        }
        unsetenv(SECRET_ENV);
        if (rc != 0 || pw1[0] == '\0') {
            if (rc == 1) fprintf(stderr, "ERROR: no password given (terminal, --key-file or "
                                         SECRET_ENV ")\n");
            secret_wipe(pw1, sizeof(pw1));
            return 1;
        }
        if (strlen(pw1) < 12)
            fprintf(stderr, "Warning: short password; every login attempt is one online "
                            "guess, prefer 12+ random characters\n");
        unsigned char w[32];
        rc = user_password_to_w(add_user, pw1, strlen(pw1), w);
        secret_wipe(pw1, sizeof(pw1));
        if (rc == 0) rc = users_set(users_file, add_user, w, have_user_opts ? user_opts : NULL);
        secret_wipe(w, sizeof(w));
        if (rc != 0) {
            fprintf(stderr, "ERROR: cannot update %s: %s\n", users_file, strerror(errno));
            return 1;
        }
        printf("user '%s' saved in %s\n", add_user, users_file);
        return 0;
    }

    if (users_file) {
        if (users_check_file(users_file) != 0) return 1;
        g_opt.users_file = users_file;
        ecdhe_set_users_file(users_file);
        if (password_from_argv || key_file)
            fprintf(stderr, "Warning: --users replaces the shared password; -k/--key-file "
                            "are ignored\n");
        unsetenv(SECRET_ENV);
        password = "per-user";        /* placeholder: the handshake uses the users file */
        goto password_done;
    }
    if (login_user && ecdhe_set_user(login_user) != 0) return 1;

    /* Password: -k > --key-file > $CLAWSEC_PASSWORD > prompt on /dev/tty */
    if (password_from_argv) {
        fprintf(stderr, "Warning: -k exposes the password to other local users "
                        "(ps, /proc) and to shell history; prefer --key-file or "
                        "the " SECRET_ENV " environment variable\n");
    } else if (key_file) {
        if (secret_from_file(key_file, s_password, sizeof(s_password)) != 0)
            return 1;
        password = s_password;
    } else {
        int rc = secret_from_env(s_password, sizeof(s_password));
        if (rc < 0) return 1;
        if (rc == 1) {
            rc = secret_prompt("ClawSec password: ", s_password, sizeof(s_password));
            if (rc < 0) return 1;
        }
        if (rc == 0) password = s_password;
    }
    /* Never pass the password on to child processes (-e, --tun tools) */
    unsetenv(SECRET_ENV);

    if (!password || *password == '\0') {
        fprintf(stderr, "ERROR: Encryption password required: use --key-file <file>, "
                        "the " SECRET_ENV " environment variable, or -k <password>.\n");
        usage(argv[0]);
        return 1;
    }

    if (strlen(password) < 8)
        log_msg(1, "Warning: password should be at least 8 characters for security");

    /* Argon2id once per process (not per connection; children inherit it) */
    if (farm9crypt_prepare_password(password, strlen(password)) != 0) {
        fprintf(stderr, "ERROR: password key derivation failed\n");
        return 1;
    }
password_done:;

    /* Parse port forwarding target */
    char fwd_host[256] = {0};
    char fwd_port[32] = {0};
    if (fwd_spec) {
        if (net_parse_host_port(fwd_spec, fwd_host, sizeof(fwd_host),
                            fwd_port, sizeof(fwd_port)) < 0) {
            fprintf(stderr, "ERROR: Invalid forward target '%s' (use host:port)\n", fwd_spec);
            return 1;
        }
    }

    ignore_sigpipe();

    /* Validate mux mode */
    if (g_mux) {
        if (listen_mode && !fwd_spec) {
            fprintf(stderr, "ERROR: --mux in server mode requires -L host:port\n");
            return 1;
        }
        if (!listen_mode && !bind_port) {
            fprintf(stderr, "ERROR: --mux in client mode requires -p <local_port>\n");
            return 1;
        }
        if (!listen_mode) {
            /* Local forwarding port: loopback unless an address is given */
            if (net_parse_listen_spec(bind_port, net_loopback_host(),
                                      g_opt.mux_host, sizeof(g_opt.mux_host),
                                      g_opt.mux_lport, sizeof(g_opt.mux_lport)) < 0) {
                fprintf(stderr, "ERROR: Invalid --mux local port '%s' (use port or host:port)\n",
                        bind_port);
                return 1;
            }
            g_opt.mux_port = bind_port;
        }
    }

    /* Validate SOCKS5 mode */
    if (g_opt.socks && listen_mode) {
        /* Server side — no local port needed, will relay outbound */
    } else if (g_opt.socks) {
        /* The proxy is unauthenticated: loopback unless an address is given */
        if (!g_opt.socks_port ||
            net_parse_listen_spec(g_opt.socks_port, net_loopback_host(),
                                  g_opt.socks_host, sizeof(g_opt.socks_host),
                                  g_opt.socks_lport, sizeof(g_opt.socks_lport)) < 0) {
            fprintf(stderr, "ERROR: Invalid --socks '%s' (use port or host:port)\n",
                    g_opt.socks_port ? g_opt.socks_port : "");
            return 1;
        }
    }

    /* Validate reverse tunnel spec */
    if (g_opt.reverse_spec) {
        char h[256], pt[8];
        if (net_parse_host_port(g_opt.reverse_spec, h, sizeof(h), pt, sizeof(pt)) < 0) {
            fprintf(stderr, "ERROR: Invalid -R '%s' (use host:port)\n", g_opt.reverse_spec);
            return 1;
        }
    }

    if (g_udp_mode)
        farm9crypt_set_udp_mode(1);

    /* TOFU: server must initialize identity key before accepting clients */
    if (g_tofu && listen_mode) {
        if (tofu_server_init() < 0) {
            fprintf(stderr, "ERROR: Failed to initialize TOFU identity key\n");
            return 1;
        }
    }

    if (listen_mode) {
        if (!bind_port) {
            fprintf(stderr, "ERROR: -p <port> is required in listen mode.\n");
            return 1;
        }

        int listen_fd = net_listen(bind_port);
        log_msg(1, "listening on *:%s%s%s%s",
                bind_port,
                g_udp_mode ? " (UDP)" : "",
                keep_open ? " [keep-open]" : "",
                fwd_spec ? " [forwarding]" : "");

        if (keep_open && !g_udp_mode && g_opt.tun_cidr) {
            int rc = run_vpn_hub(listen_fd, password);
            close(listen_fd);
            return rc;
        }
        if (keep_open && !g_udp_mode) {
            /* Multi-client mode: fork per connection, at most g_opt.max_clients
             * at a time (each handshake costs ~19 MiB of Argon2id memory) */
            install_sigchld();
            iplimit_configure(g_opt.max_per_ip, g_opt.auth_fail_limit, AUTH_FAIL_WINDOW, AUTH_BLOCK_TIME);
            children_reports_init();
            int control_fd = g_opt.control_path ? control_listen(g_opt.control_path) : -1;
            if (g_opt.control_path && control_fd < 0) return 1;
            sigset_t chld, prev;
            sigemptyset(&chld);
            sigaddset(&chld, SIGCHLD);
            int was_full = 0;
            for (;;) {
                sigprocmask(SIG_BLOCK, &chld, &prev);
                reap_handler_exits();
                int room = g_active_children < g_opt.max_clients;
                sigprocmask(SIG_SETMASK, &prev, NULL);
                if (!room && !was_full)
                    log_msg(1, "max clients (%d) reached, waiting for a handler to finish",
                            g_opt.max_clients);
                was_full = !room;

                /* a full server stops accepting; SIGCHLD (EINTR) or the
                 * 1 s timeout re-checks */
                struct pollfd pfd[3] = {
                    { room ? listen_fd : -1, POLLIN, 0 },
                    { control_fd, POLLIN, 0 },
                    { children_reports_fd(), POLLIN, 0 },
                };
                if (poll(pfd, 3, room ? -1 : 1000) < 0 && errno != EINTR) {
                    perror("poll");
                    exit_status = 1;
                    break;
                }
                if (pfd[2].revents & POLLIN) children_reports_read();
                if (pfd[1].revents & POLLIN) control_serve(control_fd, children_status, NULL);
                if (!(pfd[0].revents & POLLIN)) continue;

                char ipkey[IPLIMIT_KEY_LEN];
                int have_key = 0;
                int client_fd = accept_admitted(listen_fd, ipkey, &have_key);
                if (client_fd < 0) continue;
                sigprocmask(SIG_BLOCK, &chld, &prev);
                pid_t pid = fork();
                if (pid > 0) {
                    g_active_children++;
                    if (have_key) iplimit_started(ipkey, pid, time(NULL));
                    children_track(pid, have_key ? ipkey : NULL);
                }
                sigprocmask(SIG_SETMASK, &prev, NULL);
                if (pid < 0) {
                    perror("fork");
                    close(client_fd);
                    continue;
                }
                if (pid == 0) {
                    /* Child: handle this client */
                    signal(SIGCHLD, SIG_DFL);   /* the parent's reaper is not ours */
                    close(listen_fd);
                    if (control_fd >= 0) close(control_fd);
                    int child_rc = handle_client(client_fd, password, 1, 1, exec_arg,
                                                 fwd_spec ? fwd_host : NULL,
                                                 fwd_spec ? fwd_port : NULL,
                                                 NULL, NULL);
                    if (child_rc == 0) _exit(CHILD_OK);
                    _exit(farm9crypt_last_failure() == FARM9_FAIL_AUTH ? CHILD_AUTH_FAILED
                                                                       : CHILD_ERROR);
                }
                /* Parent: continue accepting */
                close(client_fd);
                log_msg(1, "spawned handler pid=%d", (int)pid);
            }
        } else {
            /* Single-client mode */
            int sockfd;
            if (g_udp_mode) {
                sockfd = net_udp_accept(listen_fd);
            } else {
                sockfd = net_accept(listen_fd);
                close(listen_fd);
            }

            int send_first = g_udp_mode ? 0 : 1;
            exit_status = !!handle_client(sockfd, password, 1, send_first, exec_arg,
                                        fwd_spec ? fwd_host : NULL,
                                        fwd_spec ? fwd_port : NULL,
                                        NULL, NULL);
        }
    } else {
        /* Client mode */
        if (optind + 2 != argc) {
            usage(argv[0]);
            return 1;
        }

        const char *host = argv[optind];
        const char *port = argv[optind + 1];

        if (g_opt.persistent) {
            /* Auto-reconnect loop with exponential backoff */
            int attempt = 0;
            srand(time(NULL));
            log_msg(1, "persistent mode: will auto-reconnect on disconnect");
            for (;;) {
                int sockfd = net_try_connect(host, port, timeout_sec > 0 ? timeout_sec : 10);
                if (sockfd < 0) {
                    int delay = persist_next_delay(attempt++);
                    fprintf(stderr, "persistent: connection failed, retrying in %ds...\n", delay);
                    sleep(delay);
                    continue;
                }
                log_msg(1, "connected to %s:%s", host, port);
                attempt = 0; /* reset on successful connect */

                int send_first = g_udp_mode ? 1 : 0;
                int rc = handle_client(sockfd, password, 0, send_first, NULL,
                                       fwd_spec ? fwd_host : NULL,
                                       fwd_spec ? fwd_port : NULL,
                                       host, port);
                if (rc == HC_PERMANENT) {
                    fprintf(stderr, "persistent: giving up — %s; reconnecting cannot fix this\n",
                            farm9crypt_last_failure() == FARM9_FAIL_AUTH
                                ? "authentication failed (wrong password?)"
                                : farm9crypt_last_failure() == FARM9_FAIL_CONFIG
                                    ? "--tofu / --pq differ between client and server"
                                    : "the server speaks an incompatible protocol version");
                    return 1;
                }

                if (g_opt.tun_cidr && tun_stop_requested())
                    break;          /* Ctrl-C in VPN mode: stop, don't reconnect */
                int delay = persist_next_delay(attempt++);
                fprintf(stderr, "persistent: disconnected, reconnecting in %ds...\n", delay);
                sleep(delay);
            }
        } else {
            int sockfd = net_connect(host, port, timeout_sec);
            log_msg(1, "connected to %s:%s%s", host, port, g_udp_mode ? " (UDP)" : "");

            int send_first = g_udp_mode ? 1 : 0;
            exit_status = !!handle_client(sockfd, password, 0, send_first, NULL,
                                        fwd_spec ? fwd_host : NULL,
                                        fwd_spec ? fwd_port : NULL,
                                        host, port);
        }
    }

    return exit_status;
}
