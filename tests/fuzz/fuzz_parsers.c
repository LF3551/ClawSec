/*
 * fuzz_parsers.c — libFuzzer harness for every parser of untrusted text or
 * structures, with property checks (not only "does not crash").
 * The first byte selects the parser.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>

#include "net.h"
#include "acl.h"
#include "tun.h"
#include "mux.h"
#include "obfs.h"
#include "filetx.h"
#include "persistent.h"
#include "fuzz_common.h"

static int valid_port_string(const char *p) {
    long v = 0;
    if (!*p) return 0;
    for (; *p; p++) {
        if (*p < '0' || *p > '9') return 0;
        v = v * 10 + (*p - '0');
        if (v > 65535) return 0;
    }
    return v >= 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len) {
    if (len < 1 || len > 4096) return 0;
    int which = data[0] % 12;
    data++; len--;

    char *str = malloc(len + 1);
    if (!str) return 0;
    memcpy(str, data, len);
    str[len] = '\0';

    switch (which) {
    case 0: {
        char host[256], port[8];
        if (net_parse_host_port(str, host, sizeof(host), port, sizeof(port)) == 0 &&
            (!valid_port_string(port) || strlen(host) >= sizeof(host)))
            abort();
        break;
    }
    case 1: {
        char host[256], port[8];
        if (net_parse_listen_spec(str, "127.0.0.1", host, sizeof(host), port, sizeof(port)) == 0 &&
            !valid_port_string(port))
            abort();
        break;
    }
    case 2: {
        /* acl_set_allow_list reports syntax errors on stderr: silence it for
         * this call only (libFuzzer reports crashes on stderr) */
        fflush(stderr);
        int saved = dup(STDERR_FILENO), devnull = open("/dev/null", O_WRONLY);
        dup2(devnull, STDERR_FILENO);
        close(devnull);
        int rc = acl_set_allow_list(str);
        fflush(stderr);
        dup2(saved, STDERR_FILENO);
        close(saved);
        if (rc == 0) {
            struct sockaddr_in a;
            memset(&a, 0, sizeof(a));
            a.sin_family = AF_INET;
            a.sin_addr.s_addr = htonl(0x7F000001);
            (void)acl_allowed((struct sockaddr *)&a, sizeof(a));
        }
        acl_reset();
        break;
    }
    case 3: {
        char ip[64];
        int prefix = 0;
        if (tun_parse_cidr(str, ip, sizeof(ip), &prefix) == 0) {
            struct in_addr a;
            if (inet_pton(AF_INET, ip, &a) != 1 || prefix < 8 || prefix > 30) abort();
            for (const char *c = str; *c; c++)       /* only digits, dots, one slash */
                if (!((*c >= '0' && *c <= '9') || *c == '.' || *c == '/')) abort();
        }
        break;
    }
    case 4: {
        char name[256];
        snprintf(name, sizeof(name), "%s", str);
        filetx_sanitize_name(name);
        if (name[0] == '\0' || name[0] == '.' || strchr(name, '/') || strchr(name, '\\'))
            abort();
        for (const char *c = name; *c; c++)
            if ((unsigned char)*c < 0x20 || *c == 0x7f) abort();
        break;
    }
    case 5: {
        if (len >= MUX_HDR_SIZE) {
            mux_header_t h;
            if (mux_decode_header(data, &h) == 0 && h.length > MUX_MAX_PAYLOAD) abort();
        }
        break;
    }
    case 6: {
        static const unsigned char key[32] = { 1, 2, 3 };
        unsigned char pt[TUN_MTU + 64];
        int pt_len = 0;
        uint32_t seq = 0;
        if (tun_udp_decrypt(key, data, (int)len, pt, &pt_len, &seq) == 0 &&
            (pt_len < 0 || pt_len > TUN_MTU))
            abort();
        break;
    }
    case 7: {
        unsigned char out[OBFS_PAD_SIZE];
        int n = obfs_unpad(data, len, out, sizeof(out));
        if (n > (int)sizeof(out)) abort();
        break;
    }
    case 8:
        (void)persist_heartbeat_check(str, (int)len);
        break;
    case 9: {                                   /* mux v2 OPEN from the tunnel */
        unsigned char fl;
        char host[256];
        uint16_t port;
        int has;
        if (mux_decode_open(data, len, &fl, host, sizeof(host), &port, &has) == 0 && has &&
            strlen(host) >= sizeof(host)) abort();
        break;
    }
    case 10:                                    /* SOCKS5 greeting from a local app */
        if (mux_socks_parse_greeting(data, len) > (int)len) abort();
        break;
    case 11: {                                  /* SOCKS5 request from a local app */
        char host[256];
        uint16_t port;
        unsigned char code;
        int n = mux_socks_parse_request(data, len, host, sizeof(host), &port, &code);
        if (n > (int)len || (n > 0 && strlen(host) >= sizeof(host))) abort();
        break;
    }
    }
    free(str);
    return 0;
}
