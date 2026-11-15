/*
 * session.c — one ClawSec connection (see session.h)
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
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
#include "socks5.h"
#include "filetx.h"
#include "reverse.h"
#include "persistent.h"
#include "tun.h"
#include "ecdhe.h"
#include "options.h"
#include "session.h"
#include "vpnrun.h"
#include "users.h"
#include "acl.h"
#include "children.h"

/* Bound blocking socket I/O during session setup, so a client that connects
 * and stays silent cannot hold a handler (or the single-session server)
 * forever. 0 removes the bound. */
static void set_io_timeout(int fd, int seconds) {
    struct timeval tv = { .tv_sec = seconds, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static int setup_timed_out(int err) {
    return err == EAGAIN || err == EWOULDBLOCK || err == ETIMEDOUT;
}

/* Handle one client connection (used by keep-open and normal mode) */
/* Returns 0 on success, 1 if the session could not be set up or failed,
 * HC_PERMANENT if it failed for a reason a retry cannot fix (wrong password,
 * incompatible peer). main() maps every failure to exit status 1. */
static int handle_client_inner(int sockfd, const char *password, int is_server,
                          int send_first, const char *exec_prog,
                          const char *fwd_host, const char *fwd_port,
                          const char *peer_host, const char *peer_port) {
    /* Each encrypted frame is written with one send(): disable Nagle so small
     * frames (keystrokes, mux control frames) are not held back ~40 ms */
    {
        int one = 1, type = 0;
        socklen_t tl = sizeof(type);
        if (getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &type, &tl) == 0 && type == SOCK_STREAM)
            setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }

    /* Everything up to key confirmation must finish within the timeout */
    if (g_opt.handshake_timeout > 0)
        set_io_timeout(sockfd, g_opt.handshake_timeout);

    /* TLS camouflage: wrap socket in TLS before any crypto handshake */
    if (obfs_get_mode() == OBFS_TLS) {
        errno = 0;
        int tls_rc = is_server ? obfs_tls_accept(sockfd) : obfs_tls_connect(sockfd);
        if (tls_rc < 0) {
            if (setup_timed_out(errno))
                fprintf(stderr, "ERROR: handshake timed out after %d s\n", g_opt.handshake_timeout);
            fprintf(stderr, "ERROR: TLS camouflage handshake failed\n");
            close(sockfd);
            return 1;
        }
        log_msg(1, "TLS 1.3 camouflage established");
    }

    /* Fallback: knock protocol for active probing resistance */
    if (g_fallback && obfs_get_mode() == OBFS_TLS) {
        if (is_server) {
            int knock = fallback_check_knock(sockfd);
            if (knock == 0) {
                /* Not a ClawSec client — proxy to fallback site */
                log_msg(1, "fallback: non-ClawSec probe detected, proxying");
                set_io_timeout(sockfd, 0);   /* the proxy has its own idle timeout */
                fallback_proxy(sockfd, g_fallback_host, g_fallback_port,
                               NULL, 0);
                close(sockfd);
                return 0;
            } else if (knock < 0) {
                log_msg(1, "fallback: connection error during knock");
                close(sockfd);
                return 1;
            }
            log_msg(1, "knock verified — ClawSec client");
        } else {
            /* Client sends knock before the handshake */
            if (fallback_send_knock(sockfd) < 0) {
                fprintf(stderr, "ERROR: Failed to send knock\n");
                close(sockfd);
                return 1;
            }
        }
    }

    errno = 0;
    if (g_pq) {
        if (farm9crypt_init_ecdhe_pq(sockfd, password, strlen(password),
                                     send_first, peer_host, peer_port) != 0) {
            if (setup_timed_out(errno))
                fprintf(stderr, "ERROR: handshake timed out after %d s\n", g_opt.handshake_timeout);
            fprintf(stderr, "ERROR: post-quantum hybrid handshake failed\n");
            close(sockfd);
            return farm9crypt_last_failure() != FARM9_FAIL_NONE ? HC_PERMANENT : 1;
        }
        if (g_tofu)
            log_msg(1, "session established (SPAKE2 + ML-KEM-768 + Ed25519 TOFU)");
        else
            log_msg(1, "session established (SPAKE2 + ML-KEM-768)");
    } else if (g_tofu) {
        if (farm9crypt_init_ecdhe_tofu(sockfd, password, strlen(password),
                                       send_first, peer_host, peer_port) != 0) {
            if (setup_timed_out(errno))
                fprintf(stderr, "ERROR: handshake timed out after %d s\n", g_opt.handshake_timeout);
            fprintf(stderr, "ERROR: handshake failed (TOFU)\n");
            close(sockfd);
            return farm9crypt_last_failure() != FARM9_FAIL_NONE ? HC_PERMANENT : 1;
        }
        log_msg(1, "session established (SPAKE2 + Ed25519 TOFU)");
    } else {
        if (farm9crypt_init_ecdhe(sockfd, password, strlen(password), send_first) != 0) {
            if (setup_timed_out(errno))
                fprintf(stderr, "ERROR: handshake timed out after %d s\n", g_opt.handshake_timeout);
            fprintf(stderr, "ERROR: handshake failed\n");
            close(sockfd);
            return farm9crypt_last_failure() != FARM9_FAIL_NONE ? HC_PERMANENT : 1;
        }
        log_msg(1, "session established (SPAKE2 password-authenticated key exchange)");
    }
    if (is_server && ecdhe_peer_user()) {
        log_msg(0, "user '%s' logged in", ecdhe_peer_user());
        children_report_user(ecdhe_peer_user());         /* for --status */
        setenv("CLAWSEC_USER", ecdhe_peer_user(), 1);      /* for -e programs */
        /* per-user options (this process serves only this user) */
        user_entry_t ue;
        if (g_opt.users_file && users_lookup(g_opt.users_file, ecdhe_peer_user(), &ue) == 1) {
            if (ue.socks_allow[0] && acl_set_allow_list(ue.socks_allow) != 0) {
                fprintf(stderr, "ERROR: invalid socks-allow for user '%s'\n", ecdhe_peer_user());
                OPENSSL_cleanse(&ue, sizeof(ue));
                close(sockfd);
                farm9crypt_cleanup();
                return 1;
            }
            if (ue.has_ip) g_opt.session_user_ip = ue.ip;
            OPENSSL_cleanse(&ue, sizeof(ue));
        }
    }

    /* Session established: no artificial bound on the data phase */
    set_io_timeout(sockfd, 0);

    /* SOCKS5 proxy mode */
    if (g_opt.socks) {
        if (is_server) {
            socks5_server(sockfd);
        } else {
            socks5_client(sockfd, g_opt.socks_host, g_opt.socks_lport);
        }
        close(sockfd);
        farm9crypt_cleanup();
        return 0;
    }

    /* File transfer mode */
    if (g_opt.send_file) {
        int rc = filetx_send(sockfd, g_opt.send_file) == 0 ? 0 : 1;
        close(sockfd);
        farm9crypt_cleanup();
        return rc;
    }
    if (g_opt.recv_dir) {
        int rc = filetx_recv(sockfd, g_opt.recv_dir) == 0 ? 0 : 1;
        close(sockfd);
        farm9crypt_cleanup();
        return rc;
    }

    /* TUN VPN mode (--tun) */
    if (g_opt.tun_cidr) {
        int rc = run_vpn_session(sockfd, is_server, peer_host, peer_port);
        close(sockfd);
        farm9crypt_cleanup();
        return rc;
    }

    /* Reverse tunnel mode (-R) */
    if (g_opt.reverse_spec) {
        if (is_server) {
            /* Server: listen on reverse port, relay through tunnel */
            char rev_host[256], rev_port[32];
            if (net_parse_host_port(g_opt.reverse_spec, rev_host, sizeof(rev_host),
                                rev_port, sizeof(rev_port)) == 0) {
                reverse_server(sockfd, rev_host, rev_port);
            }
        } else {
            /* Client: wait for ROPEN, connect to local target, relay back */
            char rev_host[256], rev_port[32];
            if (net_parse_host_port(g_opt.reverse_spec, rev_host, sizeof(rev_host),
                                rev_port, sizeof(rev_port)) == 0) {
                reverse_client(sockfd, rev_host, rev_port);
            }
        }
        close(sockfd);
        farm9crypt_cleanup();
        return 0;
    }

    /* Mux mode: multiplex streams over single tunnel */
    if (g_mux) {
        if (is_server && fwd_host && fwd_port) {
            mux_relay_server(sockfd, fwd_host, fwd_port);
        } else if (!is_server && g_opt.mux_port) {
            mux_relay_client(sockfd, g_opt.mux_host, g_opt.mux_lport);
        }
        close(sockfd);
        farm9crypt_cleanup();
        return 0;
    }

    /* Port forwarding mode: connect to target and relay */
    if (fwd_host && fwd_port) {
        int target_fd = net_connect(fwd_host, fwd_port, 5);
        log_msg(1, "forwarding to %s:%s", fwd_host, fwd_port);
        relay_encrypted_plain(sockfd, target_fd);
        close(target_fd);
        close(sockfd);
        farm9crypt_cleanup();
        return 0;
    }

#ifdef GAPING_SECURITY_HOLE
    if (exec_prog) {
        run_encrypted_exec(sockfd, exec_prog);
        farm9crypt_cleanup();
        return 0;
    }
#else
    (void)exec_prog;
#endif

    relay_socket_stdio(sockfd, is_server, g_chat_mode);
    close(sockfd);
    farm9crypt_cleanup();
    return 0;
}

/* One session: run it, then release per-session TLS state (the socket is
 * already closed by handle_client_inner). */
int handle_client(int sockfd, const char *password, int is_server,
                         int send_first, const char *exec_prog,
                         const char *fwd_host, const char *fwd_port,
                         const char *peer_host, const char *peer_port) {
    int rc = handle_client_inner(sockfd, password, is_server, send_first, exec_prog,
                                 fwd_host, fwd_port, peer_host, peer_port);
    obfs_tls_cleanup();
    return rc;
}

