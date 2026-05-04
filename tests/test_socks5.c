/*
 * test_socks5.c — SOCKS5 proxy protocol tests
 *
 * Unit tests for the SOCKS5 tunnel wire format and protocol.
 * Integration tests (actual tunnel) are done manually.
 */
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L
#include "test.h"
#include "socks5.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

/*
 * Test: SOCKS5 tunnel wire format encoding/decoding
 * Format: [1: host_len][N: host][2: port_be]
 */
void test_socks5_wire_format(void) {
    TEST_BEGIN("socks5 tunnel wire format encode/decode") {
        const char *host = "example.com";
        int host_len = strlen(host);
        uint16_t port = 443;

        /* Encode */
        unsigned char req[256];
        req[0] = (unsigned char)host_len;
        memcpy(req + 1, host, host_len);
        req[1 + host_len] = (port >> 8) & 0xFF;
        req[2 + host_len] = port & 0xFF;

        int total = 3 + host_len;
        ASSERT_EQ(total, 14, "total size for example.com:443");

        /* Decode */
        int dec_hlen = req[0];
        ASSERT_EQ(dec_hlen, 11, "host_len");

        char dec_host[256];
        memcpy(dec_host, req + 1, dec_hlen);
        dec_host[dec_hlen] = '\0';
        ASSERT_STR_EQ(dec_host, "example.com", "host");

        uint16_t dec_port = (req[1 + dec_hlen] << 8) | req[2 + dec_hlen];
        ASSERT_EQ(dec_port, 443, "port");
    } TEST_END;
}

/*
 * Test: Wire format with IPv4 address string
 */
void test_socks5_wire_format_ipv4(void) {
    TEST_BEGIN("socks5 wire format with IPv4 address") {
        const char *host = "192.168.1.1";
        int host_len = strlen(host);
        uint16_t port = 8080;

        unsigned char req[256];
        req[0] = (unsigned char)host_len;
        memcpy(req + 1, host, host_len);
        req[1 + host_len] = (port >> 8) & 0xFF;
        req[2 + host_len] = port & 0xFF;

        /* Decode back */
        int dec_hlen = req[0];
        char dec_host[256];
        memcpy(dec_host, req + 1, dec_hlen);
        dec_host[dec_hlen] = '\0';
        ASSERT_STR_EQ(dec_host, "192.168.1.1", "ipv4 host");

        uint16_t dec_port = (req[1 + dec_hlen] << 8) | req[2 + dec_hlen];
        ASSERT_EQ(dec_port, 8080, "port 8080");
    } TEST_END;
}

/*
 * Test: Wire format with max-length hostname (255 bytes)
 */
void test_socks5_wire_format_long_host(void) {
    TEST_BEGIN("socks5 wire format with long hostname") {
        char host[256];
        memset(host, 'a', 255);
        host[255] = '\0';
        int host_len = 255;
        uint16_t port = 65535;

        unsigned char req[260];
        req[0] = (unsigned char)host_len;
        memcpy(req + 1, host, host_len);
        req[1 + host_len] = (port >> 8) & 0xFF;
        req[2 + host_len] = port & 0xFF;

        int dec_hlen = req[0];
        ASSERT_EQ(dec_hlen, 255, "max host_len");

        uint16_t dec_port = (req[1 + dec_hlen] << 8) | req[2 + dec_hlen];
        ASSERT_EQ(dec_port, 65535, "max port");
    } TEST_END;
}

/*
 * Test: SOCKS5 server exits cleanly when tunnel fd closes
 */
void test_socks5_server_clean_exit(void) {
    TEST_BEGIN("socks5 server exits cleanly on tunnel close") {
        int fds[2];
        ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair");

        pid_t pid = fork();
        if (pid == 0) {
            close(fds[1]);
            /* socks5_server uses farm9crypt_read which on raw socket
             * will just return -1 or 0 when fd closes */
            socks5_server(fds[0]);
            close(fds[0]);
            _exit(0);
        }

        close(fds[0]);
        /* Close tunnel immediately — server should detect and exit */
        close(fds[1]);

        int status;
        alarm(3); /* timeout safety */
        waitpid(pid, &status, 0);
        alarm(0);
        ASSERT(WIFEXITED(status), "should exit normally");
        ASSERT_EQ(WEXITSTATUS(status), 0, "exit code 0");
    } TEST_END;
}

/*
 * Test: SOCKS5 client listener binds and accepts
 */
void test_socks5_client_binds(void) {
    TEST_BEGIN("socks5 client binds to local port") {
        int fds[2];
        ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair");

        /* Find free port */
        int tmp = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        bind(tmp, (struct sockaddr *)&addr, sizeof(addr));
        socklen_t alen = sizeof(addr);
        getsockname(tmp, (struct sockaddr *)&addr, &alen);
        int port = ntohs(addr.sin_port);
        close(tmp);

        char port_str[8];
        snprintf(port_str, sizeof(port_str), "%d", port);

        /* Fork: child runs socks5_client (will block on accept) */
        pid_t pid = fork();
        if (pid == 0) {
            close(fds[1]);
            socks5_client(fds[0], port_str);
            close(fds[0]);
            _exit(0);
        }
        close(fds[0]);

        usleep(200000); /* wait for bind+listen */

        /* Verify we can connect to the SOCKS5 port */
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        addr.sin_port = htons(port);
        int rc = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
        ASSERT(rc == 0, "should connect to socks5 listener");

        /* Send SOCKS5 greeting to unblock the child's handle_socks_client */
        unsigned char hello[] = {0x05, 0x01, 0x00};
        write(sock, hello, 3);

        unsigned char resp[2] = {0};
        int n = read(sock, resp, 2);
        ASSERT_EQ(n, 2, "should get auth response");
        ASSERT_EQ(resp[0], 0x05, "SOCKS version");
        ASSERT_EQ(resp[1], 0x00, "no-auth method");

        close(sock);
        /* Close tunnel fd to make child's handle_socks_client fail and exit accept loop */
        close(fds[1]);
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
    } TEST_END;
}
