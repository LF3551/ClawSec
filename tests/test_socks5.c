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
            socks5_client(fds[0], "127.0.0.1", port_str);
            close(fds[0]);
            _exit(0);
        }
        close(fds[0]);

        test_sleep_ms(200); /* wait for bind+listen */

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
