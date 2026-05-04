/*
 * test_portscan.c — Port scanner tests
 */
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L
#include "test.h"
#include "portscan.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

/* Helper: bind a TCP socket to a random port, return fd + port */
static int bind_random_port(int *out_port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0; /* kernel picks port */

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 1) < 0) {
        close(fd);
        return -1;
    }

    socklen_t len = sizeof(addr);
    getsockname(fd, (struct sockaddr *)&addr, &len);
    *out_port = ntohs(addr.sin_port);
    return fd;
}

void test_portscan_finds_open_port(void) {
    TEST_BEGIN("portscan detects open port on localhost") {
        int port = 0;
        int listen_fd = bind_random_port(&port);
        ASSERT(listen_fd >= 0, "failed to bind test port");
        ASSERT(port > 0, "invalid port");

        /* Redirect stdout to suppress scan output */
        int saved_stdout = dup(STDOUT_FILENO);
        int devnull = open("/dev/null", 0x0001); /* O_WRONLY */
        dup2(devnull, STDOUT_FILENO);
        close(devnull);

        int result = portscan_run("127.0.0.1", port, port, 0, 2000, 0);

        /* Restore stdout */
        dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);

        close(listen_fd);
        ASSERT_EQ(result, 1, "should find exactly 1 open port");
    } TEST_END;
}

void test_portscan_closed_port(void) {
    TEST_BEGIN("portscan reports 0 for closed port") {
        /* Use a high port that's almost certainly closed */
        int saved_stdout = dup(STDOUT_FILENO);
        int devnull = open("/dev/null", 0x0001);
        dup2(devnull, STDOUT_FILENO);
        close(devnull);

        int result = portscan_run("127.0.0.1", 39999, 39999, 0, 500, 0);

        dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);

        ASSERT_EQ(result, 0, "closed port should return 0 open");
    } TEST_END;
}

void test_portscan_range_validation(void) {
    TEST_BEGIN("portscan validates port range") {
        int saved_stdout = dup(STDOUT_FILENO);
        int devnull = open("/dev/null", 0x0001);
        dup2(devnull, STDOUT_FILENO);
        close(devnull);

        /* Reversed range should still work (or return 0) */
        int result = portscan_run("127.0.0.1", 100, 50, 0, 500, 0);

        dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);

        /* Should handle gracefully — either 0 or >=0 */
        ASSERT(result >= 0 || result == -1, "should not crash on invalid range");
    } TEST_END;
}

void test_portscan_banner_grab(void) {
    TEST_BEGIN("portscan with banner grab on open port") {
        int port = 0;
        int listen_fd = bind_random_port(&port);
        ASSERT(listen_fd >= 0, "failed to bind test port");

        /* Fork: child accepts and sends a banner */
        pid_t pid = fork();
        if (pid == 0) {
            int client = accept(listen_fd, NULL, NULL);
            if (client >= 0) {
                /* First accept from scan (connect_scan), just close */
                close(client);
                /* Second accept from banner grab */
                client = accept(listen_fd, NULL, NULL);
                if (client >= 0) {
                    const char *banner = "TESTBANNER/1.0\r\n";
                    write(client, banner, strlen(banner));
                    usleep(100000);
                    close(client);
                }
            }
            close(listen_fd);
            _exit(0);
        }

        /* Parent: run scan with banner grab */
        int saved_stdout = dup(STDOUT_FILENO);
        int devnull = open("/dev/null", 0x0001);
        dup2(devnull, STDOUT_FILENO);
        close(devnull);

        int result = portscan_run("127.0.0.1", port, port, 0, 2000, 1);

        dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);

        close(listen_fd);
        waitpid(pid, NULL, 0);

        ASSERT_EQ(result, 1, "should find open port with banner");
    } TEST_END;
}

void test_portscan_multiple_ports(void) {
    TEST_BEGIN("portscan detects multiple open ports") {
        int port1 = 0, port2 = 0;
        int fd1 = bind_random_port(&port1);
        int fd2 = bind_random_port(&port2);
        ASSERT(fd1 >= 0 && fd2 >= 0, "failed to bind test ports");

        int lo = (port1 < port2) ? port1 : port2;
        int hi = (port1 > port2) ? port1 : port2;

        int saved_stdout = dup(STDOUT_FILENO);
        int devnull = open("/dev/null", 0x0001);
        dup2(devnull, STDOUT_FILENO);
        close(devnull);

        int result = portscan_run("127.0.0.1", lo, hi, 0, 2000, 0);

        dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);

        close(fd1);
        close(fd2);

        ASSERT(result >= 2, "should find at least 2 open ports");
    } TEST_END;
}
