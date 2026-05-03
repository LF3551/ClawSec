#define _POSIX_C_SOURCE 200809L
#include <sys/ioctl.h>
#include <termios.h>

#if defined(__linux__)
#include <pty.h>
#elif defined(__APPLE__)
#include <util.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/wait.h>

#include "exec.h"
#include "util.h"
#include "farm9crypt.h"

#ifdef GAPING_SECURITY_HOLE

#define BUFSIZE 8192

void run_encrypted_exec(int sockfd, const char *prog) {
    int master_fd, slave_fd;
    pid_t pid;

    if (openpty(&master_fd, &slave_fd, NULL, NULL, NULL) < 0)
        fatal("openpty failed");

    pid = fork();
    if (pid < 0) fatal("fork failed");

    if (pid == 0) {
        char *argv0;
        const char *slash = strrchr(prog, '/');
        if (slash) argv0 = (char *)(slash + 1);
        else argv0 = (char *)prog;

        close(master_fd);

        if (setsid() < 0) _exit(127);
#ifdef TIOCSCTTY
        if (ioctl(slave_fd, TIOCSCTTY, NULL) < 0) _exit(127);
#endif

        dup2(slave_fd, STDIN_FILENO);
        dup2(slave_fd, STDOUT_FILENO);
        dup2(slave_fd, STDERR_FILENO);
        if (slave_fd > STDERR_FILENO) close(slave_fd);

        execl(prog, argv0, (char *)NULL);
        _exit(127);
    }

    close(slave_fd);

    char buf[BUFSIZE];

    for (;;) {
        fd_set rfds;
        int nfds = sockfd;
        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);
        FD_SET(master_fd, &rfds);
        if (master_fd > nfds) nfds = master_fd;

        int ret = select(nfds + 1, &rfds, NULL, NULL, NULL);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (FD_ISSET(sockfd, &rfds)) {
            ssize_t n = farm9crypt_read(sockfd, buf, sizeof(buf));
            if (n <= 0) break;
            if (write_all(master_fd, buf, (size_t)n) < 0) break;
        }

        if (FD_ISSET(master_fd, &rfds)) {
            ssize_t n = read(master_fd, buf, sizeof(buf));
            if (n <= 0) break;
            ssize_t wn = farm9crypt_write(sockfd, buf, (size_t)n);
            if (wn != n) break;
        }
    }

    close(master_fd);
    close(sockfd);

    int status;
    (void)waitpid(pid, &status, 0);
}

#endif /* GAPING_SECURITY_HOLE */
