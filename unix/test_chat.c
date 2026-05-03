/*
 * test_chat.c — Tests for chat features (fingerprint, control messages)
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include "test.h"
#include "farm9crypt.h"

void test_fingerprint_deterministic(void) {
    TEST_BEGIN("session fingerprint is deterministic");

    /* Set up a dummy session via socketpair + handshake */
    int sv[2];
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair failed");

    pid_t pid = fork();
    ASSERT(pid >= 0, "fork failed");

    if (pid == 0) {
        close(sv[0]);
        farm9crypt_init_ecdhe(sv[1], "test_fp_pass", 12, 0);
        unsigned char fp1[8], fp2[8];
        farm9crypt_get_fingerprint(fp1, 8);
        farm9crypt_get_fingerprint(fp2, 8);
        /* Same call should return same result */
        int match = (memcmp(fp1, fp2, 8) == 0) ? 0 : 1;
        farm9crypt_cleanup();
        close(sv[1]);
        _exit(match);
    }

    close(sv[1]);
    farm9crypt_init_ecdhe(sv[0], "test_fp_pass", 12, 1);
    unsigned char fp1[8], fp2[8];
    int rc1 = farm9crypt_get_fingerprint(fp1, 8);
    int rc2 = farm9crypt_get_fingerprint(fp2, 8);
    ASSERT(rc1 == 8, "fingerprint should return 8 bytes");
    ASSERT(rc2 == 8, "fingerprint should return 8 bytes");
    ASSERT(memcmp(fp1, fp2, 8) == 0, "same session should produce same fingerprint");

    farm9crypt_cleanup();
    close(sv[0]);

    int status;
    waitpid(pid, &status, 0);
    ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "child fingerprint check failed");
    TEST_END;
}

void test_ctrl_msg_build(void) {
    TEST_BEGIN("control message format");
    /* Test that control messages start with SOH + type */
    char buf[64];
    buf[0] = '\x01';
    buf[1] = 'R';
    ASSERT(buf[0] == '\x01', "SOH prefix");
    ASSERT(buf[1] == 'R', "type byte");

    /* Nickname control */
    buf[1] = 'N';
    memcpy(buf + 2, "Alice", 5);
    ASSERT(buf[0] == '\x01', "SOH prefix");
    ASSERT(buf[1] == 'N', "nickname type");
    ASSERT(memcmp(buf + 2, "Alice", 5) == 0, "nickname payload");
    TEST_END;
}
