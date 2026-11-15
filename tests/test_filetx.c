/*
 * test_filetx.c — File transfer protocol tests
 */
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L
#include "test.h"
#include "filetx.h"
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <signal.h>

/*
 * Test: filetx_send fails gracefully on non-existent file
 */
void test_filetx_send_no_file(void) {
    TEST_BEGIN("filetx_send rejects non-existent file") {
        int fds[2];
        ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair");

        /* Redirect stderr to suppress error message */
        int saved = dup(STDERR_FILENO);
        int devnull = open("/dev/null", O_WRONLY);
        dup2(devnull, STDERR_FILENO);
        close(devnull);

        int rc = filetx_send(fds[0], "/tmp/nonexistent_file_xyzzy_12345");

        dup2(saved, STDERR_FILENO);
        close(saved);

        ASSERT_EQ(rc, -1, "should fail on non-existent file");
        close(fds[0]);
        close(fds[1]);
    } TEST_END;
}

/*
 * Test: filetx_recv rejects short/invalid header
 */
void test_filetx_recv_bad_header(void) {
    TEST_BEGIN("filetx_recv rejects invalid header") {
        int fds[2];
        ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair");

        pid_t pid = fork();
        if (pid == 0) {
            close(fds[1]);
            int saved = dup(STDERR_FILENO);
            int devnull = open("/dev/null", O_WRONLY);
            dup2(devnull, STDERR_FILENO);
            close(devnull);

            int rc = filetx_recv(fds[0], "/tmp");

            dup2(saved, STDERR_FILENO);
            close(saved);
            close(fds[0]);
            _exit(rc == -1 ? 0 : 1);
        }

        close(fds[0]);
        /* Send garbage — too short for valid header */
        close(fds[1]); /* close immediately */

        int status;
        waitpid(pid, &status, 0);
        ASSERT(WIFEXITED(status), "child exited");
        ASSERT_EQ(WEXITSTATUS(status), 0, "recv should fail on bad header");
    } TEST_END;
}


/* Send src_path from a child (server role) and receive into dir in the
 * parent (client role) over a real encrypted channel. Returns recv's rc. */
static int transfer(const char *src_path, const char *dir) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return -2;
    pid_t pid = fork();
    if (pid < 0) return -2;
    if (pid == 0) {
        close(fds[1]);
        int devnull = open("/dev/null", O_WRONLY);
        dup2(devnull, STDERR_FILENO);
        if (farm9crypt_init_password("filetx-test-pass", 16, FARM9_ROLE_SERVER) != 0) _exit(2);
        int rc = filetx_send(fds[0], src_path);
        farm9crypt_cleanup();
        _exit(rc == 0 ? 0 : 1);
    }
    close(fds[0]);
    int saved = dup(STDERR_FILENO), devnull = open("/dev/null", O_WRONLY);
    dup2(devnull, STDERR_FILENO); close(devnull);
    int rc = farm9crypt_init_password("filetx-test-pass", 16, FARM9_ROLE_CLIENT) == 0
             ? filetx_recv(fds[1], dir) : -2;
    dup2(saved, STDERR_FILENO); close(saved);
    farm9crypt_cleanup();
    close(fds[1]);
    int status;
    waitpid(pid, &status, 0);
    return rc;
}

static int files_equal(const char *a, const char *b) {
    FILE *fa = fopen(a, "rb"), *fb = fopen(b, "rb");
    int eq = fa && fb;
    while (eq) {
        int ca = fgetc(fa), cb = fgetc(fb);
        if (ca != cb) eq = 0;
        if (ca == EOF || cb == EOF) break;
    }
    if (fa) fclose(fa);
    if (fb) fclose(fb);
    return eq;
}

void test_filetx_roundtrip_real(void) {
    TEST_BEGIN("filetx_send/filetx_recv transfer a file (real code)") {
        char dir[] = "/tmp/clawsec-ftxXXXXXX";
        ASSERT(mkdtemp(dir) != NULL, "mkdtemp");
        char src[512], dst[512], part[600];
        snprintf(src, sizeof(src), "%s/source.bin", dir);
        snprintf(dst, sizeof(dst), "%s/out/source.bin", dir);
        snprintf(part, sizeof(part), "%s%s", dst, FILETX_PART_SUFFIX);
        char outdir[256];
        snprintf(outdir, sizeof(outdir), "%s/out", dir);
        ASSERT(mkdir(outdir, 0700) == 0, "mkdir");
        FILE *f = fopen(src, "wb");
        ASSERT(f != NULL, "create source");
        for (int i = 0; i < 50000; i++) fputc((i * 131) & 0xFF, f);
        fclose(f);

        int rc = transfer(src, outdir);
        int eq = files_equal(src, dst);
        int part_left = access(part, F_OK) == 0;
        unlink(dst); unlink(src); rmdir(outdir); rmdir(dir);
        ASSERT_EQ(rc, 0, "receive failed");
        ASSERT(eq, "received file differs");
        ASSERT(!part_left, ".clawsec-part must be renamed away");
    } TEST_END;
}

void test_filetx_resume_real(void) {
    TEST_BEGIN("filetx_recv resumes from its own .clawsec-part") {
        char dir[] = "/tmp/clawsec-ftxXXXXXX";
        ASSERT(mkdtemp(dir) != NULL, "mkdtemp");
        char src[512], dst[512], part[600];
        snprintf(src, sizeof(src), "%s/data.bin", dir);
        char outdir[256];
        snprintf(outdir, sizeof(outdir), "%s/out", dir);
        ASSERT(mkdir(outdir, 0700) == 0, "mkdir");
        snprintf(dst, sizeof(dst), "%s/data.bin", outdir);
        snprintf(part, sizeof(part), "%s%s", dst, FILETX_PART_SUFFIX);
        FILE *f = fopen(src, "wb"), *pf = fopen(part, "wb");
        ASSERT(f && pf, "create files");
        for (int i = 0; i < 30000; i++) {
            int c = (i * 7 + 3) & 0xFF;
            fputc(c, f);
            if (i < 12345) fputc(c, pf);          /* correct 12345-byte prefix */
        }
        fclose(f); fclose(pf);

        int rc = transfer(src, outdir);
        int eq = files_equal(src, dst);
        unlink(dst); unlink(part); unlink(src); rmdir(outdir); rmdir(dir);
        ASSERT_EQ(rc, 0, "resume failed");
        ASSERT(eq, "resumed file differs");
    } TEST_END;
}
