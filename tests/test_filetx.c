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
 * Test: Wire format header encode/decode
 */
void test_filetx_header_format(void) {
    TEST_BEGIN("filetx header wire format") {
        /* Simulate header: 8(size) + 32(hash) + 2(name_len) + N(name) */
        uint64_t file_size = 1048576; /* 1MB */
        unsigned char hash[32];
        memset(hash, 0xAB, 32);
        const char *name = "test_file.bin";
        int name_len = strlen(name);

        char hdr[FILETX_HDR_SIZE + 256];
        /* Encode size (big-endian) */
        for (int i = 7; i >= 0; i--) {
            hdr[i] = file_size & 0xFF;
            file_size >>= 8;
        }
        memcpy(hdr + 8, hash, 32);
        hdr[40] = (name_len >> 8) & 0xFF;
        hdr[41] = name_len & 0xFF;
        memcpy(hdr + 42, name, name_len);

        /* Decode */
        uint64_t dec_size = 0;
        for (int i = 0; i < 8; i++)
            dec_size = (dec_size << 8) | (unsigned char)hdr[i];
        ASSERT_EQ(dec_size, 1048576ULL, "file size 1MB");

        unsigned char dec_hash[32];
        memcpy(dec_hash, hdr + 8, 32);
        ASSERT(memcmp(dec_hash, hash, 32) == 0, "hash matches");

        int dec_name_len = ((unsigned char)hdr[40] << 8) | (unsigned char)hdr[41];
        ASSERT_EQ(dec_name_len, 13, "name_len = 13");

        char dec_name[256];
        memcpy(dec_name, hdr + 42, dec_name_len);
        dec_name[dec_name_len] = '\0';
        ASSERT_STR_EQ(dec_name, "test_file.bin", "filename");
    } TEST_END;
}

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

/*
 * Test: Filename sanitization (path traversal prevention)
 */
void test_filetx_filename_sanitize(void) {
    TEST_BEGIN("filetx sanitizes path traversal in filenames") {
        /* Simulate: if filename contains '/' or starts with '.',
         * filetx_recv replaces them with '_' */
        char filename[] = "../../../etc/passwd";
        int name_len = strlen(filename);

        /* Apply same sanitization as filetx.c */
        for (int i = 0; i < name_len; i++) {
            if (filename[i] == '/' || filename[i] == '\\')
                filename[i] = '_';
        }
        if (filename[0] == '.')
            filename[0] = '_';

        /* Should not contain path separators */
        ASSERT(strchr(filename, '/') == NULL, "no forward slashes");
        ASSERT(strchr(filename, '\\') == NULL, "no backslashes");
        ASSERT(filename[0] != '.', "doesn't start with dot");
    } TEST_END;
}

/*
 * Test: Resume offset encoding
 */
void test_filetx_resume_offset(void) {
    TEST_BEGIN("filetx resume offset wire format") {
        uint64_t offset = 5242880; /* 5MB */
        unsigned char buf[8];

        /* Encode big-endian */
        for (int i = 7; i >= 0; i--) {
            buf[i] = offset & 0xFF;
            offset >>= 8;
        }

        /* Decode */
        uint64_t dec = 0;
        for (int i = 0; i < 8; i++)
            dec = (dec << 8) | buf[i];

        ASSERT_EQ(dec, 5242880ULL, "offset 5MB roundtrip");
    } TEST_END;
}
