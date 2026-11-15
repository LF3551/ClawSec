/*
 * test_hardening.c — password sources, SOCKS destination policy,
 * received-file name sanitising
 */
#define _POSIX_C_SOURCE 200809L
#include "test.h"
#include "secret.h"
#include "acl.h"
#include "filetx.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ── secret ── */

void test_secret_from_arg_scrubs_argv(void) {
    TEST_BEGIN("-k password is copied and argv overwritten") {
        char arg[] = "S3cret-pass";
        char out[SECRET_MAX + 1];
        ASSERT_EQ(secret_from_arg(arg, out, sizeof(out)), 0, "copy");
        ASSERT_STR_EQ(out, "S3cret-pass", "value");
        ASSERT(strchr(arg, 'S') == NULL && strlen(arg) == 11, "argv not overwritten");
    } TEST_END;
}

void test_secret_from_file(void) {
    TEST_BEGIN("--key-file reads the first line, strips CRLF") {
        char path[] = "/tmp/clawsec-keyXXXXXX";
        int fd = mkstemp(path);
        ASSERT(fd >= 0, "mkstemp");
        const char *content = "file-password\r\nsecond line\n";
        ASSERT(write(fd, content, strlen(content)) == (ssize_t)strlen(content), "write");
        close(fd);
        char out[SECRET_MAX + 1];
        int rc = secret_from_file(path, out, sizeof(out));
        unlink(path);
        ASSERT_EQ(rc, 0, "read");
        ASSERT_STR_EQ(out, "file-password", "first line only, no CR/LF");
    } TEST_END;
}

void test_secret_from_file_rejects_empty(void) {
    TEST_BEGIN("--key-file rejects empty / missing files") {
        char path[] = "/tmp/clawsec-keyXXXXXX";
        int fd = mkstemp(path);
        ASSERT(fd >= 0, "mkstemp");
        ASSERT(write(fd, "\n", 1) == 1, "write");
        close(fd);
        char out[SECRET_MAX + 1];
        int saved = dup(STDERR_FILENO), devnull = open("/dev/null", O_WRONLY);
        dup2(devnull, STDERR_FILENO); close(devnull);
        int rc1 = secret_from_file(path, out, sizeof(out));
        int rc2 = secret_from_file("/nonexistent/clawsec-key", out, sizeof(out));
        dup2(saved, STDERR_FILENO); close(saved);
        unlink(path);
        ASSERT_EQ(rc1, -1, "empty line");
        ASSERT_EQ(rc2, -1, "missing file");
    } TEST_END;
}

void test_secret_from_env_unsets(void) {
    TEST_BEGIN("CLAWSEC_PASSWORD is read and removed from the environment") {
        char out[SECRET_MAX + 1];
        unsetenv(SECRET_ENV);
        ASSERT_EQ(secret_from_env(out, sizeof(out)), 1, "unset -> 1");
        setenv(SECRET_ENV, "env-password", 1);
        ASSERT_EQ(secret_from_env(out, sizeof(out)), 0, "read");
        ASSERT_STR_EQ(out, "env-password", "value");
        ASSERT(getenv(SECRET_ENV) == NULL, "must be unset so children do not inherit it");
    } TEST_END;
}

/* ── acl ── */

static int allowed(const char *ip) {
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    if (strchr(ip, ':')) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ss;
        s6->sin6_family = AF_INET6;
        inet_pton(AF_INET6, ip, &s6->sin6_addr);
        return acl_allowed((struct sockaddr *)s6, sizeof(*s6));
    }
    struct sockaddr_in *s4 = (struct sockaddr_in *)&ss;
    s4->sin_family = AF_INET;
    inet_pton(AF_INET, ip, &s4->sin_addr);
    return acl_allowed((struct sockaddr *)s4, sizeof(*s4));
}

void test_acl_default_policy(void) {
    TEST_BEGIN("SOCKS default policy: no loopback/link-local/metadata") {
        acl_reset();
        const char *deny[] = { "127.0.0.1", "127.8.9.10", "0.0.0.0", "169.254.169.254",
                               "100.100.100.200", "168.63.129.16", "224.0.0.1",
                               "255.255.255.255", "::1", "::", "fe80::1", "ff02::1",
                               "fd00:ec2::254", "::ffff:127.0.0.1", "64:ff9b::7f00:1",
                               "::ffff:169.254.169.254", NULL };
        const char *allow[] = { "8.8.8.8", "10.1.2.3", "192.168.1.10", "172.16.5.5",
                                "2001:4860:4860::8888", "fd12:3456::1", "::ffff:8.8.8.8", NULL };
        for (int i = 0; deny[i]; i++)  ASSERT(!allowed(deny[i]), deny[i]);
        for (int i = 0; allow[i]; i++) ASSERT(allowed(allow[i]), allow[i]);
    } TEST_END;
}

void test_acl_allow_list(void) {
    TEST_BEGIN("--socks-allow replaces the default policy") {
        ASSERT_EQ(acl_set_allow_list("10.0.0.0/8, 127.0.0.1/32,2001:db8::/32"), 0, "parse");
        ASSERT(allowed("10.200.0.1"), "10/8");
        ASSERT(allowed("127.0.0.1"), "explicitly allowed loopback");
        ASSERT(!allowed("127.0.0.2"), "/32 only");
        ASSERT(allowed("2001:db8:1::5"), "v6 prefix");
        ASSERT(!allowed("8.8.8.8"), "not in list");
        ASSERT(!allowed("192.168.1.1"), "not in list");
        acl_reset();
        ASSERT(allowed("8.8.8.8") && !allowed("127.0.0.1"), "reset to default");
    } TEST_END;
}

void test_acl_rejects_bad_lists(void) {
    TEST_BEGIN("--socks-allow rejects malformed entries") {
        int saved = dup(STDERR_FILENO), devnull = open("/dev/null", O_WRONLY);
        dup2(devnull, STDERR_FILENO); close(devnull);
        const char *bad[] = { "", ",", "10.0.0.0/33", "10.0.0.0/", "not-an-ip",
                              "10.0.0.0/8;id", "::/129", "1.2.3.4/-1", NULL };
        int all_rejected = 1;
        for (int i = 0; bad[i]; i++)
            if (acl_set_allow_list(bad[i]) != -1) all_rejected = 0;
        dup2(saved, STDERR_FILENO); close(saved);
        acl_reset();
        ASSERT(all_rejected, "a malformed list was accepted");
    } TEST_END;
}

/* ── received file names ── */

void test_filetx_sanitize_real(void) {
    TEST_BEGIN("received file names are sanitised (real function)") {
        struct { const char *in, *out; } cases[] = {
            { "../../etc/passwd", "_._.._etc_passwd" },
            { ".bashrc", "_bashrc" },
            { "..", "_." },
            { "a\\b", "a_b" },
            { "line\nbreak\x1b[31m", "line_break_[31m" },
            { "", "received.bin" },
            { "report.pdf", "report.pdf" },
            { NULL, NULL }
        };
        for (int i = 0; cases[i].in; i++) {
            char buf[64];
            snprintf(buf, sizeof(buf), "%s", cases[i].in);
            filetx_sanitize_name(buf);
            ASSERT_STR_EQ(buf, cases[i].out, cases[i].in);
        }
    } TEST_END;
}
