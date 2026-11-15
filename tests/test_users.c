/*
 * test_users.c — per-user passwords (--users / --user)
 */
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#include <unistd.h>
#include "test.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include "farm9crypt.h"
#include "ecdhe.h"
#include "pqkem.h"
#include "users.h"
#include <arpa/inet.h>

void test_users_names_and_scalars(void) {
    TEST_BEGIN("users: name rules; w depends on name and password") {
        ASSERT(user_name_valid("alice") && user_name_valid("a.b_c-9"), "valid names");
        ASSERT(!user_name_valid("") && !user_name_valid("al ice") && !user_name_valid("a:b") &&
               !user_name_valid("toolongname-012345678901234567890"), "invalid names");
        unsigned char a1[32], a2[32], b1[32];
        ASSERT(user_password_to_w("alice", "same-password", 13, a1) == 0, "w alice");
        ASSERT(user_password_to_w("alice", "same-password", 13, a2) == 0, "w alice again");
        ASSERT(user_password_to_w("bob", "same-password", 13, b1) == 0, "w bob");
        ASSERT(memcmp(a1, a2, 32) == 0, "deterministic");
        ASSERT(memcmp(a1, b1, 32) != 0, "same password, other user: other w");
        ASSERT(user_password_to_w("bad name", "pw", 2, a1) == -1, "invalid name rejected");
    } TEST_END;
}

void test_users_file(void) {
    TEST_BEGIN("users: file add/replace/lookup, comments kept, mode 0600") {
        char dir[] = "/tmp/clawsec-users-XXXXXX", path[128];
        ASSERT(mkdtemp(dir) != NULL, "tmpdir");
        snprintf(path, sizeof(path), "%s/users", dir);
        unsigned char w1[32], w2[32], w3[32];
        user_entry_t got;
        memset(w1, 0x11, 32); memset(w2, 0x22, 32); memset(w3, 0x33, 32);
        ASSERT(users_set(path, "alice", w1, NULL) == 0 && users_set(path, "bob", w2, NULL) == 0, "add");
        struct stat st;
        ASSERT(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600, "mode 0600");
        FILE *f = fopen(path, "a");
        fputs("# a comment\nnot a valid line\n", f);
        fclose(f);
        ASSERT(users_set(path, "alice", w3, NULL) == 0, "replace");
        ASSERT(users_lookup(path, "alice", &got) == 1 && memcmp(got.w, w3, 32) == 0, "alice replaced");
        ASSERT(users_lookup(path, "bob", &got) == 1 && memcmp(got.w, w2, 32) == 0, "bob kept");
        ASSERT(users_lookup(path, "carol", &got) == 0, "unknown user");
        ASSERT(users_lookup("/nonexistent/users", "alice", &got) == -1, "missing file");

        /* options: set without touching the password, keep on password change */
        ASSERT(users_set(path, "bob", NULL, "ip=10.8.0.10,socks-allow=10.0.0.0/8;192.168.1.0/24") == 0,
               "set options");
        ASSERT(users_lookup(path, "bob", &got) == 1 && memcmp(got.w, w2, 32) == 0 && got.has_ip &&
               got.ip.s_addr == htonl(0x0a08000a) &&
               strcmp(got.socks_allow, "10.0.0.0/8,192.168.1.0/24") == 0 && !got.disabled,
               "options stored, password kept");
        ASSERT(users_set(path, "bob", w1, NULL) == 0 && users_lookup(path, "bob", &got) == 1 &&
               memcmp(got.w, w1, 32) == 0 && got.has_ip, "password change keeps options");
        ASSERT(users_set(path, "bob", NULL, "disabled") == 0 && users_lookup(path, "bob", &got) == 1 &&
               got.disabled && !got.has_ip, "options replaced");
        ASSERT(users_set(path, "bob", NULL, "none") == 0 && users_lookup(path, "bob", &got) == 1 &&
               !got.disabled && got.opts[0] == '\0', "options cleared");
        errno = 0;
        ASSERT(users_set(path, "nobody", NULL, "disabled") == -1 && errno == ENOENT,
               "options for an unknown user");
        ASSERT(users_delete(path, "bob") == 1 && users_lookup(path, "bob", &got) == 0, "deleted");
        ASSERT(users_delete(path, "bob") == 0, "delete twice");
        ASSERT(users_lookup(path, "alice", &got) == 1, "others kept after delete");
        f = fopen(path, "r");
        char buf[2048];
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        fclose(f);
        ASSERT(strstr(buf, "# a comment") != NULL, "comment kept");
        int alice_lines = 0;
        for (char *p = buf; (p = strstr(p, "alice:")) != NULL; p++) alice_lines++;
        ASSERT_EQ(alice_lines, 1, "one line per user");
        unlink(path);
        rmdir(dir);
    } TEST_END;
}

/* ── handshakes ── */

static char s_users_path[128];

static void make_users_file(void) {
    char dir[] = "/tmp/clawsec-hs-XXXXXX";
    if (!mkdtemp(dir)) return;
    snprintf(s_users_path, sizeof(s_users_path), "%s/users", dir);
    unsigned char w[32];
    user_password_to_w("alice", "alice-password", 14, w);
    users_set(s_users_path, "alice", w, NULL);
    user_password_to_w("carol", "carol-password", 14, w);
    users_set(s_users_path, "carol", w, "disabled");
}

static void clean_users_file(void) {
    char dir[128];
    snprintf(dir, sizeof(dir), "%s", s_users_path);
    unlink(s_users_path);
    char *slash = strrchr(dir, '/');
    if (slash) { *slash = '\0'; rmdir(dir); }
}

/* Server child exit: 0 ok (with user alice), 10+reason on failure */
static int user_handshake(const char *user, const char *password, int pq, int *client_reason) {
    int fds[2];
    if (make_socketpair(fds) != 0) return -1;
    struct timeval tv = { 5, 0 };
    setsockopt(fds[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fds[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    pid_t pid = fork();
    if (pid == 0) {
        close(fds[1]);
        ecdhe_set_users_file(s_users_path);
        int rc = pq ? farm9crypt_init_ecdhe_pq(fds[0], "unused", 6, FARM9_ROLE_SERVER, NULL, NULL)
                    : farm9crypt_init_ecdhe(fds[0], "unused", 6, FARM9_ROLE_SERVER);
        if (rc == 0) {
            const char *u = ecdhe_peer_user();
            _exit(u && strcmp(u, "alice") == 0 ? 0 : 3);
        }
        _exit(10 + farm9crypt_last_failure());
    }
    close(fds[0]);
    ecdhe_set_user(user);
    int rc = pq ? farm9crypt_init_ecdhe_pq(fds[1], password, strlen(password), FARM9_ROLE_CLIENT, NULL, NULL)
                : farm9crypt_init_ecdhe(fds[1], password, strlen(password), FARM9_ROLE_CLIENT);
    *client_reason = rc == 0 ? 0 : 10 + farm9crypt_last_failure();
    farm9crypt_cleanup();
    ecdhe_set_user(NULL);
    close(fds[1]);
    int st;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

void test_users_handshake(void) {
    TEST_BEGIN("users: login ok / wrong password / unknown user / no --user") {
        make_users_file();
        int saved = dup(STDERR_FILENO), dn = open("/dev/null", O_WRONLY);
        dup2(dn, STDERR_FILENO); close(dn);
        int cr;
        int ok = user_handshake("alice", "alice-password", 0, &cr);
        int ok_cr = cr;
        int wrong = user_handshake("alice", "wrong-password", 0, &cr);
        int wrong_cr = cr;
        int unknown = user_handshake("mallory", "alice-password", 0, &cr);
        int unknown_cr = cr;
        int disabled = user_handshake("carol", "carol-password", 0, &cr);
        int disabled_cr = cr;
        int nouser = user_handshake(NULL, "alice-password", 0, &cr);
        int nouser_cr = cr;
        int pq_ok = -1, pq_cr = -1;
        if (pq_available()) pq_ok = user_handshake("alice", "alice-password", 1, &pq_cr);
        dup2(saved, STDERR_FILENO); close(saved);
        clean_users_file();
        ASSERT(ok == 0 && ok_cr == 0, "alice with the right password, server sees 'alice'");
        ASSERT(wrong == 10 + FARM9_FAIL_AUTH && wrong_cr == 10 + FARM9_FAIL_AUTH,
               "wrong password: FAIL_AUTH on both ends");
        ASSERT(unknown == 10 + FARM9_FAIL_AUTH && unknown_cr == 10 + FARM9_FAIL_AUTH,
               "unknown user: same result as a wrong password");
        ASSERT(disabled == 10 + FARM9_FAIL_AUTH && disabled_cr == 10 + FARM9_FAIL_AUTH,
               "disabled user: refused like a wrong password");
        ASSERT(nouser_cr == 10 + FARM9_FAIL_CONFIG && nouser != 0,
               "client without --user: option mismatch");
        if (pq_available())
            ASSERT(pq_ok == 0 && pq_cr == 0, "per-user login with --pq");
    } TEST_END;
}

void test_users_options(void) {
    TEST_BEGIN("users: option syntax") {
        user_entry_t e;
        ASSERT(users_parse_options("ip=10.1.2.3,disabled", &e) == 0 && e.has_ip && e.disabled, "ok");
        ASSERT(users_parse_options("", &e) == 0 && !e.has_ip && !e.disabled, "empty");
        int saved = dup(STDERR_FILENO), dn = open("/dev/null", O_WRONLY);
        dup2(dn, STDERR_FILENO); close(dn);
        int bad1 = users_parse_options("ip=10.1.2", &e);
        int bad2 = users_parse_options("admin", &e);
        int bad3 = users_parse_options("socks-allow=10.0.0.0/8 ;x", &e);
        int bad4 = users_parse_options("ip=1.2.3.4:x", &e);
        dup2(saved, STDERR_FILENO); close(saved);
        ASSERT(bad1 == -1 && bad2 == -1 && bad3 == -1 && bad4 == -1, "invalid options rejected");
        char line[] = "dave:v1:0000000000000000000000000000000000000000000000000000000000000001:ip=10.0.0.9";
        ASSERT(users_parse_line(line, &e) == 1 && e.has_ip && strcmp(e.name, "dave") == 0 &&
               e.w[31] == 1, "line with options");
        char old[] = "erin:v1:0000000000000000000000000000000000000000000000000000000000000002";
        ASSERT(users_parse_line(old, &e) == 1 && !e.has_ip, "4.2 line without options");
    } TEST_END;
}
