/*
 * users.h — per-user passwords for the server (--users FILE)
 *
 * File format, one user per line (blank lines and "#" comments allowed):
 *     name:v1:<64 hex digits>[:options]
 * The hex value is the user's SPAKE2 password scalar
 *     w = Argon2id(password, "ClawSec v4 SPAKE2 user:" || name)  (mod order)
 * not the password itself: different users with the same password get
 * different lines, and the file does not reveal passwords directly.
 * SPAKE2 is a balanced PAKE, so a stolen line lets an attacker log in as
 * that user: protect the file like a private key (mode 0600).
 *
 * Options (comma-separated):
 *     ip=10.8.0.10                 fixed VPN address (IPv6: same host number)
 *     socks-allow=10.0.0.0/8;...   this user's SOCKS destinations (";"-separated)
 *     disabled                     login refused (fails like a wrong password)
 */
#ifndef CLAWSEC_USERS_H
#define CLAWSEC_USERS_H

#include <stddef.h>
#include <netinet/in.h>

#define USER_NAME_MAX 32
#define USER_OPTS_MAX 256

typedef struct {
    char name[USER_NAME_MAX + 1];
    unsigned char w[32];
    int disabled;
    int has_ip;
    struct in_addr ip;
    char socks_allow[USER_OPTS_MAX];   /* ","-separated for acl_set_allow_list, "" = default */
    char opts[USER_OPTS_MAX];          /* the options as written in the file */
} user_entry_t;

/* 1..32 characters from [A-Za-z0-9._-]. Returns 1 if valid. */
int user_name_valid(const char *name);

/* w for name/password (client side, and --add-user). Returns 0 or -1. */
int user_password_to_w(const char *name, const char *password, size_t pass_len,
                       unsigned char w[32]);

/* Validate an options string and fill the option fields of e (may be NULL).
 * "" and "none" mean no options. Returns 0 or -1 (message on stderr). */
int users_parse_options(const char *opts, user_entry_t *e);

/* Parse one line in place (it is modified). Returns 1 (entry filled), 0 for
 * a blank line or comment, -1 if malformed. */
int users_parse_line(char *line, user_entry_t *e);

/* Look up name. Returns 1 (entry filled), 0 if there is no such user, -1 if
 * the file cannot be read. */
int users_lookup(const char *path, const char *name, user_entry_t *e);

/* Add or update name (atomic rename, mode 0600). w == NULL keeps the
 * password, opts == NULL keeps the options. A new user needs w.
 * Returns 0, or -1 (errno set; ENOENT: no such user to update). */
int users_set(const char *path, const char *name, const unsigned char *w, const char *opts);

/* Remove name. Returns 1 if removed, 0 if there was no such user, -1 on error. */
int users_delete(const char *path, const char *name);

/* Startup check: the file exists and is readable; warns if group/other can
 * read it. Returns 0 or -1. */
int users_check_file(const char *path);

#endif
