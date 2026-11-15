/*
 * users.h — per-user passwords for the server (--users FILE)
 *
 * File format, one user per line (blank lines and "#" comments allowed):
 *     name:v1:<64 hex digits>
 * The hex value is the user's SPAKE2 password scalar
 *     w = Argon2id(password, "ClawSec v4 SPAKE2 user:" || name)  (mod order)
 * not the password itself: different users with the same password get
 * different lines, and the file does not reveal passwords directly.
 * SPAKE2 is a balanced PAKE, so a stolen line lets an attacker log in as
 * that user: protect the file like a private key (mode 0600).
 */
#ifndef CLAWSEC_USERS_H
#define CLAWSEC_USERS_H

#include <stddef.h>

#define USER_NAME_MAX 32

/* 1..32 characters from [A-Za-z0-9._-]. Returns 1 if valid. */
int user_name_valid(const char *name);

/* w for name/password (client side, and --add-user). Returns 0 or -1. */
int user_password_to_w(const char *name, const char *password, size_t pass_len,
                       unsigned char w[32]);

/* Look up name. Returns 1 (w filled), 0 if there is no such user, -1 if
 * the file cannot be read or is malformed. */
int users_lookup(const char *path, const char *name, unsigned char w[32]);

/* Add or replace name (atomic rename, mode 0600). Returns 0 or -1. */
int users_set(const char *path, const char *name, const unsigned char w[32]);

/* Startup check: the file exists and is readable; warns if group/other can
 * read it. Returns 0 or -1. */
int users_check_file(const char *path);

#endif
