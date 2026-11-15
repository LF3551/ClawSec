/*
 * secret.h — obtaining the session password without exposing it
 *
 * Sources, in order of precedence (see secret_resolve):
 *   1. -k <password>       works, but is visible to other users (ps,
 *                          /proc/<pid>/cmdline) and in shell history;
 *                          ClawSec copies it and overwrites argv
 *   2. --key-file <path>   first line of a file (should be mode 0600)
 *   3. CLAWSEC_PASSWORD    environment variable (removed from the
 *                          environment after reading, so -e children
 *                          and other subprocesses do not inherit it)
 *   4. interactive prompt  on /dev/tty, without echo
 */
#ifndef CLAWSEC_SECRET_H
#define CLAWSEC_SECRET_H

#include <stddef.h>

#define SECRET_MAX 1024              /* maximum password length (bytes) */
#define SECRET_ENV "CLAWSEC_PASSWORD"

/* Copy a password given on the command line into out and overwrite the
 * original argv bytes. Returns 0, or -1 if empty or too long. */
int secret_from_arg(char *arg, char *out, size_t out_len);

/* Read the first line of path (trailing CR/LF removed). Warns on stderr
 * if the file is readable by group or others. Returns 0 or -1. */
int secret_from_file(const char *path, char *out, size_t out_len);

/* Read and unset $CLAWSEC_PASSWORD. Returns 0, 1 if not set, -1 on error. */
int secret_from_env(char *out, size_t out_len);

/* Prompt on /dev/tty without echo. Returns 0, 1 if there is no terminal,
 * -1 on error. */
int secret_prompt(const char *prompt, char *out, size_t out_len);

/* Wipe a secret buffer (not optimised away). */
void secret_wipe(void *buf, size_t len);

#endif
