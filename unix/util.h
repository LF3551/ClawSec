#ifndef CLAWSEC_UTIL_H
#define CLAWSEC_UTIL_H

#include <stddef.h>
#include <stdarg.h>

/* Logging */
void log_msg(int level, const char *fmt, ...);
void fatal(const char *fmt, ...);

/* I/O helpers */
int write_all(int fd, const void *buf, size_t len);

/* Globals */
extern int g_verbose;

#endif
