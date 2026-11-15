/*
 * config.h — --config FILE: command-line options from a file
 *
 *   # /etc/clawsec/server.conf
 *   listen
 *   port = 9000
 *   keep-open
 *   tun = 10.8.0.1/24
 *   users = /etc/clawsec/users
 *
 * Keys are long option names, or these names for short options: listen (-l),
 * port (-p), keep-open (-K), udp (-u), ipv4 (-4), ipv6 (-6), chat (-c),
 * verbose (-v), timeout (-w), compress (-z), progress (-P), verify (-V),
 * name (-n), banner (-b), forward (-L), reverse (-R).
 * Flags: "key", or "key = yes|no". Options on the command line come after
 * the file and win. A password cannot be given here (use key-file).
 */
#ifndef CLAWSEC_CONFIG_H
#define CLAWSEC_CONFIG_H

#include <getopt.h>

/* If argv contains --config FILE (or --config=FILE), returns a new argv:
 * argv[0], the options from FILE, then the remaining command line.
 * long_opts: the program's option table (for key validation).
 * Returns 0 (argc/argv replaced only when --config was given) or -1. */
int config_expand(int *argc, char ***argv, const struct option *long_opts);

#endif
