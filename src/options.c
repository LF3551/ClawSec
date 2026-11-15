/*
 * options.c — defaults for the run-time settings (see options.h)
 */
#include "options.h"

struct clawsec_options g_opt = {
    .hub_fd = -1,
    .max_clients = 16,
    .max_per_ip = 8,
    .auth_fail_limit = 5,
    .handshake_timeout = 15,
};
