/*
 * tun_internal.h — shared by tun_dev.c, tun_net.c and tun.c (not public)
 */
#ifndef CLAWSEC_TUN_INTERNAL_H
#define CLAWSEC_TUN_INTERNAL_H

/* Run a system tool without a shell (argv vector, execvp). Returns its exit
 * status, or -1 if it could not run. quiet: discard its output. */
int tun_run_argv(char *const argv[], int quiet);

/* RUN(quiet, "tool", "arg", ...) — argv literal, NULL-terminated */
#define RUN(quiet, ...) tun_run_argv((char *const[]){ __VA_ARGS__, NULL }, (quiet))

#define TUN_SIG_VPN   "TVPN"
#define TUN_SIG_LEN   4

int tun_valid_ipv4(const char *s);

/* One IP packet from/to the TUN device (or the hub socket, tun_set_raw_fd) */
int tun_read_packet(int tun_fd, char *buf, int buf_size);
int tun_write_packet(int tun_fd, const char *buf, int len);

#endif
