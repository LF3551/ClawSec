/*
 * acl.h — destination address policy for the SOCKS5 server
 *
 * Default policy (no --socks-allow): every destination is allowed except
 * addresses that reach the server itself or cloud control planes:
 *   0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16 (link-local, cloud metadata),
 *   100.100.100.200/32 (Alibaba metadata), 168.63.129.16/32 (Azure),
 *   224.0.0.0/4, 240.0.0.0/4, ::/128, ::1/128, fe80::/10, ff00::/8,
 *   fd00:ec2::254/128 (AWS IPv6 metadata).
 * Private ranges (10/8, 172.16/12, 192.168/16, fc00::/7) stay allowed:
 * reaching the server's network is the point of the tunnel.
 *
 * With --socks-allow LIST only destinations inside LIST are allowed (the
 * defaults no longer apply, so LIST may include e.g. 127.0.0.1/32).
 * IPv4-mapped (::ffff:0:0/96) and NAT64 (64:ff9b::/96) IPv6 addresses are
 * checked as the IPv4 address they embed.
 */
#ifndef CLAWSEC_ACL_H
#define CLAWSEC_ACL_H

#include <sys/socket.h>

/* Parse a comma-separated list of addresses/CIDRs, e.g.
 * "10.0.0.0/8,192.168.1.5,2001:db8::/32", and use it as the allow list.
 * Returns 0, or -1 on a syntax error (message on stderr). */
int acl_set_allow_list(const char *list);

/* Restore the default policy (tests). */
void acl_reset(void);

/* 1 if a connection to addr is allowed, 0 if not. */
int acl_allowed(const struct sockaddr *addr, socklen_t len);

#endif
