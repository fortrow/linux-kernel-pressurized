/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LIBPRESSURESOCK_H
#define _LIBPRESSURESOCK_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

int pg_socket(int domain, int type, int protocol);

/* Dual-stack sockaddr-generic helpers (AF_INET & AF_INET6) */
int pg_bind_sa(int ufd, const struct sockaddr *addr, socklen_t addrlen,
	       const char *ifname);
int pg_connect_sa(int ufd, const struct sockaddr *addr, socklen_t addrlen,
		  const char *ifname);
int pg_accept_sa(int listen_ufd, uint64_t listener_token,
		 struct sockaddr_storage *peer_out, socklen_t *peer_len_out);
int pg_accept_sa_flags(int listen_ufd, uint64_t listener_token,
		       struct sockaddr_storage *peer_out,
		       socklen_t *peer_len_out, uint16_t sfw_flags);

/* IPv4 & IPv6 typed wrappers */
int pg_bind(int ufd, const struct sockaddr_in *addr, const char *ifname);
int pg_bind6(int ufd, const struct sockaddr_in6 *addr, const char *ifname);
int pg_listen(int ufd, uint64_t *listener_token_out);
int pg_accept(int listen_ufd, uint64_t listener_token, struct sockaddr_in *peer_out);
int pg_accept6(int listen_ufd, uint64_t listener_token, struct sockaddr_in6 *peer_out);
int pg_connect(int ufd, const struct sockaddr_in *addr, const char *ifname);
int pg_connect6(int ufd, const struct sockaddr_in6 *addr, const char *ifname);

/* Stream & connectionless UDP (SOCK_DGRAM) I/O + non-blocking flags */
ssize_t pg_send(int ufd, const void *buf, size_t len);
ssize_t pg_send_flags(int ufd, const void *buf, size_t len, uint16_t sfw_flags);
ssize_t pg_recv(int ufd, void *buf, size_t len, uint16_t sfw_flags);
ssize_t pg_sendto_sa(int ufd, const void *buf, size_t len, uint16_t sfw_flags,
		     const struct sockaddr *dst, socklen_t dstlen,
		     const char *ifname);
ssize_t pg_recvfrom_sa(int ufd, void *buf, size_t len, uint16_t sfw_flags,
		       struct sockaddr_storage *src_out, socklen_t *srclen_out);

/* Readiness, introspection, socket options & half-close */
int pg_poll_events(int ufd);
int pg_getsockname_sa(int ufd, struct sockaddr_storage *out, socklen_t *len_out);
int pg_getpeername_sa(int ufd, struct sockaddr_storage *out, socklen_t *len_out);
int pg_setsockopt_int(int ufd, uint16_t sfw_opt_id, int val);
int pg_shutdown(int ufd, int how);
int pg_close(int ufd);

#endif
