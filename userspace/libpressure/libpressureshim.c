// SPDX-License-Identifier: GPL-2.0
/*
 * libpressureshim.so: LD_PRELOAD Transparent Dual-Stack (AF_INET & AF_INET6,
 * SOCK_STREAM & SOCK_DGRAM) -> AF_UNIX sfw Interposer
 *
 * Interposes: socket, bind, listen, accept, accept4, connect, send, sendto,
 * sendmsg, writev, recv, recvfrom, recvmsg, readv, getsockname, getpeername,
 * setsockopt, getsockopt, shutdown, fcntl (O_NONBLOCK), poll, and close.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <netdb.h>
#include <pthread.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "../../include/uapi/linux/sfw.h"
#include "libpressuresock.h"

#define MAX_SHIM_SOCKS 256

struct shim_entry {
	bool active;
	bool nonblock;
	int fd;
	int sock_type;
	uint64_t listener_token;
};

static struct shim_entry g_table[MAX_SHIM_SOCKS];
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static __thread int g_in_shim;

static bool use_sfw_resolver(void)
{
	const char *enabled = getenv("PRESSURE_SFW_RESOLVE_IPV4");

	return enabled && strcmp(enabled, "1") == 0;
}

static int resolve_in_helper(const char *node, char address[INET_ADDRSTRLEN])
{
	static const char helper[] = "/usr/libexec/pressure-sfw-resolve";
	char *const argv[] = { (char *)helper, (char *)node, NULL };
	char *const env[] = { NULL };
	posix_spawn_file_actions_t actions;
	struct in_addr parsed;
	char reply[INET_ADDRSTRLEN + 1];
	int fds[2], rc, status;
	size_t used = 0;
	pid_t child, waited;

	if (pipe2(fds, O_CLOEXEC) < 0)
		return EAI_SYSTEM;
	rc = posix_spawn_file_actions_init(&actions);
	if (rc)
		goto close_pipe;
	rc = posix_spawn_file_actions_addclose(&actions, fds[0]);
	if (!rc)
		rc = posix_spawn_file_actions_adddup2(&actions, fds[1], STDOUT_FILENO);
	if (!rc)
		rc = posix_spawn(&child, helper, &actions, NULL, argv, env);
	posix_spawn_file_actions_destroy(&actions);
	if (rc)
		goto close_pipe;
	close(fds[1]);
	while (used < sizeof(reply)) {
		ssize_t n = read(fds[0], reply + used, sizeof(reply) - used);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		used += (size_t)n;
	}
	close(fds[0]);
	do {
		waited = waitpid(child, &status, 0);
	} while (waited < 0 && errno == EINTR);
	if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status) ||
	    !used || used >= sizeof(reply) || reply[used - 1] != '\n')
		return EAI_AGAIN;
	reply[used - 1] = '\0';
	if (inet_pton(AF_INET, reply, &parsed) != 1)
		return EAI_AGAIN;
	memcpy(address, reply, used);
	return 0;

close_pipe:
	close(fds[0]);
	close(fds[1]);
	errno = rc;
	return EAI_SYSTEM;
}

int getaddrinfo(const char *node, const char *service,
		const struct addrinfo *hints, struct addrinfo **result)
{
	int (*real_getaddrinfo)(const char *, const char *,
			       const struct addrinfo *, struct addrinfo **);
	struct addrinfo requested = { .ai_family = AF_INET };
	char address[INET_ADDRSTRLEN];
	struct in_addr numeric;
	int rc;

	real_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");
	if (!use_sfw_resolver() || !node || (hints && hints->ai_flags & AI_NUMERICHOST))
		return real_getaddrinfo(node, service, hints, result);
	if (hints) {
		if (hints->ai_family != AF_UNSPEC && hints->ai_family != AF_INET)
			return EAI_FAMILY;
		requested = *hints;
		requested.ai_family = AF_INET;
	}
	requested.ai_flags |= AI_NUMERICHOST;
	if (inet_pton(AF_INET, node, &numeric) == 1)
		return real_getaddrinfo(node, service, &requested, result);
	rc = resolve_in_helper(node, address);
	if (rc)
		return rc;
	return real_getaddrinfo(address, service, &requested, result);
}

static struct shim_entry *find_entry(int fd)
{
	for (int i = 0; i < MAX_SHIM_SOCKS; i++) {
		if (g_table[i].active && g_table[i].fd == fd)
			return &g_table[i];
	}
	return NULL;
}

static void add_entry(int fd, int sock_type, bool nonblock)
{
	pthread_mutex_lock(&g_lock);
	for (int i = 0; i < MAX_SHIM_SOCKS; i++) {
		if (!g_table[i].active) {
			g_table[i].active = true;
			g_table[i].nonblock = nonblock;
			g_table[i].fd = fd;
			g_table[i].sock_type = sock_type;
			g_table[i].listener_token = 0;
			break;
		}
	}
	pthread_mutex_unlock(&g_lock);
}

static bool lookup_shim(int fd, bool *nb_out, uint64_t *tok_out)
{
	bool ok = false;
	pthread_mutex_lock(&g_lock);
	struct shim_entry *e = find_entry(fd);
	if (e) {
		ok = true;
		if (nb_out)
			*nb_out = e->nonblock;
		if (tok_out)
			*tok_out = e->listener_token;
	}
	pthread_mutex_unlock(&g_lock);
	return ok;
}

int socket(int domain, int type, int protocol)
{
	static int (*real_socket)(int, int, int);
	if (!real_socket)
		real_socket = dlsym(RTLD_NEXT, "socket");

	if (!g_in_shim && domain == AF_INET6 && use_sfw_resolver()) {
		errno = EAFNOSUPPORT;
		return -1;
	}
	if (!g_in_shim && (domain == AF_INET || domain == AF_INET6)) {
		bool nb = (type & SOCK_NONBLOCK) != 0;
		int base_type = type & ~(SOCK_CLOEXEC | SOCK_NONBLOCK);
		int ufd;
		g_in_shim = 1;
		ufd = pg_socket(domain, base_type, protocol);
		g_in_shim = 0;
		if (ufd >= 0)
			add_entry(ufd, base_type, nb);
		return ufd;
	}
	return real_socket(domain, type, protocol);
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	static int (*real_bind)(int, const struct sockaddr *, socklen_t);
	if (!real_bind)
		real_bind = dlsym(RTLD_NEXT, "bind");

	if (!g_in_shim && lookup_shim(sockfd, NULL, NULL) && addr &&
	    (addr->sa_family == AF_INET || addr->sa_family == AF_INET6)) {
		int rc;
		g_in_shim = 1;
		rc = pg_bind_sa(sockfd, addr, addrlen, NULL);
		g_in_shim = 0;
		return rc;
	}
	return real_bind(sockfd, addr, addrlen);
}

int listen(int sockfd, int backlog)
{
	static int (*real_listen)(int, int);
	(void)backlog;
	if (!real_listen)
		real_listen = dlsym(RTLD_NEXT, "listen");

	if (!g_in_shim && lookup_shim(sockfd, NULL, NULL)) {
		uint64_t tok = 0;
		int rc;
		g_in_shim = 1;
		rc = pg_listen(sockfd, &tok);
		g_in_shim = 0;
		if (rc == 0) {
			pthread_mutex_lock(&g_lock);
			struct shim_entry *e = find_entry(sockfd);
			if (e)
				e->listener_token = tok;
			pthread_mutex_unlock(&g_lock);
		}
		return rc;
	}
	return real_listen(sockfd, backlog);
}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
	static int (*real_accept4)(int, struct sockaddr *, socklen_t *, int);
	bool listen_nb = false;
	uint64_t tok = 0;

	if (!real_accept4)
		real_accept4 = dlsym(RTLD_NEXT, "accept4");

	if (!g_in_shim && lookup_shim(sockfd, &listen_nb, &tok)) {
		struct sockaddr_storage peer = {};
		socklen_t plen = 0;
		uint16_t sfw_fl = listen_nb ? SFW_FLAG_NONBLOCK : 0;
		int nfd;
		g_in_shim = 1;
		nfd = pg_accept_sa_flags(sockfd, tok, &peer, &plen, sfw_fl);
		g_in_shim = 0;
		if (nfd >= 0) {
			add_entry(nfd, SOCK_STREAM, (flags & SOCK_NONBLOCK) != 0);
			if (addr && addrlen && plen > 0) {
				socklen_t cp = *addrlen < plen ? *addrlen : plen;
				memcpy(addr, &peer, cp);
				*addrlen = plen;
			}
		}
		return nfd;
	}
	return real_accept4(sockfd, addr, addrlen, flags);
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	static int (*real_accept)(int, struct sockaddr *, socklen_t *);
	if (!real_accept)
		real_accept = dlsym(RTLD_NEXT, "accept");

	if (!g_in_shim && lookup_shim(sockfd, NULL, NULL))
		return accept4(sockfd, addr, addrlen, 0);
	return real_accept(sockfd, addr, addrlen);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	static int (*real_connect)(int, const struct sockaddr *, socklen_t);
	if (!real_connect)
		real_connect = dlsym(RTLD_NEXT, "connect");

	if (!g_in_shim && lookup_shim(sockfd, NULL, NULL) && addr &&
	    (addr->sa_family == AF_INET || addr->sa_family == AF_INET6)) {
		int rc;
		g_in_shim = 1;
		rc = pg_connect_sa(sockfd, addr, addrlen, NULL);
		g_in_shim = 0;
		return rc;
	}
	return real_connect(sockfd, addr, addrlen);
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
	       const struct sockaddr *dest_addr, socklen_t addrlen)
{
	static ssize_t (*real_sendto)(int, const void *, size_t, int,
				      const struct sockaddr *, socklen_t);
	bool nb = false;
	if (!real_sendto)
		real_sendto = dlsym(RTLD_NEXT, "sendto");

	if (!g_in_shim && lookup_shim(sockfd, &nb, NULL)) {
		uint16_t sfw_fl = (nb || (flags & MSG_DONTWAIT)) ?
				  SFW_FLAG_NONBLOCK : 0;
		ssize_t r;
		g_in_shim = 1;
		r = pg_sendto_sa(sockfd, buf, len, sfw_fl, dest_addr, addrlen, NULL);
		g_in_shim = 0;
		return r;
	}
	return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
	static ssize_t (*real_send)(int, const void *, size_t, int);
	if (!real_send)
		real_send = dlsym(RTLD_NEXT, "send");

	if (!g_in_shim && lookup_shim(sockfd, NULL, NULL))
		return sendto(sockfd, buf, len, flags, NULL, 0);
	return real_send(sockfd, buf, len, flags);
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
		 struct sockaddr *src_addr, socklen_t *addrlen)
{
	static ssize_t (*real_recvfrom)(int, void *, size_t, int,
					struct sockaddr *, socklen_t *);
	bool nb = false;
	int stype = SOCK_STREAM;
	if (!real_recvfrom)
		real_recvfrom = dlsym(RTLD_NEXT, "recvfrom");

	pthread_mutex_lock(&g_lock);
	struct shim_entry *e = find_entry(sockfd);
	bool is_shim = (e != NULL);
	if (e) {
		nb = e->nonblock;
		stype = e->sock_type;
	}
	pthread_mutex_unlock(&g_lock);

	if (!g_in_shim && is_shim) {
		uint16_t sfw_fl = (nb || (flags & MSG_DONTWAIT)) ?
				  SFW_FLAG_NONBLOCK : 0;
		ssize_t r;
		g_in_shim = 1;
		if (stype == SOCK_DGRAM || src_addr != NULL) {
			struct sockaddr_storage ss = {};
			socklen_t sl = 0;
			r = pg_recvfrom_sa(sockfd, buf, len, sfw_fl, &ss, &sl);
			if (r >= 0 && src_addr && addrlen && sl > 0) {
				socklen_t cp = *addrlen < sl ? *addrlen : sl;
				memcpy(src_addr, &ss, cp);
				*addrlen = sl;
			}
		} else {
			r = pg_recv(sockfd, buf, len, sfw_fl);
		}
		g_in_shim = 0;
		return r;
	}
	return real_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
	static ssize_t (*real_recv)(int, void *, size_t, int);
	if (!real_recv)
		real_recv = dlsym(RTLD_NEXT, "recv");

	if (!g_in_shim && lookup_shim(sockfd, NULL, NULL))
		return recvfrom(sockfd, buf, len, flags, NULL, NULL);
	return real_recv(sockfd, buf, len, flags);
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
	static ssize_t (*real_writev)(int, const struct iovec *, int);
	if (!real_writev)
		real_writev = dlsym(RTLD_NEXT, "writev");

	if (!g_in_shim && lookup_shim(fd, NULL, NULL) && iov && iovcnt > 0) {
		size_t total = 0;
		for (int i = 0; i < iovcnt; i++)
			total += iov[i].iov_len;
		if (total > 65536)
			total = 65536;
		char *flat = malloc(total ? total : 1);
		if (!flat)
			return -1;
		size_t off = 0;
		for (int i = 0; i < iovcnt && off < total; i++) {
			size_t n = iov[i].iov_len;
			if (off + n > total)
				n = total - off;
			memcpy(flat + off, iov[i].iov_base, n);
			off += n;
		}
		ssize_t r = sendto(fd, flat, off, 0, NULL, 0);
		free(flat);
		return r;
	}
	return real_writev(fd, iov, iovcnt);
}

ssize_t readv(int fd, const struct iovec *iov, int iovcnt)
{
	static ssize_t (*real_readv)(int, const struct iovec *, int);
	if (!real_readv)
		real_readv = dlsym(RTLD_NEXT, "readv");

	if (!g_in_shim && lookup_shim(fd, NULL, NULL) && iov && iovcnt > 0) {
		size_t total = 0;
		for (int i = 0; i < iovcnt; i++)
			total += iov[i].iov_len;
		if (total > 65536)
			total = 65536;
		char *flat = malloc(total ? total : 1);
		if (!flat)
			return -1;
		ssize_t r = recvfrom(fd, flat, total, 0, NULL, NULL);
		if (r > 0) {
			size_t rem = (size_t)r, off = 0;
			for (int i = 0; i < iovcnt && rem > 0; i++) {
				size_t n = iov[i].iov_len < rem ? iov[i].iov_len : rem;
				memcpy(iov[i].iov_base, flat + off, n);
				off += n;
				rem -= n;
			}
		}
		free(flat);
		return r;
	}
	return real_readv(fd, iov, iovcnt);
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
	static ssize_t (*real_sendmsg)(int, const struct msghdr *, int);
	if (!real_sendmsg)
		real_sendmsg = dlsym(RTLD_NEXT, "sendmsg");

	if (!g_in_shim && lookup_shim(sockfd, NULL, NULL) && msg) {
		size_t total = 0;
		for (size_t i = 0; i < msg->msg_iovlen; i++)
			total += msg->msg_iov[i].iov_len;
		if (total > 65536)
			total = 65536;
		char *flat = malloc(total ? total : 1);
		if (!flat)
			return -1;
		size_t off = 0;
		for (size_t i = 0; i < msg->msg_iovlen && off < total; i++) {
			size_t n = msg->msg_iov[i].iov_len;
			if (off + n > total)
				n = total - off;
			memcpy(flat + off, msg->msg_iov[i].iov_base, n);
			off += n;
		}
		ssize_t r = sendto(sockfd, flat, off, flags,
				   (const struct sockaddr *)msg->msg_name,
				   msg->msg_namelen);
		free(flat);
		return r;
	}
	return real_sendmsg(sockfd, msg, flags);
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	static ssize_t (*real_recvmsg)(int, struct msghdr *, int);
	if (!real_recvmsg)
		real_recvmsg = dlsym(RTLD_NEXT, "recvmsg");

	if (!g_in_shim && lookup_shim(sockfd, NULL, NULL) && msg) {
		size_t total = 0;
		for (size_t i = 0; i < msg->msg_iovlen; i++)
			total += msg->msg_iov[i].iov_len;
		if (total > 65536)
			total = 65536;
		char *flat = malloc(total ? total : 1);
		if (!flat)
			return -1;
		socklen_t namelen = msg->msg_namelen;
		ssize_t r = recvfrom(sockfd, flat, total, flags,
				     (struct sockaddr *)msg->msg_name,
				     msg->msg_name ? &namelen : NULL);
		if (r >= 0 && msg->msg_name)
			msg->msg_namelen = namelen;
		if (r > 0) {
			size_t rem = (size_t)r, off = 0;
			for (size_t i = 0; i < msg->msg_iovlen && rem > 0; i++) {
				size_t n = msg->msg_iov[i].iov_len < rem ?
					   msg->msg_iov[i].iov_len : rem;
				memcpy(msg->msg_iov[i].iov_base, flat + off, n);
				off += n;
				rem -= n;
			}
		}
		free(flat);
		return r;
	}
	return real_recvmsg(sockfd, msg, flags);
}

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	static int (*real_getsockname)(int, struct sockaddr *, socklen_t *);
	if (!real_getsockname)
		real_getsockname = dlsym(RTLD_NEXT, "getsockname");

	if (!g_in_shim && lookup_shim(sockfd, NULL, NULL)) {
		struct sockaddr_storage ss = {};
		socklen_t sl = 0;
		int rc;
		g_in_shim = 1;
		rc = pg_getsockname_sa(sockfd, &ss, &sl);
		g_in_shim = 0;
		if (rc == 0 && addr && addrlen && sl > 0) {
			socklen_t cp = *addrlen < sl ? *addrlen : sl;
			memcpy(addr, &ss, cp);
			*addrlen = sl;
		}
		return rc;
	}
	return real_getsockname(sockfd, addr, addrlen);
}

int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	static int (*real_getpeername)(int, struct sockaddr *, socklen_t *);
	if (!real_getpeername)
		real_getpeername = dlsym(RTLD_NEXT, "getpeername");

	if (!g_in_shim && lookup_shim(sockfd, NULL, NULL)) {
		struct sockaddr_storage ss = {};
		socklen_t sl = 0;
		int rc;
		g_in_shim = 1;
		rc = pg_getpeername_sa(sockfd, &ss, &sl);
		g_in_shim = 0;
		if (rc == 0 && addr && addrlen && sl > 0) {
			socklen_t cp = *addrlen < sl ? *addrlen : sl;
			memcpy(addr, &ss, cp);
			*addrlen = sl;
		}
		return rc;
	}
	return real_getpeername(sockfd, addr, addrlen);
}

int setsockopt(int sockfd, int level, int optname, const void *optval,
	       socklen_t optlen)
{
	static int (*real_setsockopt)(int, int, int, const void *, socklen_t);
	if (!real_setsockopt)
		real_setsockopt = dlsym(RTLD_NEXT, "setsockopt");

	if (!g_in_shim && lookup_shim(sockfd, NULL, NULL)) {
		int val = (optval && optlen >= (socklen_t)sizeof(int)) ?
			  *(const int *)optval : 1;
		uint16_t oid = 0;
		if (level == SOL_SOCKET && optname == SO_REUSEADDR)
			oid = SFW_SOCKOPT_REUSEADDR;
		else if (level == SOL_SOCKET && optname == SO_REUSEPORT)
			oid = SFW_SOCKOPT_REUSEPORT;
		else if (level == SOL_SOCKET && optname == SO_KEEPALIVE)
			oid = SFW_SOCKOPT_KEEPALIVE;
		else if (level == SOL_SOCKET && optname == SO_BROADCAST)
			oid = SFW_SOCKOPT_BROADCAST;
		else if (level == IPPROTO_TCP && optname == TCP_NODELAY)
			oid = SFW_SOCKOPT_TCP_NODELAY;
		else if (level == IPPROTO_IPV6 && optname == IPV6_V6ONLY)
			oid = SFW_SOCKOPT_IPV6_V6ONLY;
		else
			return 0; /* Benign unsupported tuning option */

		g_in_shim = 1;
		int rc = pg_setsockopt_int(sockfd, oid, val);
		g_in_shim = 0;
		return rc;
	}
	return real_setsockopt(sockfd, level, optname, optval, optlen);
}

int shutdown(int sockfd, int how)
{
	static int (*real_shutdown)(int, int);
	if (!real_shutdown)
		real_shutdown = dlsym(RTLD_NEXT, "shutdown");

	if (!g_in_shim && lookup_shim(sockfd, NULL, NULL)) {
		int rc;
		g_in_shim = 1;
		rc = pg_shutdown(sockfd, how);
		g_in_shim = 0;
		return rc;
	}
	return real_shutdown(sockfd, how);
}

int fcntl(int fd, int cmd, ...)
{
	static int (*real_fcntl)(int, int, ...);
	va_list ap;
	unsigned long arg = 0;

	if (!real_fcntl)
		real_fcntl = dlsym(RTLD_NEXT, "fcntl");

	va_start(ap, cmd);
	arg = va_arg(ap, unsigned long);
	va_end(ap);

	if (!g_in_shim && (cmd == F_SETFL || cmd == F_GETFL)) {
		pthread_mutex_lock(&g_lock);
		struct shim_entry *e = find_entry(fd);
		if (e) {
			if (cmd == F_SETFL) {
				e->nonblock = (arg & O_NONBLOCK) != 0;
				pthread_mutex_unlock(&g_lock);
				return 0;
			} else {
				int fl = O_RDWR | (e->nonblock ? O_NONBLOCK : 0);
				pthread_mutex_unlock(&g_lock);
				return fl;
			}
		}
		pthread_mutex_unlock(&g_lock);
	}
	return real_fcntl(fd, cmd, arg);
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	static int (*real_poll)(struct pollfd *, nfds_t, int);
	bool any_shim = false;

	if (!real_poll)
		real_poll = dlsym(RTLD_NEXT, "poll");

	if (g_in_shim || !fds)
		return real_poll(fds, nfds, timeout);

	for (nfds_t i = 0; i < nfds; i++) {
		if (fds[i].fd >= 0 && lookup_shim(fds[i].fd, NULL, NULL)) {
			any_shim = true;
			break;
		}
	}
	if (!any_shim)
		return real_poll(fds, nfds, timeout);

	int elapsed = 0;
	for (;;) {
		int ready = 0;
		for (nfds_t i = 0; i < nfds; i++) {
			fds[i].revents = 0;
			if (fds[i].fd < 0)
				continue;
			if (lookup_shim(fds[i].fd, NULL, NULL)) {
				g_in_shim = 1;
				int ev = pg_poll_events(fds[i].fd);
				g_in_shim = 0;
				if (ev > 0) {
					short rev = (short)ev &
						    (fds[i].events | POLLERR | POLLHUP);
					fds[i].revents = rev;
					if (rev)
						ready++;
				}
			} else {
				struct pollfd single = fds[i];
				if (real_poll(&single, 1, 0) > 0) {
					fds[i].revents = single.revents;
					ready++;
				}
			}
		}
		if (ready > 0 || timeout == 0 ||
		    (timeout > 0 && elapsed >= timeout))
			return ready;
		usleep(5000);
		elapsed += 5;
	}
}

int close(int fd)
{
	static int (*real_close)(int);
	bool was_shim = false;

	if (!real_close)
		real_close = dlsym(RTLD_NEXT, "close");

	if (!g_in_shim) {
		pthread_mutex_lock(&g_lock);
		struct shim_entry *e = find_entry(fd);
		if (e) {
			e->active = false;
			was_shim = true;
		}
		pthread_mutex_unlock(&g_lock);
		if (was_shim) {
			int rc;
			g_in_shim = 1;
			rc = pg_close(fd);
			g_in_shim = 0;
			return rc;
		}
	}
	return real_close(fd);
}
