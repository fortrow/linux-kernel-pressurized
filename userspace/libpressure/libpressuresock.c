// SPDX-License-Identifier: GPL-2.0
/*
 * libpressuresock: Dual-Stack (IPv4 + IPv6, TCP + UDP) Client Library for sfw
 * Root-Owned AF_UNIX Socket Worker (/run/pressure/sfw/mux.sock)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "../../include/uapi/linux/sfw.h"
#include "libpressuresock.h"

static int write_all(int fd, const void *buf, size_t len)
{
	size_t off = 0;

	while (off < len) {
		ssize_t r = write(fd, (const char *)buf + off, len - off);
		if (r <= 0)
			return -1;
		off += (size_t)r;
	}
	return 0;
}

static int read_all(int fd, void *buf, size_t len)
{
	size_t off = 0;

	while (off < len) {
		ssize_t r = read(fd, (char *)buf + off, len - off);
		if (r <= 0)
			return -1;
		off += (size_t)r;
	}
	return 0;
}

static int open_mux_channel(void)
{
	struct sockaddr_un sun = { .sun_family = AF_UNIX };
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);

	if (fd < 0)
		return -1;
	snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", SFW_MUX_SOCK_PATH);
	if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		int e = errno;
		close(fd);
		errno = e;
		return -1;
	}
	return fd;
}

static int fill_req_sockaddr(struct sfw_req_hdr *req,
			     const struct sockaddr *addr, socklen_t addrlen)
{
	if (!addr) {
		errno = EINVAL;
		return -1;
	}
	if (addr->sa_family == AF_INET) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
		if (addrlen < sizeof(*sin)) {
			errno = EINVAL;
			return -1;
		}
		req->family = AF_INET;
		req->ipv4_addr = sin->sin_addr.s_addr;
		req->port = sin->sin_port;
		return 0;
	}
	if (addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
		if (addrlen < sizeof(*sin6)) {
			errno = EINVAL;
			return -1;
		}
		req->family = AF_INET6;
		memcpy(req->ipv6_addr, &sin6->sin6_addr, 16);
		req->port = sin6->sin6_port;
		return 0;
	}
	errno = EAFNOSUPPORT;
	return -1;
}

static void unpack_resp_sockaddr(const struct sfw_resp_hdr *resp,
				 struct sockaddr_storage *out,
				 socklen_t *len_out)
{
	if (!out)
		return;
	memset(out, 0, sizeof(*out));
	if (resp->family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)out;
		sin6->sin6_family = AF_INET6;
		memcpy(&sin6->sin6_addr, resp->peer_addr6, 16);
		sin6->sin6_port = resp->peer_port;
		if (len_out)
			*len_out = sizeof(*sin6);
	} else {
		struct sockaddr_in *sin = (struct sockaddr_in *)out;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = resp->peer_addr;
		sin->sin_port = resp->peer_port;
		if (len_out)
			*len_out = sizeof(*sin);
	}
}

int pg_socket(int domain, int type, int protocol)
{
	struct sfw_req_hdr req = {
		.magic = SFW_PROTO_MAGIC,
		.op = SFW_OP_OPEN,
		.family = (uint16_t)domain,
		.sock_type = (uint16_t)(type & ~(SOCK_CLOEXEC | SOCK_NONBLOCK)),
		.proto = (uint16_t)protocol,
	};
	struct sfw_resp_hdr resp = {};
	int ufd;

	if (domain != AF_INET && domain != AF_INET6) {
		errno = EAFNOSUPPORT;
		return -1;
	}
	ufd = open_mux_channel();
	if (ufd < 0)
		return -1;
	if (write_all(ufd, &req, sizeof(req)) < 0 ||
	    read_all(ufd, &resp, sizeof(resp)) < 0 || resp.status < 0) {
		int err = resp.status < 0 ? -resp.status : EIO;
		close(ufd);
		errno = err;
		return -1;
	}
	return ufd;
}

int pg_bind_sa(int ufd, const struct sockaddr *addr, socklen_t addrlen,
	       const char *ifname)
{
	struct sfw_req_hdr req = {
		.magic = SFW_PROTO_MAGIC,
		.op = SFW_OP_BIND,
	};
	struct sfw_resp_hdr resp = {};

	if (fill_req_sockaddr(&req, addr, addrlen) < 0)
		return -1;
	if (ifname)
		snprintf(req.ifname, sizeof(req.ifname), "%s", ifname);
	if (write_all(ufd, &req, sizeof(req)) < 0 ||
	    read_all(ufd, &resp, sizeof(resp)) < 0) {
		errno = EIO;
		return -1;
	}
	if (resp.status < 0) {
		errno = -resp.status;
		return -1;
	}
	return 0;
}

int pg_bind(int ufd, const struct sockaddr_in *addr, const char *ifname)
{
	return pg_bind_sa(ufd, (const struct sockaddr *)addr,
			  sizeof(*addr), ifname);
}

int pg_bind6(int ufd, const struct sockaddr_in6 *addr, const char *ifname)
{
	return pg_bind_sa(ufd, (const struct sockaddr *)addr,
			  sizeof(*addr), ifname);
}

int pg_listen(int ufd, uint64_t *listener_token_out)
{
	struct sfw_req_hdr req = {
		.magic = SFW_PROTO_MAGIC,
		.op = SFW_OP_LISTEN,
	};
	struct sfw_resp_hdr resp = {};

	if (write_all(ufd, &req, sizeof(req)) < 0 ||
	    read_all(ufd, &resp, sizeof(resp)) < 0) {
		errno = EIO;
		return -1;
	}
	if (resp.status < 0) {
		errno = -resp.status;
		return -1;
	}
	if (listener_token_out)
		*listener_token_out = resp.handle_token;
	return 0;
}

int pg_accept_sa_flags(int listen_ufd, uint64_t listener_token,
		       struct sockaddr_storage *peer_out,
		       socklen_t *peer_len_out, uint16_t sfw_flags)
{
	struct sfw_req_hdr req = {
		.magic = SFW_PROTO_MAGIC,
		.op = SFW_OP_ACCEPT,
		.flags = sfw_flags,
		.listener_token = listener_token,
	};
	struct sfw_resp_hdr resp = {};
	int new_ufd;

	(void)listen_ufd;
	new_ufd = open_mux_channel();
	if (new_ufd < 0)
		return -1;
	if (write_all(new_ufd, &req, sizeof(req)) < 0 ||
	    read_all(new_ufd, &resp, sizeof(resp)) < 0 || resp.status < 0) {
		int err = resp.status < 0 ? -resp.status : EIO;
		close(new_ufd);
		errno = err;
		return -1;
	}
	unpack_resp_sockaddr(&resp, peer_out, peer_len_out);
	return new_ufd;
}

int pg_accept_sa(int listen_ufd, uint64_t listener_token,
		 struct sockaddr_storage *peer_out, socklen_t *peer_len_out)
{
	return pg_accept_sa_flags(listen_ufd, listener_token, peer_out,
				  peer_len_out, 0);
}

int pg_accept(int listen_ufd, uint64_t listener_token,
	      struct sockaddr_in *peer_out)
{
	struct sockaddr_storage ss;
	int nfd = pg_accept_sa(listen_ufd, listener_token, &ss, NULL);
	if (nfd >= 0 && peer_out && ss.ss_family == AF_INET)
		memcpy(peer_out, &ss, sizeof(*peer_out));
	return nfd;
}

int pg_accept6(int listen_ufd, uint64_t listener_token,
	       struct sockaddr_in6 *peer_out)
{
	struct sockaddr_storage ss;
	int nfd = pg_accept_sa(listen_ufd, listener_token, &ss, NULL);
	if (nfd >= 0 && peer_out && ss.ss_family == AF_INET6)
		memcpy(peer_out, &ss, sizeof(*peer_out));
	return nfd;
}

int pg_connect_sa(int ufd, const struct sockaddr *addr, socklen_t addrlen,
		  const char *ifname)
{
	struct sfw_req_hdr req = {
		.magic = SFW_PROTO_MAGIC,
		.op = SFW_OP_CONNECT,
	};
	struct sfw_resp_hdr resp = {};

	if (fill_req_sockaddr(&req, addr, addrlen) < 0)
		return -1;
	if (ifname)
		snprintf(req.ifname, sizeof(req.ifname), "%s", ifname);
	if (write_all(ufd, &req, sizeof(req)) < 0 ||
	    read_all(ufd, &resp, sizeof(resp)) < 0) {
		errno = EIO;
		return -1;
	}
	if (resp.status < 0) {
		errno = -resp.status;
		return -1;
	}
	return 0;
}

int pg_connect(int ufd, const struct sockaddr_in *addr, const char *ifname)
{
	return pg_connect_sa(ufd, (const struct sockaddr *)addr,
			     sizeof(*addr), ifname);
}

int pg_connect6(int ufd, const struct sockaddr_in6 *addr, const char *ifname)
{
	return pg_connect_sa(ufd, (const struct sockaddr *)addr,
			     sizeof(*addr), ifname);
}

ssize_t pg_send_flags(int ufd, const void *buf, size_t len, uint16_t sfw_flags)
{
	struct sfw_req_hdr req = {
		.magic = SFW_PROTO_MAGIC,
		.op = SFW_OP_SEND,
		.flags = sfw_flags,
		.payload_len = (uint32_t)len,
	};
	struct sfw_resp_hdr resp = {};

	if (write_all(ufd, &req, sizeof(req)) < 0 ||
	    (len > 0 && write_all(ufd, buf, len) < 0) ||
	    read_all(ufd, &resp, sizeof(resp)) < 0) {
		errno = EIO;
		return -1;
	}
	if (resp.status < 0) {
		errno = -resp.status;
		return -1;
	}
	return (ssize_t)resp.status;
}

ssize_t pg_send(int ufd, const void *buf, size_t len)
{
	return pg_send_flags(ufd, buf, len, 0);
}

ssize_t pg_recv(int ufd, void *buf, size_t len, uint16_t sfw_flags)
{
	struct sfw_req_hdr req = {
		.magic = SFW_PROTO_MAGIC,
		.op = SFW_OP_RECV,
		.flags = sfw_flags,
		.payload_len = (uint32_t)len,
	};
	struct sfw_resp_hdr resp = {};

	if (write_all(ufd, &req, sizeof(req)) < 0 ||
	    read_all(ufd, &resp, sizeof(resp)) < 0) {
		errno = EIO;
		return -1;
	}
	if (resp.status < 0) {
		errno = -resp.status;
		return -1;
	}
	if (resp.payload_len > 0 &&
	    read_all(ufd, buf, resp.payload_len) < 0) {
		errno = EIO;
		return -1;
	}
	return (ssize_t)resp.status;
}

ssize_t pg_sendto_sa(int ufd, const void *buf, size_t len, uint16_t sfw_flags,
		     const struct sockaddr *dst, socklen_t dstlen,
		     const char *ifname)
{
	struct sfw_req_hdr req = {
		.magic = SFW_PROTO_MAGIC,
		.op = SFW_OP_SENDTO,
		.flags = sfw_flags,
		.payload_len = (uint32_t)len,
	};
	struct sfw_resp_hdr resp = {};

	if (!dst)
		return pg_send_flags(ufd, buf, len, sfw_flags);
	if (fill_req_sockaddr(&req, dst, dstlen) < 0)
		return -1;
	if (ifname)
		snprintf(req.ifname, sizeof(req.ifname), "%s", ifname);
	if (write_all(ufd, &req, sizeof(req)) < 0 ||
	    (len > 0 && write_all(ufd, buf, len) < 0) ||
	    read_all(ufd, &resp, sizeof(resp)) < 0) {
		errno = EIO;
		return -1;
	}
	if (resp.status < 0) {
		errno = -resp.status;
		return -1;
	}
	return (ssize_t)resp.status;
}

ssize_t pg_recvfrom_sa(int ufd, void *buf, size_t len, uint16_t sfw_flags,
		       struct sockaddr_storage *src_out, socklen_t *srclen_out)
{
	struct sfw_req_hdr req = {
		.magic = SFW_PROTO_MAGIC,
		.op = SFW_OP_RECVFROM,
		.flags = sfw_flags,
		.payload_len = (uint32_t)len,
	};
	struct sfw_resp_hdr resp = {};

	if (write_all(ufd, &req, sizeof(req)) < 0 ||
	    read_all(ufd, &resp, sizeof(resp)) < 0) {
		errno = EIO;
		return -1;
	}
	if (resp.status < 0) {
		errno = -resp.status;
		return -1;
	}
	if (resp.payload_len > 0 &&
	    read_all(ufd, buf, resp.payload_len) < 0) {
		errno = EIO;
		return -1;
	}
	unpack_resp_sockaddr(&resp, src_out, srclen_out);
	return (ssize_t)resp.status;
}

int pg_poll_events(int ufd)
{
	struct sfw_req_hdr req = {
		.magic = SFW_PROTO_MAGIC,
		.op = SFW_OP_POLL,
	};
	struct sfw_resp_hdr resp = {};

	if (write_all(ufd, &req, sizeof(req)) < 0 ||
	    read_all(ufd, &resp, sizeof(resp)) < 0) {
		errno = EIO;
		return -1;
	}
	if (resp.status < 0) {
		errno = -resp.status;
		return -1;
	}
	return resp.status;
}

int pg_getsockname_sa(int ufd, struct sockaddr_storage *out, socklen_t *len_out)
{
	struct sfw_req_hdr req = {
		.magic = SFW_PROTO_MAGIC,
		.op = SFW_OP_GETSOCKNAME,
	};
	struct sfw_resp_hdr resp = {};

	if (write_all(ufd, &req, sizeof(req)) < 0 ||
	    read_all(ufd, &resp, sizeof(resp)) < 0) {
		errno = EIO;
		return -1;
	}
	if (resp.status < 0) {
		errno = -resp.status;
		return -1;
	}
	unpack_resp_sockaddr(&resp, out, len_out);
	return 0;
}

int pg_getpeername_sa(int ufd, struct sockaddr_storage *out, socklen_t *len_out)
{
	struct sfw_req_hdr req = {
		.magic = SFW_PROTO_MAGIC,
		.op = SFW_OP_GETPEERNAME,
	};
	struct sfw_resp_hdr resp = {};

	if (write_all(ufd, &req, sizeof(req)) < 0 ||
	    read_all(ufd, &resp, sizeof(resp)) < 0) {
		errno = EIO;
		return -1;
	}
	if (resp.status < 0) {
		errno = -resp.status;
		return -1;
	}
	unpack_resp_sockaddr(&resp, out, len_out);
	return 0;
}

int pg_setsockopt_int(int ufd, uint16_t sfw_opt_id, int val)
{
	struct sfw_req_hdr req = {
		.magic = SFW_PROTO_MAGIC,
		.op = SFW_OP_SETSOCKOPT,
		.proto = sfw_opt_id,
		.payload_len = (uint32_t)val,
	};
	struct sfw_resp_hdr resp = {};

	if (write_all(ufd, &req, sizeof(req)) < 0 ||
	    read_all(ufd, &resp, sizeof(resp)) < 0) {
		errno = EIO;
		return -1;
	}
	if (resp.status < 0) {
		errno = -resp.status;
		return -1;
	}
	return 0;
}

int pg_shutdown(int ufd, int how)
{
	struct sfw_req_hdr req = {
		.magic = SFW_PROTO_MAGIC,
		.op = SFW_OP_SHUTDOWN,
		.payload_len = (uint32_t)how,
	};
	struct sfw_resp_hdr resp = {};

	if (write_all(ufd, &req, sizeof(req)) < 0 ||
	    read_all(ufd, &resp, sizeof(resp)) < 0) {
		errno = EIO;
		return -1;
	}
	if (resp.status < 0) {
		errno = -resp.status;
		return -1;
	}
	return 0;
}

int pg_close(int ufd)
{
	struct sfw_req_hdr req = {
		.magic = SFW_PROTO_MAGIC,
		.op = SFW_OP_CLOSE,
	};
	struct sfw_resp_hdr resp = {};

	(void)write_all(ufd, &req, sizeof(req));
	(void)read_all(ufd, &resp, sizeof(resp));
	return close(ufd);
}
