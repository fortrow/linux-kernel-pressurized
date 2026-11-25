// SPDX-License-Identifier: GPL-2.0
/*
 * sfw (Socket Firewall) & Root-Owned AF_UNIX Kernel Socket Worker
 *
 * Replaces Netfilter by converting all localhost (127.0.0.1) and external
 * IP/device socket operations into root-owned local AF_UNIX streams at
 * /run/pressure/sfw/mux.sock, authenticating every operation against
 * Pressure LSM's IP, device, secret UID/session, provenance, and FD mappings.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/sched/signal.h>
#include <linux/fs_struct.h>
#include <linux/namei.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/un.h>
#include <linux/poll.h>
#include <linux/tcp.h>
#include <linux/netdevice.h>
#include <linux/random.h>
#include <linux/delay.h>
#include <net/sock.h>
#include <net/ipv6.h>
#include <net/af_unix.h>
#include <uapi/linux/sfw.h>
#include "sfw_internal.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pressure Security Project");
MODULE_DESCRIPTION("sfw: Root-owned AF_UNIX Socket Worker & Provenance Firewall");

/* Symbols exported by security/pressure/ident_policy.c */
extern int pressure_register_sfw_worker(struct task_struct *worker);
extern int pressure_sfw_authorize(struct task_struct *peer_task,
				  const struct cred *peer_cred, u32 dir,
				  __be32 ipv4_addr, u16 host_port,
				  const char *ifname, u64 sock_pub_id);
extern int pressure_sfw_authorize6(struct task_struct *peer_task,
				   const struct cred *peer_cred, u32 dir,
				   const struct in6_addr *ipv6_addr,
				   u16 host_port, const char *ifname,
				   u64 sock_pub_id);
extern void pressure_taint_task_remote(struct task_struct *peer_task);

#define SFW_MAX_PAYLOAD (64 * 1024)

struct sfw_conn_ctx {
	struct list_head listener_node;
	struct socket *unix_sock;
	struct socket *ip_sock;
	u64 token;
	uid_t owner_pub_uid;
	u16 family;
	__be32 bound_or_peer_ip;
	struct in6_addr bound_or_peer_ip6;
	u16 bound_or_peer_port;
	char ifname[16];
	bool is_listener;
	bool remote_peer;
};

static DEFINE_MUTEX(listener_lock);
static LIST_HEAD(listener_list);
static struct socket *sfw_mux_sock;
static struct task_struct *sfw_accept_task;
static atomic_t sfw_stopping = ATOMIC_INIT(0);

static int ksock_read_exact(struct socket *sock, void *buf, size_t len)
{
	size_t off = 0;

	while (off < len) {
		struct msghdr msg = {};
		struct kvec iov = {
			.iov_base = (char *)buf + off,
			.iov_len  = len - off,
		};
		int r = kernel_recvmsg(sock, &msg, &iov, 1, len - off, 0);
		if (r <= 0)
			return r == 0 ? -ECONNRESET : r;
		off += (size_t)r;
	}
	return 0;
}

static int ksock_write_exact(struct socket *sock, const void *buf, size_t len)
{
	size_t off = 0;

	while (off < len) {
		struct msghdr msg = { .msg_flags = MSG_NOSIGNAL };
		struct kvec iov = {
			.iov_base = (void *)((const char *)buf + off),
			.iov_len  = len - off,
		};
		int r = kernel_sendmsg(sock, &msg, &iov, 1, len - off);
		if (r < 0)
			return r;
		if (r == 0)
			return -EPIPE;
		off += (size_t)r;
	}
	return 0;
}

static int bind_sock_to_dev(struct socket *ip_sock, u16 family,
			    __be32 ipv4_addr, const struct in6_addr *ipv6_addr,
			    const char *ifname)
{
	const char *want = NULL;
	struct net_device *ndev;
	int err;

	if (family == AF_INET6) {
		if (ipv6_addr && (ipv6_addr_loopback(ipv6_addr) ||
				  ipv6_addr_v4mapped_loopback(ipv6_addr)))
			want = "lo";
		else if (ifname && ifname[0])
			want = ifname;
	} else {
		if (ipv4_is_loopback(ipv4_addr))
			want = "lo";
		else if (ifname && ifname[0])
			want = ifname;
	}

	if (!want)
		return 0;

	ndev = dev_get_by_name(&init_net, want);
	if (!ndev)
		return -ENODEV;

	err = sock_bindtoindex(ip_sock->sk, ndev->ifindex, true);
	dev_put(ndev);
	return err;
}

static int sfw_conn_worker(void *arg)
{
	struct sfw_conn_ctx *ctx = arg;
	struct sock *usk = ctx->unix_sock->sk;
	const struct cred *peer_cred = NULL;
	struct pid *peer_pid = NULL;
	void *pbuf = NULL;

	spin_lock(&usk->sk_peer_lock);
	if (usk->sk_peer_cred)
		peer_cred = get_cred(usk->sk_peer_cred);
	if (usk->sk_peer_pid)
		peer_pid = get_pid(usk->sk_peer_pid);
	spin_unlock(&usk->sk_peer_lock);

	ctx->owner_pub_uid = peer_cred ?
		from_kuid_munged(&init_user_ns, peer_cred->uid) : 0;
	ctx->token = get_random_u64() | 1ULL;
	pbuf = kvmalloc(SFW_MAX_PAYLOAD, GFP_KERNEL);
	if (!pbuf)
		goto out;

	while (!kthread_should_stop() && !atomic_read(&sfw_stopping)) {
		struct sfw_req_hdr req;
		struct sfw_resp_hdr resp = { .magic = SFW_PROTO_MAGIC };
		struct task_struct *peer_task = NULL;
		int err;

		err = ksock_read_exact(ctx->unix_sock, &req, sizeof(req));
		if (err < 0)
			break;
		if (req.magic != SFW_PROTO_MAGIC ||
		    req.payload_len > SFW_MAX_PAYLOAD) {
			resp.status = -EINVAL;
			ksock_write_exact(ctx->unix_sock, &resp, sizeof(resp));
			break;
		}
		req.ifname[sizeof(req.ifname) - 1] = '\0';

		rcu_read_lock();
		if (peer_pid) {
			peer_task = pid_task(peer_pid, PIDTYPE_PID);
			if (peer_task)
				get_task_struct(peer_task);
		}
		rcu_read_unlock();

		switch (req.op) {
		case SFW_OP_OPEN: {
			int stype = req.sock_type ? req.sock_type : SOCK_STREAM;
			u16 fam = (req.family == AF_INET6) ? AF_INET6 : AF_INET;
			if (ctx->ip_sock) {
				resp.status = -EALREADY;
				break;
			}
			err = sock_create_kern(&init_net, fam, stype,
					       req.proto, &ctx->ip_sock);
			if (err == 0) {
				ctx->family = fam;
				sock_set_reuseaddr(ctx->ip_sock->sk);
				resp.family = fam;
				resp.handle_token = ctx->token;
			}
			resp.status = err;
			break;
		}
		case SFW_OP_BIND: {
			u16 fam = ctx->family ? ctx->family :
				  ((req.family == AF_INET6) ? AF_INET6 : AF_INET);
			if (!ctx->ip_sock) {
				resp.status = -EBADF;
				break;
			}
			if (fam == AF_INET6) {
				struct in6_addr addr6;
				struct sockaddr_in6 sin6 = {
					.sin6_family = AF_INET6,
					.sin6_port = req.port,
				};
				memcpy(&addr6, req.ipv6_addr, 16);
				sin6.sin6_addr = addr6;
				err = pressure_sfw_authorize6(peer_task, peer_cred,
							      SFW_DIR_BIND, &addr6,
							      ntohs(req.port),
							      req.ifname,
							      ctx->token);
				if (err < 0) {
					resp.status = err;
					break;
				}
				err = bind_sock_to_dev(ctx->ip_sock, AF_INET6,
						       0, &addr6, req.ifname);
				if (err == 0)
					err = kernel_bind(ctx->ip_sock,
							  (struct sockaddr_unsized *)&sin6,
							  sizeof(sin6));
				if (err == 0) {
					ctx->family = AF_INET6;
					ctx->bound_or_peer_ip6 = addr6;
					ctx->bound_or_peer_port = ntohs(req.port);
					strscpy(ctx->ifname, req.ifname,
						sizeof(ctx->ifname));
					resp.family = AF_INET6;
					resp.handle_token = ctx->token;
				}
				resp.status = err;
			} else {
				struct sockaddr_in sin = {
					.sin_family = AF_INET,
					.sin_addr.s_addr = req.ipv4_addr,
					.sin_port = req.port,
				};
				err = pressure_sfw_authorize(peer_task, peer_cred,
							     SFW_DIR_BIND,
							     req.ipv4_addr,
							     ntohs(req.port),
							     req.ifname,
							     ctx->token);
				if (err < 0) {
					resp.status = err;
					break;
				}
				err = bind_sock_to_dev(ctx->ip_sock, AF_INET,
						       req.ipv4_addr, NULL,
						       req.ifname);
				if (err == 0)
					err = kernel_bind(ctx->ip_sock,
							  (struct sockaddr_unsized *)&sin,
							  sizeof(sin));
				if (err == 0) {
					ctx->family = AF_INET;
					ctx->bound_or_peer_ip = req.ipv4_addr;
					ctx->bound_or_peer_port = ntohs(req.port);
					strscpy(ctx->ifname, req.ifname,
						sizeof(ctx->ifname));
					resp.family = AF_INET;
					resp.handle_token = ctx->token;
				}
				resp.status = err;
			}
			break;
		}
		case SFW_OP_LISTEN: {
			if (!ctx->ip_sock) {
				resp.status = -EBADF;
				break;
			}
			err = kernel_listen(ctx->ip_sock, 16);
			if (err == 0 && !ctx->is_listener) {
				mutex_lock(&listener_lock);
				ctx->is_listener = true;
				list_add_tail(&ctx->listener_node, &listener_list);
				mutex_unlock(&listener_lock);
				resp.handle_token = ctx->token;
			}
			resp.status = err;
			break;
		}
		case SFW_OP_ACCEPT: {
			struct sfw_conn_ctx *lctx = NULL, *iter;
			struct socket *newsock = NULL;

			if (ctx->ip_sock) {
				resp.status = -EALREADY;
				break;
			}
			mutex_lock(&listener_lock);
			list_for_each_entry(iter, &listener_list, listener_node) {
				if (iter->token == req.listener_token &&
				    iter->owner_pub_uid == ctx->owner_pub_uid) {
					lctx = iter;
					break;
				}
			}
			mutex_unlock(&listener_lock);
			if (!lctx || !lctx->ip_sock) {
				resp.status = -EACCES;
				break;
			}
			err = kernel_accept(lctx->ip_sock, &newsock,
					    (req.flags & SFW_FLAG_NONBLOCK) ?
					    SOCK_NONBLOCK : 0);
			if (err < 0) {
				resp.status = err;
				break;
			}
			if (newsock)
				newsock->file = NULL;
			if (lctx->family == AF_INET6) {
				struct sockaddr_in6 psin6 = {};
				kernel_getpeername(newsock,
						   (struct sockaddr *)&psin6);
				err = pressure_sfw_authorize6(peer_task,
							      peer_cred,
							      SFW_DIR_RECV,
							      &psin6.sin6_addr,
							      ntohs(psin6.sin6_port),
							      lctx->ifname,
							      ctx->token);
				if (err < 0) {
					sock_release(newsock);
					resp.status = err;
					break;
				}
				ctx->ip_sock = newsock;
				ctx->family = AF_INET6;
				ctx->bound_or_peer_ip6 = psin6.sin6_addr;
				ctx->bound_or_peer_port = ntohs(psin6.sin6_port);
				strscpy(ctx->ifname, lctx->ifname,
					sizeof(ctx->ifname));
				ctx->remote_peer = !(ipv6_addr_loopback(&psin6.sin6_addr) ||
						     ipv6_addr_v4mapped_loopback(&psin6.sin6_addr));
				if (ctx->remote_peer && peer_task)
					pressure_taint_task_remote(peer_task);

				resp.status = 0;
				resp.family = AF_INET6;
				memcpy(resp.peer_addr6, &psin6.sin6_addr, 16);
				resp.peer_port = psin6.sin6_port;
				resp.handle_token = ctx->token;
			} else {
				struct sockaddr_in psin = {};
				kernel_getpeername(newsock,
						   (struct sockaddr *)&psin);
				err = pressure_sfw_authorize(peer_task, peer_cred,
							     SFW_DIR_RECV,
							     psin.sin_addr.s_addr,
							     ntohs(psin.sin_port),
							     lctx->ifname,
							     ctx->token);
				if (err < 0) {
					sock_release(newsock);
					resp.status = err;
					break;
				}
				ctx->ip_sock = newsock;
				ctx->family = AF_INET;
				ctx->bound_or_peer_ip = psin.sin_addr.s_addr;
				ctx->bound_or_peer_port = ntohs(psin.sin_port);
				strscpy(ctx->ifname, lctx->ifname,
					sizeof(ctx->ifname));
				ctx->remote_peer = !ipv4_is_loopback(psin.sin_addr.s_addr);
				if (ctx->remote_peer && peer_task)
					pressure_taint_task_remote(peer_task);

				resp.status = 0;
				resp.family = AF_INET;
				resp.peer_addr = psin.sin_addr.s_addr;
				resp.peer_port = psin.sin_port;
				resp.handle_token = ctx->token;
			}
			break;
		}
		case SFW_OP_CONNECT: {
			u16 fam = (req.family == AF_INET6 ||
				   ctx->family == AF_INET6) ? AF_INET6 : AF_INET;
			if (fam == AF_INET6) {
				struct in6_addr dst6;
				struct sockaddr_in6 sin6 = {
					.sin6_family = AF_INET6,
				};
				memcpy(&dst6, req.ipv6_addr, 16);
				sfw_apply_broker_dnat6(&dst6, &req.port,
						       req.ifname);
				sin6.sin6_addr = dst6;
				sin6.sin6_port = req.port;
				if (!ctx->ip_sock) {
					err = sock_create_kern(&init_net,
							       AF_INET6,
							       SOCK_STREAM, 0,
							       &ctx->ip_sock);
					if (err < 0) {
						resp.status = err;
						break;
					}
					ctx->family = AF_INET6;
				}
				err = pressure_sfw_authorize6(peer_task,
							      peer_cred,
							      SFW_DIR_CONNECT,
							      &dst6,
							      ntohs(req.port),
							      req.ifname,
							      ctx->token);
				if (err < 0) {
					resp.status = err;
					break;
				}
				err = bind_sock_to_dev(ctx->ip_sock, AF_INET6,
						       0, &dst6, req.ifname);
				if (err == 0)
					err = kernel_connect(ctx->ip_sock,
							     (struct sockaddr_unsized *)&sin6,
							     sizeof(sin6), 0);
				if (err == 0) {
					ctx->family = AF_INET6;
					ctx->bound_or_peer_ip6 = dst6;
					ctx->bound_or_peer_port = ntohs(req.port);
					strscpy(ctx->ifname, req.ifname,
						sizeof(ctx->ifname));
					ctx->remote_peer = !(ipv6_addr_loopback(&dst6) ||
							     ipv6_addr_v4mapped_loopback(&dst6));
					resp.family = AF_INET6;
					resp.handle_token = ctx->token;
				}
				resp.status = err;
			} else {
				sfw_apply_broker_dnat(&req.ipv4_addr, &req.port,
						      req.ifname);
				struct sockaddr_in sin = {
					.sin_family = AF_INET,
					.sin_addr.s_addr = req.ipv4_addr,
					.sin_port = req.port,
				};
				if (!ctx->ip_sock) {
					err = sock_create_kern(&init_net, AF_INET,
							       SOCK_STREAM, 0,
							       &ctx->ip_sock);
					if (err < 0) {
						resp.status = err;
						break;
					}
					ctx->family = AF_INET;
				}
				err = pressure_sfw_authorize(peer_task, peer_cred,
							     SFW_DIR_CONNECT,
							     req.ipv4_addr,
							     ntohs(req.port),
							     req.ifname,
							     ctx->token);
				if (err < 0) {
					resp.status = err;
					break;
				}
				err = bind_sock_to_dev(ctx->ip_sock, AF_INET,
						       req.ipv4_addr, NULL,
						       req.ifname);
				if (err == 0)
					err = kernel_connect(ctx->ip_sock,
							     (struct sockaddr_unsized *)&sin,
							     sizeof(sin), 0);
				if (err == 0) {
					ctx->family = AF_INET;
					ctx->bound_or_peer_ip = req.ipv4_addr;
					ctx->bound_or_peer_port = ntohs(req.port);
					strscpy(ctx->ifname, req.ifname,
						sizeof(ctx->ifname));
					ctx->remote_peer = !ipv4_is_loopback(req.ipv4_addr);
					resp.family = AF_INET;
					resp.handle_token = ctx->token;
				}
				resp.status = err;
			}
			break;
		}
		case SFW_OP_SEND: {
			struct msghdr msg = {
				.msg_flags = MSG_NOSIGNAL |
					((req.flags & SFW_FLAG_NONBLOCK) ?
					 MSG_DONTWAIT : 0),
			};
			struct kvec iov = { .iov_base = pbuf, .iov_len = req.payload_len };

			if (req.payload_len > 0) {
				err = ksock_read_exact(ctx->unix_sock, pbuf,
						       req.payload_len);
				if (err < 0) {
					if (peer_task)
						put_task_struct(peer_task);
					goto out;
				}
			}
			if (!ctx->ip_sock) {
				resp.status = -EBADF;
				break;
			}
			if (ctx->family == AF_INET6)
				err = pressure_sfw_authorize6(peer_task,
							      peer_cred,
							      SFW_DIR_SEND,
							      &ctx->bound_or_peer_ip6,
							      ctx->bound_or_peer_port,
							      ctx->ifname,
							      ctx->token);
			else
				err = pressure_sfw_authorize(peer_task, peer_cred,
							     SFW_DIR_SEND,
							     ctx->bound_or_peer_ip,
							     ctx->bound_or_peer_port,
							     ctx->ifname,
							     ctx->token);
			if (err < 0) {
				resp.status = err;
				break;
			}
			resp.status = kernel_sendmsg(ctx->ip_sock, &msg, &iov, 1,
						     req.payload_len);
			break;
		}
		case SFW_OP_RECV: {
			struct msghdr msg = {};
			struct kvec iov = { .iov_base = pbuf, .iov_len = req.payload_len };
			int rflags = (req.flags & SFW_FLAG_NONBLOCK) ?
				     MSG_DONTWAIT : 0;
			int rlen;

			if (!ctx->ip_sock) {
				resp.status = -EBADF;
				break;
			}
			if (ctx->family == AF_INET6)
				err = pressure_sfw_authorize6(peer_task,
							      peer_cred,
							      SFW_DIR_RECV,
							      &ctx->bound_or_peer_ip6,
							      ctx->bound_or_peer_port,
							      ctx->ifname,
							      ctx->token);
			else
				err = pressure_sfw_authorize(peer_task, peer_cred,
							     SFW_DIR_RECV,
							     ctx->bound_or_peer_ip,
							     ctx->bound_or_peer_port,
							     ctx->ifname,
							     ctx->token);
			if (err < 0) {
				resp.status = err;
				break;
			}
			rlen = kernel_recvmsg(ctx->ip_sock, &msg, &iov, 1,
					      req.payload_len, rflags);
			if (rlen > 0) {
				if ((ctx->remote_peer ||
				     (req.flags & SFW_FLAG_REMOTE_TAINT)) &&
				    peer_task)
					pressure_taint_task_remote(peer_task);
				resp.status = rlen;
				resp.payload_len = (u32)rlen;
			} else {
				resp.status = rlen;
			}
			break;
		}
		case SFW_OP_SENDTO: {
			struct sockaddr_in sin = { .sin_family = AF_INET };
			struct sockaddr_in6 sin6 = { .sin6_family = AF_INET6 };
			struct msghdr msg = {
				.msg_flags = MSG_NOSIGNAL |
					((req.flags & SFW_FLAG_NONBLOCK) ?
					 MSG_DONTWAIT : 0),
			};
			struct kvec iov = { .iov_base = pbuf, .iov_len = req.payload_len };
			u16 fam = (req.family == AF_INET6 ||
				   ctx->family == AF_INET6) ? AF_INET6 : AF_INET;

			if (req.payload_len > 0) {
				err = ksock_read_exact(ctx->unix_sock, pbuf,
						       req.payload_len);
				if (err < 0) {
					if (peer_task)
						put_task_struct(peer_task);
					goto out;
				}
			}
			if (!ctx->ip_sock) {
				resp.status = -EBADF;
				break;
			}
			if (fam == AF_INET6) {
				struct in6_addr dst6;
				memcpy(&dst6, req.ipv6_addr, 16);
				sfw_apply_broker_dnat6(&dst6, &req.port, req.ifname);
				err = pressure_sfw_authorize6(peer_task, peer_cred,
							      SFW_DIR_SEND, &dst6,
							      ntohs(req.port),
							      req.ifname,
							      ctx->token);
				if (err < 0) {
					resp.status = err;
					break;
				}
				sin6.sin6_addr = dst6;
				sin6.sin6_port = req.port;
				msg.msg_name = &sin6;
				msg.msg_namelen = sizeof(sin6);
			} else {
				sfw_apply_broker_dnat(&req.ipv4_addr, &req.port,
						      req.ifname);
				err = pressure_sfw_authorize(peer_task, peer_cred,
							     SFW_DIR_SEND,
							     req.ipv4_addr,
							     ntohs(req.port),
							     req.ifname,
							     ctx->token);
				if (err < 0) {
					resp.status = err;
					break;
				}
				sin.sin_addr.s_addr = req.ipv4_addr;
				sin.sin_port = req.port;
				msg.msg_name = &sin;
				msg.msg_namelen = sizeof(sin);
			}
			resp.status = kernel_sendmsg(ctx->ip_sock, &msg, &iov, 1,
						     req.payload_len);
			break;
		}
		case SFW_OP_RECVFROM: {
			struct sockaddr_storage pss = {};
			struct msghdr msg = {
				.msg_name = &pss,
				.msg_namelen = sizeof(pss),
			};
			struct kvec iov = { .iov_base = pbuf, .iov_len = req.payload_len };
			int rflags = (req.flags & SFW_FLAG_NONBLOCK) ?
				     MSG_DONTWAIT : 0;
			int rlen;

			if (!ctx->ip_sock) {
				resp.status = -EBADF;
				break;
			}
			rlen = kernel_recvmsg(ctx->ip_sock, &msg, &iov, 1,
					      req.payload_len, rflags);
			if (rlen < 0) {
				resp.status = rlen;
				break;
			}
			if (pss.ss_family == AF_INET6) {
				struct sockaddr_in6 *s6 =
					(struct sockaddr_in6 *)&pss;
				err = pressure_sfw_authorize6(peer_task, peer_cred,
							      SFW_DIR_RECV,
							      &s6->sin6_addr,
							      ntohs(s6->sin6_port),
							      ctx->ifname,
							      ctx->token);
				if (err < 0) {
					resp.status = err;
					break;
				}
				if (!(ipv6_addr_loopback(&s6->sin6_addr) ||
				      ipv6_addr_v4mapped_loopback(&s6->sin6_addr)) &&
				    peer_task)
					pressure_taint_task_remote(peer_task);
				resp.family = AF_INET6;
				memcpy(resp.peer_addr6, &s6->sin6_addr, 16);
				resp.peer_port = s6->sin6_port;
			} else {
				struct sockaddr_in *s4 =
					(struct sockaddr_in *)&pss;
				err = pressure_sfw_authorize(peer_task, peer_cred,
							     SFW_DIR_RECV,
							     s4->sin_addr.s_addr,
							     ntohs(s4->sin_port),
							     ctx->ifname,
							     ctx->token);
				if (err < 0) {
					resp.status = err;
					break;
				}
				if (!ipv4_is_loopback(s4->sin_addr.s_addr) &&
				    peer_task)
					pressure_taint_task_remote(peer_task);
				resp.family = AF_INET;
				resp.peer_addr = s4->sin_addr.s_addr;
				resp.peer_port = s4->sin_port;
			}
			resp.status = rlen;
			resp.payload_len = (u32)rlen;
			break;
		}
		case SFW_OP_POLL: {
			struct file dummy_file = { .f_flags = O_NONBLOCK };
			__poll_t pmask;
			if (!ctx->ip_sock || !ctx->ip_sock->ops ||
			    !ctx->ip_sock->ops->poll) {
				resp.status = -EBADF;
				break;
			}
			pmask = ctx->ip_sock->ops->poll(&dummy_file,
							ctx->ip_sock, NULL);
			resp.status = (s32)((__force u32)pmask & 0x7fffffffU);
			break;
		}
		case SFW_OP_GETSOCKNAME:
		case SFW_OP_GETPEERNAME: {
			struct sockaddr_storage ss = {};
			if (!ctx->ip_sock) {
				resp.status = -EBADF;
				break;
			}
			err = (req.op == SFW_OP_GETSOCKNAME) ?
			      kernel_getsockname(ctx->ip_sock, (struct sockaddr *)&ss) :
			      kernel_getpeername(ctx->ip_sock, (struct sockaddr *)&ss);
			if (err < 0) {
				resp.status = err;
				break;
			}
			if (ss.ss_family == AF_INET6) {
				struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ss;
				resp.family = AF_INET6;
				memcpy(resp.peer_addr6, &s6->sin6_addr, 16);
				resp.peer_port = s6->sin6_port;
			} else {
				struct sockaddr_in *s4 = (struct sockaddr_in *)&ss;
				resp.family = AF_INET;
				resp.peer_addr = s4->sin_addr.s_addr;
				resp.peer_port = s4->sin_port;
			}
			resp.status = 0;
			break;
		}
		case SFW_OP_SETSOCKOPT: {
			struct sock *sk;
			int val = (int)req.payload_len;
			if (!ctx->ip_sock || !ctx->ip_sock->sk) {
				resp.status = -EBADF;
				break;
			}
			sk = ctx->ip_sock->sk;
			resp.status = 0;
			switch (req.proto) {
			case SFW_SOCKOPT_REUSEADDR:
				if (val)
					sock_set_reuseaddr(sk);
				break;
			case SFW_SOCKOPT_REUSEPORT:
				if (val)
					sock_set_reuseport(sk);
				break;
			case SFW_SOCKOPT_KEEPALIVE:
				if (val)
					sock_set_keepalive(sk);
				break;
			case SFW_SOCKOPT_BROADCAST:
				sock_valbool_flag(sk, SOCK_BROADCAST, val != 0);
				break;
			case SFW_SOCKOPT_TCP_NODELAY:
				if (sk_is_tcp(sk) && val)
					tcp_sock_set_nodelay(sk);
				break;
			case SFW_SOCKOPT_IPV6_V6ONLY:
				if (sk->sk_family == AF_INET6)
					sk->sk_ipv6only = val ? 1 : 0;
				break;
			default:
				resp.status = -ENOPROTOOPT;
				break;
			}
			break;
		}
		case SFW_OP_SHUTDOWN: {
			if (!ctx->ip_sock) {
				resp.status = -EBADF;
				break;
			}
			resp.status = kernel_sock_shutdown(
				ctx->ip_sock,
				(enum sock_shutdown_cmd)req.payload_len);
			break;
		}
		case SFW_OP_CLOSE:
			if (peer_task)
				put_task_struct(peer_task);
			resp.status = 0;
			ksock_write_exact(ctx->unix_sock, &resp, sizeof(resp));
			goto out;
		default:
			resp.status = -EOPNOTSUPP;
			break;
		}

		if (peer_task)
			put_task_struct(peer_task);

		if (ksock_write_exact(ctx->unix_sock, &resp, sizeof(resp)) < 0)
			break;
		if (resp.payload_len > 0 &&
		    ksock_write_exact(ctx->unix_sock, pbuf, resp.payload_len) < 0)
			break;
	}

out:
	if (ctx->is_listener) {
		mutex_lock(&listener_lock);
		list_del(&ctx->listener_node);
		ctx->is_listener = false;
		mutex_unlock(&listener_lock);
	}
	if (ctx->ip_sock)
		sock_release(ctx->ip_sock);
	if (ctx->unix_sock)
		sock_release(ctx->unix_sock);
	if (peer_cred)
		put_cred(peer_cred);
	if (peer_pid)
		put_pid(peer_pid);
	kvfree(pbuf);
	kfree(ctx);
	return 0;
}

static void unlink_old_mux_sock(void)
{
	struct path p;
	struct dentry *parent;

	if (kern_path(SFW_MUX_SOCK_PATH, 0, &p) == 0) {
		parent = dget_parent(p.dentry);
		inode_lock_nested(d_inode(parent), I_MUTEX_PARENT);
		vfs_unlink(&nop_mnt_idmap, d_inode(parent), p.dentry, NULL);
		inode_unlock(d_inode(parent));
		dput(parent);
		path_put(&p);
	}
}

static int sfwd_accept_loop(void *unused)
{
	int err;

	allow_signal(SIGTERM);

	while (!kthread_should_stop() && !atomic_read(&sfw_stopping)) {
		struct socket *client = NULL;
		struct sfw_conn_ctx *ctx;
		struct task_struct *wt;

		err = kernel_accept(sfw_mux_sock, &client, SOCK_NONBLOCK);
		if (err == -EAGAIN || err == -EWOULDBLOCK) {
			msleep_interruptible(15);
			continue;
		}
		if (err < 0) {
			if (signal_pending(current))
				break;
			msleep_interruptible(20);
			continue;
		}

		/* Clear O_NONBLOCK on accepted Unix data stream */
		client->file = NULL;
		ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
		if (!ctx) {
			sock_release(client);
			continue;
		}
		ctx->unix_sock = client;
		wt = kthread_run(sfw_conn_worker, ctx, "sfw_conn");
		if (IS_ERR(wt)) {
			sock_release(client);
			kfree(ctx);
		}
	}
	return 0;
}

static int __init sfw_init(void)
{
	struct sockaddr_un sun = { .sun_family = AF_UNIX };
	int old_umask;
	int err;

	atomic_set(&sfw_stopping, 0);
	err = sfw_nat_fwd_init();
	if (err < 0)
		return err;

	unlink_old_mux_sock();

	err = sock_create_kern(&init_net, AF_UNIX, SOCK_STREAM, 0, &sfw_mux_sock);
	if (err < 0) {
		sfw_nat_fwd_exit();
		return err;
	}

	old_umask = current->fs->umask;
	current->fs->umask = 0;
	strscpy(sun.sun_path, SFW_MUX_SOCK_PATH, sizeof(sun.sun_path));
	err = kernel_bind(sfw_mux_sock, (struct sockaddr_unsized *)&sun,
			  sizeof(sun));
	current->fs->umask = old_umask;
	if (err < 0) {
		pr_err("sfw: failed to bind %s: %d\n", SFW_MUX_SOCK_PATH, err);
		sock_release(sfw_mux_sock);
		sfw_mux_sock = NULL;
		sfw_nat_fwd_exit();
		return err;
	}

	err = kernel_listen(sfw_mux_sock, 64);
	if (err < 0) {
		sock_release(sfw_mux_sock);
		sfw_mux_sock = NULL;
		unlink_old_mux_sock();
		sfw_nat_fwd_exit();
		return err;
	}

	pr_info("sfw: root-owned AF_UNIX socket firewall worker listening at %s\n",
		SFW_MUX_SOCK_PATH);

	sfw_accept_task = kthread_run(sfwd_accept_loop, NULL, "sfwd");
	if (IS_ERR(sfw_accept_task)) {
		err = PTR_ERR(sfw_accept_task);
		sfw_accept_task = NULL;
		sock_release(sfw_mux_sock);
		sfw_mux_sock = NULL;
		unlink_old_mux_sock();
		sfw_nat_fwd_exit();
		return err;
	}

	pressure_register_sfw_worker(sfw_accept_task);
	return 0;
}

static void __exit sfw_exit(void)
{
	atomic_set(&sfw_stopping, 1);
	pressure_register_sfw_worker(NULL);
	sfw_nat_fwd_exit();
	if (sfw_accept_task) {
		send_sig(SIGTERM, sfw_accept_task, 1);
		kthread_stop(sfw_accept_task);
	}
	if (sfw_mux_sock) {
		sock_release(sfw_mux_sock);
		sfw_mux_sock = NULL;
	}
	unlink_old_mux_sock();
	pr_info("sfw: unloaded\n");
}

module_init(sfw_init);
module_exit(sfw_exit);
