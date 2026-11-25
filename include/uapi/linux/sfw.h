/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_SFW_H
#define _UAPI_LINUX_SFW_H

#include <linux/ioctl.h>
#include <linux/types.h>
#ifdef __KERNEL__
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#else
#include <netinet/in.h>
#endif

/* Boot & Session Stages */
#define PRESSURE_STAGE_PRELOGIN		0
#define PRESSURE_STAGE_POSTLOGIN	1

/* Read-only tty1 session verification via the Pressure session securityfs node. */
struct pressure_session_query {
	__s32 pidfd;
	__u32 uid;
};

#define PRESSURE_SESSION_CHECK _IOW('P', 0x01, struct pressure_session_query)

/* Universal Provenance Origin Flags */
#define PRESSURE_PROV_PRELOGIN_LOCAL	0
#define PRESSURE_PROV_AUTH_LOCAL	1
#define PRESSURE_PROV_REMOTE		2

/* Account Types Managed by pressure-authd */
#define PRESSURE_ACCT_SYSTEM		0
#define PRESSURE_ACCT_HUMAN		1
#define PRESSURE_ACCT_DAEMON		2
#define PRESSURE_ACCT_AUTHD		3

/* /dev & Network Device Classes */
#define PDEV_PSEUDO_SAFE		0
#define PDEV_SEAT_TTY			1
#define PDEV_SEAT_INPUT			2
#define PDEV_STORAGE_BLK		3
#define PDEV_PTY_SLAVE			4
#define PDEV_NET_LO			5
#define PDEV_NET_EXT			6
#define PDEV_OTHER_CHR			7

/* Event Confinement Labels (bitmask) */
#define PEV_OPEN			(1U << 0)
#define PEV_READ			(1U << 1)
#define PEV_WRITE			(1U << 2)
#define PEV_IOCTL			(1U << 3)
#define PEV_MKNOD			(1U << 4)
#define PEV_EXEC			(1U << 5)
#define PEV_MMAP_EXEC			(1U << 6)
#define PEV_SETUID			(1U << 7)
#define PEV_SOCK_BIND			(1U << 8)
#define PEV_SOCK_CONNECT		(1U << 9)
#define PEV_SOCK_SEND			(1U << 10)
#define PEV_SOCK_RECV			(1U << 11)
#define PEV_LOGIN			(1U << 12)
#define PEV_MMAP_WRITE			(1U << 13)
#define PEV_USERNS			(1U << 14)
#define PEV_USERNS_NESTED		(1U << 15)
#define PEV_LOCAL_PROXY			(1U << 16)
#define PEV_PROC_SELF_FD		(1U << 17)
#define PEV_LOCAL_CALLBACK		(1U << 18)
#define PEV_LOCAL_CALLBACK_RELAY	(1U << 19)
#define PEV_ALL				0x3ffffU

#define SFW_LOCAL_PROXY_PORT		18443

/* AF_UNIX Socket Policy Operation Bitmask */
#define PUNIX_OP_CREATE			(1U << 0)
#define PUNIX_OP_SOCKETPAIR		(1U << 1)
#define PUNIX_OP_BIND			(1U << 2)
#define PUNIX_OP_CONNECT		(1U << 3)
#define PUNIX_OP_SEND			(1U << 4)
#define PUNIX_OP_RECV			(1U << 5)
#define PUNIX_OP_PASS_FD		(1U << 6)
#define PUNIX_OP_ALL			0x7fU

/* File / Inode Policy Flags (stored in security.pressure xattr) */
#define PRESSURE_XATTR_MAGIC		0x50525352U /* 'PRSR' */
#define PRESSURE_FILE_LOCAL_ONLY	(1U << 0)
#define PRESSURE_FILE_USER_PRIVATE	(1U << 1)
#define PRESSURE_FILE_AUTHD_VAULT	(1U << 2)
#define PRESSURE_FILE_PROTECTED		(1U << 3)

#define XATTR_PRESSURE_SUFFIX		"pressure"
#define XATTR_NAME_PRESSURE		"security.pressure"

struct pressure_xattr_disk {
	__u32 magic;
	__u32 flags;
	__u64 file_pub_id;
	__u32 owner_pub_uid;
	char  label[32];
} __attribute__((packed));

/*
 * sfw (Socket Firewall) & Root-Owned AF_UNIX Socket Worker Protocol (IPv4 + IPv6)
 * Socket path: /run/pressure/sfw/mux.sock
 */
#define SFW_MUX_SOCK_PATH		"/run/pressure/sfw/mux.sock"
#define SFW_PROTO_MAGIC			0x53465732U /* 'SFW2' Dual-Stack */

#define SFW_OP_OPEN			1
#define SFW_OP_BIND			2
#define SFW_OP_LISTEN			3
#define SFW_OP_ACCEPT			4
#define SFW_OP_CONNECT			5
#define SFW_OP_SEND			6
#define SFW_OP_RECV			7
#define SFW_OP_CLOSE			8
#define SFW_OP_SENDTO			9
#define SFW_OP_RECVFROM			10
#define SFW_OP_POLL			11
#define SFW_OP_GETSOCKNAME		12
#define SFW_OP_GETPEERNAME		13
#define SFW_OP_SETSOCKOPT		14
#define SFW_OP_SHUTDOWN			15

#define SFW_FLAG_NONBLOCK		0x0001U
#define SFW_FLAG_REMOTE_TAINT		0x8000U

#define SFW_SOCKOPT_REUSEADDR		1
#define SFW_SOCKOPT_REUSEPORT		2
#define SFW_SOCKOPT_KEEPALIVE		3
#define SFW_SOCKOPT_BROADCAST		4
#define SFW_SOCKOPT_TCP_NODELAY		5
#define SFW_SOCKOPT_IPV6_V6ONLY		6

#define SFW_RULE_ALLOW			1
#define SFW_RULE_DENY			0

#define SFW_DIR_ANY			0
#define SFW_DIR_BIND			1
#define SFW_DIR_CONNECT			2
#define SFW_DIR_SEND			3
#define SFW_DIR_RECV			4

struct sfw_req_hdr {
	__u32 magic;
	__u16 op;
	__u16 family;       /* AF_INET or AF_INET6 */
	__u16 sock_type;    /* SOCK_STREAM / SOCK_DGRAM */
	__u16 proto;
	__be32 ipv4_addr;
	__u8  ipv6_addr[16];
	__be16 port;
	__u16 flags;
	__u64 listener_token;
	__u32 payload_len;
	char  ifname[16];
} __attribute__((packed));

struct sfw_resp_hdr {
	__u32 magic;
	__s32 status;       /* 0 or -errno, or byte count for SEND/RECV */
	__u16 family;
	__be16 peer_port;
	__be32 peer_addr;
	__u8  peer_addr6[16];
	__u64 handle_token;
	__u32 payload_len;
} __attribute__((packed));

struct sfw_firewall_rule {
	__u32 action;       /* SFW_RULE_ALLOW / SFW_RULE_DENY */
	__u32 direction;    /* SFW_DIR_* */
	__u16 family;       /* AF_INET or AF_INET6 */
	__u16 prefixlen;    /* Used for AF_INET6 prefix matching (0..128) */
	__u32 pub_uid;      /* 0 = wildcard */
	__u32 max_prov;     /* Max allowed provenance: 0=PRELOGIN, 1=AUTH_LOCAL, 2=REMOTE */
	__be32 ipv4_net;
	__be32 ipv4_mask;
	__u8  ipv6_net[16];
	__u16 port_min;
	__u16 port_max;
	__u64 sock_pub_id;  /* 0 = wildcard */
	char  dev_label[32];
};

#endif /* _UAPI_LINUX_SFW_H */
