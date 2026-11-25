/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SECURITY_PRESSURE_H
#define _SECURITY_PRESSURE_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/hashtable.h>
#include <linux/lsm_hooks.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/siphash.h>
#include <net/sock.h>
#include <linux/pressure_vfs.h>
#include <uapi/linux/sfw.h>

#define PRESSURE_MAX_STRIKES		3
#define PRESSURE_AUDIT_RING_SIZE	256
#define PRESSURE_MAX_GROUPS		16
#define PRESSURE_MAX_POLICY_RULES	256
#define PRESSURE_MAX_SFW_RULES		256
#define PRESSURE_MAX_UNIX_RULES		256

/* Violation reason codes for audit & 3-strike SIGKILL */
enum pressure_violation_reason {
	PVIO_NONE = 0,
	PVIO_BAD_FD_TOKEN = 1,
	PVIO_FORBIDDEN_DUP2 = 2,
	PVIO_UNAUTHORIZED_SETUID = 3,
	PVIO_VAULT_ACCESS = 4,
	PVIO_USER_PRIVATE_DATA = 5,
	PVIO_REMOTE_TO_LOCAL_FD = 6,
	PVIO_DEV_ACCESS_DENIED = 7,
	PVIO_SEAT_MAX_SESSIONS = 8,
	PVIO_MKNOD_BLOCKED = 9,
	PVIO_RAW_IP_SOCKET = 10,
	PVIO_REMOTE_EXEC_BLOCKED = 11,
	PVIO_REMOTE_WX_MMAP = 12,
	PVIO_PROC_FD_ENUM = 13,
	PVIO_SFW_FIREWALL_DROP = 14,
	PVIO_POLICY_DENY = 15,
	PVIO_UNIX_SOCKET_DENY = 16,
	PVIO_TTY_SPOOF_BLOCKED = 17,
	PVIO_SESSION_REVOKED = 18,
	PVIO_USERNS_DENIED = 19,
};

struct pressure_cred_blob {
	uid_t pub_uid;
	gid_t pub_gid;
	u64 kpriv_uid;          /* Secret kernel-only user/daemon ID */
	u64 kpriv_gid;          /* Secret kernel-only primary group ID */
	u64 session_pub_id;
	u64 session_priv_id;    /* Secret kernel-only session ID */
	u64 seat_kpriv_id;      /* Secret kernel-only physical seat ID */
	u64 bound_dev_kpriv_id; /* Secret kernel-only login device ID */
	dev_t bound_ctty_dev;   /* Kernel-verified controlling TTY dev_t */
	pid_t bound_sid;        /* Kernel-verified POSIX session ID */
	u8 account_type;        /* PRESSURE_ACCT_* */
	u8 provenance;          /* PRESSURE_PROV_* (sticky across setuid!) */
	u8 confined;            /* 1 if confined under Pressure rules */
	char label[32];
};

struct pressure_task_blob {
	atomic_t strikes;
	atomic_t remote_tainted;
	u64 proc_pub_id;
	u64 proc_priv_id;
};

struct pressure_inode_blob {
	bool initialized;
	bool is_device;
	u32 flags;              /* PRESSURE_FILE_* */
	u64 obj_pub_id;
	u64 obj_priv_id;        /* Secret kernel-only inode/device ID */
	uid_t owner_pub_uid;
	u64 owner_kpriv_uid;    /* Secret kernel-only owner ID */
	dev_t rdev;
	u8 dev_class;           /* PDEV_* */
	char label[32];
};

struct pressure_file_blob {
	u64 file_pub_id;
	u64 file_priv_id;
	u64 opener_kpriv_uid;
	dev_t claimed_rdev;
	u8 opener_provenance;
};

struct pressure_sock_blob {
	u64 sock_pub_id;
	u64 sock_priv_id;
	bool is_sfw_worker;
	bool remote_tainted;
	bool local_proxy;
	bool local_callback;
	bool local_callback_relay;
	u16 unix_type;          /* SOCK_STREAM / SOCK_DGRAM / SOCK_SEQPACKET */
	bool unix_is_pair;      /* Created via socketpair() */
	bool unix_has_bound;    /* Local AF_UNIX endpoint bound */
	bool unix_has_peer;     /* Connected to an AF_UNIX peer */
	u64 owner_kpriv_uid;    /* Secret kernel UID of socket creator/owner */
	u64 owner_session_priv_id; /* Verified session ID of socket creator/owner */
	char owner_label[32];   /* Subject label of creator/owner */
	char peer_label[32];    /* Subject label of connected peer */
	char bound_addr[112];   /* Canonical local bound endpoint */
	char peer_addr[112];    /* Canonical remote peer endpoint */
};

/* Kernel-only user / daemon account table entry */
struct pressure_user_entry {
	struct hlist_node node;
	uid_t pub_uid;
	gid_t pub_gid;
	u64 kpriv_uid;
	u64 kpriv_gid;
	u8 account_type;
	char label[32];
};

/* Active kernel-verified human login session table entry */
struct pressure_session_entry {
	struct hlist_node node;
	u64 session_priv_id;
	u64 bound_dev_kpriv_id;
	dev_t bound_ctty_dev;
	pid_t leader_pid;
	pid_t bound_sid;
	u64 expires_jiffies;
	bool revoked;
};

/* One-time setuid/login transition ticket minted by pressure-authd */
struct pressure_uid_ticket {
	struct list_head list;
	pid_t target_pid;
	pid_t bound_sid;
	dev_t bound_ctty_dev;
	uid_t pub_uid;
	u64 kpriv_uid;
	u64 kpriv_gid;
	u64 session_pub_id;
	u64 session_priv_id;
	u64 seat_kpriv_id;
	u64 bound_dev_kpriv_id;
	u8 account_type;
	u8 provenance;
	char label[32];
	u64 expires_jiffies;
};

/* Universal /dev (major:minor) & net_device (ifindex) table entry */
struct pressure_dev_entry {
	struct hlist_node node;
	bool is_netdev;
	dev_t rdev;
	int ifindex;
	char name[32];
	char label[32];
	u64 dev_pub_id;
	u64 dev_kpriv_id;       /* Secret kernel-only device ID */
	u8 dev_class;           /* PDEV_* */
	u8 provenance;          /* PRESSURE_PROV_* */
	u32 max_sessions;
	u32 active_sessions;
	pid_t owner_leader_pid;
	u64 owner_session_priv_id;
	u64 owner_seat_kpriv_id;
};

/* General 6-tuple event & descriptor access policy rule */
struct pressure_policy_rule {
	bool active;
	u32 action;             /* 1 = allow, 0 = deny */
	char subj_label[32];    /* "*" = wildcard */
	char obj_label[32];     /* "*" = wildcard */
	char dev_label[32];     /* "*" = wildcard */
	u32 event_mask;         /* PEV_* bitmask */
	u8 max_provenance;      /* Max allowed provenance (LOCAL vs REMOTE) */
};

/* AF_UNIX creation, endpoint & descriptor-transfer policy rule */
struct pressure_unix_rule {
	bool active;
	u32 action;             /* 1 = allow, 0 = deny */
	u16 sock_type;          /* 0 = any, SOCK_STREAM / SOCK_DGRAM / SOCK_SEQPACKET */
	u32 op_mask;            /* PUNIX_OP_* bitmask */
	u8 max_provenance;      /* Max allowed provenance */
	char subj_label[32];    /* exact, prefix*, or "*" */
	char peer_label[32];    /* exact, prefix*, or "*" */
	char dev_label[32];     /* verified session/device label or "*" */
	char exe_label[32];     /* exact executable label, or empty */
	char endpoint[112];     /* "-", exact path, @abstract, pair:*, prefix*, or "*" */
};

struct pressure_audit_entry {
	u64 seq;
	u64 ts_nsec;
	pid_t pid;
	pid_t ppid;
	pid_t tid;
	uid_t pub_uid;
	u8 provenance;
	u8 strikes;
	bool sigkilled;
	enum pressure_violation_reason reason;
	u32 extra_val;
	char comm[TASK_COMM_LEN];
	char subject[32];
	char device[32];
	char peer[32];
	u32 unix_op;
	char detail[112];
};

extern struct lsm_blob_sizes pressure_blob_sizes;
extern int pressure_enforce;
extern int pressure_stage;
extern pid_t pressure_authd_pid;
extern struct task_struct *pressure_sfw_kthread;

static inline struct pressure_cred_blob *pressure_cred(const struct cred *cred)
{
	if (unlikely(!cred || !cred->security))
		return NULL;
	return (struct pressure_cred_blob *)((char *)cred->security +
					     pressure_blob_sizes.lbs_cred);
}

static inline struct pressure_task_blob *pressure_task(const struct task_struct *tsk)
{
	if (unlikely(!tsk || !tsk->security))
		return NULL;
	return (struct pressure_task_blob *)((char *)tsk->security +
					     pressure_blob_sizes.lbs_task);
}

static inline struct pressure_inode_blob *pressure_inode(const struct inode *inode)
{
	if (unlikely(!inode || !inode->i_security))
		return NULL;
	return (struct pressure_inode_blob *)((char *)inode->i_security +
					      pressure_blob_sizes.lbs_inode);
}

static inline struct pressure_file_blob *pressure_file(const struct file *file)
{
	if (unlikely(!file || !file->f_security))
		return NULL;
	return (struct pressure_file_blob *)((char *)file->f_security +
					     pressure_blob_sizes.lbs_file);
}

static inline struct pressure_sock_blob *pressure_sock(const struct sock *sk)
{
	if (unlikely(!sk || !sk->sk_security))
		return NULL;
	return (struct pressure_sock_blob *)((char *)sk->sk_security +
					     pressure_blob_sizes.lbs_sock);
}

static inline u8 pressure_effective_prov(const struct task_struct *tsk,
					 const struct cred *cred)
{
	const struct pressure_cred_blob *cb = pressure_cred(cred);
	const struct pressure_task_blob *tb = pressure_task(tsk);

	if (tb && atomic_read(&tb->remote_tainted))
		return PRESSURE_PROV_REMOTE;
	if (cb)
		return cb->provenance;
	return PRESSURE_PROV_PRELOGIN_LOCAL;
}

/* fd_crypto.c */
void pressure_enable_task_fd_crypto(struct task_struct *tsk);
void pressure_record_violation(struct task_struct *tsk,
			       enum pressure_violation_reason reason,
			       u32 extra_val, const char *detail);
void pressure_record_object_denial(u32 events, const char *object,
				   const char *subject, const char *device);
void pressure_record_unix_denial(u16 type, u32 operation, const char *endpoint,
				 const char *subject, const char *device, const char *peer);
const char *pressure_reason_str(enum pressure_violation_reason r);

/* ident_policy.c */
void __init pressure_ident_policy_init(void);
int pressure_register_user(uid_t pub_uid, gid_t pub_gid, u8 acct_type,
			   const char *label);
bool pressure_lookup_user_kpriv(uid_t pub_uid, u64 *kpriv_uid_out,
				u64 *kpriv_gid_out, u8 *acct_type_out,
				char *label_out);
int pressure_issue_uid_ticket(pid_t target_pid, uid_t pub_uid, u8 provenance,
			      dev_t tty_dev, const char *override_label,
			      u32 ttl_sec);
bool pressure_consume_uid_ticket(pid_t pid, uid_t target_pub_uid,
				 struct pressure_uid_ticket *out);
void pressure_release_session_devices(u64 session_priv_id);
void pressure_release_leader_devices(pid_t leader_pid);
bool pressure_get_verified_session_dev(struct task_struct *tsk,
				       const struct cred *cred,
				       char *dev_lbl_out, size_t sz);
void pressure_get_unix_session_dev(const struct cred *cred, char *out, size_t sz);
bool pressure_get_proxy_session_dev(const struct cred *cred, char *out, size_t sz, bool established);
bool pressure_session_is_active(u64 session_priv_id);

struct pressure_dev_entry *pressure_get_or_create_chrblk_dev(dev_t rdev,
							     umode_t mode);
int pressure_configure_dev_label(bool is_netdev, dev_t rdev,
				 const char *ifname, const char *label,
				 u8 dev_class, u8 prov, u32 max_sessions);
int pressure_add_policy_rule(u32 action, const char *subj, const char *obj,
			     const char *dev, u32 ev_mask, u8 max_prov);
void pressure_flush_policy_rules(void);
bool pressure_posix_fd_allowed(const struct cred *cred);
bool pressure_eval_exact_local_rule(const char *subject, const char *object,
			       const char *device, u32 event);
bool pressure_eval_policy_rule(const char *subj, const char *obj,
			       const char *dev, u32 ev_bit, u8 prov,
			       bool *matched);
int pressure_unix_add_rule(u32 action, const char *subj, u16 sock_type,
			   u32 op_mask, const char *endpoint, const char *peer,
			   const char *dev_lbl, u8 max_prov, const char *exe);
void pressure_unix_flush_rules(void);
bool pressure_unix_eval_rule(const char *subj, u16 sock_type, u32 op_bit,
			     const char *endpoint, const char *peer,
			     const char *dev_lbl, u8 prov, bool *matched);
int pressure_format_unix_rules(struct seq_file *m, void *v);

int pressure_check_inode_access(const struct cred *cred, struct inode *inode,
				u32 ev_bit);
int pressure_claim_dev_file(struct inode *inode, struct pressure_file_blob *fb);
void pressure_release_dev_file(struct pressure_file_blob *fb);
void pressure_refresh_inode_xattr(struct dentry *dentry, struct inode *inode);

/* Transactional policy reload & readiness generation counter */
int pressure_txn_begin(void);
int pressure_txn_prepare(void);
int pressure_txn_commit(void);
int pressure_txn_abort(void);
void pressure_txn_mark_degraded(void);
bool pressure_txn_is_active(void);
bool pressure_txn_is_degraded(void);
u64 pressure_get_policy_gen(void);
void pressure_bump_policy_gen_if_not_txn(void);

/* sfw firewall & exported broker hooks */
int pressure_sfw_add_rule(const struct sfw_firewall_rule *rule);
void pressure_sfw_flush_rules(void);
int pressure_register_sfw_worker(struct task_struct *worker);
int pressure_sfw_authorize(struct task_struct *peer_task,
			   const struct cred *peer_cred, u32 dir,
			   __be32 ipv4_addr, u16 host_port,
			   const char *ifname, u64 sock_pub_id);
int pressure_sfw_authorize6(struct task_struct *peer_task,
			    const struct cred *peer_cred, u32 dir,
			    const struct in6_addr *ipv6_addr, u16 host_port,
			    const char *ifname, u64 sock_pub_id);
void pressure_taint_task_remote(struct task_struct *peer_task);

/* Audit ring helpers for securityfs.c */
int pressure_format_users(struct seq_file *m, void *v);
int pressure_format_devices(struct seq_file *m, void *v);
int pressure_format_policy(struct seq_file *m, void *v);
int pressure_format_sfw_rules(struct seq_file *m, void *v);
int pressure_format_audit(struct seq_file *m, void *v);
u64 pressure_get_total_violations(void);
u64 pressure_get_total_sigkills(void);

/* securityfs.c */
int __init pressure_securityfs_init(void);

#endif /* _SECURITY_PRESSURE_H */
