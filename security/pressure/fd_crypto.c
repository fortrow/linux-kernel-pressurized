// SPDX-License-Identifier: GPL-2.0
/*
 * Pressure LSM - 30-bit SipHash Feistel FD Cipher & 3-Strike SIGKILL Engine
 */

#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/sched/signal.h>
#include <linux/fdtable.h>
#include <linux/rcupdate.h>
#include <linux/ktime.h>
#include "pressure.h"

static DEFINE_SPINLOCK(audit_lock);
static struct pressure_audit_entry audit_ring[PRESSURE_AUDIT_RING_SIZE];
static u64 audit_seq;
static atomic64_t total_violations = ATOMIC64_INIT(0);
static atomic64_t total_sigkills = ATOMIC64_INIT(0);

const char *pressure_reason_str(enum pressure_violation_reason r)
{
	switch (r) {
	case PVIO_BAD_FD_TOKEN:		return "BAD_FD_TOKEN";
	case PVIO_FORBIDDEN_DUP2:	return "FORBIDDEN_DUP2";
	case PVIO_UNAUTHORIZED_SETUID:	return "UNAUTHORIZED_SETUID";
	case PVIO_VAULT_ACCESS:		return "AUTHD_VAULT_HARDSTOP";
	case PVIO_USER_PRIVATE_DATA:	return "USER_PRIVATE_DATA_HARDSTOP";
	case PVIO_REMOTE_TO_LOCAL_FD:	return "REMOTE_PROVENANCE_FD_BLOCK";
	case PVIO_DEV_ACCESS_DENIED:	return "DEV_PROVENANCE_HARDSTOP";
	case PVIO_SEAT_MAX_SESSIONS:	return "SEAT_MAX_SESSIONS_LOCKED";
	case PVIO_MKNOD_BLOCKED:	return "UNAUTHORIZED_MKNOD";
	case PVIO_RAW_IP_SOCKET:	return "DIRECT_IP_SOCKET_BLOCKED";
	case PVIO_REMOTE_EXEC_BLOCKED:	return "REMOTE_EXEC_BLOCKED";
	case PVIO_REMOTE_WX_MMAP:	return "REMOTE_WX_MMAP_BLOCKED";
	case PVIO_PROC_FD_ENUM:		return "PROC_FD_ENUM_BLOCKED";
	case PVIO_SFW_FIREWALL_DROP:	return "SFW_FIREWALL_DROP";
	case PVIO_POLICY_DENY:		return "POLICY_RULE_DENY";
	case PVIO_UNIX_SOCKET_DENY:	return "UNIX_SOCKET_POLICY_DENY";
	case PVIO_TTY_SPOOF_BLOCKED:	return "TTY_SPOOF_BLOCKED";
	case PVIO_USERNS_DENIED:	return "USER_NAMESPACE_POLICY_DENY";
	case PVIO_SESSION_REVOKED:	return "SESSION_REVOKED_OR_DETACHED";
	default:			return "UNKNOWN";
	}
}

/*
 * Balanced 6-round Feistel network on 30-bit values (two 15-bit halves).
 * Because 15 + 15 = 30 bits, this is an exact mathematical bijection over
 * [0 .. 0x3fffffff] for any 128-bit SipHash key, guaranteeing zero collisions
 * across distinct (nonce16, priv_fd14) pairs.
 */
static inline u32 feistel_prf15(const siphash_key_t *key, u32 half15, u32 round)
{
	u64 h = siphash_2u32(half15, round * 0x9e3779b9U, key);
	return (u32)(h & 0x7fffU);
}

u32 pressure_feistel30_encrypt(const siphash_key_t *key, u32 val30)
{
	u32 l = (val30 >> 15) & 0x7fffU;
	u32 r = val30 & 0x7fffU;
	u32 round;

	for (round = 0; round < 6; round++) {
		u32 next_l = r;
		u32 next_r = (l ^ feistel_prf15(key, r, round)) & 0x7fffU;
		l = next_l;
		r = next_r;
	}
	return ((l << 15) | r) & PRESSURE_PUB_FD_MASK;
}

u32 pressure_feistel30_decrypt(const siphash_key_t *key, u32 cipher30)
{
	u32 l = (cipher30 >> 15) & 0x7fffU;
	u32 r = cipher30 & 0x7fffU;
	int round;

	for (round = 5; round >= 0; round--) {
		u32 prev_r = l;
		u32 prev_l = (r ^ feistel_prf15(key, l, (u32)round)) & 0x7fffU;
		l = prev_l;
		r = prev_r;
	}
	return ((l << 15) | r) & PRESSURE_PUB_FD_MASK;
}

void pressure_vfs_init_files_key(struct files_struct *files,
				 const struct files_struct *oldf)
{
	if (oldf && READ_ONCE(oldf->pressure_fd_mode)) {
		files->pressure_fd_key = oldf->pressure_fd_key;
		files->pressure_fd_mode = oldf->pressure_fd_mode;
	} else {
		get_random_bytes(&files->pressure_fd_key,
				 sizeof(files->pressure_fd_key));
		files->pressure_fd_mode = 0;
	}
}

void pressure_enable_task_fd_crypto(struct task_struct *tsk)
{
	struct files_struct *files;

	task_lock(tsk);
	files = tsk->files;
	if (files && !READ_ONCE(files->pressure_fd_mode)) {
		struct fdtable *fdt;
		unsigned int i;

		spin_lock(&files->file_lock);
		fdt = files_fdtable(files);
		if (fdt && fdt->pg_slots) {
			/*
			 * Preserve any descriptors >= 3 legitimately opened
			 * prior to privilege drop (e.g. setup wrapper opening
			 * /dev/quadtap0 or /dev/kvm before setresuid). Each
			 * lookup still passes through security_file_fd_lookup()
			 * under the post-drop credential, and closing the slot
			 * permanently clears PRESSURE_FDSLOT_PREOPENED.
			 */
			for (i = 3; i < fdt->max_fds; i++) {
				if (rcu_access_pointer(fdt->fd[i]) != NULL &&
				    fdt->pg_slots[i].nonce == 0)
					WRITE_ONCE(fdt->pg_slots[i].flags,
						   PRESSURE_FDSLOT_PREOPENED);
			}
		}
		get_random_bytes(&files->pressure_fd_key,
				 sizeof(files->pressure_fd_key));
		WRITE_ONCE(files->pressure_fd_mode, 1);
		spin_unlock(&files->file_lock);
	}
	task_unlock(tsk);
}

int pressure_vfs_encode_new_fd(struct files_struct *files, struct fdtable *fdt,
			       unsigned int priv_fd)
{
	u16 nonce, last;
	u32 pt30, ct30;

	if (!READ_ONCE(files->pressure_fd_mode) || priv_fd < 3 ||
	    priv_fd >= PRESSURE_MAX_PRIV_FD || !fdt->pg_slots)
		return (int)priv_fd;

	last = fdt->pg_slots[priv_fd].last_nonce;
	nonce = get_random_u16();
	if (nonce == 0 || nonce == last)
		nonce ^= 0x6d5aU;
	if (nonce == 0 || nonce == last)
		nonce = (last + 1U) ? (u16)(last + 1U) : 1U;

	WRITE_ONCE(fdt->pg_slots[priv_fd].nonce, nonce);
	fdt->pg_slots[priv_fd].file_priv_id = 0;

	pt30 = (((u32)nonce) << 14) | (priv_fd & 0x3fffU);
	ct30 = pressure_feistel30_encrypt(&files->pressure_fd_key, pt30);
	return (int)(PRESSURE_PUB_FD_BIT | ct30);
}

int pressure_vfs_decode_fd_install(struct files_struct *files,
				   struct fdtable *fdt, unsigned int fd,
				   struct file *file, unsigned int *priv_out)
{
	struct pressure_file_blob *fblob;
	u32 pt30, priv_fd;
	u16 nonce;

	if (!READ_ONCE(files->pressure_fd_mode) || fd < 3) {
		*priv_out = fd;
		return 0;
	}
	if (!(fd & PRESSURE_PUB_FD_BIT) || !fdt->pg_slots)
		return -EBADF;

	pt30 = pressure_feistel30_decrypt(&files->pressure_fd_key,
					  fd & PRESSURE_PUB_FD_MASK);
	nonce = (u16)(pt30 >> 14);
	priv_fd = pt30 & 0x3fffU;

	if (priv_fd >= fdt->max_fds || nonce == 0 ||
	    READ_ONCE(fdt->pg_slots[priv_fd].nonce) != nonce)
		return -EBADF;

	fblob = pressure_file(file);
	if (fblob)
		WRITE_ONCE(fdt->pg_slots[priv_fd].file_priv_id,
			   fblob->file_priv_id);

	*priv_out = priv_fd;
	return 0;
}

int pressure_vfs_decode_fd_rcu(struct files_struct *files, unsigned int fd,
			       unsigned int *priv_out, bool *is_forged)
{
	struct fdtable *fdt;
	u32 pt30, priv_fd;
	u16 nonce, slot_nonce;

	if (is_forged)
		*is_forged = false;

	if (!files || !READ_ONCE(files->pressure_fd_mode)) {
		*priv_out = fd;
		return 0;
	}

	/* Allow inherited stdio 0, 1, 2 (still checked by security_file_fd_lookup) */
	if (fd <= 2) {
		*priv_out = fd;
		return 0;
	}

	fdt = rcu_dereference_raw(files->fdt);
	if (unlikely(!fdt || !fdt->pg_slots))
		return -EBADF;

	if (!(fd & PRESSURE_PUB_FD_BIT)) {
		if (fd < fdt->max_fds &&
		    (READ_ONCE(fdt->pg_slots[fd].flags) & PRESSURE_FDSLOT_PREOPENED)) {
			*priv_out = fd;
			return 0;
		}
		if (is_forged)
			*is_forged = true;
		return -EBADF;
	}

	pt30 = pressure_feistel30_decrypt(&files->pressure_fd_key,
					  fd & PRESSURE_PUB_FD_MASK);
	nonce = (u16)(pt30 >> 14);
	priv_fd = pt30 & 0x3fffU;

	if (priv_fd < 3 || priv_fd >= fdt->max_fds || nonce == 0) {
		if (is_forged)
			*is_forged = true;
		return -EBADF;
	}

	slot_nonce = READ_ONCE(fdt->pg_slots[priv_fd].nonce);
	if (slot_nonce != nonce) {
		if (is_forged)
			*is_forged = true;
		return -EBADF;
	}

	*priv_out = priv_fd;
	return 0;
}

void pressure_vfs_release_slot(struct fdtable *fdt, unsigned int priv_fd)
{
	if (!fdt || !fdt->pg_slots || priv_fd >= fdt->max_fds)
		return;
	fdt->pg_slots[priv_fd].last_nonce =
		READ_ONCE(fdt->pg_slots[priv_fd].nonce);
	WRITE_ONCE(fdt->pg_slots[priv_fd].nonce, 0);
	WRITE_ONCE(fdt->pg_slots[priv_fd].flags, 0);
	WRITE_ONCE(fdt->pg_slots[priv_fd].file_priv_id, 0);
}

static void record_violation(struct task_struct *tsk,
			     enum pressure_violation_reason reason,
			     u32 extra_val, const char *detail,
			     const char *subject, const char *device,
			     u32 unix_op, const char *peer)
{
	const struct cred *cred;
	struct pressure_task_blob *tblob;
	struct pressure_audit_entry *ent;
	unsigned long flags;
	int strikes = 1;
	bool killed = false;
	uid_t pub_uid = 0;
	u8 prov = 0;
	pid_t ppid = 0;

	if (!tsk)
		tsk = current;

	tblob = pressure_task(tsk);
	if (tblob)
		strikes = atomic_inc_return(&tblob->strikes);

	rcu_read_lock();
	cred = __task_cred(tsk);
	pub_uid = from_kuid_munged(&init_user_ns, cred->uid);
	prov = pressure_effective_prov(tsk, cred);
	if (tsk->real_parent)
		ppid = task_tgid_nr(tsk->real_parent);
	rcu_read_unlock();

	if (READ_ONCE(pressure_enforce) && strikes >= PRESSURE_MAX_STRIKES &&
	    !is_global_init(tsk) &&
	    task_tgid_nr(tsk) != READ_ONCE(pressure_authd_pid)) {
		killed = true;
		atomic64_inc(&total_sigkills);
	}
	atomic64_inc(&total_violations);

	spin_lock_irqsave(&audit_lock, flags);
	ent = &audit_ring[audit_seq % PRESSURE_AUDIT_RING_SIZE];
	ent->seq = ++audit_seq;
	ent->ts_nsec = ktime_get_boottime_ns();
	ent->pid = task_tgid_nr(tsk);
	ent->ppid = ppid;
	ent->tid = task_pid_nr(tsk);
	ent->pub_uid = pub_uid;
	ent->provenance = prov;
	ent->strikes = (u8)min(strikes, 255);
	ent->sigkilled = killed;
	ent->reason = reason;
	ent->extra_val = extra_val;
	get_task_comm(ent->comm, tsk);
	strscpy(ent->subject, subject ? subject : "", sizeof(ent->subject));
	strscpy(ent->device, device ? device : "", sizeof(ent->device));
	ent->unix_op = unix_op;
	strscpy(ent->peer, peer ? peer : "-", sizeof(ent->peer));
	strscpy(ent->detail, detail ? detail : "-", unix_op ? sizeof(ent->detail) : 48);
	for (char *cursor = ent->detail; *cursor; cursor++)
		if ((unsigned char)*cursor < ' ' || *cursor == 127)
			*cursor = '?';
	spin_unlock_irqrestore(&audit_lock, flags);

	pr_notice_ratelimited("pressure: VIOLATION pid=%d comm=%s uid=%u prov=%u reason=%s extra=0x%x strike=%d%s\n",
			      task_tgid_nr(tsk), tsk->comm, pub_uid, prov,
			      pressure_reason_str(reason), extra_val, strikes,
			      killed ? " [STRIKEOUT_SIGKILL]" : "");

	if (killed && tsk == current)
		force_sig(SIGKILL);
	else if (killed)
		send_sig_info(SIGKILL, SEND_SIG_PRIV, tsk);
}

void pressure_record_violation(struct task_struct *tsk,
			       enum pressure_violation_reason reason,
			       u32 extra_val, const char *detail)
{
	record_violation(tsk, reason, extra_val, detail, NULL, NULL, 0, NULL);
}

void pressure_record_object_denial(u32 events, const char *object,
				   const char *subject, const char *device)
{
	static const char allowed[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_:-";

	if (strspn(subject, allowed) != strlen(subject) ||
	    strspn(device, allowed) != strlen(device)) {
		subject = NULL;
		device = NULL;
	}
	record_violation(current, PVIO_POLICY_DENY, events, object, subject, device, 0, NULL);
}

void pressure_record_unix_denial(u16 type, u32 operation, const char *endpoint,
				 const char *subject, const char *device, const char *peer)
{
	static const char allowed[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_:-";

	if (strspn(subject, allowed) != strlen(subject) ||
	    strspn(device, allowed) != strlen(device) ||
	    (peer && strspn(peer, allowed) != strlen(peer))) {
		record_violation(current, PVIO_UNIX_SOCKET_DENY, type, endpoint,
				 NULL, NULL, 0, NULL);
		return;
	}
	record_violation(current, PVIO_UNIX_SOCKET_DENY, type, endpoint,
			 subject, device, operation, peer);
}

void pressure_vfs_report_bad_fd(unsigned int bad_fd, int reason)
{
	enum pressure_violation_reason r = (reason == 2) ?
		PVIO_FORBIDDEN_DUP2 : PVIO_BAD_FD_TOKEN;
	pressure_record_violation(current, r, bad_fd,
				  reason == 2 ? "dup2_fixed_fd" : "forged_pub_fd");
}

int pressure_format_audit(struct seq_file *m, void *v)
{
	unsigned long flags;
	u64 start, s;

	(void)v;

	spin_lock_irqsave(&audit_lock, flags);
	start = (audit_seq > PRESSURE_AUDIT_RING_SIZE) ?
		(audit_seq - PRESSURE_AUDIT_RING_SIZE + 1) : 1;
	for (s = start; s <= audit_seq; s++) {
		struct pressure_audit_entry *e =
			&audit_ring[(s - 1) % PRESSURE_AUDIT_RING_SIZE];
		const char *pstr = (e->provenance == PRESSURE_PROV_REMOTE) ? "REMOTE" :
				   (e->provenance == PRESSURE_PROV_AUTH_LOCAL) ? "AUTH_LOCAL" :
				   "PRELOGIN_LOCAL";
		seq_printf(m, "seq=%llu ts_ms=%llu pid=%d ppid=%d tid=%d comm=%s pub_uid=%u prov=%s strike=%u action=%s reason=%s val=0x%x",
			   e->seq, e->ts_nsec / 1000000ULL, e->pid, e->ppid, e->tid,
			   e->comm, e->pub_uid, pstr, e->strikes,
			   e->sigkilled ? "SIGKILL" : "DENY",
			   pressure_reason_str(e->reason), e->extra_val);
		if (e->subject[0] && e->device[0])
			seq_printf(m, " subject=%s device=%s", e->subject, e->device);
		if (e->unix_op)
			seq_printf(m, " unix_op=0x%x peer=%s", e->unix_op, e->peer);
		seq_printf(m, " detail=%s\n", e->detail);
	}
	spin_unlock_irqrestore(&audit_lock, flags);
	return 0;
}

u64 pressure_get_total_violations(void)
{
	return (u64)atomic64_read(&total_violations);
}

u64 pressure_get_total_sigkills(void)
{
	return (u64)atomic64_read(&total_sigkills);
}
