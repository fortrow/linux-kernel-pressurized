// SPDX-License-Identifier: GPL-2.0
/*
 * Pressure Linux Security Module - Hook Implementations
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/lsm_hooks.h>
#include <linux/binfmts.h>
#include <linux/file.h>
#include <linux/in.h>
#include <linux/fdtable.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/xattr.h>
#include <linux/random.h>
#include <linux/socket.h>
#include <linux/un.h>
#include <linux/vm_sockets.h>
#include <linux/nsproxy.h>
#include <net/af_unix.h>
#include <net/inet_sock.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <uapi/linux/lsm.h>
#include "pressure.h"

int pressure_enforce;
int pressure_stage = PRESSURE_STAGE_PRELOGIN;
pid_t pressure_authd_pid;

struct lsm_blob_sizes pressure_blob_sizes __ro_after_init = {
	.lbs_cred  = sizeof(struct pressure_cred_blob),
	.lbs_task  = sizeof(struct pressure_task_blob),
	.lbs_inode = sizeof(struct pressure_inode_blob),
	.lbs_file  = sizeof(struct pressure_file_blob),
	.lbs_sock  = sizeof(struct pressure_sock_blob),
};

static int pressure_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	struct pressure_cred_blob *cb = pressure_cred(cred);

	if (cb)
		strscpy(cb->label, "subj:boot", sizeof(cb->label));
	return 0;
}

static void copy_cred_blob(struct cred *new, const struct cred *old)
{
	struct pressure_cred_blob *ncb = pressure_cred(new);
	const struct pressure_cred_blob *ocb = pressure_cred(old);

	if (!ncb || !ocb)
		return;
	*ncb = *ocb;
	if (pressure_effective_prov(current, old) == PRESSURE_PROV_REMOTE)
		ncb->provenance = PRESSURE_PROV_REMOTE;
}

static int pressure_cred_prepare(struct cred *new, const struct cred *old,
				 gfp_t gfp)
{
	copy_cred_blob(new, old);
	return 0;
}

static void pressure_cred_transfer(struct cred *new, const struct cred *old)
{
	copy_cred_blob(new, old);
}

static void pressure_task_free(struct task_struct *task)
{
	/* Automatically release claimed TTY/seat slots when session leader exits */
	if (thread_group_leader(task))
		pressure_release_leader_devices(task_pid_nr(task));
}

static int pressure_task_alloc(struct task_struct *task, u64 clone_flags)
{
	struct pressure_task_blob *ntb = pressure_task(task);
	struct pressure_task_blob *ctb = pressure_task(current);

	if (ntb) {
		atomic_set(&ntb->strikes, ctb ? atomic_read(&ctb->strikes) : 0);
		atomic_set(&ntb->remote_tainted,
			   (ctb && atomic_read(&ctb->remote_tainted)) ? 1 : 0);
		ntb->proc_pub_id = get_random_u64() | 1ULL;
		ntb->proc_priv_id = get_random_u64() | 1ULL;
	}
	return 0;
}

/*
 * Hard-stop unauthorized setuid / setreuid / setresuid / setfsuid!
 * Even CAP_SETUID / uid=0 cannot transition into a human or daemon user's
 * secret kpriv_uid without a valid one-time ticket minted by pressure-authd.
 */
static int pressure_task_fix_setuid(struct cred *new, const struct cred *old,
				    int flags)
{
	struct pressure_cred_blob *ncb = pressure_cred(new);
	const struct pressure_cred_blob *ocb = pressure_cred(old);
	uid_t target_uid = from_kuid_munged(&init_user_ns, new->uid);
	uid_t old_uid = from_kuid_munged(&init_user_ns, old->uid);
	struct pressure_uid_ticket tk;
	u8 prev_prov;

	if (!ncb || !ocb)
		return 0;

	copy_cred_blob(new, old);
	prev_prov = pressure_effective_prov(current, old);
	if (prev_prov == PRESSURE_PROV_REMOTE)
		ncb->provenance = PRESSURE_PROV_REMOTE;

	/* Same-UID no-op */
	if (target_uid == old_uid &&
	    uid_eq(new->euid, old->euid) &&
	    uid_eq(new->suid, old->suid))
		return 0;

	/* Consume one-time pressure-authd kernel transition ticket if present */
	if (pressure_consume_uid_ticket(task_tgid_nr(current), target_uid, &tk)) {
		ncb->pub_uid = tk.pub_uid;
		ncb->kpriv_uid = tk.kpriv_uid;
		ncb->kpriv_gid = tk.kpriv_gid;
		ncb->session_pub_id = tk.session_pub_id;
		ncb->session_priv_id = tk.session_priv_id;
		ncb->seat_kpriv_id = tk.seat_kpriv_id;
		ncb->bound_dev_kpriv_id = tk.bound_dev_kpriv_id;
		ncb->bound_ctty_dev = tk.bound_ctty_dev;
		ncb->bound_sid = tk.bound_sid;
		ncb->account_type = tk.account_type;
		/* REMOTE provenance is sticky even across ticketed transitions! */
		ncb->provenance = (prev_prov == PRESSURE_PROV_REMOTE) ?
				  PRESSURE_PROV_REMOTE : tk.provenance;
		ncb->confined = 1;
		strscpy(ncb->label, tk.label, sizeof(ncb->label));

		if (tk.provenance == PRESSURE_PROV_REMOTE)
			pressure_taint_task_remote(current);

		if (tk.account_type == PRESSURE_ACCT_HUMAN &&
		    ncb->provenance == PRESSURE_PROV_AUTH_LOCAL)
			WRITE_ONCE(pressure_stage, PRESSURE_STAGE_POSTLOGIN);

		/* ABI selection never converts an already tokenized file table. */
		if (!pressure_posix_fd_allowed(new))
			pressure_enable_task_fd_crypto(current);
		return 0;
	}

	/*
	 * No valid pressure-authd ticket!
	 * Clear any secret kpriv_uid so the new cred never inherits another
	 * user's secret kernel identity, and hard-stop if enforcing or confined!
	 */
	ncb->kpriv_uid = 0;
	ncb->seat_kpriv_id = 0;
	ncb->session_priv_id = 0;
	ncb->bound_dev_kpriv_id = 0;
	ncb->bound_ctty_dev = 0;
	ncb->bound_sid = 0;

	if (READ_ONCE(pressure_enforce) || ocb->confined ||
	    prev_prov == PRESSURE_PROV_REMOTE) {
		pressure_record_violation(current, PVIO_UNAUTHORIZED_SETUID,
					  target_uid, "missing_authd_ticket");
		if (READ_ONCE(pressure_enforce))
			return -EPERM;
	}
	return 0;
}

static int pressure_task_fix_setgid(struct cred *new, const struct cred *old,
				    int flags)
{
	const struct pressure_cred_blob *ocb = pressure_cred(old);
	gid_t target_gid = from_kgid_munged(&init_user_ns, new->gid);
	gid_t old_gid = from_kgid_munged(&init_user_ns, old->gid);

	copy_cred_blob(new, old);
	if (target_gid == old_gid)
		return 0;

	/* Allow pressure-authd or ticketed login flow prior to UID drop */
	if (ocb && ocb->account_type == PRESSURE_ACCT_AUTHD)
		return 0;
	if (!ocb || (!ocb->confined &&
	    pressure_effective_prov(current, old) != PRESSURE_PROV_REMOTE))
		return 0;

	pressure_record_violation(current, PVIO_UNAUTHORIZED_SETUID,
				  target_gid, "unauthorized_setgid");
	return READ_ONCE(pressure_enforce) ? -EPERM : 0;
}

static int pressure_bprm_creds_for_exec(struct linux_binprm *bprm)
{
	copy_cred_blob(bprm->cred, current_cred());
	return 0;
}

static int pressure_bprm_check_security(struct linux_binprm *bprm)
{
	const struct cred *cred = current_cred();
	const struct pressure_cred_blob *cb = pressure_cred(cred);
	struct inode *inode = file_inode(bprm->file);
	struct pressure_inode_blob *ib = pressure_inode(inode);
	u8 prov = pressure_effective_prov(current, cred);

	if (bprm->file && bprm->file->f_path.dentry)
		pressure_refresh_inode_xattr(bprm->file->f_path.dentry, inode);

	/*
	 * RCE hard-stop: tasks carrying REMOTE provenance (e.g. web/PHP workers
	 * tainted by external socket ingress or remote login) cannot execve()
	 * unless an explicit policy rule grants PEV_EXEC for that binary!
	 */
	if (prov == PRESSURE_PROV_REMOTE) {
		bool matched = false;
		const char *slbl = (cb && cb->label[0]) ? cb->label : "subj:remote";
		const char *olbl = (ib && ib->label[0]) ? ib->label : "obj:unlabeled";
		bool ok = pressure_eval_policy_rule(slbl, olbl, "*", PEV_EXEC,
						    prov, &matched);
		if (!matched || !ok) {
			pressure_record_violation(current,
						  PVIO_REMOTE_EXEC_BLOCKED,
						  (u32)inode->i_ino,
						  bprm->filename);
			if (READ_ONCE(pressure_enforce))
				return -EACCES;
		}
	}

	return pressure_check_inode_access(cred, inode, PEV_EXEC);
}

static int pressure_userns_create(const struct cred *new)
{
	const struct cred *cred = current_cred();
	const struct pressure_cred_blob *cb = pressure_cred(cred);
	const struct pressure_inode_blob *inode;
	struct file *executable;
	const char *detail;
	char device[32];
	u32 event = PEV_USERNS;
	bool allowed = false;

	if (!READ_ONCE(pressure_enforce))
		return 0;
	if (!cb || cb->account_type != PRESSURE_ACCT_HUMAN) {
		detail = "userns_requires_human";
		goto denied;
	}
	if (cred->user_ns != &init_user_ns) {
		if (cred->user_ns->parent != &init_user_ns ||
		    !uid_eq(cred->user_ns->owner, cred->euid)) {
			detail = "userns_nested_scope";
			goto denied;
		}
		event = PEV_USERNS_NESTED;
	}
	if (!pressure_get_verified_session_dev(current, cred, device,
					       sizeof(device)) ||
	    strcmp(device, "dev:console_tty1")) {
		detail = "userns_requires_tty1_session";
		goto denied;
	}

	executable = get_task_exe_file(current);
	if (!executable) {
		detail = "userns_no_executable";
		goto denied;
	}
	inode = pressure_inode(file_inode(executable));
	detail = "userns_executable_unlabeled";
	if (inode && inode->label[0]) {
		detail = "userns_no_matching_rule";
		allowed = pressure_eval_exact_local_rule(cb->label, inode->label, device, event);
	}
	fput(executable);
	if (allowed)
		return 0;
denied:
	pressure_record_violation(current, PVIO_USERNS_DENIED, 0, detail);
	return -EACCES;
}

static int pressure_inode_alloc_security(struct inode *inode)
{
	struct pressure_inode_blob *ib = pressure_inode(inode);

	if (ib) {
		ib->obj_pub_id = get_random_u64() | 1ULL;
		ib->obj_priv_id = get_random_u64() | 1ULL;
	}
	return 0;
}

static void pressure_d_instantiate(struct dentry *dentry, struct inode *inode)
{
	struct pressure_inode_blob *ib;
	struct dentry *parent;

	if (!inode)
		return;

	ib = pressure_inode(inode);
	if (!ib)
		return;

	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode)) {
		pressure_refresh_inode_xattr(dentry, inode);
		return;
	}

	/* Inherit user/daemon private data protection from parent directory! */
	if (!ib->initialized && dentry && !IS_ROOT(dentry)) {
		parent = dget_parent(dentry);
		if (parent && d_inode(parent)) {
			struct pressure_inode_blob *pib =
				pressure_inode(d_inode(parent));
			if (pib && (pib->flags & (PRESSURE_FILE_USER_PRIVATE |
						  PRESSURE_FILE_LOCAL_ONLY |
						  PRESSURE_FILE_AUTHD_VAULT |
						  PRESSURE_FILE_PROTECTED))) {
				ib->flags |= pib->flags;
				ib->owner_pub_uid = pib->owner_pub_uid;
				ib->owner_kpriv_uid = pib->owner_kpriv_uid;
				strscpy(ib->label, pib->label, sizeof(ib->label));
				ib->initialized = true;
			}
		}
		dput(parent);
	}
}

static int check_dentry_inode_write(struct dentry *dentry)
{
	struct inode *inode;
	struct pressure_inode_blob *ib;

	if (!dentry)
		return 0;
	inode = d_inode(dentry);
	if (!inode)
		return 0;
	ib = pressure_inode(inode);
	if (ib && !ib->initialized) {
		pressure_d_instantiate(dentry, inode);
		if (!ib->initialized)
			pressure_refresh_inode_xattr(dentry, inode);
	}
	return pressure_check_inode_access(current_cred(), inode, PEV_WRITE);
}

static int pressure_inode_create(struct inode *dir, struct dentry *dentry,
				 umode_t mode)
{
	(void)dentry;
	(void)mode;
	return pressure_check_inode_access(current_cred(), dir, PEV_WRITE);
}

static int pressure_inode_mkdir(struct inode *dir, struct dentry *dentry,
				umode_t mode)
{
	(void)dentry;
	(void)mode;
	return pressure_check_inode_access(current_cred(), dir, PEV_WRITE);
}

static int pressure_inode_symlink(struct inode *dir, struct dentry *dentry,
				  const char *old_name)
{
	(void)dentry;
	(void)old_name;
	return pressure_check_inode_access(current_cred(), dir, PEV_WRITE);
}

static int pressure_inode_link(struct dentry *old_dentry, struct inode *dir,
			       struct dentry *new_dentry)
{
	int rc;

	(void)new_dentry;
	rc = pressure_check_inode_access(current_cred(), dir, PEV_WRITE);
	if (rc < 0)
		return rc;
	return check_dentry_inode_write(old_dentry);
}

static int pressure_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	int rc = pressure_check_inode_access(current_cred(), dir, PEV_WRITE);

	if (rc < 0)
		return rc;
	return check_dentry_inode_write(dentry);
}

static int pressure_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	int rc = pressure_check_inode_access(current_cred(), dir, PEV_WRITE);

	if (rc < 0)
		return rc;
	return check_dentry_inode_write(dentry);
}

static int pressure_inode_rename(struct inode *old_dir,
				 struct dentry *old_dentry,
				 struct inode *new_dir,
				 struct dentry *new_dentry)
{
	int rc;

	rc = pressure_check_inode_access(current_cred(), old_dir, PEV_WRITE);
	if (rc < 0)
		return rc;
	rc = check_dentry_inode_write(old_dentry);
	if (rc < 0)
		return rc;
	if (new_dir != old_dir) {
		rc = pressure_check_inode_access(current_cred(), new_dir,
						 PEV_WRITE);
		if (rc < 0)
			return rc;
	}
	return check_dentry_inode_write(new_dentry);
}

static int pressure_inode_setattr(struct mnt_idmap *idmap,
				  struct dentry *dentry, struct iattr *attr)
{
	(void)idmap;
	if (!attr)
		return 0;
	if (attr->ia_valid & (ATTR_SIZE | ATTR_MODE | ATTR_UID | ATTR_GID |
			      ATTR_FORCE))
		return check_dentry_inode_write(dentry);
	return 0;
}

static int pressure_inode_mknod(struct inode *dir, struct dentry *dentry,
				umode_t mode, dev_t dev)
{
	const struct cred *cred = current_cred();
	const struct pressure_cred_blob *cb = pressure_cred(cred);
	u8 prov = pressure_effective_prov(current, cred);
	int rc;

	rc = pressure_check_inode_access(cred, dir, PEV_WRITE);
	if (rc < 0)
		return rc;

	if (S_ISCHR(mode) || S_ISBLK(mode)) {
		if (prov == PRESSURE_PROV_REMOTE ||
		    (cb && (cb->confined ||
			    cb->account_type == PRESSURE_ACCT_DAEMON ||
			    cb->account_type == PRESSURE_ACCT_HUMAN))) {
			pressure_record_violation(current, PVIO_MKNOD_BLOCKED,
						  (u32)dev,
						  dentry ? (const char *)dentry->d_name.name :
						  "mknod");
			if (READ_ONCE(pressure_enforce))
				return -EPERM;
		}
	}
	return 0;
}

static int pressure_inode_setxattr(struct mnt_idmap *idmap,
				   struct dentry *dentry, const char *name,
				   const void *value, size_t size, int flags)
{
	const struct cred *cred = current_cred();
	const struct pressure_cred_blob *cb = pressure_cred(cred);
	u8 prov = pressure_effective_prov(current, cred);

	if (strcmp(name, XATTR_NAME_PRESSURE) != 0)
		return 0;

	/* Only local admin (sure) or pressure-authd may write security.pressure */
	if (prov == PRESSURE_PROV_REMOTE ||
	    (cb && cb->confined && cb->account_type != PRESSURE_ACCT_AUTHD) ||
	    !capable(CAP_MAC_ADMIN)) {
		pressure_record_violation(current, PVIO_POLICY_DENY, 0,
					  "setxattr_pressure");
		return -EPERM;
	}
	return 0;
}

static void pressure_inode_post_setxattr(struct dentry *dentry,
					 const char *name, const void *value,
					 size_t size, int flags)
{
	if (dentry && d_inode(dentry) &&
	    strcmp(name, XATTR_NAME_PRESSURE) == 0)
		pressure_refresh_inode_xattr(dentry, d_inode(dentry));
}

static int pressure_inode_removexattr(struct mnt_idmap *idmap,
				      struct dentry *dentry, const char *name)
{
	if (strcmp(name, XATTR_NAME_PRESSURE) == 0 && !capable(CAP_MAC_ADMIN))
		return -EPERM;
	return 0;
}

static int pressure_file_alloc_security(struct file *file)
{
	struct pressure_file_blob *fb = pressure_file(file);
	const struct cred *cred = current_cred();
	const struct pressure_cred_blob *cb = pressure_cred(cred);

	if (fb) {
		fb->file_pub_id = get_random_u64() | 1ULL;
		fb->file_priv_id = get_random_u64() | 1ULL;
		fb->opener_kpriv_uid = cb ? cb->kpriv_uid : 0;
		fb->opener_provenance = pressure_effective_prov(current, cred);
	}
	return 0;
}

static int pressure_file_open(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct pressure_inode_blob *ib = pressure_inode(inode);
	u32 ev = PEV_OPEN;
	int rc;

	if (file->f_path.dentry) {
		pressure_d_instantiate(file->f_path.dentry, inode);
		if (ib && !ib->initialized)
			pressure_refresh_inode_xattr(file->f_path.dentry, inode);
	}

	if (file->f_mode & FMODE_READ)
		ev |= PEV_READ;
	if (file->f_mode & FMODE_WRITE)
		ev |= PEV_WRITE;

	rc = pressure_check_inode_access(current_cred(), inode, ev);
	if (rc < 0)
		return rc;
	return pressure_claim_dev_file(inode, pressure_file(file));
}

static void pressure_file_release(struct file *file)
{
	pressure_release_dev_file(pressure_file(file));
}

static int pressure_file_permission(struct file *file, int mask)
{
	u32 ev = (mask & MAY_WRITE) ? PEV_WRITE : PEV_READ;

	return pressure_check_inode_access(current_cred(), file_inode(file), ev);
}

static int check_unix_fd_transfer(struct sock *sk, const char *op_name);

static bool is_local_proxy_socket(struct socket *sock);
static bool local_proxy_owned(struct socket *sock, bool established);
static bool local_callback_endpoint(const struct sock *sk);

static int pressure_file_fd_lookup(struct file *file, unsigned int priv_fd,
				   unsigned int pub_fd)
{
	struct inode *inode;
	const struct cred *cred = current_cred();
	const struct pressure_cred_blob *cb = pressure_cred(cred);
	const char *slbl = (cb && cb->label[0]) ? cb->label : "subj:boot";
	u8 prov;
	u32 ev;

	if (!file || (current->flags & PF_KTHREAD))
		return 0;

	inode = file_inode(file);
	prov = pressure_effective_prov(current, cred);

	/* Socket descriptor check: enforce LOCAL/REMOTE, cross-subject/session inheritance & revocation! */
	if (S_ISSOCK(inode->i_mode)) {
		struct socket *sock = sock_from_file(file);
		if (is_local_proxy_socket(sock) && !local_proxy_owned(sock, true))
			return -EACCES;
		if (sock && sock->sk) {
			struct pressure_sock_blob *sb = pressure_sock(sock->sk);
			if (sb && sb->remote_tainted &&
			    prov != PRESSURE_PROV_REMOTE)
				pressure_taint_task_remote(current);
			if (sock->sk->sk_family == AF_UNIX &&
			    READ_ONCE(pressure_enforce) && sb) {
				bool cross_subj = sb->owner_label[0] &&
						  strcmp(sb->owner_label, slbl) != 0;
				bool cross_sess = sb->owner_session_priv_id != 0 &&
						  (!cb ||
						   sb->owner_session_priv_id != cb->session_priv_id ||
						   !pressure_session_is_active(sb->owner_session_priv_id));
				if (cross_subj || cross_sess) {
					int urc = check_unix_fd_transfer(
						sock->sk,
						cross_sess ?
						"unix_revoked_or_cross_sess_fd" :
						"unix_inherited_fd");
					if (urc < 0)
						return urc;
				}
			}
		}
	}

	ev = (!(file->f_mode & FMODE_READ) && (file->f_mode & FMODE_WRITE)) ?
	     PEV_WRITE : PEV_READ;
	return pressure_check_inode_access(cred, inode, ev);
}

static int pressure_file_receive(struct file *file)
{
	struct inode *inode;
	const struct cred *cred = current_cred();
	u32 ev = PEV_OPEN;

	if (!file || (current->flags & PF_KTHREAD))
		return 0;

	inode = file_inode(file);
	if (S_ISSOCK(inode->i_mode)) {
		struct socket *sock = sock_from_file(file);
		if (is_local_proxy_socket(sock))
			return -EACCES;
		if (sock && sock->sk && sock->sk->sk_family == AF_UNIX &&
		    READ_ONCE(pressure_enforce)) {
			int urc = check_unix_fd_transfer(sock->sk,
							 "unix_scm_recv");
			if (urc < 0)
				return urc;
		}
	}

	if (file->f_mode & FMODE_READ)
		ev |= PEV_READ;
	if (file->f_mode & FMODE_WRITE)
		ev |= PEV_WRITE;
	return pressure_check_inode_access(cred, inode, ev);
}

static int pressure_file_ioctl(struct file *file, unsigned int cmd,
			       unsigned long arg)
{
	return pressure_check_inode_access(current_cred(), file_inode(file),
					   PEV_IOCTL);
}

static int pressure_mmap_file(struct file *file, unsigned long reqprot,
			      unsigned long prot, unsigned long flags)
{
	const struct cred *cred = current_cred();
	u8 prov = pressure_effective_prov(current, cred);

	(void)reqprot;
	if ((prot & PROT_EXEC) &&
	    ((prot & PROT_WRITE) || (!file && prov == PRESSURE_PROV_REMOTE))) {
		pressure_record_violation(current, PVIO_REMOTE_WX_MMAP,
					  (u32)prot, "wx_or_anon_exec_mmap");
		if (READ_ONCE(pressure_enforce))
			return -EACCES;
	}
	if (file) {
		u32 ev = 0;

		if (prot & PROT_READ)
			ev |= PEV_READ;
		if ((prot & PROT_WRITE) && (flags & MAP_SHARED))
			ev |= PEV_WRITE | PEV_MMAP_WRITE;
		else if (prot & PROT_WRITE)
			ev |= PEV_READ;
		if (prot & PROT_EXEC)
			ev |= PEV_MMAP_EXEC;
		if (ev)
			return pressure_check_inode_access(cred,
							   file_inode(file), ev);
	}
	return 0;
}

static int pressure_file_mprotect(struct vm_area_struct *vma,
				  unsigned long reqprot, unsigned long prot)
{
	const struct cred *cred = current_cred();
	u8 prov = pressure_effective_prov(current, cred);

	(void)reqprot;
	if ((prot & PROT_EXEC) &&
	    ((prot & PROT_WRITE) || prov == PRESSURE_PROV_REMOTE)) {
		pressure_record_violation(current, PVIO_REMOTE_WX_MMAP,
					  (u32)prot, "mprotect_exec_blocked");
		if (READ_ONCE(pressure_enforce))
			return -EACCES;
	}
	if (vma && vma->vm_file) {
		u32 ev = 0;

		if (prot & PROT_READ)
			ev |= PEV_READ;
		if ((prot & PROT_WRITE) && (vma->vm_flags & VM_SHARED))
			ev |= PEV_WRITE | PEV_MMAP_WRITE;
		if (prot & PROT_EXEC)
			ev |= PEV_MMAP_EXEC;
		if (ev)
			return pressure_check_inode_access(
				cred, file_inode(vma->vm_file), ev);
	}
	return 0;
}

static bool pressure_proc_self_fd_allowed(const struct cred *cred)
{
	const struct pressure_cred_blob *cb = pressure_cred(cred);
	const struct pressure_inode_blob *ib;
	struct file *exe;
	char device[32];
	bool allowed;

	if (!cb || cb->account_type != PRESSURE_ACCT_HUMAN ||
	    !pressure_get_proxy_session_dev(cred, device, sizeof(device), false) ||
	    (strcmp(device, "dev:console_tty1") && strcmp(device, "dev:tty1_helper")))
		return false;

	exe = current->mm ? get_mm_exe_file(current->mm) : NULL;
	if (!exe)
		return false;
	ib = pressure_inode(file_inode(exe));
	allowed = ib && ib->label[0] &&
		  pressure_eval_exact_local_rule(cb->label, ib->label, device,
						 PEV_PROC_SELF_FD);
	fput(exe);
	return allowed;
}

static int pressure_proc_fd_access(struct task_struct *target)
{
	const struct cred *cred = current_cred();
	const struct pressure_cred_blob *cb = pressure_cred(cred);
	u8 prov = pressure_effective_prov(current, cred);

	/* The explicitly selected POSIX ABI exposes ordinary descriptor
	 * numbers. Confine enumeration to the caller's own file table.
	 */
	if (prov == PRESSURE_PROV_AUTH_LOCAL &&
	    same_thread_group(current, target)) {
		struct files_struct *files = current->files;
		bool own_posix_files;

		task_lock(target);
		own_posix_files = files && target->files == files &&
				  !READ_ONCE(files->pressure_fd_mode);
		task_unlock(target);
		if (own_posix_files && (pressure_posix_fd_allowed(cred) ||
					pressure_proc_self_fd_allowed(cred)))
			return 0;
	}

	if (prov == PRESSURE_PROV_REMOTE ||
	    (cb && cb->confined && cb->account_type != PRESSURE_ACCT_AUTHD)) {
		pressure_record_violation(current, PVIO_PROC_FD_ENUM,
					  task_tgid_nr(target),
					  "/proc/pid/fd");
		if (READ_ONCE(pressure_enforce))
			return -EACCES;
	}
	return 0;
}

static const char *current_subj_label(const struct cred *cred)
{
	const struct pressure_cred_blob *cb = pressure_cred(cred);

	if (current->flags & PF_KTHREAD)
		return "subj:kernel";
	return (cb && cb->label[0]) ? cb->label : "subj:boot";
}

static void format_unix_sockaddr_raw(const struct sockaddr_un *sun, int addrlen,
				     char *out, size_t out_sz,
				     bool *is_abstract)
{
	int plen;

	if (!out || out_sz == 0)
		return;
	if (!sun || addrlen <= (int)offsetof(struct sockaddr_un, sun_path)) {
		if (is_abstract)
			*is_abstract = true;
		strscpy(out, "@autobind", out_sz);
		return;
	}

	plen = addrlen - (int)offsetof(struct sockaddr_un, sun_path);
	if (plen > (int)sizeof(sun->sun_path))
		plen = (int)sizeof(sun->sun_path);

	if (sun->sun_path[0] == '\0') {
		size_t oi = 0;
		int i;

		if (is_abstract)
			*is_abstract = true;
		if (out_sz > 1)
			out[oi++] = '@';
		for (i = 1; i < plen && oi + 1 < out_sz; i++) {
			unsigned char c = (unsigned char)sun->sun_path[i];

			if (c >= 0x21 && c <= 0x7e)
				out[oi++] = (char)c;
			else
				out[oi++] = '?';
		}
		out[oi] = '\0';
		if (oi <= 1)
			strscpy(out, "@autobind", out_sz);
		return;
	}

	if (is_abstract)
		*is_abstract = false;
	{
		size_t n = strnlen(sun->sun_path, (size_t)plen);

		if (n >= out_sz)
			n = out_sz - 1;
		memcpy(out, sun->sun_path, n);
		out[n] = '\0';
	}
}

static void canonicalize_unix_path_sleepable(const char *raw_path,
					     bool for_bind,
					     char *out, size_t out_sz)
{
	struct path p;
	char *tmp;

	if (!raw_path || !raw_path[0]) {
		strscpy(out, "unbound", out_sz);
		return;
	}

	tmp = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!tmp) {
		strscpy(out, raw_path, out_sz);
		return;
	}

	if (!for_bind && kern_path(raw_path, LOOKUP_FOLLOW, &p) == 0) {
		char *res = d_path(&p, tmp, PATH_MAX);

		if (!IS_ERR(res)) {
			strscpy(out, res, out_sz);
			path_put(&p);
			kfree(tmp);
			return;
		}
		path_put(&p);
	}

	{
		const char *slash = strrchr(raw_path, '/');

		if (slash) {
			char dirbuf[112];
			size_t dlen = (size_t)(slash - raw_path);
			const char *base = slash + 1;

			if (dlen == 0) {
				strscpy(dirbuf, "/", sizeof(dirbuf));
			} else {
				if (dlen >= sizeof(dirbuf))
					dlen = sizeof(dirbuf) - 1;
				memcpy(dirbuf, raw_path, dlen);
				dirbuf[dlen] = '\0';
			}
			if (kern_path(dirbuf, LOOKUP_FOLLOW, &p) == 0) {
				char *res = d_path(&p, tmp, PATH_MAX);

				if (!IS_ERR(res)) {
					if (strcmp(res, "/") == 0)
						snprintf(out, out_sz, "/%s", base);
					else
						snprintf(out, out_sz, "%s/%s",
							 res, base);
					path_put(&p);
					kfree(tmp);
					return;
				}
				path_put(&p);
			}
		} else if (current->fs) {
			char *res;

			get_fs_pwd(current->fs, &p);
			res = d_path(&p, tmp, PATH_MAX);
			if (!IS_ERR(res)) {
				if (strcmp(res, "/") == 0)
					snprintf(out, out_sz, "/%s", raw_path);
				else
					snprintf(out, out_sz, "%s/%s",
						 res, raw_path);
				path_put(&p);
				kfree(tmp);
				return;
			}
			path_put(&p);
		}
	}

	strscpy(out, raw_path, out_sz);
	kfree(tmp);
}

static void unix_extract_peer_info_atomic(struct sock *other,
					  char *ep_out, size_t ep_sz,
					  char *peer_out, size_t peer_sz)
{
	struct pressure_sock_blob *osb = pressure_sock(other);
	struct unix_address *uaddr;
	bool is_abs = false;

	if (osb && osb->bound_addr[0]) {
		strscpy(ep_out, osb->bound_addr, ep_sz);
	} else {
		uaddr = smp_load_acquire(&unix_sk(other)->addr);
		if (uaddr)
			format_unix_sockaddr_raw(uaddr->name, uaddr->len,
						 ep_out, ep_sz, &is_abs);
		else if (osb && osb->peer_addr[0])
			strscpy(ep_out, osb->peer_addr, ep_sz);
		else
			strscpy(ep_out, "unbound", ep_sz);
	}

	if (strcmp(ep_out, SFW_MUX_SOCK_PATH) == 0)
		strscpy(peer_out, "subj:sfw_worker", peer_sz);
	else if (osb && osb->owner_label[0])
		strscpy(peer_out, osb->owner_label, peer_sz);
	else
		strscpy(peer_out, "subj:kernel", peer_sz);
}

static int check_unix_fd_transfer(struct sock *sk, const char *op_name)
{
	const struct cred *cred = current_cred();
	const char *slbl = current_subj_label(cred);
	u8 prov = pressure_effective_prov(current, cred);
	struct pressure_sock_blob *sb = pressure_sock(sk);
	u16 stype = sk ? sk->sk_type : 0;
	char ep1[112], peer_lbl[32], caller_dev[32];
	bool matched = false;

	if (!sk || (current->flags & PF_KTHREAD))
		return 0;

	pressure_get_unix_session_dev(cred, caller_dev, sizeof(caller_dev));

	if (sb && sb->peer_addr[0]) {
		strscpy(ep1, sb->peer_addr, sizeof(ep1));
		strscpy(peer_lbl,
			sb->peer_label[0] ? sb->peer_label :
			(sb->owner_label[0] ? sb->owner_label : "*"),
			sizeof(peer_lbl));
	} else if (sb && sb->bound_addr[0]) {
		strscpy(ep1, sb->bound_addr, sizeof(ep1));
		strscpy(peer_lbl,
			sb->owner_label[0] ? sb->owner_label : "*",
			sizeof(peer_lbl));
	} else {
		unix_extract_peer_info_atomic(sk, ep1, sizeof(ep1),
					      peer_lbl, sizeof(peer_lbl));
	}

	if (!pressure_unix_eval_rule(slbl, stype, PUNIX_OP_PASS_FD,
				     ep1, peer_lbl, caller_dev, prov,
				     &matched)) {
		if (strcmp(op_name, "unix_revoked_or_cross_sess_fd") && peer_lbl[0] != '*')
			pressure_record_unix_denial(stype, PUNIX_OP_PASS_FD, ep1,
						    slbl, caller_dev, peer_lbl);
		else
			pressure_record_violation(current, PVIO_UNIX_SOCKET_DENY, stype, op_name);
		return -EACCES;
	}

	if (sb && sb->bound_addr[0] && sb->peer_addr[0] &&
	    strcmp(sb->bound_addr, sb->peer_addr) != 0) {
		if (!pressure_unix_eval_rule(slbl, stype, PUNIX_OP_PASS_FD,
					     sb->bound_addr,
					     sb->owner_label[0] ?
					     sb->owner_label : "*",
					     caller_dev, prov, &matched)) {
			if (strcmp(op_name, "unix_revoked_or_cross_sess_fd") && sb->owner_label[0])
				pressure_record_unix_denial(stype, PUNIX_OP_PASS_FD, sb->bound_addr,
							    slbl, caller_dev, sb->owner_label);
			else
				pressure_record_violation(current, PVIO_UNIX_SOCKET_DENY, stype, op_name);
			return -EACCES;
		}
	}
	return 0;
}

static u64 pressure_unix_owner_session(const struct pressure_cred_blob *cb)
{
	return cb && cb->account_type == PRESSURE_ACCT_HUMAN ?
	       cb->session_priv_id : 0;
}

static int pressure_sk_alloc_security(struct sock *sk, int family,
				      gfp_t priority)
{
	struct pressure_sock_blob *sb = pressure_sock(sk);
	const struct cred *cred = current_cred();
	const struct pressure_cred_blob *cb = pressure_cred(cred);

	if (sb) {
		sb->sock_pub_id = get_random_u64() | 1ULL;
		sb->sock_priv_id = get_random_u64() | 1ULL;
		if (family == AF_UNIX) {
			sb->owner_kpriv_uid = cb ? cb->kpriv_uid : 0;
			sb->owner_session_priv_id = pressure_unix_owner_session(cb);
			strscpy(sb->owner_label, current_subj_label(cred),
				sizeof(sb->owner_label));
		}
	}
	return 0;
}

static int check_vsock_access(u32 ev_bit, const char *op_name)
{
	const struct cred *cred = current_cred();
	const struct pressure_cred_blob *cb = pressure_cred(cred);
	u8 prov = pressure_effective_prov(current, cred);
	const char *slbl = (cb && cb->label[0]) ? cb->label : "subj:boot";
	bool matched = false;
	bool ok;

	if (current->flags & PF_KTHREAD)
		return 0;

	ok = pressure_eval_policy_rule(slbl, "obj:vsock", "dev:vsock",
				       ev_bit, prov, &matched);
	if (matched && !ok) {
		pressure_record_violation(current, PVIO_POLICY_DENY,
					  AF_VSOCK, op_name);
		return READ_ONCE(pressure_enforce) ? -EACCES : 0;
	}
	if (prov == PRESSURE_PROV_REMOTE && !matched) {
		pressure_record_violation(current, PVIO_REMOTE_TO_LOCAL_FD,
					  AF_VSOCK, "remote_vsock_blocked");
		return READ_ONCE(pressure_enforce) ? -EACCES : 0;
	}
	return 0;
}

/*
 * Socket isolation:
 * - Direct AF_INET / AF_INET6 / AF_PACKET sockets are hard-stopped in userspace;
 *   IP networking flows through the root-owned AF_UNIX sfw worker.
 * - AF_UNIX creation (including socketpair) is default-deny in enforcing mode
 *   unless explicitly authorized by unix_rules for the subject, socket type,
 *   and verified session/device; bind/connect/send/recv and FD passing or
 *   inheritance are gated separately.
 * - AF_VSOCK is gated by obj:vsock / dev:vsock MAC rules and hard-stopped for
 *   REMOTE tasks.
 */
/*
 * A statically linked native app can use the supervised SFW gateway.
 * File/terminal authority still uses pressure_get_verified_session_dev().
 */
#define PRESSURE_CALLBACK_PORT 1455

static bool local_socket_authorized(const struct cred *cred, bool established,
				    u32 event)
{
	const struct pressure_cred_blob *cb = pressure_cred(cred);
	const struct pressure_inode_blob *ib;
	struct file *exe;
	char device[32];
	bool allowed;

	if (!cb || cb->account_type != PRESSURE_ACCT_HUMAN ||
	    !current->nsproxy || current->nsproxy->net_ns != &init_net ||
	    !pressure_get_proxy_session_dev(cred, device, sizeof(device), established) ||
	    (strcmp(device, "dev:console_tty1") && strcmp(device, "dev:tty1_helper")))
		return false;

	exe = current->mm ? get_mm_exe_file(current->mm) : NULL;
	if (!exe)
		return false;
	ib = pressure_inode(file_inode(exe));
	allowed = ib && ib->label[0] &&
		  pressure_eval_exact_local_rule(cb->label, ib->label, device, event);
	fput(exe);
	return allowed;
}

static bool is_local_proxy_socket(struct socket *sock)
{
	const struct pressure_sock_blob *sb;

	if (!sock || !sock->sk || sock->sk->sk_family != AF_INET)
		return false;
	sb = pressure_sock(sock->sk);
	return sb && sb->local_proxy;
}

static bool local_proxy_owned(struct socket *sock, bool established)
{
	const struct pressure_cred_blob *cb = pressure_cred(current_cred());
	const struct pressure_sock_blob *sb = pressure_sock(sock->sk);
	bool callback = READ_ONCE(sb->local_callback);
	u32 event = sb->local_callback_relay ? PEV_LOCAL_CALLBACK_RELAY : PEV_LOCAL_PROXY;

	if (callback) {
		__be32 peer = READ_ONCE(inet_sk(sock->sk)->inet_daddr);

		if (!local_callback_endpoint(sock->sk) ||
		    (peer && peer != htonl(INADDR_LOOPBACK)))
			return false;
		event = PEV_LOCAL_CALLBACK;
	}

	return cb && sb->owner_session_priv_id &&
	       sb->owner_session_priv_id == cb->session_priv_id &&
	       local_socket_authorized(current_cred(), established, event);
}

static bool local_callback_endpoint(const struct sock *sk)
{
	const struct inet_sock *inet = inet_sk(sk);

	return READ_ONCE(inet->inet_rcv_saddr) == htonl(INADDR_LOOPBACK) &&
	       READ_ONCE(inet->inet_sport) == htons(PRESSURE_CALLBACK_PORT);
}

static void pressure_sk_clone_security(const struct sock *parent, struct sock *child)
{
	const struct pressure_sock_blob *source = pressure_sock(parent);
	struct pressure_sock_blob *target = pressure_sock(child);

	if (source && target && READ_ONCE(source->local_callback)) {
		target->local_proxy = true;
		target->local_callback = true;
		target->owner_session_priv_id = source->owner_session_priv_id;
	}
}

static int pressure_socket_create(int family, int type, int protocol, int kern)
{
	const struct cred *cred = current_cred();
	const struct pressure_cred_blob *cb = pressure_cred(cred);
	u8 prov = pressure_effective_prov(current, cred);

	if (kern || (current->flags & PF_KTHREAD) ||
	    current == READ_ONCE(pressure_sfw_kthread))
		return 0;

	if (family == AF_UNIX) {
		u16 stype = (u16)(type & SOCK_TYPE_MASK);
		char caller_dev[32];
		bool matched = false;

		if (!READ_ONCE(pressure_enforce))
			return 0;
		pressure_get_unix_session_dev(cred, caller_dev, sizeof(caller_dev));
		if (!pressure_unix_eval_rule(current_subj_label(cred), stype,
					     PUNIX_OP_CREATE, "-", "*",
					     caller_dev, prov, &matched)) {
			pressure_record_unix_denial(stype, PUNIX_OP_CREATE, "-",
						    current_subj_label(cred), caller_dev, NULL);
			return -EACCES;
		}
		return 0;
	}

	if (family == AF_VSOCK)
		return check_vsock_access(PEV_OPEN, "vsock_create");

	/* Allow isolated external simulation netns peers created by unconfined local admin */
	if (current->nsproxy && current->nsproxy->net_ns != &init_net &&
	    (!cb || !cb->confined) && prov != PRESSURE_PROV_REMOTE &&
	    capable(CAP_NET_ADMIN))
		return 0;

	if (family == AF_INET && type == SOCK_STREAM &&
	    (!protocol || protocol == IPPROTO_TCP) &&
	    (local_socket_authorized(cred, false, PEV_LOCAL_PROXY) ||
	     local_socket_authorized(cred, false, PEV_LOCAL_CALLBACK_RELAY)))
		return 0;
	if (family == AF_INET || family == AF_INET6 || family == AF_PACKET) {
		if (READ_ONCE(pressure_enforce) ||
		    (cb && cb->confined) ||
		    prov == PRESSURE_PROV_REMOTE) {
			pressure_record_violation(current, PVIO_RAW_IP_SOCKET,
						  (u32)family,
						  "must_use_af_unix_sfw");
			if (READ_ONCE(pressure_enforce))
				return -EACCES;
		}
	}
	return 0;
}

static int pressure_socket_post_create(struct socket *sock, int family,
				       int type, int protocol, int kern)
{
	const struct cred *cred = current_cred();
	const struct pressure_cred_blob *cb = pressure_cred(cred);

	if (family == AF_INET && sock && sock->sk && !kern &&
	    !(current->flags & PF_KTHREAD) &&
	    current != READ_ONCE(pressure_sfw_kthread) &&
	    sock_net(sock->sk) == &init_net) {
		struct pressure_sock_blob *sb = pressure_sock(sock->sk);

		if (sb && cb && type == SOCK_STREAM &&
		    (!protocol || protocol == IPPROTO_TCP)) {
			bool proxy = local_socket_authorized(cred, false, PEV_LOCAL_PROXY);
			bool relay = !proxy &&
				     local_socket_authorized(cred, false, PEV_LOCAL_CALLBACK_RELAY);

			if (proxy || relay) {
				sb->local_proxy = true;
				sb->local_callback_relay = relay;
				sb->owner_session_priv_id = cb->session_priv_id;
			}
		}
		if ((!sb || !sb->local_proxy) && READ_ONCE(pressure_enforce))
			return -EACCES;
	}

	if (family == AF_UNIX && sock && sock->sk) {
		struct pressure_sock_blob *sb = pressure_sock(sock->sk);

		if (sb) {
			bool is_k = kern || (current->flags & PF_KTHREAD);

			sb->unix_type = (u16)(type & SOCK_TYPE_MASK);
			sb->owner_kpriv_uid = is_k ? 0 : (cb ? cb->kpriv_uid : 0);
			sb->owner_session_priv_id = is_k ? 0 :
						    pressure_unix_owner_session(cb);
			strscpy(sb->owner_label,
				is_k ? "subj:kernel" : current_subj_label(cred),
				sizeof(sb->owner_label));
		}
	}
	return 0;
}

static int pressure_socket_socketpair(struct socket *socka,
				      struct socket *sockb)
{
	const struct cred *cred = current_cred();
	const struct pressure_cred_blob *cb = pressure_cred(cred);
	const char *slbl = current_subj_label(cred);
	u8 prov = pressure_effective_prov(current, cred);
	struct pressure_sock_blob *sba, *sbb;
	u16 stype;
	char pair_ep[112], caller_dev[32];
	bool matched = false;

	if (!socka || !socka->sk || !sockb || !sockb->sk)
		return 0;
	if (socka->sk->sk_family != AF_UNIX)
		return 0;

	stype = (u16)(socka->type & SOCK_TYPE_MASK);
	snprintf(pair_ep, sizeof(pair_ep), "pair:%s", slbl);

	sba = pressure_sock(socka->sk);
	sbb = pressure_sock(sockb->sk);
	if (sba) {
		sba->unix_type = stype;
		sba->unix_is_pair = true;
		sba->unix_has_peer = true;
		sba->owner_kpriv_uid = cb ? cb->kpriv_uid : 0;
		sba->owner_session_priv_id = pressure_unix_owner_session(cb);
		strscpy(sba->owner_label, slbl, sizeof(sba->owner_label));
		strscpy(sba->peer_label, slbl, sizeof(sba->peer_label));
		strscpy(sba->bound_addr, pair_ep, sizeof(sba->bound_addr));
		strscpy(sba->peer_addr, pair_ep, sizeof(sba->peer_addr));
	}
	if (sbb) {
		sbb->unix_type = stype;
		sbb->unix_is_pair = true;
		sbb->unix_has_peer = true;
		sbb->owner_kpriv_uid = cb ? cb->kpriv_uid : 0;
		sbb->owner_session_priv_id = pressure_unix_owner_session(cb);
		strscpy(sbb->owner_label, slbl, sizeof(sbb->owner_label));
		strscpy(sbb->peer_label, slbl, sizeof(sbb->peer_label));
		strscpy(sbb->bound_addr, pair_ep, sizeof(sbb->bound_addr));
		strscpy(sbb->peer_addr, pair_ep, sizeof(sbb->peer_addr));
	}

	if ((current->flags & PF_KTHREAD) || !READ_ONCE(pressure_enforce))
		return 0;

	pressure_get_unix_session_dev(cred, caller_dev, sizeof(caller_dev));
	if (!pressure_unix_eval_rule(slbl, stype, PUNIX_OP_SOCKETPAIR,
				     pair_ep, slbl, caller_dev, prov,
				     &matched)) {
		pressure_record_unix_denial(stype, PUNIX_OP_SOCKETPAIR, pair_ep,
					    slbl, caller_dev, slbl);
		return -EACCES;
	}
	return 0;
}

static int pressure_socket_bind(struct socket *sock, struct sockaddr *address,
				int addrlen)
{
	if (!sock || !sock->sk)
		return 0;
	if (is_local_proxy_socket(sock)) {
		const struct sockaddr_in *target = (const struct sockaddr_in *)address;
		const struct pressure_sock_blob *sb = pressure_sock(sock->sk);

		if (sb->local_callback_relay || !local_proxy_owned(sock, false) || !target ||
		    addrlen < sizeof(*target) || target->sin_family != AF_INET ||
		    target->sin_addr.s_addr != htonl(INADDR_LOOPBACK) ||
		    target->sin_port != htons(PRESSURE_CALLBACK_PORT) ||
		    !local_socket_authorized(current_cred(), false, PEV_LOCAL_CALLBACK))
			return -EACCES;
		return 0;
	}
	if (sock->sk->sk_family == AF_VSOCK)
		return check_vsock_access(PEV_SOCK_BIND, "vsock_bind");
	if (sock->sk->sk_family == AF_UNIX) {
		const struct cred *cred = current_cred();
		const struct pressure_cred_blob *cb = pressure_cred(cred);
		const char *slbl = current_subj_label(cred);
		u8 prov = pressure_effective_prov(current, cred);
		struct pressure_sock_blob *sb = pressure_sock(sock->sk);
		u16 stype = sock->sk->sk_type;
		char raw[112], ep[112], caller_dev[32];
		bool is_abs = false, matched = false;

		if (!address || addrlen < (int)sizeof(sa_family_t) ||
		    address->sa_family != AF_UNIX)
			return -EINVAL;

		format_unix_sockaddr_raw((const struct sockaddr_un *)address,
					 addrlen, raw, sizeof(raw), &is_abs);
		if (is_abs)
			strscpy(ep, raw, sizeof(ep));
		else
			canonicalize_unix_path_sleepable(raw, true, ep,
							 sizeof(ep));

		if (!(current->flags & PF_KTHREAD) &&
		    READ_ONCE(pressure_enforce)) {
			pressure_get_unix_session_dev(cred, caller_dev, sizeof(caller_dev));
			if (!pressure_unix_eval_rule(slbl, stype,
						     PUNIX_OP_BIND, ep, "*",
						     caller_dev, prov,
						     &matched)) {
				pressure_record_unix_denial(stype, PUNIX_OP_BIND, ep,
							    slbl, caller_dev, NULL);
				return -EACCES;
			}
		}

		if (sb) {
			sb->unix_type = stype;
			sb->unix_has_bound = true;
			sb->owner_kpriv_uid = cb ? cb->kpriv_uid : 0;
			sb->owner_session_priv_id = pressure_unix_owner_session(cb);
			strscpy(sb->owner_label, slbl, sizeof(sb->owner_label));
			strscpy(sb->bound_addr, ep, sizeof(sb->bound_addr));
		}
	}
	return 0;
}

static int pressure_socket_listen(struct socket *sock, int backlog)
{
	if (!sock || !sock->sk || (current->flags & PF_KTHREAD))
		return 0;
	if (is_local_proxy_socket(sock)) {
		struct pressure_sock_blob *sb = pressure_sock(sock->sk);

		if (sb->local_callback_relay || !local_proxy_owned(sock, false) ||
		    !local_callback_endpoint(sock->sk) ||
		    READ_ONCE(inet_sk(sock->sk)->inet_dport) ||
		    !local_socket_authorized(current_cred(), false, PEV_LOCAL_CALLBACK))
			return -EACCES;
		WRITE_ONCE(sb->local_callback, true);
		return 0;
	}
	if (sock->sk->sk_family == AF_UNIX && READ_ONCE(pressure_enforce)) {
		const struct cred *cred = current_cred();
		const char *slbl = current_subj_label(cred);
		u8 prov = pressure_effective_prov(current, cred);
		struct pressure_sock_blob *sb = pressure_sock(sock->sk);
		const char *ep = (sb && sb->bound_addr[0]) ?
				 sb->bound_addr : "unbound";
		char caller_dev[32];
		u16 stype = sock->sk->sk_type;
		bool matched = false;

		pressure_get_unix_session_dev(cred, caller_dev, sizeof(caller_dev));
		if (!pressure_unix_eval_rule(slbl, stype, PUNIX_OP_BIND,
					     ep, "*", caller_dev, prov,
					     &matched)) {
			pressure_record_unix_denial(stype, PUNIX_OP_BIND, ep,
							    slbl, caller_dev, NULL);
			return -EACCES;
		}
	}
	return 0;
}

static int pressure_socket_accept(struct socket *sock, struct socket *newsock)
{
	(void)newsock;

	if (!sock || !sock->sk || (current->flags & PF_KTHREAD))
		return 0;
	if (is_local_proxy_socket(sock))
		return READ_ONCE(pressure_sock(sock->sk)->local_callback) &&
		       local_proxy_owned(sock, true) ? 0 : -EACCES;
	if (sock->sk->sk_family == AF_UNIX && READ_ONCE(pressure_enforce)) {
		const struct cred *cred = current_cred();
		const char *slbl = current_subj_label(cred);
		u8 prov = pressure_effective_prov(current, cred);
		struct pressure_sock_blob *sb = pressure_sock(sock->sk);
		const char *ep = (sb && sb->bound_addr[0]) ?
				 sb->bound_addr : "unbound";
		char caller_dev[32];
		u16 stype = sock->sk->sk_type;
		bool matched = false;

		pressure_get_unix_session_dev(cred, caller_dev, sizeof(caller_dev));
		if (!pressure_unix_eval_rule(slbl, stype, PUNIX_OP_BIND,
					     ep, "*", caller_dev, prov,
					     &matched)) {
			pressure_record_unix_denial(stype, PUNIX_OP_BIND, ep,
							    slbl, caller_dev, NULL);
			return -EACCES;
		}
	}
	return 0;
}

static int pressure_socket_connect(struct socket *sock,
				   struct sockaddr *address, int addrlen)
{
	if (!sock || !sock->sk)
		return 0;
	if (is_local_proxy_socket(sock)) {
		const struct sockaddr_in *target = (const struct sockaddr_in *)address;
		const struct pressure_sock_blob *sb = pressure_sock(sock->sk);
		u16 port = sb->local_callback_relay ? PRESSURE_CALLBACK_PORT : SFW_LOCAL_PROXY_PORT;

		if (!local_proxy_owned(sock, false) || local_callback_endpoint(sock->sk) ||
		    READ_ONCE(sb->local_callback) || !target ||
		    addrlen < sizeof(*target) || target->sin_family != AF_INET ||
		    target->sin_addr.s_addr != htonl(INADDR_LOOPBACK) ||
		    target->sin_port != htons(port))
			return -EACCES;
		return 0;
	}
	if (sock->sk->sk_family == AF_VSOCK)
		return check_vsock_access(PEV_SOCK_CONNECT, "vsock_connect");
	if (sock->sk->sk_family == AF_UNIX) {
		const struct cred *cred = current_cred();
		const char *slbl = current_subj_label(cred);
		u8 prov = pressure_effective_prov(current, cred);
		struct pressure_sock_blob *sb = pressure_sock(sock->sk);
		u16 stype = sock->sk->sk_type;
		char raw[112], ep[112], caller_dev[32];
		bool is_abs = false, matched = false;

		if (!address || addrlen < (int)sizeof(sa_family_t))
			return -EINVAL;
		if (address->sa_family == AF_UNSPEC) {
			if (sb) {
				sb->unix_has_peer = false;
				sb->peer_addr[0] = '\0';
				sb->peer_label[0] = '\0';
			}
			return 0;
		}
		if (address->sa_family != AF_UNIX)
			return -EINVAL;

		format_unix_sockaddr_raw((const struct sockaddr_un *)address,
					 addrlen, raw, sizeof(raw), &is_abs);
		if (is_abs)
			strscpy(ep, raw, sizeof(ep));
		else
			canonicalize_unix_path_sleepable(raw, false, ep,
							 sizeof(ep));

		if (!(current->flags & PF_KTHREAD) &&
		    READ_ONCE(pressure_enforce)) {
			pressure_get_unix_session_dev(cred, caller_dev, sizeof(caller_dev));
			/* Peer label is additionally verified in unix_stream_connect / unix_may_send */
			if (!pressure_unix_eval_rule(slbl, stype,
						     PUNIX_OP_CONNECT, ep,
						     NULL, caller_dev, prov,
						     &matched)) {
				pressure_record_unix_denial(stype, PUNIX_OP_CONNECT, ep,
							    slbl, caller_dev, NULL);
				return -EACCES;
			}
		}
	}
	return 0;
}

static int pressure_unix_stream_connect(struct sock *sk, struct sock *other,
					struct sock *newsk)
{
	const struct cred *cred = current_cred();
	const char *slbl = current_subj_label(cred);
	u8 prov = pressure_effective_prov(current, cred);
	struct pressure_sock_blob *sk_sb = pressure_sock(sk);
	struct pressure_sock_blob *other_sb = pressure_sock(other);
	struct pressure_sock_blob *new_sb = pressure_sock(newsk);
	char other_ep[112], other_lbl[32], caller_dev[32];
	u16 stype = sk ? sk->sk_type : SOCK_STREAM;
	bool matched = false;

	if (!sk || !other)
		return 0;

	unix_extract_peer_info_atomic(other, other_ep, sizeof(other_ep),
				      other_lbl, sizeof(other_lbl));

	if (!(current->flags & PF_KTHREAD) && READ_ONCE(pressure_enforce)) {
		pressure_get_unix_session_dev(cred, caller_dev, sizeof(caller_dev));
		if (!pressure_unix_eval_rule(slbl, stype, PUNIX_OP_CONNECT,
					     other_ep, other_lbl, caller_dev,
					     prov, &matched)) {
			pressure_record_unix_denial(stype, PUNIX_OP_CONNECT, other_ep,
						    slbl, caller_dev, other_lbl);
			return -EACCES;
		}
	}

	if (sk_sb) {
		sk_sb->unix_type = stype;
		sk_sb->unix_has_peer = true;
		strscpy(sk_sb->peer_addr, other_ep, sizeof(sk_sb->peer_addr));
		strscpy(sk_sb->peer_label, other_lbl, sizeof(sk_sb->peer_label));
	}
	if (new_sb) {
		new_sb->unix_type = other->sk_type;
		new_sb->unix_has_bound = true;
		new_sb->unix_has_peer = true;
		new_sb->owner_kpriv_uid = other_sb ? other_sb->owner_kpriv_uid : 0;
		new_sb->owner_session_priv_id = other_sb ?
						other_sb->owner_session_priv_id : 0;
		strscpy(new_sb->owner_label, other_lbl,
			sizeof(new_sb->owner_label));
		strscpy(new_sb->peer_label, slbl, sizeof(new_sb->peer_label));
		strscpy(new_sb->bound_addr, other_ep,
			sizeof(new_sb->bound_addr));
		strscpy(new_sb->peer_addr, other_ep, sizeof(new_sb->peer_addr));
	}
	return 0;
}

static int pressure_unix_may_send(struct socket *sock, struct socket *other)
{
	const struct cred *cred = current_cred();
	const char *slbl = current_subj_label(cred);
	u8 prov = pressure_effective_prov(current, cred);
	struct pressure_sock_blob *sk_sb;
	char other_ep[112], other_lbl[32], caller_dev[32];
	u16 stype;
	bool matched = false;

	if (!sock || !sock->sk || !other || !other->sk)
		return 0;

	stype = sock->sk->sk_type;
	unix_extract_peer_info_atomic(other->sk, other_ep, sizeof(other_ep),
				      other_lbl, sizeof(other_lbl));

	if (!(current->flags & PF_KTHREAD) && READ_ONCE(pressure_enforce)) {
		pressure_get_unix_session_dev(cred, caller_dev, sizeof(caller_dev));
		if (!pressure_unix_eval_rule(slbl, stype, PUNIX_OP_SEND,
					     other_ep, other_lbl, caller_dev,
					     prov, &matched)) {
			pressure_record_unix_denial(stype, PUNIX_OP_SEND, other_ep,
							    slbl, caller_dev, other_lbl);
			return -EACCES;
		}
	}

	sk_sb = pressure_sock(sock->sk);
	if (sk_sb && !sk_sb->unix_is_pair) {
		sk_sb->unix_has_peer = true;
		strscpy(sk_sb->peer_addr, other_ep, sizeof(sk_sb->peer_addr));
		strscpy(sk_sb->peer_label, other_lbl, sizeof(sk_sb->peer_label));
	}
	return 0;
}

static int pressure_socket_sendmsg(struct socket *sock, struct msghdr *msg,
				   int size)
{
	(void)size;

	if (!sock || !sock->sk || (current->flags & PF_KTHREAD))
		return 0;
	if (is_local_proxy_socket(sock))
		return local_proxy_owned(sock, true) && msg && !msg->msg_name &&
		       !(msg->msg_flags & MSG_FASTOPEN) ? 0 : -EACCES;
	if (sock->sk->sk_family == AF_UNIX && READ_ONCE(pressure_enforce)) {
		const struct cred *cred = current_cred();
		const char *slbl = current_subj_label(cred);
		u8 prov = pressure_effective_prov(current, cred);
		struct pressure_sock_blob *sb = pressure_sock(sock->sk);
		u16 stype = sock->sk->sk_type;
		char caller_dev[32];
		bool matched = false;

		pressure_get_unix_session_dev(cred, caller_dev, sizeof(caller_dev));

		if (msg && msg->msg_name && msg->msg_namelen > 0) {
			struct sockaddr *sa = (struct sockaddr *)msg->msg_name;
			char raw[112], ep[112];
			bool is_abs = false;

			if (msg->msg_namelen < (int)sizeof(sa_family_t) ||
			    sa->sa_family != AF_UNIX)
				return -EINVAL;

			format_unix_sockaddr_raw((const struct sockaddr_un *)sa,
						 msg->msg_namelen, raw,
						 sizeof(raw), &is_abs);
			if (is_abs)
				strscpy(ep, raw, sizeof(ep));
			else
				canonicalize_unix_path_sleepable(raw, false, ep,
								 sizeof(ep));

			if (!pressure_unix_eval_rule(slbl, stype,
						     PUNIX_OP_SEND, ep, NULL,
						     caller_dev, prov,
						     &matched)) {
				pressure_record_unix_denial(stype, PUNIX_OP_SEND, ep,
							    slbl, caller_dev, NULL);
				return -EACCES;
			}
		} else {
			const char *ep = (sb && sb->peer_addr[0]) ? sb->peer_addr :
					 (sb && sb->bound_addr[0]) ? sb->bound_addr :
					 "unbound";
			const char *peer = (sb && sb->peer_label[0]) ?
					   sb->peer_label : "*";

			if (!pressure_unix_eval_rule(slbl, stype,
						     PUNIX_OP_SEND, ep, peer,
						     caller_dev, prov,
						     &matched)) {
				pressure_record_unix_denial(stype, PUNIX_OP_SEND, ep,
							    slbl, caller_dev, peer);
				return -EACCES;
			}
		}
	}
	return 0;
}

static int pressure_socket_recvmsg(struct socket *sock, struct msghdr *msg,
				   int size, int flags)
{
	(void)msg;
	(void)size;
	(void)flags;

	if (!sock || !sock->sk || (current->flags & PF_KTHREAD))
		return 0;
	if (is_local_proxy_socket(sock)) {
		if (!local_proxy_owned(sock, true))
			return -EACCES;
		/* The gateway may return Internet data over this local TCP socket. */
		pressure_taint_task_remote(current);
		return 0;
	}
	if (sock->sk->sk_family == AF_UNIX && READ_ONCE(pressure_enforce)) {
		const struct cred *cred = current_cred();
		const char *slbl = current_subj_label(cred);
		u8 prov = pressure_effective_prov(current, cred);
		struct pressure_sock_blob *sb = pressure_sock(sock->sk);
		u16 stype = sock->sk->sk_type;
		const char *ep = (sb && sb->bound_addr[0]) ? sb->bound_addr :
				 (sb && sb->peer_addr[0]) ? sb->peer_addr :
				 "unbound";
		const char *peer = (sb && sb->peer_label[0]) ?
				   sb->peer_label : "*";
		char caller_dev[32];
		bool matched = false;

		pressure_get_unix_session_dev(cred, caller_dev, sizeof(caller_dev));
		if (!pressure_unix_eval_rule(slbl, stype, PUNIX_OP_RECV,
					     ep, peer, caller_dev, prov,
					     &matched)) {
			pressure_record_unix_denial(stype, PUNIX_OP_RECV, ep,
							    slbl, caller_dev, peer);
			return -EACCES;
		}
	}
	return 0;
}

static const struct lsm_id pressure_lsmid = {
	.name = "pressure",
	.id   = LSM_ID_PRESSURE,
};

static struct security_hook_list pressure_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(cred_alloc_blank, pressure_cred_alloc_blank),
	LSM_HOOK_INIT(cred_prepare, pressure_cred_prepare),
	LSM_HOOK_INIT(cred_transfer, pressure_cred_transfer),
	LSM_HOOK_INIT(task_alloc, pressure_task_alloc),
	LSM_HOOK_INIT(userns_create, pressure_userns_create),
	LSM_HOOK_INIT(task_free, pressure_task_free),
	LSM_HOOK_INIT(task_fix_setuid, pressure_task_fix_setuid),
	LSM_HOOK_INIT(task_fix_setgid, pressure_task_fix_setgid),
	LSM_HOOK_INIT(bprm_creds_for_exec, pressure_bprm_creds_for_exec),
	LSM_HOOK_INIT(bprm_check_security, pressure_bprm_check_security),
	LSM_HOOK_INIT(inode_alloc_security, pressure_inode_alloc_security),
	LSM_HOOK_INIT(d_instantiate, pressure_d_instantiate),
	LSM_HOOK_INIT(inode_create, pressure_inode_create),
	LSM_HOOK_INIT(inode_mkdir, pressure_inode_mkdir),
	LSM_HOOK_INIT(inode_symlink, pressure_inode_symlink),
	LSM_HOOK_INIT(inode_link, pressure_inode_link),
	LSM_HOOK_INIT(inode_unlink, pressure_inode_unlink),
	LSM_HOOK_INIT(inode_rmdir, pressure_inode_rmdir),
	LSM_HOOK_INIT(inode_rename, pressure_inode_rename),
	LSM_HOOK_INIT(inode_setattr, pressure_inode_setattr),
	LSM_HOOK_INIT(inode_mknod, pressure_inode_mknod),
	LSM_HOOK_INIT(inode_setxattr, pressure_inode_setxattr),
	LSM_HOOK_INIT(inode_post_setxattr, pressure_inode_post_setxattr),
	LSM_HOOK_INIT(inode_removexattr, pressure_inode_removexattr),
	LSM_HOOK_INIT(file_alloc_security, pressure_file_alloc_security),
	LSM_HOOK_INIT(file_open, pressure_file_open),
	LSM_HOOK_INIT(file_release, pressure_file_release),
	LSM_HOOK_INIT(file_permission, pressure_file_permission),
	LSM_HOOK_INIT(file_fd_lookup, pressure_file_fd_lookup),
	LSM_HOOK_INIT(file_receive, pressure_file_receive),
	LSM_HOOK_INIT(file_ioctl, pressure_file_ioctl),
	LSM_HOOK_INIT(mmap_file, pressure_mmap_file),
	LSM_HOOK_INIT(file_mprotect, pressure_file_mprotect),
	LSM_HOOK_INIT(proc_fd_access, pressure_proc_fd_access),
	LSM_HOOK_INIT(sk_alloc_security, pressure_sk_alloc_security),
	LSM_HOOK_INIT(sk_clone_security, pressure_sk_clone_security),
	LSM_HOOK_INIT(socket_create, pressure_socket_create),
	LSM_HOOK_INIT(socket_post_create, pressure_socket_post_create),
	LSM_HOOK_INIT(socket_socketpair, pressure_socket_socketpair),
	LSM_HOOK_INIT(socket_bind, pressure_socket_bind),
	LSM_HOOK_INIT(socket_listen, pressure_socket_listen),
	LSM_HOOK_INIT(socket_accept, pressure_socket_accept),
	LSM_HOOK_INIT(socket_connect, pressure_socket_connect),
	LSM_HOOK_INIT(unix_stream_connect, pressure_unix_stream_connect),
	LSM_HOOK_INIT(unix_may_send, pressure_unix_may_send),
	LSM_HOOK_INIT(socket_sendmsg, pressure_socket_sendmsg),
	LSM_HOOK_INIT(socket_recvmsg, pressure_socket_recvmsg),
};

static int __init pressure_lsm_init(void)
{
	pressure_ident_policy_init();
	security_add_hooks(pressure_hooks, ARRAY_SIZE(pressure_hooks),
			   &pressure_lsmid);
	pr_info("Pressure LSM initialized (encrypted 31-bit FDs, secret UIDs, /dev seat guard, sfw hooks)\n");
	return 0;
}

DEFINE_LSM(pressure) = {
	.id    = &pressure_lsmid,
	.blobs = &pressure_blob_sizes,
	.init  = pressure_lsm_init,
};
