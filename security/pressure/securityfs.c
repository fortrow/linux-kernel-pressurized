// SPDX-License-Identifier: GPL-2.0
/*
 * Pressure LSM - securityfs Control & Reporting Interface
 * Mounted at /sys/kernel/security/pressure/
 */

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/pid.h>
#include <linux/namei.h>
#include <linux/inet.h>
#include <linux/kdev_t.h>
#include "pressure.h"

static DEFINE_MUTEX(secfs_lock);

static bool caller_is_authd(void)
{
	const struct pressure_cred_blob *cb = pressure_cred(current_cred());
	return cb && cb->account_type == PRESSURE_ACCT_AUTHD;
}

static bool caller_is_local_admin(void)
{
	const struct cred *cred = current_cred();
	const struct pressure_cred_blob *cb = pressure_cred(cred);

	if (pressure_effective_prov(current, cred) == PRESSURE_PROV_REMOTE)
		return false;
	if (cb && cb->confined && cb->account_type != PRESSURE_ACCT_AUTHD)
		return false;
	return capable(CAP_MAC_ADMIN) || capable(CAP_SYS_ADMIN);
}

/* 1. status */
static int status_show(struct seq_file *m, void *v)
{
	seq_printf(m, "project:          pressure\n");
	seq_printf(m, "enforce:          %d\n", READ_ONCE(pressure_enforce));
	seq_printf(m, "stage:            %s\n",
		   READ_ONCE(pressure_stage) == PRESSURE_STAGE_POSTLOGIN ?
		   "POSTLOGIN" : "PRELOGIN");
	seq_printf(m, "authd_pid:        %d\n", READ_ONCE(pressure_authd_pid));
	seq_printf(m, "sfw_worker:       %s\n",
		   READ_ONCE(pressure_sfw_kthread) ? "ACTIVE" : "UNLOADED");
	seq_printf(m, "policy_gen:       %llu\n", pressure_get_policy_gen());
	seq_printf(m, "txn_active:       %d\n", pressure_txn_is_active() ? 1 : 0);
	seq_printf(m, "txn_degraded:     %d\n", pressure_txn_is_degraded() ? 1 : 0);
	seq_printf(m, "max_strikes:      %d\n", PRESSURE_MAX_STRIKES);
	seq_printf(m, "total_violations: %llu\n", pressure_get_total_violations());
	seq_printf(m, "total_sigkills:   %llu\n", pressure_get_total_sigkills());
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(status);

static long session_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct pressure_session_query query;
	struct task_struct *task;
	const struct cred *cred;
	unsigned int flags;
	char device[32];
	long ret = -EACCES;

	if (cmd != PRESSURE_SESSION_CHECK)
		return -ENOTTY;
	if (!caller_is_local_admin())
		return -EPERM;
	if (copy_from_user(&query, (void __user *)arg, sizeof(query)))
		return -EFAULT;
	if (!READ_ONCE(pressure_enforce) || !query.uid)
		return -EACCES;

	task = pidfd_get_task(query.pidfd, &flags);
	if (IS_ERR(task))
		return PTR_ERR(task);
	cred = get_task_cred(task);
	if (uid_eq(cred->euid, make_kuid(&init_user_ns, query.uid)) &&
	    pressure_get_verified_session_dev(task, cred, device, sizeof(device)) &&
	    !strcmp(device, "dev:console_tty1"))
		ret = 0;
	put_cred(cred);
	put_task_struct(task);
	return ret;
}

static const struct file_operations session_fops = {
	.unlocked_ioctl = session_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
};

/* 2. enforce (written by 'press') */
static ssize_t enforce_read(struct file *file, char __user *buf, size_t count,
			    loff_t *ppos)
{
	char tmp[8];
	int len = snprintf(tmp, sizeof(tmp), "%d\n", READ_ONCE(pressure_enforce));
	return simple_read_from_buffer(buf, count, ppos, tmp, len);
}

static ssize_t enforce_write(struct file *file, const char __user *buf,
			     size_t count, loff_t *ppos)
{
	char kbuf[16];
	int val;

	if (!caller_is_local_admin() && !caller_is_authd())
		return -EPERM;
	if (count == 0 || count >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;
	kbuf[count] = '\0';
	if (kstrtoint(strim(kbuf), 10, &val) < 0 || (val != 0 && val != 1))
		return -EINVAL;
	WRITE_ONCE(pressure_enforce, val);
	pr_info("pressure: enforcement set to %d by pid=%d (%s)\n",
		val, task_tgid_nr(current), current->comm);
	return count;
}

static const struct file_operations enforce_fops = {
	.read  = enforce_read,
	.write = enforce_write,
	.llseek = default_llseek,
};

/* 3. authd_register (one-time exclusive claim by pressure-authd) */
static ssize_t authd_reg_write(struct file *file, const char __user *buf,
			       size_t count, loff_t *ppos)
{
	struct cred *new_cred;
	struct pressure_cred_blob *ncb;
	struct task_struct *existing = NULL;

	if (!caller_is_local_admin())
		return -EPERM;

	mutex_lock(&secfs_lock);
	if (pressure_authd_pid > 0) {
		rcu_read_lock();
		existing = pid_task(find_vpid(pressure_authd_pid), PIDTYPE_PID);
		if (existing && (existing->exit_state != 0))
			existing = NULL;
		rcu_read_unlock();
	}
	if (existing && task_tgid_nr(existing) != task_tgid_nr(current)) {
		mutex_unlock(&secfs_lock);
		return -EBUSY;
	}

	new_cred = prepare_creds();
	if (!new_cred) {
		mutex_unlock(&secfs_lock);
		return -ENOMEM;
	}
	ncb = pressure_cred(new_cred);
	ncb->account_type = PRESSURE_ACCT_AUTHD;
	ncb->kpriv_uid = get_random_u64() | 1ULL;
	ncb->provenance = PRESSURE_PROV_PRELOGIN_LOCAL;
	strscpy(ncb->label, "subj:pressure_authd", sizeof(ncb->label));
	commit_creds(new_cred);

	WRITE_ONCE(pressure_authd_pid, task_tgid_nr(current));
	mutex_unlock(&secfs_lock);
	pr_info("pressure: pressure-authd registered (pid=%d)\n",
		task_tgid_nr(current));
	return count;
}

static const struct file_operations authd_reg_fops = {
	.write = authd_reg_write,
	.llseek = noop_llseek,
};

/* 4. users ("add <pub_uid> <pub_gid> <human|daemon> <label>") */
static int users_open(struct inode *inode, struct file *file)
{
	return single_open(file, pressure_format_users, NULL);
}

static ssize_t users_write(struct file *file, const char __user *buf,
			   size_t count, loff_t *ppos)
{
	char kbuf[128], cmd[16], type_s[16], label[32];
	unsigned int pub_uid, pub_gid;
	u8 acct_type;
	int ret;

	if (!caller_is_authd())
		return -EPERM;
	if (count == 0 || count >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;
	kbuf[count] = '\0';

	if (sscanf(kbuf, "%15s %u %u %15s %31s", cmd, &pub_uid, &pub_gid,
		   type_s, label) != 5 || strcmp(cmd, "add") != 0)
		return -EINVAL;

	acct_type = (strcmp(type_s, "human") == 0) ? PRESSURE_ACCT_HUMAN :
						     PRESSURE_ACCT_DAEMON;
	ret = pressure_register_user((uid_t)pub_uid, (gid_t)pub_gid, acct_type,
				     label);
	return ret < 0 ? ret : (ssize_t)count;
}

static const struct file_operations users_fops = {
	.open    = users_open,
	.read    = seq_read,
	.write   = users_write,
	.llseek  = seq_lseek,
	.release = single_release,
};

/*
 * 5. auth_grant ("grant <pid> <pub_uid> <local|remote> <maj>:<min> <label>"
 *    or "close_session <session_priv_or_pid>")
 */
static ssize_t auth_grant_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	char kbuf[160], cmd[20], prov_s[16], label[32];
	int target_pid, nfields;
	unsigned int pub_uid, maj = 0, min = 0, ttl_sec = 0;
	u8 prov;
	int ret;

	if (!caller_is_authd())
		return -EPERM;
	if (count == 0 || count >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;
	kbuf[count] = '\0';

	if (sscanf(kbuf, "release_pid %d", &target_pid) == 1 ||
	    sscanf(kbuf, "revoke_session %d", &target_pid) == 1) {
		struct task_struct *t;
		u64 spriv = 0;

		pressure_release_leader_devices((pid_t)target_pid);
		rcu_read_lock();
		t = pid_task(find_vpid(target_pid), PIDTYPE_PID);
		if (t) {
			const struct pressure_cred_blob *cb =
				pressure_cred(__task_cred(t));
			if (cb)
				spriv = cb->session_priv_id;
		}
		rcu_read_unlock();
		if (spriv)
			pressure_release_session_devices(spriv);
		return count;
	}

	nfields = sscanf(kbuf, "%19s %d %u %15s %u:%u %31s %u", cmd, &target_pid,
			 &pub_uid, prov_s, &maj, &min, label, &ttl_sec);
	if ((nfields != 7 && nfields != 8) || strcmp(cmd, "grant") != 0)
		return -EINVAL;

	prov = (strcmp(prov_s, "remote") == 0) ? PRESSURE_PROV_REMOTE :
						 PRESSURE_PROV_AUTH_LOCAL;
	ret = pressure_issue_uid_ticket((pid_t)target_pid, (uid_t)pub_uid, prov,
					(maj || min) ? MKDEV(maj, min) : 0,
					label, ttl_sec);
	return ret < 0 ? ret : (ssize_t)count;
}

static const struct file_operations auth_grant_fops = {
	.write  = auth_grant_write,
	.llseek = noop_llseek,
};

/*
 * 6. self_confine (used by 'press exec' to confine a task, set initial
 *    provenance/label, and turn on 31-bit random encrypted FDs)
 *    Format: "confine <local|remote> <fd_crypto:0|1> <label>"
 */
static ssize_t self_confine_write(struct file *file, const char __user *buf,
				  size_t count, loff_t *ppos)
{
	char kbuf[128], prov_s[16], label[32];
	int fd_enc = 1;
	struct cred *new_cred;
	struct pressure_cred_blob *ncb;
	const struct pressure_cred_blob *ocb;

	if (count == 0 || count >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;
	kbuf[count] = '\0';

	if (strncmp(strim(kbuf), "fd_crypto_init", 14) == 0) {
		pressure_enable_task_fd_crypto(current);
		return count;
	}

	if (sscanf(kbuf, "confine %15s %d %31s", prov_s, &fd_enc, label) != 3)
		return -EINVAL;

	new_cred = prepare_creds();
	if (!new_cred)
		return -ENOMEM;

	ocb = pressure_cred(current_cred());
	ncb = pressure_cred(new_cred);
	if (ocb)
		*ncb = *ocb;
	ncb->confined = 1;
	if (strcmp(prov_s, "remote") == 0 ||
	    pressure_effective_prov(current, current_cred()) == PRESSURE_PROV_REMOTE) {
		ncb->provenance = PRESSURE_PROV_REMOTE;
		pressure_taint_task_remote(current);
	}
	strscpy(ncb->label, label, sizeof(ncb->label));
	commit_creds(new_cred);

	if (fd_enc)
		pressure_enable_task_fd_crypto(current);
	return count;
}

static const struct file_operations self_confine_fops = {
	.write  = self_confine_write,
	.llseek = noop_llseek,
};

/*
 * 7. label_path (direct kernel inode tagging by 'sure' or 'pressure-authd'
 *    so even ramfs/initramfs paths without xattr backing get full hard-stops!)
 *    Format: "<flags_hex> <owner_pub_uid> <label> <path>"
 */
static ssize_t label_path_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	char kbuf[256], label[32], path_s[160];
	unsigned int flags_val, owner_pub_uid;
	struct path p;
	struct inode *inode;
	struct pressure_inode_blob *ib;
	int err;

	if (!caller_is_local_admin() && !caller_is_authd())
		return -EPERM;
	if (count == 0 || count >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;
	kbuf[count] = '\0';

	if (sscanf(kbuf, "%x %u %31s %159s", &flags_val, &owner_pub_uid,
		   label, path_s) != 4)
		return -EINVAL;

	err = kern_path(path_s, LOOKUP_FOLLOW, &p);
	if (err)
		return err;

	inode = d_inode(p.dentry);
	ib = pressure_inode(inode);
	if (ib) {
		u64 kpriv = 0;

		ib->flags = flags_val;
		ib->owner_pub_uid = (uid_t)owner_pub_uid;
		if (owner_pub_uid &&
		    pressure_lookup_user_kpriv((uid_t)owner_pub_uid, &kpriv,
					       NULL, NULL, NULL))
			ib->owner_kpriv_uid = kpriv;
		strscpy(ib->label, label, sizeof(ib->label));
		ib->initialized = true;
	}
	path_put(&p);
	return count;
}

static const struct file_operations label_path_fops = {
	.write  = label_path_write,
	.llseek = noop_llseek,
};

/* 8. devices */
static int devices_open(struct inode *inode, struct file *file)
{
	return single_open(file, pressure_format_devices, NULL);
}

static ssize_t devices_write(struct file *file, const char __user *buf,
			     size_t count, loff_t *ppos)
{
	char kbuf[128], kind[16], target[32], label[32], prov_s[16];
	unsigned int dclass, max_sess, maj, min;
	u8 prov;
	int ret;

	if (!caller_is_local_admin() && !caller_is_authd())
		return -EPERM;
	if (count == 0 || count >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;
	kbuf[count] = '\0';

	/* Format: "dev <maj:min|ifname> <label> <class> <local|remote> <max_sessions>" */
	if (sscanf(kbuf, "%15s %31s %31s %u %15s %u", kind, target, label,
		   &dclass, prov_s, &max_sess) != 6)
		return -EINVAL;

	prov = (strcmp(prov_s, "remote") == 0) ? PRESSURE_PROV_REMOTE :
						 PRESSURE_PROV_PRELOGIN_LOCAL;
	if (strcmp(kind, "net") == 0) {
		ret = pressure_configure_dev_label(true, 0, target, label,
						   (u8)dclass, prov, max_sess);
	} else if (sscanf(target, "%u:%u", &maj, &min) == 2) {
		ret = pressure_configure_dev_label(false, MKDEV(maj, min), NULL,
						   label, (u8)dclass, prov,
						   max_sess);
	} else {
		return -EINVAL;
	}
	return ret < 0 ? ret : (ssize_t)count;
}

static const struct file_operations devices_fops = {
	.open    = devices_open,
	.read    = seq_read,
	.write   = devices_write,
	.llseek  = seq_lseek,
	.release = single_release,
};

/* 9. policy ("<allow|deny> <subj> <obj> <dev> <ev_hex> <max_prov>") */
static int policy_open(struct inode *inode, struct file *file)
{
	return single_open(file, pressure_format_policy, NULL);
}

static ssize_t policy_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	char kbuf[160], act_s[16], subj[32], obj[32], dev[32];
	unsigned int ev_mask, max_prov;
	int ret;

	if (!caller_is_local_admin())
		return -EPERM;
	if (count == 0 || count >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;
	kbuf[count] = '\0';

	if (strncmp(strim(kbuf), "flush", 5) == 0) {
		pressure_flush_policy_rules();
		return count;
	}

	if (sscanf(kbuf, "%15s %31s %31s %31s %x %u", act_s, subj, obj, dev,
		   &ev_mask, &max_prov) != 6)
		return -EINVAL;

	ret = pressure_add_policy_rule(strcmp(act_s, "allow") == 0 ? 1 : 0,
				       subj, obj, dev, ev_mask, (u8)max_prov);
	return ret < 0 ? ret : (ssize_t)count;
}

static const struct file_operations policy_fops = {
	.open    = policy_open,
	.read    = seq_read,
	.write   = policy_write,
	.llseek  = seq_lseek,
	.release = single_release,
};

/*
 * 10. sfw_rules ("flush" or
 *     "<allow|deny> <dir> <pub_uid> <ip> <mask> <pmin> <pmax> <dev_lbl> <max_prov>")
 */
static int sfw_open(struct inode *inode, struct file *file)
{
	return single_open(file, pressure_format_sfw_rules, NULL);
}

static ssize_t sfw_write(struct file *file, const char __user *buf,
			 size_t count, loff_t *ppos)
{
	char kbuf[256], act_s[16], ip_s[64], mask_s[32], dev_lbl[32];
	unsigned int dir, pub_uid, pmin, pmax, max_prov, plen;
	struct sfw_firewall_rule r = {};
	char *trimmed;
	int ret;

	if (!caller_is_local_admin())
		return -EPERM;
	if (count == 0 || count >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;
	kbuf[count] = '\0';
	trimmed = strim(kbuf);

	if (strncmp(trimmed, "flush", 5) == 0) {
		pressure_sfw_flush_rules();
		return count;
	}

	if (strncmp(trimmed, "inet6 ", 6) == 0) {
		if (sscanf(trimmed + 6, "%15s %u %u %63s %u %u %u %31s %u",
			   act_s, &dir, &pub_uid, ip_s, &plen, &pmin, &pmax,
			   dev_lbl, &max_prov) != 9)
			return -EINVAL;
		if (plen > 128 || !in6_pton(ip_s, -1, r.ipv6_net, -1, NULL))
			return -EINVAL;
		r.family = AF_INET6;
		r.prefixlen = (u16)plen;
	} else {
		if (sscanf(trimmed, "%15s %u %u %63s %31s %u %u %31s %u",
			   act_s, &dir, &pub_uid, ip_s, mask_s, &pmin, &pmax,
			   dev_lbl, &max_prov) != 9)
			return -EINVAL;
		if (!in4_pton(ip_s, -1, (u8 *)&r.ipv4_net, -1, NULL) ||
		    !in4_pton(mask_s, -1, (u8 *)&r.ipv4_mask, -1, NULL))
			return -EINVAL;
		r.family = AF_INET;
	}

	r.action = (strcmp(act_s, "allow") == 0) ? SFW_RULE_ALLOW : SFW_RULE_DENY;
	r.direction = dir;
	r.pub_uid = pub_uid;
	r.port_min = (u16)pmin;
	r.port_max = (u16)pmax;
	r.max_prov = max_prov;
	strscpy(r.dev_label, dev_lbl, sizeof(r.dev_label));

	ret = pressure_sfw_add_rule(&r);
	return ret < 0 ? ret : (ssize_t)count;
}

static const struct file_operations sfw_fops = {
	.open    = sfw_open,
	.read    = seq_read,
	.write   = sfw_write,
	.llseek  = seq_lseek,
	.release = single_release,
};

/* 11. audit */
static int audit_open(struct inode *inode, struct file *file)
{
	if (!caller_is_local_admin() && !caller_is_authd())
		return -EPERM;
	return single_open(file, pressure_format_audit, NULL);
}

static const struct file_operations audit_fops = {
	.open    = audit_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};

/* 12. txn ("begin" | "commit" | "abort" for atomic sure load rollback) */
static ssize_t txn_write(struct file *file, const char __user *buf,
			 size_t count, loff_t *ppos)
{
	char kbuf[32], *cmd;
	int ret;

	if (!caller_is_local_admin())
		return -EPERM;
	if (count == 0 || count >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;
	kbuf[count] = '\0';
	cmd = strim(kbuf);

	if (strcmp(cmd, "begin") == 0)
		ret = pressure_txn_begin();
	else if (strcmp(cmd, "prepare") == 0)
		ret = pressure_txn_prepare();
	else if (strcmp(cmd, "commit") == 0)
		ret = pressure_txn_commit();
	else if (strcmp(cmd, "abort") == 0)
		ret = pressure_txn_abort();
	else if (strcmp(cmd, "mark_degraded") == 0) {
		pressure_txn_mark_degraded();
		ret = 0;
	} else
		return -EINVAL;

	return ret < 0 ? ret : (ssize_t)count;
}

static const struct file_operations txn_fops = {
	.write  = txn_write,
	.llseek = noop_llseek,
};

/*
 * 13. unix_rules ("flush" or
 *     "<allow|deny> <subj> <type_num> <ops_hex> <endpoint> <peer> <max_prov>")
 */
static int unix_rules_open(struct inode *inode, struct file *file)
{
	return single_open(file, pressure_format_unix_rules, NULL);
}

static ssize_t unix_rules_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	char kbuf[320], act_s[16], subj[32], ep[112], peer[32], dev_lbl[32] = "*";
	char exe[32] = "";
	unsigned int sock_type, op_mask, max_prov;
	char *trimmed;
	bool allow, scoped;
	int ret, nfields;

	if (!caller_is_local_admin())
		return -EPERM;
	if (count == 0 || count >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;
	kbuf[count] = '\0';
	trimmed = strim(kbuf);

	if (strncmp(trimmed, "flush", 5) == 0) {
		pressure_unix_flush_rules();
		return count;
	}

	nfields = sscanf(trimmed, "%15s %31s %u %x %111s %31s %31s %u %31s",
			 act_s, subj, &sock_type, &op_mask, ep, peer,
			 dev_lbl, &max_prov, exe);
	if (nfields < 8) {
		strscpy(dev_lbl, "*", sizeof(dev_lbl));
		if (sscanf(trimmed, "%15s %31s %u %x %111s %31s %u",
			   act_s, subj, &sock_type, &op_mask, ep, peer,
			   &max_prov) != 7)
			return -EINVAL;
	}

	scoped = !strcmp(act_s, "allow_exe") || !strcmp(act_s, "deny_exe");
	allow = !strcmp(act_s, "allow") || !strcmp(act_s, "allow_exe");
	if (!allow && strcmp(act_s, "deny") && strcmp(act_s, "deny_exe"))
		return -EINVAL;
	if (scoped != (nfields == 9))
		return -EINVAL;

	ret = pressure_unix_add_rule(allow,
				     subj, (u16)sock_type, op_mask, ep, peer,
				     dev_lbl, (u8)max_prov, exe);
	return ret < 0 ? ret : (ssize_t)count;
}

static const struct file_operations unix_rules_fops = {
	.open    = unix_rules_open,
	.read    = seq_read,
	.write   = unix_rules_write,
	.llseek  = seq_lseek,
	.release = single_release,
};

int __init pressure_securityfs_init(void)
{
	struct dentry *dir;

	dir = securityfs_create_dir("pressure", NULL);
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	securityfs_create_file("status", 0444, dir, NULL, &status_fops);
	securityfs_create_file("session", 0400, dir, NULL, &session_fops);
	securityfs_create_file("enforce", 0644, dir, NULL, &enforce_fops);
	securityfs_create_file("authd_register", 0200, dir, NULL, &authd_reg_fops);
	securityfs_create_file("users", 0600, dir, NULL, &users_fops);
	securityfs_create_file("auth_grant", 0200, dir, NULL, &auth_grant_fops);
	securityfs_create_file("self_confine", 0222, dir, NULL, &self_confine_fops);
	securityfs_create_file("label_path", 0200, dir, NULL, &label_path_fops);
	securityfs_create_file("devices", 0644, dir, NULL, &devices_fops);
	securityfs_create_file("policy", 0600, dir, NULL, &policy_fops);
	securityfs_create_file("sfw_rules", 0600, dir, NULL, &sfw_fops);
	securityfs_create_file("unix_rules", 0600, dir, NULL, &unix_rules_fops);
	securityfs_create_file("audit", 0400, dir, NULL, &audit_fops);
	securityfs_create_file("txn", 0200, dir, NULL, &txn_fops);
	return 0;
}
fs_initcall(pressure_securityfs_init);
