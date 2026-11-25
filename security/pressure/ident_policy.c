// SPDX-License-Identifier: GPL-2.0
/*
 * Pressure LSM - Secret Kernel UIDs, Universal /dev & net_device IDs,
 * Seat Exclusivity, Event Policy, and sfw Firewall Engine
 */

#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/pid_namespace.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/jiffies.h>
#include <linux/netdevice.h>
#include <linux/inet.h>
#include <linux/xattr.h>
#include <linux/dcache.h>
#include <linux/kdev_t.h>
#include <uapi/linux/major.h>
#include <linux/seq_file.h>
#include <linux/export.h>
#include <linux/tty.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/sfw_pkt.h>
#include <net/ipv6.h>
#include <net/net_namespace.h>
#include "pressure.h"

static sfw_pkt_hook_t __rcu g_sfw_pkt_hook;
static sfw_pkt_hook_t __rcu g_sfw_pkt6_hook;

static DEFINE_SPINLOCK(ident_lock);
static DEFINE_HASHTABLE(user_table, 8);
static DEFINE_HASHTABLE(dev_table, 8);
static DEFINE_HASHTABLE(session_table, 8);
static LIST_HEAD(ticket_list);

static struct pressure_policy_rule policy_rules[PRESSURE_MAX_POLICY_RULES];
static unsigned int policy_rule_count;

static struct sfw_firewall_rule sfw_rules[PRESSURE_MAX_SFW_RULES];
static unsigned int sfw_rule_count;

static struct pressure_unix_rule unix_rules[PRESSURE_MAX_UNIX_RULES];
static unsigned int unix_rule_count;

static atomic64_t g_policy_gen = ATOMIC64_INIT(0);
static DEFINE_MUTEX(txn_lock);
static bool g_txn_active;
static bool g_txn_prepared;
static bool g_txn_degraded;
static pid_t g_txn_owner_pid;

#define PRESSURE_MAX_DEV_SNAP 256
struct pressure_dev_snap_item {
	bool is_netdev;
	dev_t rdev;
	int ifindex;
	u64 dev_pub_id;
	char label[32];
	u8 dev_class;
	u8 provenance;
	u32 max_sessions;
};

struct pressure_txn_snapshot {
	int enforce_bak;
	unsigned int policy_cnt;
	struct pressure_policy_rule policy_bak[PRESSURE_MAX_POLICY_RULES];
	unsigned int sfw_cnt;
	struct sfw_firewall_rule sfw_bak[PRESSURE_MAX_SFW_RULES];
	unsigned int unix_cnt;
	struct pressure_unix_rule unix_bak[PRESSURE_MAX_UNIX_RULES];
	unsigned int dev_cnt;
	struct pressure_dev_snap_item dev_bak[PRESSURE_MAX_DEV_SNAP];
};

static struct pressure_txn_snapshot *g_txn_snap;

static u64 local_seat_kpriv_id;
struct task_struct *pressure_sfw_kthread;

static u64 gen_secret_id(void)
{
	u64 v = get_random_u64();
	return v ? v : 1ULL;
}

/* Classify /dev character and block devices automatically by major:minor */
static u8 classify_default_dev(dev_t rdev, umode_t mode, u8 *prov_out,
			       u32 *max_sess_out, char *label_buf)
{
	unsigned int maj = MAJOR(rdev);
	unsigned int min = MINOR(rdev);

	*prov_out = PRESSURE_PROV_PRELOGIN_LOCAL;
	*max_sess_out = 0; /* 0 = unlimited unless seat-locked */

	if (S_ISBLK(mode)) {
		strscpy(label_buf, "dev:storage_blk", 32);
		return PDEV_STORAGE_BLK;
	}

	/* Memory & safe pseudo devices (major 1) */
	if (maj == 1) {
		if (min == 3 || min == 5 || min == 7 || min == 8 || min == 9 ||
		    min == 11) {
			strscpy(label_buf, "dev:pseudo_safe", 32);
			return PDEV_PSEUDO_SAFE;
		}
		strscpy(label_buf, "dev:raw_mem", 32);
		return PDEV_STORAGE_BLK;
	}

	/* Keyboards, mice, evdev (major 13), uinput (10:223), hidraw (240+) */
	if (maj == 13 || (maj == 10 && min == 223)) {
		*max_sess_out = 1;
		strscpy(label_buf, "dev:seat_input", 32);
		return PDEV_SEAT_INPUT;
	}

	/* /dev/net/tun (10:200) */
	if (maj == 10 && min == 200) {
		*prov_out = PRESSURE_PROV_REMOTE;
		strscpy(label_buf, "dev:net_tun", 32);
		return PDEV_NET_EXT;
	}

	/* Primary physical console /dev/tty1 (major 4, minor 1) */
	if (maj == 4 && min == 1) {
		*max_sess_out = 1;
		strscpy(label_buf, "dev:console_tty1", 32);
		return PDEV_SEAT_TTY;
	}

	/* Other virtual terminals /dev/tty2..63 */
	if (maj == 4 && min >= 2 && min <= 63) {
		*max_sess_out = 1;
		strscpy(label_buf, "dev:seat_tty", 32);
		return PDEV_SEAT_TTY;
	}

	/* Serial consoles /dev/ttyS*, /dev/console (5:1), ttyAMA*, hvc* */
	if ((maj == 4 && min >= 64) || (maj == 5 && min == 1) ||
	    maj == 204 || maj == 229) {
		*max_sess_out = 1;
		strscpy(label_buf, "dev:serial_tty", 32);
		return PDEV_SEAT_TTY;
	}

	/* /dev/tty (5:0), /dev/ptmx (5:2), /dev/pts/N (136..143), BSD ptys (3) */
	if ((maj == 5 && (min == 0 || min == 2)) ||
	    (maj >= 136 && maj <= 143) || maj == 3) {
		strscpy(label_buf, "dev:pty", 32);
		return PDEV_PTY_SLAVE;
	}

	strscpy(label_buf, "dev:chr_generic", 32);
	return PDEV_OTHER_CHR;
}

struct pressure_dev_entry *pressure_get_or_create_chrblk_dev(dev_t rdev,
							     umode_t mode)
{
	struct pressure_dev_entry *d;
	unsigned long flags;
	u8 def_prov;
	u32 def_max;
	char def_label[32];
	u8 dclass;

	spin_lock_irqsave(&ident_lock, flags);
	hash_for_each_possible(dev_table, d, node, (u32)rdev) {
		if (!d->is_netdev && d->rdev == rdev) {
			spin_unlock_irqrestore(&ident_lock, flags);
			return d;
		}
	}

	d = kzalloc(sizeof(*d), GFP_ATOMIC);
	if (!d) {
		spin_unlock_irqrestore(&ident_lock, flags);
		return NULL;
	}
	dclass = classify_default_dev(rdev, mode, &def_prov, &def_max,
				      def_label);
	d->is_netdev = false;
	d->rdev = rdev;
	snprintf(d->name, sizeof(d->name), "%s_%u:%u",
		 S_ISBLK(mode) ? "blk" : "chr", MAJOR(rdev), MINOR(rdev));
	strscpy(d->label, def_label, sizeof(d->label));
	d->dev_pub_id = gen_secret_id();
	d->dev_kpriv_id = gen_secret_id();
	d->dev_class = dclass;
	d->provenance = def_prov;
	d->max_sessions = def_max;
	hash_add(dev_table, &d->node, (u32)rdev);
	spin_unlock_irqrestore(&ident_lock, flags);
	return d;
}

static int pressure_netdev_event(struct notifier_block *this,
				 unsigned long event, void *ptr)
{
	struct net_device *ndev = netdev_notifier_info_to_dev(ptr);
	struct pressure_dev_entry *d;
	unsigned long flags;
	bool is_lo;

	if (!ndev || !net_eq(dev_net(ndev), &init_net) ||
	    (event != NETDEV_REGISTER && event != NETDEV_CHANGENAME &&
	     event != NETDEV_UNREGISTER))
		return NOTIFY_DONE;

	is_lo = (ndev->flags & IFF_LOOPBACK) || strcmp(ndev->name, "lo") == 0;

	spin_lock_irqsave(&ident_lock, flags);
	hash_for_each_possible(dev_table, d, node, (u32)ndev->ifindex + 0x10000U) {
		if (d->is_netdev && d->ifindex == ndev->ifindex) {
			if (event == NETDEV_CHANGENAME)
				strscpy(d->name, ndev->name, sizeof(d->name));
			else if (event == NETDEV_UNREGISTER) {
				hash_del(&d->node);
				kfree(d);
			}
			spin_unlock_irqrestore(&ident_lock, flags);
			return NOTIFY_DONE;
		}
	}
	if (event != NETDEV_REGISTER) {
		spin_unlock_irqrestore(&ident_lock, flags);
		return NOTIFY_DONE;
	}

	d = kzalloc(sizeof(*d), GFP_ATOMIC);
	if (d) {
		d->is_netdev = true;
		d->ifindex = ndev->ifindex;
		strscpy(d->name, ndev->name, sizeof(d->name));
		strscpy(d->label, is_lo ? "dev:net_lo" : "dev:net_ext",
			sizeof(d->label));
		d->dev_pub_id = gen_secret_id();
		d->dev_kpriv_id = gen_secret_id();
		d->dev_class = is_lo ? PDEV_NET_LO : PDEV_NET_EXT;
		d->provenance = is_lo ? PRESSURE_PROV_PRELOGIN_LOCAL :
					PRESSURE_PROV_REMOTE;
		d->max_sessions = 0;
		hash_add(dev_table, &d->node, (u32)ndev->ifindex + 0x10000U);
	}
	spin_unlock_irqrestore(&ident_lock, flags);
	return NOTIFY_DONE;
}

static struct notifier_block pressure_netdev_notifier = {
	.notifier_call = pressure_netdev_event,
};

int pressure_configure_dev_label(bool is_netdev, dev_t rdev,
				 const char *ifname, const char *label,
				 u8 dev_class, u8 prov, u32 max_sessions)
{
	struct pressure_dev_entry *d;
	unsigned long flags;

	spin_lock_irqsave(&ident_lock, flags);
	if (is_netdev) {
		int bkt;
		hash_for_each(dev_table, bkt, d, node) {
			if (d->is_netdev && strcmp(d->name, ifname) == 0) {
				strscpy(d->label, label, sizeof(d->label));
				d->dev_class = dev_class;
				d->provenance = prov;
				d->max_sessions = max_sessions;
				spin_unlock_irqrestore(&ident_lock, flags);
				return 0;
			}
		}
		spin_unlock_irqrestore(&ident_lock, flags);
		return -ENOENT;
	}

	hash_for_each_possible(dev_table, d, node, (u32)rdev) {
		if (!d->is_netdev && d->rdev == rdev) {
			strscpy(d->label, label, sizeof(d->label));
			d->dev_class = dev_class;
			d->provenance = prov;
			d->max_sessions = max_sessions;
			spin_unlock_irqrestore(&ident_lock, flags);
			return 0;
		}
	}

	d = kzalloc(sizeof(*d), GFP_ATOMIC);
	if (!d) {
		spin_unlock_irqrestore(&ident_lock, flags);
		return -ENOMEM;
	}
	d->is_netdev = false;
	d->rdev = rdev;
	snprintf(d->name, sizeof(d->name), "dev_%u:%u", MAJOR(rdev), MINOR(rdev));
	strscpy(d->label, label, sizeof(d->label));
	d->dev_pub_id = gen_secret_id();
	d->dev_kpriv_id = gen_secret_id();
	d->dev_class = dev_class;
	d->provenance = prov;
	d->max_sessions = max_sessions;
	hash_add(dev_table, &d->node, (u32)rdev);
	spin_unlock_irqrestore(&ident_lock, flags);
	return 0;
}

int pressure_register_user(uid_t pub_uid, gid_t pub_gid, u8 acct_type,
			   const char *label)
{
	struct pressure_user_entry *u;
	unsigned long flags;

	if (pub_uid == 0 || pub_uid == (uid_t)-1)
		return -EINVAL;

	spin_lock_irqsave(&ident_lock, flags);
	hash_for_each_possible(user_table, u, node, pub_uid) {
		if (u->pub_uid == pub_uid) {
			u->pub_gid = pub_gid;
			u->account_type = acct_type;
			if (label && label[0])
				strscpy(u->label, label, sizeof(u->label));
			spin_unlock_irqrestore(&ident_lock, flags);
			return 0;
		}
	}

	u = kzalloc(sizeof(*u), GFP_ATOMIC);
	if (!u) {
		spin_unlock_irqrestore(&ident_lock, flags);
		return -ENOMEM;
	}
	u->pub_uid = pub_uid;
	u->pub_gid = pub_gid;
	u->kpriv_uid = gen_secret_id();
	u->kpriv_gid = gen_secret_id();
	u->account_type = acct_type;
	strscpy(u->label, (label && label[0]) ? label : "subj:user",
		sizeof(u->label));
	hash_add(user_table, &u->node, pub_uid);
	spin_unlock_irqrestore(&ident_lock, flags);
	return 0;
}

bool pressure_lookup_user_kpriv(uid_t pub_uid, u64 *kpriv_uid_out,
				u64 *kpriv_gid_out, u8 *acct_type_out,
				char *label_out)
{
	struct pressure_user_entry *u;
	unsigned long flags;
	bool found = false;

	spin_lock_irqsave(&ident_lock, flags);
	hash_for_each_possible(user_table, u, node, pub_uid) {
		if (u->pub_uid == pub_uid) {
			if (kpriv_uid_out)
				*kpriv_uid_out = u->kpriv_uid;
			if (kpriv_gid_out)
				*kpriv_gid_out = u->kpriv_gid;
			if (acct_type_out)
				*acct_type_out = u->account_type;
			if (label_out)
				strscpy(label_out, u->label, 32);
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&ident_lock, flags);
	return found;
}

static dev_t task_real_ctty_dev(struct task_struct *tsk, pid_t *sid_out)
{
	unsigned long flags;
	struct tty_struct *tty;
	dev_t rdev = 0;

	if (sid_out)
		*sid_out = 0;
	if (!tsk)
		return 0;

	/*
	 * siglock pins tsk->signal->tty (proc_clear_tty() acquires siglock
	 * before dropping the tty kref), so reading tty->flags and
	 * tty_devnum(tty) under siglock is race-free and safe in atomic context.
	 */
	rcu_read_lock();
	/* Use the initial PID namespace for the lifetime of the ticket. */
	if (sid_out)
		*sid_out = pid_nr(task_session(tsk));
	if (lock_task_sighand(tsk, &flags)) {
		tty = tsk->signal ? tsk->signal->tty : NULL;
		if (tty &&
		    !test_bit(TTY_HUPPED, &tty->flags) &&
		    !test_bit(TTY_HUPPING, &tty->flags))
			rdev = tty_devnum(tty);
		unlock_task_sighand(tsk, &flags);
	}
	rcu_read_unlock();

	return rdev;
}

static void prune_revoked_sessions_locked(void)
{
	struct pressure_session_entry *s;
	struct hlist_node *tmp;
	int bkt;
	u64 now = get_jiffies_64();

	hash_for_each_safe(session_table, bkt, tmp, s, node) {
		if (s->revoked &&
		    (s->expires_jiffies == 0 ||
		     time_after64(now, s->expires_jiffies + 60 * HZ))) {
			hash_del(&s->node);
			kfree(s);
		}
	}
}

int pressure_issue_uid_ticket(pid_t target_pid, uid_t pub_uid, u8 provenance,
			      dev_t claimed_tty_dev, const char *override_label,
			      u32 ttl_sec)
{
	struct pressure_user_entry *u = NULL, *iter;
	struct pressure_dev_entry *d = NULL;
	struct pressure_uid_ticket *tk;
	struct pressure_session_entry *sess = NULL;
	struct task_struct *target_tsk = NULL;
	unsigned long flags;
	u64 sess_priv = gen_secret_id();
	u64 sess_pub = gen_secret_id();
	u64 bound_dev_priv = 0;
	u64 seat_priv = 0;
	dev_t real_ctty = 0;
	pid_t real_sid = 0;
	u64 sess_expires;

	/* Inspect the target task's REAL kernel controlling TTY and POSIX session */
	rcu_read_lock();
	target_tsk = pid_task(find_vpid(target_pid), PIDTYPE_PID);
	if (target_tsk)
		get_task_struct(target_tsk);
	rcu_read_unlock();

	if (!target_tsk)
		return -ESRCH;

	real_ctty = task_real_ctty_dev(target_tsk, &real_sid);

	if (ttl_sec == 0)
		ttl_sec = 43200U; /* 12-hour default grant TTL */
	sess_expires = get_jiffies_64() + (u64)ttl_sec * HZ;

	spin_lock_irqsave(&ident_lock, flags);
	hash_for_each_possible(user_table, iter, node, pub_uid) {
		if (iter->pub_uid == pub_uid) {
			u = iter;
			break;
		}
	}
	if (!u) {
		spin_unlock_irqrestore(&ident_lock, flags);
		put_task_struct(target_tsk);
		return -ENOENT;
	}

	/*
	 * Anti-spoofing gate for interactive human sessions:
	 * Never trust a userspace-claimed tty pathname (e.g. "/dev/tty1") unless
	 * the target task's real kernel controlling terminal matches!
	 */
	if (u->account_type == PRESSURE_ACCT_HUMAN) {
		if (claimed_tty_dev != 0 && real_ctty != claimed_tty_dev) {
			spin_unlock_irqrestore(&ident_lock, flags);
			pressure_record_violation(target_tsk,
						  PVIO_TTY_SPOOF_BLOCKED,
						  (u32)claimed_tty_dev,
						  "ctty_spoof_mismatch");
			put_task_struct(target_tsk);
			return -EACCES;
		}
	}

	if (u->account_type == PRESSURE_ACCT_HUMAN && real_ctty != 0) {
		hash_for_each_possible(dev_table, d, node, (u32)real_ctty) {
			if (!d->is_netdev && d->rdev == real_ctty)
				break;
			d = NULL;
		}
		if (!d) {
			u8 dprov;
			u32 dmax;
			char dlab[32];
			u8 dcls = classify_default_dev(real_ctty, S_IFCHR, &dprov,
						       &dmax, dlab);
			d = kzalloc(sizeof(*d), GFP_ATOMIC);
			if (!d) {
				spin_unlock_irqrestore(&ident_lock, flags);
				put_task_struct(target_tsk);
				return -ENOMEM;
			}
			d->rdev = real_ctty;
			snprintf(d->name, sizeof(d->name), "chr_%u:%u",
				 MAJOR(real_ctty), MINOR(real_ctty));
			strscpy(d->label, dlab, sizeof(d->label));
			d->dev_pub_id = gen_secret_id();
			d->dev_kpriv_id = gen_secret_id();
			d->dev_class = dcls;
			d->provenance = dprov;
			d->max_sessions = dmax;
			hash_add(dev_table, &d->node, (u32)real_ctty);
		}

		if (d->provenance == PRESSURE_PROV_REMOTE)
			provenance = PRESSURE_PROV_REMOTE;

		if (d->max_sessions > 0 &&
		    d->active_sessions >= d->max_sessions) {
			spin_unlock_irqrestore(&ident_lock, flags);
			pressure_record_violation(target_tsk,
						  PVIO_SEAT_MAX_SESSIONS,
						  (u32)real_ctty, d->label);
			put_task_struct(target_tsk);
			return -EBUSY;
		}

		d->active_sessions++;
		d->owner_leader_pid = target_pid;
		d->owner_session_priv_id = sess_priv;
		/*
		 * Only true physical virtual terminals (tty1..tty63, major 4
		 * minor 1..63) with AUTH_LOCAL provenance receive physical seat
		 * input authority; serial consoles and PTYs do not.
		 */
		if (provenance == PRESSURE_PROV_AUTH_LOCAL &&
		    MAJOR(real_ctty) == 4 &&
		    MINOR(real_ctty) >= 1 && MINOR(real_ctty) <= 63) {
			seat_priv = local_seat_kpriv_id;
			d->owner_seat_kpriv_id = seat_priv;
		}
		bound_dev_priv = d->dev_kpriv_id;
	}

	tk = kzalloc(sizeof(*tk), GFP_ATOMIC);
	if (!tk) {
		if (d && d->active_sessions > 0) {
			d->active_sessions--;
			if (d->active_sessions == 0)
				d->owner_session_priv_id = 0;
		}
		spin_unlock_irqrestore(&ident_lock, flags);
		put_task_struct(target_tsk);
		return -ENOMEM;
	}

	if (u->account_type == PRESSURE_ACCT_HUMAN) {
		sess = kzalloc(sizeof(*sess), GFP_ATOMIC);
		if (!sess) {
			kfree(tk);
			if (d && d->active_sessions > 0) {
				d->active_sessions--;
				if (d->active_sessions == 0)
					d->owner_session_priv_id = 0;
			}
			spin_unlock_irqrestore(&ident_lock, flags);
			put_task_struct(target_tsk);
			return -ENOMEM;
		}
		sess->session_priv_id = sess_priv;
		sess->bound_dev_kpriv_id = bound_dev_priv;
		sess->bound_ctty_dev = real_ctty;
		sess->leader_pid = target_pid;
		sess->bound_sid = real_sid;
		sess->expires_jiffies = sess_expires;
		sess->revoked = false;
		prune_revoked_sessions_locked();
		hash_add(session_table, &sess->node, (u32)sess_priv);
	}

	tk->target_pid = target_pid;
	tk->bound_sid = real_sid;
	tk->bound_ctty_dev = (u->account_type == PRESSURE_ACCT_HUMAN) ? real_ctty : 0;
	tk->pub_uid = pub_uid;
	tk->kpriv_uid = u->kpriv_uid;
	tk->kpriv_gid = u->kpriv_gid;
	tk->session_pub_id = sess_pub;
	tk->session_priv_id = sess_priv;
	tk->seat_kpriv_id = seat_priv;
	tk->bound_dev_kpriv_id = bound_dev_priv;
	tk->account_type = u->account_type;
	tk->provenance = provenance;
	strscpy(tk->label, (override_label && override_label[0]) ?
		override_label : u->label, sizeof(tk->label));
	tk->expires_jiffies = get_jiffies_64() + 30 * HZ;
	list_add_tail(&tk->list, &ticket_list);
	spin_unlock_irqrestore(&ident_lock, flags);
	put_task_struct(target_tsk);
	return 0;
}

bool pressure_consume_uid_ticket(pid_t pid, uid_t target_pub_uid,
				 struct pressure_uid_ticket *out)
{
	struct pressure_uid_ticket *tk, *tmp;
	unsigned long flags;
	u64 now = get_jiffies_64();
	pid_t cur_sid = 0;
	dev_t cur_ctty = task_real_ctty_dev(current, &cur_sid);
	bool matched = false;

	spin_lock_irqsave(&ident_lock, flags);
	list_for_each_entry_safe(tk, tmp, &ticket_list, list) {
		if (time_after64(now, tk->expires_jiffies)) {
			list_del(&tk->list);
			kfree(tk);
			continue;
		}
		if (!matched && tk->target_pid == pid &&
		    tk->pub_uid == target_pub_uid) {
			/* Re-verify real controlling TTY & session at setuid time */
			if (tk->account_type == PRESSURE_ACCT_HUMAN &&
			    (cur_sid != tk->bound_sid ||
			     cur_ctty != tk->bound_ctty_dev)) {
				list_del(&tk->list);
				kfree(tk);
				continue;
			}
			*out = *tk;
			list_del(&tk->list);
			kfree(tk);
			matched = true;
		}
	}
	spin_unlock_irqrestore(&ident_lock, flags);
	return matched;
}

void pressure_release_session_devices(u64 session_priv_id)
{
	struct pressure_dev_entry *d;
	struct pressure_session_entry *s;
	unsigned long flags;
	int bkt;

	if (!session_priv_id)
		return;

	spin_lock_irqsave(&ident_lock, flags);
	hash_for_each_possible(session_table, s, node, (u32)session_priv_id) {
		if (s->session_priv_id == session_priv_id)
			s->revoked = true;
	}
	hash_for_each(dev_table, bkt, d, node) {
		if (d->owner_session_priv_id == session_priv_id) {
			if (d->active_sessions > 0)
				d->active_sessions--;
			if (d->active_sessions == 0) {
				d->owner_leader_pid = 0;
				d->owner_session_priv_id = 0;
				d->owner_seat_kpriv_id = 0;
			}
		}
	}
	spin_unlock_irqrestore(&ident_lock, flags);
}

void pressure_release_leader_devices(pid_t leader_pid)
{
	struct pressure_dev_entry *d;
	struct pressure_session_entry *s;
	unsigned long flags;
	int bkt;

	if (leader_pid <= 0)
		return;

	spin_lock_irqsave(&ident_lock, flags);
	hash_for_each(session_table, bkt, s, node) {
		if (s->leader_pid == leader_pid)
			s->revoked = true;
	}
	hash_for_each(dev_table, bkt, d, node) {
		if (d->owner_leader_pid == leader_pid) {
			if (d->active_sessions > 0)
				d->active_sessions--;
			if (d->active_sessions == 0) {
				d->owner_leader_pid = 0;
				d->owner_session_priv_id = 0;
				d->owner_seat_kpriv_id = 0;
			}
		}
	}
	spin_unlock_irqrestore(&ident_lock, flags);
}

bool pressure_session_is_active(u64 session_priv_id)
{
	struct pressure_session_entry *s;
	unsigned long flags;
	u64 now = get_jiffies_64();
	bool active = false;

	if (!session_priv_id)
		return false;

	spin_lock_irqsave(&ident_lock, flags);
	hash_for_each_possible(session_table, s, node, (u32)session_priv_id) {
		if (s->session_priv_id == session_priv_id) {
			if (!s->revoked &&
			    (s->expires_jiffies == 0 ||
			     !time_after64(now, s->expires_jiffies)))
				active = true;
			break;
		}
	}
	spin_unlock_irqrestore(&ident_lock, flags);
	return active;
}

/*
 * Resolve a task's live, kernel-verified controlling device/session label:
 * - Interactive human accounts: verified ONLY when the session exists, is not
 *   revoked or expired, provenance == AUTH_LOCAL, AND current's real kernel
 *   controlling TTY and POSIX SID still match the session grant! Otherwise
 *   returns "dev:none".
 * - Daemons: "dev:service" (independent of interactive login, never tty1).
 * - authd:   "dev:authd".
 * - Boot/unauthenticated system tasks: "dev:none".
 */
static bool verified_session_dev(struct task_struct *tsk,
				       const struct cred *cred,
				       char *dev_lbl_out, size_t sz, bool unix_ipc, bool allow_remote)
{
	const struct pressure_cred_blob *cb = pressure_cred(cred);
	struct pressure_session_entry *s = NULL, *iter;
	struct pressure_dev_entry *d = NULL;
	unsigned long flags;
	u8 prov;
	pid_t cur_sid = 0;
	dev_t cur_ctty = 0;
	u64 now;
	bool verified = false, delegated_pty, detached;
	pid_t leader_pid = 0;

	strscpy(dev_lbl_out, "dev:none", sz);
	if (!cb || !tsk)
		return false;
	if (tsk->flags & PF_KTHREAD) {
		strscpy(dev_lbl_out, "dev:kernel", sz);
		return true;
	}

	if (cb->account_type == PRESSURE_ACCT_DAEMON) {
		strscpy(dev_lbl_out, "dev:service", sz);
		return true;
	}
	if (cb->account_type == PRESSURE_ACCT_AUTHD) {
		strscpy(dev_lbl_out, "dev:authd", sz);
		return true;
	}
	if (cb->account_type != PRESSURE_ACCT_HUMAN)
		return false;

	prov = pressure_effective_prov(tsk, cred);
	if ((prov != PRESSURE_PROV_AUTH_LOCAL &&
	     !(allow_remote && prov == PRESSURE_PROV_REMOTE)) || !cb->session_priv_id ||
	    !cb->bound_ctty_dev)
		return false;

	cur_ctty = task_real_ctty_dev(tsk, &cur_sid);
	/*
	 * A graphical terminal starts a new POSIX session on a Unix98 PTY.
	 * Keep that context separate from the physical console's authority.
	 * The inherited Pressure credential still names the original ticket.
	 */
	delegated_pty = MAJOR(cb->bound_ctty_dev) == 4 &&
			MINOR(cb->bound_ctty_dev) == 1 &&
			MAJOR(cur_ctty) >= UNIX98_PTY_SLAVE_MAJOR &&
			MAJOR(cur_ctty) < UNIX98_PTY_SLAVE_MAJOR + UNIX98_PTY_MAJOR_COUNT &&
			cur_sid && cur_sid != cb->bound_sid;
	detached = unix_ipc && MAJOR(cb->bound_ctty_dev) == 4 &&
		   MINOR(cb->bound_ctty_dev) == 1 && !cur_ctty &&
		   cur_sid && cur_sid != cb->bound_sid;
	if (!delegated_pty && !detached &&
	    (!cur_ctty || cur_ctty != cb->bound_ctty_dev ||
	     cur_sid != cb->bound_sid))
		return false;

	now = get_jiffies_64();
	spin_lock_irqsave(&ident_lock, flags);
	hash_for_each_possible(session_table, iter, node, (u32)cb->session_priv_id) {
		if (iter->session_priv_id == cb->session_priv_id) {
			s = iter;
			break;
		}
	}
	if (s && !s->revoked &&
	    (s->expires_jiffies == 0 || !time_after64(now, s->expires_jiffies)) &&
	    s->bound_ctty_dev == cb->bound_ctty_dev &&
	    s->bound_sid == cb->bound_sid &&
	    s->bound_dev_kpriv_id == cb->bound_dev_kpriv_id) {
		if (detached) {
			leader_pid = s->leader_pid;
			goto out;
		}
		if (delegated_pty) {
			strscpy(dev_lbl_out, "dev:delegated_pty", sz);
			verified = true;
			goto out;
		}
		hash_for_each_possible(dev_table, d, node, (u32)cur_ctty) {
			if (!d->is_netdev && d->rdev == cur_ctty) {
				strscpy(dev_lbl_out, d->label, sz);
				verified = true;
				break;
			}
		}
	}
out:
	spin_unlock_irqrestore(&ident_lock, flags);
	if (leader_pid) {
		struct task_struct *leader;
		pid_t leader_sid;
		dev_t leader_tty;

		rcu_read_lock();
		leader = find_task_by_pid_ns(leader_pid, &init_pid_ns);
		leader_tty = task_real_ctty_dev(leader, &leader_sid);
		rcu_read_unlock();
		if (leader_tty == cb->bound_ctty_dev && leader_sid == cb->bound_sid) {
			strscpy(dev_lbl_out, "dev:tty1_helper", sz);
			verified = true;
		}
	}
	return verified;
}

bool pressure_get_verified_session_dev(struct task_struct *tsk,
				       const struct cred *cred,
				       char *dev_lbl_out, size_t sz)
{
	return verified_session_dev(tsk, cred, dev_lbl_out, sz, false, false);
}

void pressure_get_unix_session_dev(const struct cred *cred, char *out, size_t sz)
{
	verified_session_dev(current, cred, out, sz, true, false);
}

bool pressure_get_proxy_session_dev(const struct cred *cred, char *out,
				    size_t sz, bool established)
{
	return verified_session_dev(current, cred, out, sz, true, established);
}

static bool label_match(const char *rule_lbl, const char *actual)
{
	size_t rlen;

	if (!rule_lbl || !rule_lbl[0] || strcmp(rule_lbl, "*") == 0)
		return true;
	if (!actual || !actual[0])
		return false;
	rlen = strlen(rule_lbl);
	if (rlen >= 2 && rule_lbl[rlen - 1] == '*')
		return strncmp(rule_lbl, actual, rlen - 1) == 0;
	return strcmp(rule_lbl, actual) == 0;
}

int pressure_add_policy_rule(u32 action, const char *subj, const char *obj,
			     const char *dev, u32 ev_mask, u8 max_prov)
{
	unsigned long flags;
	struct pressure_policy_rule *r;

	if ((ev_mask & (PEV_LOCAL_PROXY | PEV_PROC_SELF_FD | PEV_LOCAL_CALLBACK |
			PEV_LOCAL_CALLBACK_RELAY)) &&
	    ((ev_mask != PEV_LOCAL_PROXY && ev_mask != PEV_PROC_SELF_FD &&
	      ev_mask != PEV_LOCAL_CALLBACK && ev_mask != PEV_LOCAL_CALLBACK_RELAY) ||
	     max_prov != PRESSURE_PROV_AUTH_LOCAL ||
	     strncmp(subj, "subj:", 5) || !subj[5] || strchr(subj, '*') ||
	     strncmp(obj, "obj:", 4) || !obj[4] || strchr(obj, '*') ||
	     (strcmp(dev, "dev:console_tty1") && strcmp(dev, "dev:tty1_helper"))))
		return -EINVAL;

	spin_lock_irqsave(&ident_lock, flags);
	if (policy_rule_count >= PRESSURE_MAX_POLICY_RULES) {
		spin_unlock_irqrestore(&ident_lock, flags);
		return -ENOSPC;
	}
	r = &policy_rules[policy_rule_count++];
	r->active = true;
	r->action = action;
	strscpy(r->subj_label, subj ? subj : "*", sizeof(r->subj_label));
	strscpy(r->obj_label, obj ? obj : "*", sizeof(r->obj_label));
	strscpy(r->dev_label, dev ? dev : "*", sizeof(r->dev_label));
	r->event_mask = ev_mask ? ev_mask : PEV_ALL;
	r->max_provenance = max_prov;
	spin_unlock_irqrestore(&ident_lock, flags);
	return 0;
}

void pressure_flush_policy_rules(void)
{
	unsigned long flags;

	spin_lock_irqsave(&ident_lock, flags);
	policy_rule_count = 0;
	spin_unlock_irqrestore(&ident_lock, flags);
}

bool pressure_eval_policy_rule(const char *subj, const char *obj,
			       const char *dev, u32 ev_bit, u8 prov,
			       bool *matched)
{
	unsigned long flags;
	unsigned int i;
	bool decision = true;

	*matched = false;
	spin_lock_irqsave(&ident_lock, flags);
	for (i = 0; i < policy_rule_count; i++) {
		struct pressure_policy_rule *r = &policy_rules[i];
		if (!r->active)
			continue;
		if (r->action == 0) {
			if (!(r->event_mask & ev_bit))
				continue;
		} else {
			if ((r->event_mask & ev_bit) != ev_bit)
				continue;
		}
		if (!label_match(r->subj_label, subj) ||
		    !label_match(r->obj_label, obj) ||
		    !label_match(r->dev_label, dev))
			continue;
		if (r->action == 0) {
			*matched = true;
			decision = false;
			break;
		}
		if (prov <= r->max_provenance) {
			*matched = true;
			decision = true;
			break;
		}
	}
	spin_unlock_irqrestore(&ident_lock, flags);
	return decision;
}

/*
 * Descriptor numbering is part of the session ABI. Require an explicit,
 * exact login rule for a verified local human seat. Generic MAC grants
 * and wildcard rules cannot select this ABI.
 */
bool pressure_posix_fd_allowed(const struct cred *cred)
{
	const struct pressure_cred_blob *cb = pressure_cred(cred);
	char device[32];
	unsigned long flags;
	bool allowed = false;
	unsigned int i;

	if (!pressure_get_verified_session_dev(current, cred, device,
					       sizeof(device)))
		return false;
	if (!cb || cb->account_type != PRESSURE_ACCT_HUMAN)
		return false;

	spin_lock_irqsave(&ident_lock, flags);
	for (i = 0; i < policy_rule_count; i++) {
		const struct pressure_policy_rule *r = &policy_rules[i];

		if (!r->active || r->event_mask != PEV_LOGIN ||
		    r->max_provenance != PRESSURE_PROV_AUTH_LOCAL ||
		    strcmp(r->subj_label, cb->label) ||
		    strcmp(r->obj_label, "obj:posix_fd_abi") ||
		    strcmp(r->dev_label, device))
			continue;
		allowed = r->action != 0;
		break;
	}
	spin_unlock_irqrestore(&ident_lock, flags);
	return allowed;
}

bool pressure_eval_exact_local_rule(const char *subject, const char *object,
			       const char *device, u32 event)
{
	unsigned long flags;
	bool allowed = false;
	unsigned int i;

	spin_lock_irqsave(&ident_lock, flags);
	for (i = 0; i < policy_rule_count; i++) {
		const struct pressure_policy_rule *rule = &policy_rules[i];

		if (!rule->active || rule->event_mask != event ||
		    rule->max_provenance != PRESSURE_PROV_AUTH_LOCAL ||
		    strcmp(rule->subj_label, subject) ||
		    strcmp(rule->obj_label, object) ||
		    strcmp(rule->dev_label, device))
			continue;
		allowed = rule->action != 0;
		break;
	}
	spin_unlock_irqrestore(&ident_lock, flags);
	return allowed;
}

int pressure_unix_add_rule(u32 action, const char *subj, u16 sock_type,
			   u32 op_mask, const char *endpoint, const char *peer,
			   const char *dev_lbl, u8 max_prov, const char *exe)
{
	unsigned long flags;
	struct pressure_unix_rule *r;

	if (sock_type != 0 && sock_type != SOCK_STREAM &&
	    sock_type != SOCK_DGRAM && sock_type != SOCK_SEQPACKET)
		return -EINVAL;

	if (exe[0] && (strncmp(exe, "obj:", 4) || !exe[4] || strchr(exe, '*')))
		return -EINVAL;

	if (!strcmp(dev_lbl, "dev:tty1_helper")) {
		u32 pair_ops = PUNIX_OP_SOCKETPAIR | PUNIX_OP_SEND | PUNIX_OP_RECV;
		bool local_pair = op_mask && !(op_mask & ~pair_ops) &&
				  !strncmp(endpoint, "pair:", 5) &&
				  !strcmp(endpoint + 5, subj) && !strcmp(peer, subj);
		bool chatgpt_adapter =
			!strcmp(endpoint, "/run/trimos/chatgpt-auth.sock") &&
			!strcmp(peer, "subj:boot") && !strcmp(subj, "subj:user_desktop") &&
			((!strcmp(exe, "obj:chatgpt_connector") && op_mask == PUNIX_OP_CONNECT) ||
			 (!strcmp(exe, "obj:chatgpt_adapter") &&
			  op_mask && !(op_mask & ~(PUNIX_OP_SEND | PUNIX_OP_RECV))));

		if (!exe[0] || strncmp(subj, "subj:", 5) || !subj[5] ||
		    strchr(subj, '*') || max_prov != PRESSURE_PROV_AUTH_LOCAL ||
		    sock_type != SOCK_STREAM ||
		    (!local_pair && !chatgpt_adapter &&
		     (op_mask != PUNIX_OP_CREATE || strcmp(endpoint, "-"))))
			return -EINVAL;
	}

	spin_lock_irqsave(&ident_lock, flags);
	if (unix_rule_count >= PRESSURE_MAX_UNIX_RULES) {
		spin_unlock_irqrestore(&ident_lock, flags);
		return -ENOSPC;
	}
	r = &unix_rules[unix_rule_count++];
	r->active = true;
	r->action = action ? 1U : 0U;
	r->sock_type = sock_type;
	r->op_mask = op_mask ? (op_mask & PUNIX_OP_ALL) : PUNIX_OP_ALL;
	r->max_provenance = max_prov;
	strscpy(r->exe_label, exe, sizeof(r->exe_label));
	strscpy(r->subj_label, (subj && subj[0]) ? subj : "*",
		sizeof(r->subj_label));
	strscpy(r->endpoint, (endpoint && endpoint[0]) ? endpoint : "-",
		sizeof(r->endpoint));
	strscpy(r->peer_label, (peer && peer[0]) ? peer : "*",
		sizeof(r->peer_label));
	strscpy(r->dev_label, (dev_lbl && dev_lbl[0]) ? dev_lbl : "*",
		sizeof(r->dev_label));
	spin_unlock_irqrestore(&ident_lock, flags);
	return 0;
}

void pressure_unix_flush_rules(void)
{
	unsigned long flags;

	spin_lock_irqsave(&ident_lock, flags);
	unix_rule_count = 0;
	spin_unlock_irqrestore(&ident_lock, flags);
}

bool pressure_unix_eval_rule(const char *subj, u16 sock_type, u32 op_bit,
			     const char *endpoint, const char *peer,
			     const char *dev_lbl, u8 prov, bool *matched)
{
	unsigned long flags;
	unsigned int i;
	bool decision = false, exe_checked = false;
	struct file *executable = NULL;
	const struct pressure_inode_blob *exe_inode = NULL;

	if (matched)
		*matched = false;

	spin_lock_irqsave(&ident_lock, flags);
	for (i = 0; i < unix_rule_count; i++) {
		struct pressure_unix_rule *r = &unix_rules[i];

		if (!r->active)
			continue;
		if (!(r->op_mask & op_bit))
			continue;
		if (r->sock_type != 0 && sock_type != 0 &&
		    r->sock_type != sock_type)
			continue;
		if (!label_match(r->subj_label, subj))
			continue;
		if (dev_lbl && !strcmp(dev_lbl, "dev:tty1_helper") &&
		    strcmp(r->dev_label, "dev:tty1_helper"))
			continue;
		if (!label_match(r->dev_label,
				 (dev_lbl && dev_lbl[0]) ? dev_lbl : "dev:none"))
			continue;

		if (op_bit == PUNIX_OP_CREATE) {
			/*
			 * Endpoint-specific deny rules do not block generic
			 * socket() creation; only create-only/global denies do.
			 * Any matching allow rule containing PUNIX_OP_CREATE
			 * authorizes creation of that socket type while still
			 * gating all endpoints separately.
			 */
			if (r->action == 0 &&
			    strcmp(r->endpoint, "-") != 0 &&
			    strcmp(r->endpoint, "*") != 0)
				continue;
		} else if (op_bit == PUNIX_OP_SOCKETPAIR) {
			if (strcmp(r->endpoint, "-") != 0 &&
			    !label_match(r->endpoint, endpoint))
				continue;
			if (peer && !label_match(r->peer_label, peer))
				continue;
		} else {
			/*
			 * Endpoint & descriptor-transfer operations:
			 * creation-only rules ("-") NEVER grant endpoint
			 * access or descriptor receipt/inheritance!
			 */
			if (strcmp(r->endpoint, "-") == 0)
				continue;
			if (!label_match(r->endpoint, endpoint))
				continue;
			if (peer && !label_match(r->peer_label, peer))
				continue;
		}

		if (r->exe_label[0]) {
			if (!exe_checked) {
				exe_checked = true;
				if (current->mm)
					executable = get_mm_exe_file(current->mm);
				if (executable)
					exe_inode = pressure_inode(file_inode(executable));
			}
			if (!exe_inode || strcmp(r->exe_label, exe_inode->label))
				continue;
		}

		if (r->action == 0) {
			if (matched)
				*matched = true;
			decision = false;
			break;
		}

		if (prov <= r->max_provenance) {
			if (matched)
				*matched = true;
			decision = true;
			break;
		}
	}
	spin_unlock_irqrestore(&ident_lock, flags);
	if (executable)
		fput(executable);
	return decision;
}

void pressure_refresh_inode_xattr(struct dentry *dentry, struct inode *inode)
{
	struct pressure_inode_blob *ib = pressure_inode(inode);
	struct pressure_xattr_disk xdisk;
	ssize_t sz;

	if (!ib || !inode)
		return;

	if (!ib->obj_priv_id) {
		ib->obj_pub_id = gen_secret_id();
		ib->obj_priv_id = gen_secret_id();
	}

	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode)) {
		struct pressure_dev_entry *d =
			pressure_get_or_create_chrblk_dev(inode->i_rdev,
							  inode->i_mode);
		ib->is_device = true;
		ib->rdev = inode->i_rdev;
		if (d) {
			ib->obj_pub_id = d->dev_pub_id;
			ib->obj_priv_id = d->dev_kpriv_id;
			ib->dev_class = d->dev_class;
			strscpy(ib->label, d->label, sizeof(ib->label));
		}
		ib->initialized = true;
		return;
	}

	if (!dentry || !(inode->i_opflags & IOP_XATTR) ||
	    !(inode->i_sb->s_flags & SB_ACTIVE))
		return;

	sz = __vfs_getxattr(dentry, inode, XATTR_NAME_PRESSURE, &xdisk,
			    sizeof(xdisk));
	ib->initialized = true;
	if (sz == sizeof(xdisk) && xdisk.magic == PRESSURE_XATTR_MAGIC) {
		u64 owner_kpriv = 0;

		ib->flags = xdisk.flags;
		if (xdisk.file_pub_id)
			ib->obj_pub_id = xdisk.file_pub_id;
		ib->owner_pub_uid = xdisk.owner_pub_uid;
		if (xdisk.owner_pub_uid &&
		    pressure_lookup_user_kpriv(xdisk.owner_pub_uid,
					       &owner_kpriv, NULL, NULL, NULL))
			ib->owner_kpriv_uid = owner_kpriv;
		xdisk.label[sizeof(xdisk.label) - 1] = '\0';
		strscpy(ib->label, xdisk.label, sizeof(ib->label));
		ib->initialized = true;
	}
}

/*
 * Core hard-stop enforcement across:
 * 1) /etc/pressure/auth.vault (PRESSURE_FILE_AUTHD_VAULT -> authd ONLY)
 * 2) Per-user / per-daemon private files (PRESSURE_FILE_USER_PRIVATE -> secret kpriv_uid ONLY)
 * 3) Universal /dev cryptographic IDs, storage disks, keyboards/mice, TTY seat exclusivity
 * 4) Universal LOCAL vs. REMOTE provenance on every file & socket descriptor
 * 5) Explicit 6-tuple event policy rules
 */
int pressure_check_inode_access(const struct cred *cred, struct inode *inode,
				u32 ev_bit)
{
	const struct pressure_cred_blob *cb = pressure_cred(cred);
	struct pressure_inode_blob *ib = pressure_inode(inode);
	u8 prov;

	if (!cb || !ib || !inode)
		return 0;

	/* Kernel threads (e.g. sfwd) are trusted internal workers */
	if (current->flags & PF_KTHREAD)
		return 0;

	prov = pressure_effective_prov(current, cred);

	/* 1. Auth vault hard-stop: ONLY pressure-authd may touch the vault! */
	if (unlikely(ib->flags & PRESSURE_FILE_AUTHD_VAULT)) {
		if (cb->account_type != PRESSURE_ACCT_AUTHD) {
			pressure_record_violation(current, PVIO_VAULT_ACCESS,
						  (u32)inode->i_ino, ib->label);
			return READ_ONCE(pressure_enforce) ? -EACCES : 0;
		}
		return 0;
	}

	/* 2. Per-user & per-daemon private data hard-stop (matches secret kpriv_uid!) */
	if (ib->flags & PRESSURE_FILE_USER_PRIVATE) {
		u64 req_kpriv = ib->owner_kpriv_uid;

		if (!req_kpriv && ib->owner_pub_uid) {
			if (pressure_lookup_user_kpriv(ib->owner_pub_uid,
						       &req_kpriv, NULL, NULL,
						       NULL))
				ib->owner_kpriv_uid = req_kpriv;
		}

		/* Allow pressure-authd only to provision initial home/state dirs */
		if (cb->account_type == PRESSURE_ACCT_AUTHD)
			return 0;

		if (!req_kpriv || cb->kpriv_uid != req_kpriv ||
		    prov == PRESSURE_PROV_REMOTE) {
			pressure_record_violation(current,
						  PVIO_USER_PRIVATE_DATA,
						  ib->owner_pub_uid, ib->label);
			return READ_ONCE(pressure_enforce) ? -EACCES : 0;
		}
	}

	/* 3. Universal /dev device node hard-stops & seat anti-impersonation */
	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode)) {
		struct pressure_dev_entry *d =
			pressure_get_or_create_chrblk_dev(inode->i_rdev,
							  inode->i_mode);
		if (d && (cb->confined || prov == PRESSURE_PROV_REMOTE ||
			  cb->account_type == PRESSURE_ACCT_DAEMON ||
			  READ_ONCE(pressure_enforce))) {
			bool matched_rule = false;
			bool rule_ok = pressure_eval_policy_rule(
				cb->label, d->label, d->label, ev_bit, prov,
				&matched_rule);

			if (matched_rule && !rule_ok) {
				pressure_record_violation(current,
							  PVIO_DEV_ACCESS_DENIED,
							  (u32)d->rdev, d->label);
				return READ_ONCE(pressure_enforce) ? -EACCES : 0;
			}

			switch (d->dev_class) {
			case PDEV_PSEUDO_SAFE:
				break;
			case PDEV_STORAGE_BLK:
			case PDEV_NET_EXT:
				/* Raw storage disks, /dev/mem, /dev/net/tun locked unless unconfined boot root or explicit rule */
				if (!matched_rule &&
				    (cb->confined || prov == PRESSURE_PROV_REMOTE ||
				     cb->account_type == PRESSURE_ACCT_DAEMON)) {
					pressure_record_violation(
						current, PVIO_DEV_ACCESS_DENIED,
						(u32)d->rdev, d->name);
					return READ_ONCE(pressure_enforce) ?
					       -EACCES : 0;
				}
				break;
			case PDEV_SEAT_INPUT:
				/* Keyboards, mice, uinput: MUST hold active local seat_kpriv_id! */
				if (prov == PRESSURE_PROV_REMOTE ||
				    cb->account_type == PRESSURE_ACCT_DAEMON ||
				    (cb->confined &&
				     cb->seat_kpriv_id != local_seat_kpriv_id)) {
					pressure_record_violation(
						current, PVIO_DEV_ACCESS_DENIED,
						(u32)d->rdev, d->name);
					return READ_ONCE(pressure_enforce) ?
					       -EACCES : 0;
				}
				break;
			case PDEV_SEAT_TTY:
				/* TTY exclusivity: REMOTE blocked; if claimed by a session, ONLY that session may access! */
				if (prov == PRESSURE_PROV_REMOTE) {
					pressure_record_violation(
						current, PVIO_REMOTE_TO_LOCAL_FD,
						(u32)d->rdev, d->name);
					return READ_ONCE(pressure_enforce) ?
					       -EACCES : 0;
				}
				if (d->owner_session_priv_id != 0 &&
				    cb->account_type != PRESSURE_ACCT_AUTHD &&
				    cb->session_priv_id != d->owner_session_priv_id) {
					/* Permit inherited stdio fd 0..2 only for non-remote boot console messages if unconfined */
					if (cb->confined ||
					    cb->account_type == PRESSURE_ACCT_DAEMON ||
					    cb->account_type == PRESSURE_ACCT_HUMAN) {
						pressure_record_violation(
							current,
							PVIO_SEAT_MAX_SESSIONS,
							(u32)d->rdev, d->name);
						return READ_ONCE(pressure_enforce) ?
						       -EACCES : 0;
					}
				}
				break;
			default:
				if (prov == PRESSURE_PROV_REMOTE && !matched_rule) {
					pressure_record_violation(
						current, PVIO_DEV_ACCESS_DENIED,
						(u32)d->rdev, d->name);
					return READ_ONCE(pressure_enforce) ?
					       -EACCES : 0;
				}
				break;
			}
		}
	}

	/* 4. Universal LOCAL vs. REMOTE check on LOCAL_ONLY files & sockets */
	if ((ib->flags & PRESSURE_FILE_LOCAL_ONLY) &&
	    prov == PRESSURE_PROV_REMOTE) {
		pressure_record_violation(current, PVIO_REMOTE_TO_LOCAL_FD,
					  (u32)inode->i_ino, ib->label);
		return READ_ONCE(pressure_enforce) ? -EACCES : 0;
	}

	/* 5. General 6-tuple policy rules evaluated against live verified session/device */
	if (ib->label[0] && strcmp(ib->label, "obj:unlabeled") != 0) {
		char caller_dev_lbl[32];
		bool matched = false;
		bool ok;

		pressure_get_verified_session_dev(current, cred,
						  caller_dev_lbl,
						  sizeof(caller_dev_lbl));
		ok = pressure_eval_policy_rule(cb->label, ib->label,
					       caller_dev_lbl, ev_bit, prov,
					       &matched);
		if ((matched && !ok) || (!matched && (ib->flags & PRESSURE_FILE_PROTECTED))) {
			pressure_record_object_denial(ev_bit, ib->label, cb->label,
						      caller_dev_lbl);
			return READ_ONCE(pressure_enforce) ? -EACCES : 0;
		}
	}

	return 0;
}

int pressure_claim_dev_file(struct inode *inode, struct pressure_file_blob *fb)
{
	struct pressure_dev_entry *d;
	unsigned long flags;

	if (!inode || !fb || (current->flags & PF_KTHREAD))
		return 0;
	if (!S_ISCHR(inode->i_mode) && !S_ISBLK(inode->i_mode))
		return 0;

	d = pressure_get_or_create_chrblk_dev(inode->i_rdev, inode->i_mode);
	if (!d)
		return 0;
	/* Seat TTYs & input devices track session ownership via PAM auth_grant */
	if (d->dev_class == PDEV_SEAT_TTY || d->dev_class == PDEV_SEAT_INPUT)
		return 0;

	spin_lock_irqsave(&ident_lock, flags);
	if (d->max_sessions > 0) {
		if (d->active_sessions >= d->max_sessions) {
			spin_unlock_irqrestore(&ident_lock, flags);
			pressure_record_violation(current,
						  PVIO_SEAT_MAX_SESSIONS,
						  (u32)d->rdev, d->label);
			return READ_ONCE(pressure_enforce) ? -EBUSY : 0;
		}
		d->active_sessions++;
		fb->claimed_rdev = d->rdev;
	}
	spin_unlock_irqrestore(&ident_lock, flags);
	return 0;
}

void pressure_release_dev_file(struct pressure_file_blob *fb)
{
	struct pressure_dev_entry *d;
	unsigned long flags;
	dev_t rdev;

	if (!fb || !fb->claimed_rdev)
		return;
	rdev = fb->claimed_rdev;
	fb->claimed_rdev = 0;

	spin_lock_irqsave(&ident_lock, flags);
	hash_for_each_possible(dev_table, d, node, (u32)rdev) {
		if (!d->is_netdev && d->rdev == rdev) {
			if (d->active_sessions > 0)
				d->active_sessions--;
			break;
		}
	}
	spin_unlock_irqrestore(&ident_lock, flags);
}

bool pressure_txn_is_active(void)
{
	return READ_ONCE(g_txn_active);
}

bool pressure_txn_is_degraded(void)
{
	return READ_ONCE(g_txn_degraded);
}

void pressure_txn_mark_degraded(void)
{
	WRITE_ONCE(g_txn_degraded, true);
}

u64 pressure_get_policy_gen(void)
{
	return (u64)atomic64_read(&g_policy_gen);
}

void pressure_bump_policy_gen_if_not_txn(void)
{
	if (!READ_ONCE(g_txn_active))
		atomic64_inc(&g_policy_gen);
}

static void restore_txn_snapshot_locked(const struct pressure_txn_snapshot *snap)
{
	struct pressure_dev_entry *d;
	unsigned int i;
	int bkt;

	WRITE_ONCE(pressure_enforce, snap->enforce_bak);
	policy_rule_count = snap->policy_cnt;
	memcpy(policy_rules, snap->policy_bak,
	       snap->policy_cnt * sizeof(policy_rules[0]));
	sfw_rule_count = snap->sfw_cnt;
	memcpy(sfw_rules, snap->sfw_bak,
	       snap->sfw_cnt * sizeof(sfw_rules[0]));
	unix_rule_count = snap->unix_cnt;
	memcpy(unix_rules, snap->unix_bak,
	       snap->unix_cnt * sizeof(unix_rules[0]));

	hash_for_each(dev_table, bkt, d, node) {
		for (i = 0; i < snap->dev_cnt; i++) {
			const struct pressure_dev_snap_item *it = &snap->dev_bak[i];
			if (d->is_netdev == it->is_netdev &&
			    (d->is_netdev ? (d->ifindex == it->ifindex &&
					     d->dev_pub_id == it->dev_pub_id) :
					    (d->rdev == it->rdev))) {
				strscpy(d->label, it->label, sizeof(d->label));
				d->dev_class = it->dev_class;
				d->provenance = it->provenance;
				d->max_sessions = it->max_sessions;
				break;
			}
		}
	}
}

static bool txn_owner_alive(pid_t pid)
{
	struct task_struct *t;
	bool alive = false;

	if (pid <= 0)
		return false;
	rcu_read_lock();
	t = pid_task(find_vpid(pid), PIDTYPE_PID);
	if (t && t->exit_state == 0 && !(t->flags & PF_EXITING))
		alive = true;
	rcu_read_unlock();
	return alive;
}

int pressure_txn_begin(void)
{
	struct pressure_txn_snapshot *snap;
	struct pressure_dev_entry *d;
	unsigned long flags;
	int bkt;

	mutex_lock(&txn_lock);
	if (g_txn_active) {
		if (txn_owner_alive(g_txn_owner_pid)) {
			mutex_unlock(&txn_lock);
			return -EBUSY;
		}
		/* Previous loader crashed mid-txn: auto-rollback its uncommitted edits first */
		if (g_txn_snap) {
			spin_lock_irqsave(&ident_lock, flags);
			restore_txn_snapshot_locked(g_txn_snap);
			spin_unlock_irqrestore(&ident_lock, flags);
			kvfree(g_txn_snap);
			g_txn_snap = NULL;
		}
		WRITE_ONCE(g_txn_active, false);
		g_txn_prepared = false;
		g_txn_owner_pid = 0;
	}
	snap = kvzalloc(sizeof(*snap), GFP_KERNEL);
	if (!snap) {
		mutex_unlock(&txn_lock);
		return -ENOMEM;
	}

	spin_lock_irqsave(&ident_lock, flags);
	snap->enforce_bak = READ_ONCE(pressure_enforce);
	snap->policy_cnt = policy_rule_count;
	memcpy(snap->policy_bak, policy_rules,
	       policy_rule_count * sizeof(policy_rules[0]));
	snap->sfw_cnt = sfw_rule_count;
	memcpy(snap->sfw_bak, sfw_rules,
	       sfw_rule_count * sizeof(sfw_rules[0]));
	snap->unix_cnt = unix_rule_count;
	memcpy(snap->unix_bak, unix_rules,
	       unix_rule_count * sizeof(unix_rules[0]));
	hash_for_each(dev_table, bkt, d, node) {
		if (snap->dev_cnt < PRESSURE_MAX_DEV_SNAP) {
			struct pressure_dev_snap_item *it =
				&snap->dev_bak[snap->dev_cnt++];
			it->is_netdev = d->is_netdev;
			it->rdev = d->rdev;
			it->ifindex = d->ifindex;
			it->dev_pub_id = d->dev_pub_id;
			strscpy(it->label, d->label, sizeof(it->label));
			it->dev_class = d->dev_class;
			it->provenance = d->provenance;
			it->max_sessions = d->max_sessions;
		}
	}
	g_txn_snap = snap;
	g_txn_prepared = false;
	g_txn_owner_pid = task_tgid_nr(current);
	WRITE_ONCE(g_txn_active, true);
	spin_unlock_irqrestore(&ident_lock, flags);
	mutex_unlock(&txn_lock);
	return 0;
}

int pressure_txn_prepare(void)
{
	mutex_lock(&txn_lock);
	if (!g_txn_active || !g_txn_snap) {
		mutex_unlock(&txn_lock);
		return -EINVAL;
	}
	g_txn_prepared = true;
	mutex_unlock(&txn_lock);
	return 0;
}

int pressure_txn_commit(void)
{
	struct pressure_txn_snapshot *snap;

	mutex_lock(&txn_lock);
	if (!g_txn_active || !g_txn_snap) {
		mutex_unlock(&txn_lock);
		return -EINVAL;
	}
	snap = g_txn_snap;
	g_txn_snap = NULL;
	g_txn_prepared = false;
	g_txn_owner_pid = 0;
	WRITE_ONCE(g_txn_active, false);
	WRITE_ONCE(g_txn_degraded, false);
	atomic64_inc(&g_policy_gen);
	mutex_unlock(&txn_lock);
	kvfree(snap);
	return 0;
}

int pressure_txn_abort(void)
{
	struct pressure_txn_snapshot *snap;
	unsigned long flags;

	mutex_lock(&txn_lock);
	if (!g_txn_active || !g_txn_snap) {
		mutex_unlock(&txn_lock);
		return -EINVAL;
	}
	snap = g_txn_snap;

	spin_lock_irqsave(&ident_lock, flags);
	restore_txn_snapshot_locked(snap);
	g_txn_snap = NULL;
	g_txn_prepared = false;
	g_txn_owner_pid = 0;
	WRITE_ONCE(g_txn_active, false);
	spin_unlock_irqrestore(&ident_lock, flags);
	mutex_unlock(&txn_lock);
	kvfree(snap);
	return 0;
}

/*
 * sfw (Socket Firewall) Rule Management & Kernel Broker Hooks
 */
int pressure_sfw_add_rule(const struct sfw_firewall_rule *rule)
{
	unsigned long flags;

	spin_lock_irqsave(&ident_lock, flags);
	if (sfw_rule_count >= PRESSURE_MAX_SFW_RULES) {
		spin_unlock_irqrestore(&ident_lock, flags);
		return -ENOSPC;
	}
	sfw_rules[sfw_rule_count++] = *rule;
	spin_unlock_irqrestore(&ident_lock, flags);
	return 0;
}

void pressure_sfw_flush_rules(void)
{
	unsigned long flags;

	spin_lock_irqsave(&ident_lock, flags);
	sfw_rule_count = 0;
	spin_unlock_irqrestore(&ident_lock, flags);
}

int pressure_register_sfw_worker(struct task_struct *worker)
{
	WRITE_ONCE(pressure_sfw_kthread, worker);
	return 0;
}
EXPORT_SYMBOL_GPL(pressure_register_sfw_worker);

int pressure_register_sfw_pkt_hook(sfw_pkt_hook_t fn)
{
	rcu_assign_pointer(g_sfw_pkt_hook, fn);
	if (!fn)
		synchronize_rcu();
	return 0;
}
EXPORT_SYMBOL_GPL(pressure_register_sfw_pkt_hook);

int pressure_sfw_pkt_run(unsigned int chain, struct net *net, struct sock *sk,
			 struct sk_buff *skb, struct net_device *in_dev,
			 struct net_device *out_dev)
{
	sfw_pkt_hook_t fn;
	int ret = 0;

	rcu_read_lock();
	fn = rcu_dereference(g_sfw_pkt_hook);
	if (fn)
		ret = fn(chain, net, sk, skb, in_dev, out_dev);
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(pressure_sfw_pkt_run);

int pressure_register_sfw_pkt6_hook(sfw_pkt_hook_t fn)
{
	rcu_assign_pointer(g_sfw_pkt6_hook, fn);
	if (!fn)
		synchronize_rcu();
	return 0;
}
EXPORT_SYMBOL_GPL(pressure_register_sfw_pkt6_hook);

int pressure_sfw_pkt6_run(unsigned int chain, struct net *net, struct sock *sk,
			  struct sk_buff *skb, struct net_device *in_dev,
			  struct net_device *out_dev)
{
	sfw_pkt_hook_t fn;
	int ret = 0;

	rcu_read_lock();
	fn = rcu_dereference(g_sfw_pkt6_hook);
	if (fn)
		ret = fn(chain, net, sk, skb, in_dev, out_dev);
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(pressure_sfw_pkt6_run);

bool pressure_lookup_netdev_label(int ifindex, char *label_out)
{
	struct pressure_dev_entry *d;
	unsigned long flags;
	bool found = false;

	spin_lock_irqsave(&ident_lock, flags);
	hash_for_each_possible(dev_table, d, node, (u32)ifindex + 0x10000U) {
		if (d->is_netdev && d->ifindex == ifindex) {
			strscpy(label_out, d->label, 32);
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&ident_lock, flags);
	return found;
}
EXPORT_SYMBOL_GPL(pressure_lookup_netdev_label);

void pressure_taint_task_remote(struct task_struct *peer_task)
{
	struct pressure_task_blob *tb;

	if (!peer_task)
		return;
	tb = pressure_task(peer_task);
	if (tb)
		atomic_set(&tb->remote_tainted, 1);
}
EXPORT_SYMBOL_GPL(pressure_taint_task_remote);

static const char *sfw_configured_netdev_label(const char *ifname)
{
	struct pressure_dev_entry *entry;
	int bucket;

	lockdep_assert_held(&ident_lock);
	if (ifname && ifname[0]) {
		hash_for_each(dev_table, bucket, entry, node) {
			if (entry->is_netdev && !strcmp(entry->name, ifname))
				return entry->label;
		}
	}
	return NULL;
}

int pressure_sfw_authorize(struct task_struct *peer_task,
			   const struct cred *peer_cred, u32 dir,
			   __be32 ipv4_addr, u16 host_port,
			   const char *ifname, u64 sock_pub_id)
{
	const struct pressure_cred_blob *cb = pressure_cred(peer_cred);
	u8 prov = pressure_effective_prov(peer_task, peer_cred);
	uid_t pub_uid = peer_cred ?
		from_kuid_munged(&init_user_ns, peer_cred->uid) : 0;
	bool is_loopback = ipv4_is_loopback(ipv4_addr) ||
			   (ifname && strcmp(ifname, "lo") == 0);
	const char *dev_lbl = is_loopback ? "dev:net_lo" : "dev:net_ext";
	const char *configured_label;
	unsigned long flags;
	unsigned int i;
	bool explicit_match = false;
	bool allowed = false;

	spin_lock_irqsave(&ident_lock, flags);
	configured_label = sfw_configured_netdev_label(is_loopback ? "lo" : ifname);
	for (i = 0; i < sfw_rule_count; i++) {
		struct sfw_firewall_rule *r = &sfw_rules[i];

		if (r->family != 0 && r->family != AF_INET)
			continue;
		if (r->direction != SFW_DIR_ANY && r->direction != dir)
			continue;
		if (r->pub_uid != 0 && r->pub_uid != pub_uid)
			continue;
		if (r->sock_pub_id != 0 && r->sock_pub_id != sock_pub_id)
			continue;
		if (!label_match(r->dev_label, dev_lbl) &&
		    !label_match(r->dev_label, configured_label) &&
		    !(ifname && ifname[0] && label_match(r->dev_label, ifname)))
			continue;
		if ((ipv4_addr & r->ipv4_mask) != (r->ipv4_net & r->ipv4_mask))
			continue;
		if (r->port_max != 0 &&
		    (host_port < r->port_min || host_port > r->port_max))
			continue;

		explicit_match = true;
		if (prov <= r->max_prov && r->action == SFW_RULE_ALLOW)
			allowed = true;
		else
			allowed = false;
		break;
	}
	spin_unlock_irqrestore(&ident_lock, flags);

	if (!explicit_match) {
		/*
		 * Default sfw invariance:
		 * - Loopback (127.0.0.0/8 on dev:net_lo) is permitted both
		 *   PRELOGIN_LOCAL and AUTH_LOCAL, and DENIED to REMOTE tasks!
		 * - External non-loopback IPs/interfaces are default-DENY
		 *   unless explicitly permitted by an sfw rule!
		 */
		if (is_loopback && prov != PRESSURE_PROV_REMOTE)
			allowed = true;
		else
			allowed = false;
	}

	if (!allowed) {
		char det[48];
		snprintf(det, sizeof(det), "sfw_dir=%u port=%u dev=%s",
			 dir, host_port, (ifname && ifname[0]) ? ifname : dev_lbl);
		pressure_record_violation(peer_task ? peer_task : current,
					  PVIO_SFW_FIREWALL_DROP,
					  ntohl(ipv4_addr), det);
		if (READ_ONCE(pressure_enforce))
			return -EACCES;
	}
	(void)cb;
	return 0;
}
EXPORT_SYMBOL_GPL(pressure_sfw_authorize);

static bool ipv6_rule_prefix_match(const struct in6_addr *addr,
				   const u8 raw_net[16], u16 plen)
{
	struct in6_addr net6;

	if (plen == 0)
		return true;
	if (plen > 128)
		plen = 128;
	memcpy(&net6, raw_net, 16);
	return ipv6_addr_diff(addr, &net6) >= (int)plen;
}

int pressure_sfw_authorize6(struct task_struct *peer_task,
			    const struct cred *peer_cred, u32 dir,
			    const struct in6_addr *ipv6_addr, u16 host_port,
			    const char *ifname, u64 sock_pub_id)
{
	u8 prov = pressure_effective_prov(peer_task, peer_cred);
	uid_t pub_uid = peer_cred ?
		from_kuid_munged(&init_user_ns, peer_cred->uid) : 0;
	bool is_any = ipv6_addr_any(ipv6_addr);
	bool is_loopback = ipv6_addr_loopback(ipv6_addr) ||
			   ipv6_addr_v4mapped_loopback(ipv6_addr) ||
			   (ifname && strcmp(ifname, "lo") == 0);
	const char *dev_lbl = is_loopback ? "dev:net_lo" : "dev:net_ext";
	const char *configured_label;
	unsigned long flags;
	unsigned int i;
	bool explicit_match = false;
	bool allowed = false;

	spin_lock_irqsave(&ident_lock, flags);
	configured_label = sfw_configured_netdev_label(is_loopback ? "lo" : ifname);
	for (i = 0; i < sfw_rule_count; i++) {
		struct sfw_firewall_rule *r = &sfw_rules[i];

		if (r->family != AF_INET6)
			continue;
		if (r->direction != SFW_DIR_ANY && r->direction != dir)
			continue;
		if (r->pub_uid != 0 && r->pub_uid != pub_uid)
			continue;
		if (r->sock_pub_id != 0 && r->sock_pub_id != sock_pub_id)
			continue;
		if (!label_match(r->dev_label, dev_lbl) &&
		    !label_match(r->dev_label, configured_label) &&
		    !(ifname && ifname[0] && label_match(r->dev_label, ifname)))
			continue;
		if (!ipv6_rule_prefix_match(ipv6_addr, r->ipv6_net, r->prefixlen))
			continue;
		if (r->port_max != 0 &&
		    (host_port < r->port_min || host_port > r->port_max))
			continue;

		explicit_match = true;
		if (prov <= r->max_prov && r->action == SFW_RULE_ALLOW)
			allowed = true;
		else
			allowed = false;
		break;
	}
	spin_unlock_irqrestore(&ident_lock, flags);

	if (!explicit_match) {
		/*
		 * Default IPv6 sfw invariance:
		 * - Loopback (::1 on dev:net_lo) is permitted for PRELOGIN_LOCAL
		 *   and AUTH_LOCAL, and DENIED to REMOTE tasks!
		 * - External IPv6 addresses/interfaces (including :: wildcard bind
		 *   without lo) are default-DENY unless matched by an inet6 rule!
		 */
		if (is_loopback && !is_any && prov != PRESSURE_PROV_REMOTE)
			allowed = true;
		else
			allowed = false;
	}

	if (!allowed) {
		char det[48];
		snprintf(det, sizeof(det), "sfw6_dir=%u port=%u dev=%s",
			 dir, host_port, (ifname && ifname[0]) ? ifname : dev_lbl);
		pressure_record_violation(peer_task ? peer_task : current,
					  PVIO_SFW_FIREWALL_DROP,
					  ntohl(ipv6_addr->s6_addr32[3]), det);
		if (READ_ONCE(pressure_enforce))
			return -EACCES;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(pressure_sfw_authorize6);

int pressure_format_users(struct seq_file *m, void *v)
{
	struct pressure_user_entry *u;
	unsigned long flags;
	int bkt;

	(void)v;

	spin_lock_irqsave(&ident_lock, flags);
	hash_for_each(user_table, bkt, u, node) {
		const char *tstr = (u->account_type == PRESSURE_ACCT_HUMAN) ? "human" :
				   (u->account_type == PRESSURE_ACCT_DAEMON) ? "daemon" :
				   "system";
		seq_printf(m, "pub_uid=%u pub_gid=%u type=%s label=%s kpriv_uid=<SECRET>\n",
			   u->pub_uid, u->pub_gid, tstr, u->label);
	}
	spin_unlock_irqrestore(&ident_lock, flags);
	return 0;
}

int pressure_format_devices(struct seq_file *m, void *v)
{
	struct pressure_dev_entry *d;
	unsigned long flags;
	int bkt;

	(void)v;

	spin_lock_irqsave(&ident_lock, flags);
	hash_for_each(dev_table, bkt, d, node) {
		const char *pstr = (d->provenance == PRESSURE_PROV_REMOTE) ?
				   "REMOTE" : "LOCAL";
		if (d->is_netdev) {
			seq_printf(m, "netdev=%s ifindex=%d label=%s class=%u prov=%s pub_id=0x%llx kpriv_id=<SECRET>\n",
				   d->name, d->ifindex, d->label, d->dev_class,
				   pstr, d->dev_pub_id);
		} else {
			seq_printf(m, "dev=%s major=%u minor=%u label=%s class=%u prov=%s sessions=%u/%u pub_id=0x%llx kpriv_id=<SECRET>\n",
				   d->name, MAJOR(d->rdev), MINOR(d->rdev),
				   d->label, d->dev_class, pstr,
				   d->active_sessions, d->max_sessions,
				   d->dev_pub_id);
		}
	}
	spin_unlock_irqrestore(&ident_lock, flags);
	return 0;
}

int pressure_format_policy(struct seq_file *m, void *v)
{
	unsigned long flags;
	unsigned int i;

	(void)v;

	spin_lock_irqsave(&ident_lock, flags);
	for (i = 0; i < policy_rule_count; i++) {
		struct pressure_policy_rule *r = &policy_rules[i];
		seq_printf(m, "idx=%u action=%s subj=%s obj=%s dev=%s events=0x%x max_prov=%u\n",
			   i, r->action ? "allow" : "deny", r->subj_label,
			   r->obj_label, r->dev_label, r->event_mask,
			   r->max_provenance);
	}
	spin_unlock_irqrestore(&ident_lock, flags);
	return 0;
}

int pressure_format_sfw_rules(struct seq_file *m, void *v)
{
	unsigned long flags;
	unsigned int i;

	(void)v;

	spin_lock_irqsave(&ident_lock, flags);
	for (i = 0; i < sfw_rule_count; i++) {
		struct sfw_firewall_rule *r = &sfw_rules[i];
		if (r->family == AF_INET6) {
			seq_printf(m, "idx=%u family=inet6 action=%s dir=%u pub_uid=%u net=%pI6c/%u ports=%u-%u dev=%s max_prov=%u\n",
				   i, r->action == SFW_RULE_ALLOW ? "allow" : "deny",
				   r->direction, r->pub_uid, r->ipv6_net,
				   r->prefixlen, r->port_min, r->port_max,
				   r->dev_label, r->max_prov);
		} else {
			seq_printf(m, "idx=%u family=inet4 action=%s dir=%u pub_uid=%u net=%pI4 mask=%pI4 ports=%u-%u dev=%s max_prov=%u\n",
				   i, r->action == SFW_RULE_ALLOW ? "allow" : "deny",
				   r->direction, r->pub_uid, &r->ipv4_net,
				   &r->ipv4_mask, r->port_min, r->port_max,
				   r->dev_label, r->max_prov);
		}
	}
	spin_unlock_irqrestore(&ident_lock, flags);
	return 0;
}

int pressure_format_unix_rules(struct seq_file *m, void *v)
{
	unsigned long flags;
	unsigned int i;

	(void)v;

	spin_lock_irqsave(&ident_lock, flags);
	for (i = 0; i < unix_rule_count; i++) {
		struct pressure_unix_rule *r = &unix_rules[i];
		const char *tstr = (r->sock_type == SOCK_STREAM) ? "stream" :
				   (r->sock_type == SOCK_DGRAM) ? "dgram" :
				   (r->sock_type == SOCK_SEQPACKET) ? "seqpacket" :
				   "any";
		seq_printf(m, "idx=%u action=%s subj=%s type=%s ops=0x%x ep=%s peer=%s dev=%s max_prov=%u exe=%s\n",
			   i, r->action ? "allow" : "deny", r->subj_label,
			   tstr, r->op_mask, r->endpoint, r->peer_label,
			   r->dev_label, r->max_provenance,
			   r->exe_label[0] ? r->exe_label : "-");
	}
	spin_unlock_irqrestore(&ident_lock, flags);
	return 0;
}

void __init pressure_ident_policy_init(void)
{
	local_seat_kpriv_id = gen_secret_id();
	register_netdevice_notifier(&pressure_netdev_notifier);
}
