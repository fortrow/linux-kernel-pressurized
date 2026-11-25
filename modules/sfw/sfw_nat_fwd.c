// SPDX-License-Identifier: GPL-2.0
/*
 * sfw Stateful Dual-Stack (IPv4 + IPv6) NAT (DNAT, SNAT, MASQUERADE) &
 * 5-Chain Packet Engine (PREROUTING, INPUT, FORWARD, OUTPUT, POSTROUTING)
 * -- Zero Netfilter!
 *
 * All chains, NAT44/NAT66 rules, default policies, and conntrack states can be
 * inspected and modified live while the kernel is running via /proc/pressure_sfw/
 * and the `sfw` / `sure` userspace tools.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/jiffies.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/route.h>
#include <net/ip6_route.h>
#include <net/addrconf.h>
#include <net/checksum.h>
#include <net/net_namespace.h>
#include <linux/sfw_pkt.h>

#include "sfw_internal.h"

extern int pressure_register_sfw_pkt_hook(sfw_pkt_hook_t fn);
extern int pressure_register_sfw_pkt6_hook(sfw_pkt_hook_t fn);
extern bool pressure_lookup_netdev_label(int ifindex, char *label_out);

#define SFW_MAX_CHAIN_RULES	256
#define SFW_MAX_NAT_RULES	128
#define SFW_MAX_CT_ENTRIES	2048
#define SFW_CT_TIMEOUT_JIFFIES	(120 * HZ)

enum sfw_nat_type {
	SFW_NAT_NONE = 0,
	SFW_NAT_DNAT = 1,
	SFW_NAT_SNAT = 2,
	SFW_NAT_MASQ = 3,
};

enum sfw_ct_state_match {
	SFW_STATE_ANY = 0,
	SFW_STATE_NEW = 1,
	SFW_STATE_ESTABLISHED = 2,
};

struct sfw_chain_rule {
	bool active;
	u16 family;     /* 0 = any, AF_INET, or AF_INET6 */
	u8 chain;       /* SFW_CHAIN_* */
	u8 action;      /* 1 = allow, 0 = drop */
	u8 proto;       /* 0 = all, IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP, IPPROTO_ICMPV6 */
	u8 state_match; /* SFW_STATE_* */
	char in_dev[32];
	char out_dev[32];
	__be32 src_net;
	__be32 src_mask;
	__be32 dst_net;
	__be32 dst_mask;
	struct in6_addr src6_net;
	struct in6_addr dst6_net;
	u8 src6_plen;
	u8 dst6_plen;
	bool src_any;
	bool dst_any;
	u16 dport_min;
	u16 dport_max;
	u64 hit_pkts;
};

struct sfw_nat_rule {
	bool active;
	u16 family;     /* AF_INET or AF_INET6 */
	u8 nat_type;    /* SFW_NAT_DNAT, SFW_NAT_SNAT, SFW_NAT_MASQ */
	u8 proto;       /* 0 = all, IPPROTO_TCP, IPPROTO_UDP */
	char dev_match[32]; /* in_dev for DNAT, out_dev for SNAT/MASQ */
	__be32 match_net;
	__be32 match_mask;
	struct in6_addr match6_net;
	u8 match6_plen;
	bool match_any;
	u16 match_port; /* 0 = any */
	__be32 target_ip;   /* 0 for MASQ (selected dynamically from out_dev) */
	struct in6_addr target_ip6;
	u16 target_port;/* 0 = keep original port */
	u64 hit_flows;
};

struct sfw_tuple {
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
	u8 proto;
};

struct sfw_ct_entry {
	struct hlist_node orig_node;
	struct hlist_node reply_node;
	struct sfw_tuple orig;
	struct sfw_tuple reply;
	u8 nat_type;
	bool seen_reply;
	u64 pkts;
	u64 bytes;
	u64 updated_jiffies;
};

struct sfw_tuple6 {
	struct in6_addr saddr;
	struct in6_addr daddr;
	__be16 sport;
	__be16 dport;
	u8 proto;
};

struct sfw_ct6_entry {
	struct hlist_node orig_node;
	struct hlist_node reply_node;
	struct sfw_tuple6 orig;
	struct sfw_tuple6 reply;
	u8 nat_type;
	bool seen_reply;
	u64 pkts;
	u64 bytes;
	u64 updated_jiffies;
};

static DEFINE_SPINLOCK(sfw_pkt_lock);
static DEFINE_HASHTABLE(ct_orig_ht, 9);
static DEFINE_HASHTABLE(ct_reply_ht, 9);
static unsigned int ct_count;

static DEFINE_HASHTABLE(ct6_orig_ht, 9);
static DEFINE_HASHTABLE(ct6_reply_ht, 9);
static unsigned int ct6_count;

static struct sfw_chain_rule chain_rules[SFW_MAX_CHAIN_RULES];
static unsigned int chain_rule_cnt;
static bool default_input_drop;
module_param(default_input_drop, bool, 0444);
MODULE_PARM_DESC(default_input_drop,
		 "Initialize INPUT chain default policy to DROP (loopback still permitted)");

static bool router_protected_forwarding;
module_param(router_protected_forwarding, bool, 0444);
MODULE_PARM_DESC(router_protected_forwarding,
		 "Restrict initial-namespace forwarding to the inner0 and lan0 pair");

static bool router_forward_path_allowed(const struct net_device *in_dev,
					const struct net_device *out_dev)
{
	if (!in_dev || !out_dev)
		return false;
	return (!strcmp(in_dev->name, "inner0") && !strcmp(out_dev->name, "lan0")) ||
	       (!strcmp(in_dev->name, "lan0") && !strcmp(out_dev->name, "inner0"));
}

static u8 chain_default_policy[SFW_CHAIN_MAX] = {
	[SFW_CHAIN_PREROUTING]  = 1, /* ACCEPT */
	[SFW_CHAIN_INPUT]       = 1, /* ACCEPT (or DROP if default_input_drop=1) */
	[SFW_CHAIN_FORWARD]     = 0, /* DROP (fail-closed routing until policy loaded!) */
	[SFW_CHAIN_OUTPUT]      = 1, /* ACCEPT */
	[SFW_CHAIN_POSTROUTING] = 1, /* ACCEPT */
};

static struct sfw_nat_rule nat_rules[SFW_MAX_NAT_RULES];
static unsigned int nat_rule_cnt;

static atomic64_t sfw_policy_gen = ATOMIC64_INIT(0);
static DEFINE_MUTEX(sfw_txn_lock);
static bool sfw_txn_active;
static bool sfw_txn_prepared;
static bool sfw_txn_degraded;
static pid_t sfw_txn_owner_pid;

struct sfw_pkt_txn_snap {
	u8 default_policy_bak[SFW_CHAIN_MAX];
	unsigned int chain_cnt_bak;
	struct sfw_chain_rule chain_bak[SFW_MAX_CHAIN_RULES];
	unsigned int nat_cnt_bak;
	struct sfw_nat_rule nat_bak[SFW_MAX_NAT_RULES];
};
static struct sfw_pkt_txn_snap *g_sfw_snap;

static atomic64_t pkt_accepted[SFW_CHAIN_MAX];
static atomic64_t pkt_dropped[SFW_CHAIN_MAX];
static atomic64_t nat_translations = ATOMIC64_INIT(0);

static struct proc_dir_entry *sfw_proc_dir;

static const char *chain_name(u8 c)
{
	switch (c) {
	case SFW_CHAIN_PREROUTING:  return "prerouting";
	case SFW_CHAIN_INPUT:       return "input";
	case SFW_CHAIN_FORWARD:     return "forward";
	case SFW_CHAIN_OUTPUT:      return "output";
	case SFW_CHAIN_POSTROUTING: return "postrouting";
	default:                    return "unknown";
	}
}

static bool v6_prefix_match(const struct in6_addr *addr,
			    const struct in6_addr *net, u8 plen, bool any)
{
	if (any || plen == 0)
		return true;
	if (plen > 128)
		plen = 128;
	return ipv6_addr_diff(addr, net) >= (int)plen;
}

static u32 hash_tuple(const struct sfw_tuple *t)
{
	/*
	 * Key buckets on (proto, saddr, sport) so a packet stays in the exact
	 * same hash bucket both before and after PREROUTING daddr:dport NAT!
	 */
	return jhash_2words((__force u32)t->saddr,
			    ((u32)(__force u16)t->sport << 16) | t->proto, 0);
}

static u32 hash_tuple6(const struct sfw_tuple6 *t)
{
	return jhash2((__force const u32 *)t->saddr.s6_addr32, 4,
		      ((u32)(__force u16)t->sport << 16) | t->proto);
}

static bool orig_tuple_matches(const struct sfw_ct_entry *ct,
			       const struct sfw_tuple *t)
{
	if (t->proto != ct->orig.proto || t->saddr != ct->orig.saddr ||
	    t->sport != ct->orig.sport)
		return false;
	if (t->daddr == ct->orig.daddr && t->dport == ct->orig.dport)
		return true;
	/* Post-PREROUTING DNAT tuple */
	if (ct->nat_type == SFW_NAT_DNAT &&
	    t->daddr == ct->reply.saddr && t->dport == ct->reply.sport)
		return true;
	return false;
}

static bool reply_tuple_matches(const struct sfw_ct_entry *ct,
				const struct sfw_tuple *t)
{
	if (t->proto != ct->reply.proto || t->saddr != ct->reply.saddr ||
	    t->sport != ct->reply.sport)
		return false;
	if (t->daddr == ct->reply.daddr && t->dport == ct->reply.dport)
		return true;
	/* Post-PREROUTING reverse-SNAT/MASQUERADE tuple */
	if ((ct->nat_type == SFW_NAT_SNAT || ct->nat_type == SFW_NAT_MASQ) &&
	    t->daddr == ct->orig.saddr && t->dport == ct->orig.sport)
		return true;
	return false;
}

static bool orig_tuple6_matches(const struct sfw_ct6_entry *ct,
				const struct sfw_tuple6 *t)
{
	if (t->proto != ct->orig.proto ||
	    !ipv6_addr_equal(&t->saddr, &ct->orig.saddr) ||
	    t->sport != ct->orig.sport)
		return false;
	if (ipv6_addr_equal(&t->daddr, &ct->orig.daddr) &&
	    t->dport == ct->orig.dport)
		return true;
	if (ct->nat_type == SFW_NAT_DNAT &&
	    ipv6_addr_equal(&t->daddr, &ct->reply.saddr) &&
	    t->dport == ct->reply.sport)
		return true;
	return false;
}

static bool reply_tuple6_matches(const struct sfw_ct6_entry *ct,
				 const struct sfw_tuple6 *t)
{
	if (t->proto != ct->reply.proto ||
	    !ipv6_addr_equal(&t->saddr, &ct->reply.saddr) ||
	    t->sport != ct->reply.sport)
		return false;
	if (ipv6_addr_equal(&t->daddr, &ct->reply.daddr) &&
	    t->dport == ct->reply.dport)
		return true;
	if ((ct->nat_type == SFW_NAT_SNAT || ct->nat_type == SFW_NAT_MASQ) &&
	    ipv6_addr_equal(&t->daddr, &ct->orig.saddr) &&
	    t->dport == ct->orig.sport)
		return true;
	return false;
}

static bool dev_matches(const char *rule_dev, const struct net_device *dev)
{
	char dlbl[32];

	if (!rule_dev[0] || strcmp(rule_dev, "*") == 0)
		return true;
	if (!dev)
		return false;
	if (strcmp(rule_dev, dev->name) == 0)
		return true;
	if (pressure_lookup_netdev_label(dev->ifindex, dlbl) &&
	    strcmp(rule_dev, dlbl) == 0)
		return true;
	return false;
}

static bool extract_tuple(struct sk_buff *skb, struct sfw_tuple *t)
{
	const struct iphdr *iph;
	unsigned int ihl;

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		return false;
	iph = ip_hdr(skb);
	ihl = iph->ihl * 4;
	if (ihl < sizeof(struct iphdr) || !pskb_may_pull(skb, ihl))
		return false;

	iph = ip_hdr(skb);
	t->saddr = iph->saddr;
	t->daddr = iph->daddr;
	t->proto = iph->protocol;
	t->sport = 0;
	t->dport = 0;

	if (iph->protocol == IPPROTO_TCP) {
		const struct tcphdr *th;
		if (!pskb_may_pull(skb, ihl + sizeof(struct tcphdr)))
			return false;
		th = (const struct tcphdr *)((const u8 *)ip_hdr(skb) + ihl);
		t->sport = th->source;
		t->dport = th->dest;
	} else if (iph->protocol == IPPROTO_UDP) {
		const struct udphdr *uh;
		if (!pskb_may_pull(skb, ihl + sizeof(struct udphdr)))
			return false;
		uh = (const struct udphdr *)((const u8 *)ip_hdr(skb) + ihl);
		t->sport = uh->source;
		t->dport = uh->dest;
	} else if (iph->protocol == IPPROTO_ICMP) {
		const struct icmphdr *icmph;
		if (!pskb_may_pull(skb, ihl + sizeof(struct icmphdr)))
			return false;
		icmph = (const struct icmphdr *)((const u8 *)ip_hdr(skb) + ihl);
		t->sport = icmph->un.echo.id;
		t->dport = icmph->un.echo.id;
	}
	return true;
}

static bool extract_tuple6(struct sk_buff *skb, struct sfw_tuple6 *t,
			   unsigned int *l4_off_out, bool *is_ndp_bypass)
{
	const struct ipv6hdr *ip6h;
	unsigned int off = sizeof(struct ipv6hdr);
	u8 nexthdr;
	int ext_steps = 0;

	*is_ndp_bypass = false;
	if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
		return false;

	ip6h = ipv6_hdr(skb);
	t->saddr = ip6h->saddr;
	t->daddr = ip6h->daddr;
	nexthdr = ip6h->nexthdr;

	while ((nexthdr == NEXTHDR_HOP || nexthdr == NEXTHDR_ROUTING ||
		nexthdr == NEXTHDR_DEST) && ext_steps++ < 6) {
		const u8 *eh;
		unsigned int ehlen;

		if (!pskb_may_pull(skb, off + 2))
			return false;
		eh = (const u8 *)ipv6_hdr(skb) + off;
		nexthdr = eh[0];
		ehlen = ((unsigned int)eh[1] + 1) * 8;
		if (!pskb_may_pull(skb, off + ehlen))
			return false;
		off += ehlen;
	}

	t->proto = nexthdr;
	t->sport = 0;
	t->dport = 0;
	*l4_off_out = off;

	if (nexthdr == IPPROTO_TCP) {
		const struct tcphdr *th;
		if (!pskb_may_pull(skb, off + sizeof(struct tcphdr)))
			return false;
		th = (const struct tcphdr *)((const u8 *)ipv6_hdr(skb) + off);
		t->sport = th->source;
		t->dport = th->dest;
	} else if (nexthdr == IPPROTO_UDP) {
		const struct udphdr *uh;
		if (!pskb_may_pull(skb, off + sizeof(struct udphdr)))
			return false;
		uh = (const struct udphdr *)((const u8 *)ipv6_hdr(skb) + off);
		t->sport = uh->source;
		t->dport = uh->dest;
	} else if (nexthdr == IPPROTO_ICMPV6) {
		const struct icmp6hdr *icmp6h;
		if (!pskb_may_pull(skb, off + sizeof(struct icmp6hdr)))
			return false;
		icmp6h = (const struct icmp6hdr *)((const u8 *)ipv6_hdr(skb) + off);
		/*
		 * Permit L2 Neighbor Discovery (RS=133, RA=134, NS=135, NA=136)
		 * and MLDv1/v2 (130, 131, 132, 143) unconditionally so IPv6
		 * neighbor resolution works even under default DROP policies!
		 */
		if ((icmp6h->icmp6_type >= 130 && icmp6h->icmp6_type <= 136) ||
		    icmp6h->icmp6_type == 143) {
			*is_ndp_bypass = true;
			return true;
		}
		if (icmp6h->icmp6_type == ICMPV6_ECHO_REQUEST ||
		    icmp6h->icmp6_type == ICMPV6_ECHO_REPLY) {
			t->sport = icmp6h->icmp6_identifier;
			t->dport = icmp6h->icmp6_identifier;
		}
	}
	return true;
}

static int rewrite_ipv4_l4(struct sk_buff *skb, bool change_dst,
			   __be32 new_ip, __be16 new_port)
{
	struct iphdr *iph;
	unsigned int ihl, need_len;
	__be32 old_ip;

	iph = ip_hdr(skb);
	ihl = iph->ihl * 4;
	need_len = ihl;
	if (iph->protocol == IPPROTO_TCP)
		need_len += sizeof(struct tcphdr);
	else if (iph->protocol == IPPROTO_UDP)
		need_len += sizeof(struct udphdr);

	if (skb_ensure_writable(skb, need_len))
		return -ENOMEM;

	iph = ip_hdr(skb);
	old_ip = change_dst ? iph->daddr : iph->saddr;

	if (old_ip != new_ip) {
		csum_replace4(&iph->check, old_ip, new_ip);
		if (change_dst)
			iph->daddr = new_ip;
		else
			iph->saddr = new_ip;
	}

	if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr *th = (struct tcphdr *)((u8 *)iph + ihl);
		__be16 old_port = change_dst ? th->dest : th->source;

		if (old_ip != new_ip)
			inet_proto_csum_replace4(&th->check, skb, old_ip,
						 new_ip, true);
		if (new_port && old_port != new_port) {
			inet_proto_csum_replace2(&th->check, skb, old_port,
						 new_port, false);
			if (change_dst)
				th->dest = new_port;
			else
				th->source = new_port;
		}
	} else if (iph->protocol == IPPROTO_UDP) {
		struct udphdr *uh = (struct udphdr *)((u8 *)iph + ihl);
		__be16 old_port = change_dst ? uh->dest : uh->source;

		if (uh->check || skb->ip_summed == CHECKSUM_PARTIAL) {
			if (old_ip != new_ip)
				inet_proto_csum_replace4(&uh->check, skb,
							 old_ip, new_ip, true);
			if (new_port && old_port != new_port)
				inet_proto_csum_replace2(&uh->check, skb,
							 old_port, new_port,
							 false);
			if (uh->check == 0)
				uh->check = CSUM_MANGLED_0;
		}
		if (new_port && old_port != new_port) {
			if (change_dst)
				uh->dest = new_port;
			else
				uh->source = new_port;
		}
	}

	atomic64_inc(&nat_translations);
	return 0;
}

static int rewrite_ipv6_l4(struct sk_buff *skb, unsigned int l4_off,
			   u8 l4_proto, bool change_dst,
			   const struct in6_addr *new_ip6, __be16 new_port)
{
	struct ipv6hdr *ip6h;
	unsigned int need_len = l4_off;
	struct in6_addr old_ip6;
	bool ip_changed;

	if (l4_proto == IPPROTO_TCP)
		need_len += sizeof(struct tcphdr);
	else if (l4_proto == IPPROTO_UDP)
		need_len += sizeof(struct udphdr);
	else if (l4_proto == IPPROTO_ICMPV6)
		need_len += sizeof(struct icmp6hdr);

	if (skb_ensure_writable(skb, need_len))
		return -ENOMEM;

	ip6h = ipv6_hdr(skb);
	old_ip6 = change_dst ? ip6h->daddr : ip6h->saddr;
	ip_changed = !ipv6_addr_equal(&old_ip6, new_ip6);

	if (ip_changed) {
		if (change_dst)
			ip6h->daddr = *new_ip6;
		else
			ip6h->saddr = *new_ip6;
	}

	if (l4_proto == IPPROTO_TCP) {
		struct tcphdr *th = (struct tcphdr *)((u8 *)ip6h + l4_off);
		__be16 old_port = change_dst ? th->dest : th->source;

		if (ip_changed)
			inet_proto_csum_replace16(&th->check, skb,
						  old_ip6.s6_addr32,
						  new_ip6->s6_addr32, true);
		if (new_port && old_port != new_port) {
			inet_proto_csum_replace2(&th->check, skb, old_port,
						 new_port, false);
			if (change_dst)
				th->dest = new_port;
			else
				th->source = new_port;
		}
	} else if (l4_proto == IPPROTO_UDP) {
		struct udphdr *uh = (struct udphdr *)((u8 *)ip6h + l4_off);
		__be16 old_port = change_dst ? uh->dest : uh->source;

		if (uh->check || skb->ip_summed == CHECKSUM_PARTIAL) {
			if (ip_changed)
				inet_proto_csum_replace16(&uh->check, skb,
							  old_ip6.s6_addr32,
							  new_ip6->s6_addr32,
							  true);
			if (new_port && old_port != new_port)
				inet_proto_csum_replace2(&uh->check, skb,
							 old_port, new_port,
							 false);
			if (uh->check == 0)
				uh->check = CSUM_MANGLED_0;
		}
		if (new_port && old_port != new_port) {
			if (change_dst)
				uh->dest = new_port;
			else
				uh->source = new_port;
		}
	} else if (l4_proto == IPPROTO_ICMPV6 && ip_changed) {
		struct icmp6hdr *icmp6h =
			(struct icmp6hdr *)((u8 *)ip6h + l4_off);
		inet_proto_csum_replace16(&icmp6h->icmp6_cksum, skb,
					  old_ip6.s6_addr32,
					  new_ip6->s6_addr32, true);
	}

	atomic64_inc(&nat_translations);
	return 0;
}

/* Re-route locally-generated packet if OUTPUT DNAT altered iph->daddr */
static int reroute_output_skb(struct net *net, struct sock *sk,
			      struct sk_buff *skb)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct flowi4 fl4 = {};
	struct rtable *rt;

	fl4.daddr = iph->daddr;
	fl4.saddr = iph->saddr;
	fl4.flowi4_oif = sk ? sk->sk_bound_dev_if : 0;
	fl4.flowi4_proto = iph->protocol;

	rt = ip_route_output_key(net, &fl4);
	if (IS_ERR(rt))
		return PTR_ERR(rt);

	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->dst);
	return 0;
}

static int reroute_output_skb6(struct net *net, struct sock *sk,
			       struct sk_buff *skb, u8 l4_proto)
{
	const struct ipv6hdr *ip6h = ipv6_hdr(skb);
	struct flowi6 fl6 = {};
	struct dst_entry *dst;

	fl6.daddr = ip6h->daddr;
	fl6.saddr = ip6h->saddr;
	fl6.flowi6_oif = sk ? sk->sk_bound_dev_if : 0;
	fl6.flowi6_proto = l4_proto;

	dst = ip6_route_output(net, sk, &fl6);
	if (dst->error) {
		int err = dst->error;
		dst_release(dst);
		return err;
	}

	skb_dst_drop(skb);
	skb_dst_set(skb, dst);
	return 0;
}

static struct sfw_ct_entry *lookup_ct_locked(const struct sfw_tuple *t,
					     bool *is_reply)
{
	struct sfw_ct_entry *ct;
	struct hlist_node *tmp;
	u64 now = get_jiffies_64();

	hash_for_each_possible_safe(ct_orig_ht, ct, tmp, orig_node,
				    hash_tuple(t)) {
		if (time_after64(now, ct->updated_jiffies + SFW_CT_TIMEOUT_JIFFIES)) {
			hash_del(&ct->orig_node);
			hash_del(&ct->reply_node);
			kfree(ct);
			ct_count--;
			continue;
		}
		if (orig_tuple_matches(ct, t)) {
			*is_reply = false;
			return ct;
		}
	}

	hash_for_each_possible_safe(ct_reply_ht, ct, tmp, reply_node,
				    hash_tuple(t)) {
		if (reply_tuple_matches(ct, t)) {
			*is_reply = true;
			return ct;
		}
	}
	return NULL;
}

static struct sfw_ct_entry *create_ct_locked(const struct sfw_tuple *orig,
					     const struct sfw_tuple *reply,
					     u8 nat_type)
{
	struct sfw_ct_entry *ct;

	if (ct_count >= SFW_MAX_CT_ENTRIES)
		return NULL;
	ct = kzalloc(sizeof(*ct), GFP_ATOMIC);
	if (!ct)
		return NULL;
	ct->orig = *orig;
	ct->reply = *reply;
	ct->nat_type = nat_type;
	ct->updated_jiffies = get_jiffies_64();
	hash_add(ct_orig_ht, &ct->orig_node, hash_tuple(&ct->orig));
	hash_add(ct_reply_ht, &ct->reply_node, hash_tuple(&ct->reply));
	ct_count++;
	return ct;
}

static struct sfw_ct6_entry *lookup_ct6_locked(const struct sfw_tuple6 *t,
					       bool *is_reply)
{
	struct sfw_ct6_entry *ct;
	struct hlist_node *tmp;
	u64 now = get_jiffies_64();

	hash_for_each_possible_safe(ct6_orig_ht, ct, tmp, orig_node,
				    hash_tuple6(t)) {
		if (time_after64(now, ct->updated_jiffies + SFW_CT_TIMEOUT_JIFFIES)) {
			hash_del(&ct->orig_node);
			hash_del(&ct->reply_node);
			kfree(ct);
			ct6_count--;
			continue;
		}
		if (orig_tuple6_matches(ct, t)) {
			*is_reply = false;
			return ct;
		}
	}

	hash_for_each_possible_safe(ct6_reply_ht, ct, tmp, reply_node,
				    hash_tuple6(t)) {
		if (reply_tuple6_matches(ct, t)) {
			*is_reply = true;
			return ct;
		}
	}
	return NULL;
}

static struct sfw_ct6_entry *create_ct6_locked(const struct sfw_tuple6 *orig,
					       const struct sfw_tuple6 *reply,
					       u8 nat_type)
{
	struct sfw_ct6_entry *ct;

	if (ct6_count >= SFW_MAX_CT_ENTRIES)
		return NULL;
	ct = kzalloc(sizeof(*ct), GFP_ATOMIC);
	if (!ct)
		return NULL;
	ct->orig = *orig;
	ct->reply = *reply;
	ct->nat_type = nat_type;
	ct->updated_jiffies = get_jiffies_64();
	hash_add(ct6_orig_ht, &ct->orig_node, hash_tuple6(&ct->orig));
	hash_add(ct6_reply_ht, &ct->reply_node, hash_tuple6(&ct->reply));
	ct6_count++;
	return ct;
}

static bool eval_chain_locked(u8 chain, const struct sfw_tuple *t,
			      const struct net_device *in_dev,
			      const struct net_device *out_dev,
			      bool is_established)
{
	unsigned int i;
	u16 dport = ntohs(t->dport);

	for (i = 0; i < chain_rule_cnt; i++) {
		struct sfw_chain_rule *r = &chain_rules[i];

		if (!r->active || r->chain != chain)
			continue;
		if (r->family != 0 && r->family != AF_INET)
			continue;
		if (r->proto != 0 && r->proto != t->proto)
			continue;
		if (r->state_match == SFW_STATE_ESTABLISHED && !is_established)
			continue;
		if (r->state_match == SFW_STATE_NEW && is_established)
			continue;
		if (!dev_matches(r->in_dev, in_dev) ||
		    !dev_matches(r->out_dev, out_dev))
			continue;
		if (!r->src_any &&
		    (t->saddr & r->src_mask) != (r->src_net & r->src_mask))
			continue;
		if (!r->dst_any &&
		    (t->daddr & r->dst_mask) != (r->dst_net & r->dst_mask))
			continue;
		if (r->dport_max != 0 &&
		    (dport < r->dport_min || dport > r->dport_max))
			continue;

		r->hit_pkts++;
		return r->action != 0;
	}
	if (chain == SFW_CHAIN_INPUT && in_dev && (in_dev->flags & IFF_LOOPBACK))
		return true;
	return chain_default_policy[chain] != 0;
}

static bool eval_chain6_locked(u8 chain, const struct sfw_tuple6 *t,
			       const struct net_device *in_dev,
			       const struct net_device *out_dev,
			       bool is_established)
{
	unsigned int i;
	u16 dport = ntohs(t->dport);

	for (i = 0; i < chain_rule_cnt; i++) {
		struct sfw_chain_rule *r = &chain_rules[i];

		if (!r->active || r->chain != chain)
			continue;
		if (r->family != 0 && r->family != AF_INET6)
			continue;
		if (r->proto != 0 && r->proto != t->proto &&
		    !(r->proto == IPPROTO_ICMP && t->proto == IPPROTO_ICMPV6))
			continue;
		if (r->state_match == SFW_STATE_ESTABLISHED && !is_established)
			continue;
		if (r->state_match == SFW_STATE_NEW && is_established)
			continue;
		if (!dev_matches(r->in_dev, in_dev) ||
		    !dev_matches(r->out_dev, out_dev))
			continue;
		if (!v6_prefix_match(&t->saddr, &r->src6_net, r->src6_plen,
				     r->src_any))
			continue;
		if (!v6_prefix_match(&t->daddr, &r->dst6_net, r->dst6_plen,
				     r->dst_any))
			continue;
		if (r->dport_max != 0 &&
		    (dport < r->dport_min || dport > r->dport_max))
			continue;

		r->hit_pkts++;
		return r->action != 0;
	}
	if (chain == SFW_CHAIN_INPUT && in_dev && (in_dev->flags & IFF_LOOPBACK))
		return true;
	return chain_default_policy[chain] != 0;
}

/* Permit stateful replies only for an accepted TCP connection opener. */
static bool incoming_tcp_syn(struct sk_buff *skb, unsigned int offset, u8 proto)
{
	struct tcphdr header;
	const struct tcphdr *tcp;

	if (proto != IPPROTO_TCP)
		return false;
	tcp = skb_header_pointer(skb, offset, sizeof(header), &header);
	return tcp && tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst;
}

static int sfw_ipv4_pkt_hook(unsigned int chain, struct net *net,
			     struct sock *sk, struct sk_buff *skb,
			     struct net_device *in_dev,
			     struct net_device *out_dev)
{
	struct sfw_tuple tup;
	struct sfw_ct_entry *ct;
	unsigned long flags;
	bool is_reply = false;
	bool is_est = false;
	bool do_rewrite = false;
	bool rw_dst = false;
	__be32 rw_ip = 0;
	__be16 rw_port = 0;
	bool reroute = false;
	bool verdict = true;

	/* Operate on the primary router namespace (&init_net) */
	if (net != &init_net || chain >= SFW_CHAIN_MAX)
		return 0;

	/* Keep the physical WAN outside the forwarding path even after policy reloads. */
	if (router_protected_forwarding && chain == SFW_CHAIN_FORWARD &&
	    !router_forward_path_allowed(in_dev, out_dev)) {
		atomic64_inc(&pkt_dropped[chain]);
		return -EPERM;
	}

	if (!extract_tuple(skb, &tup))
		return 0;

	spin_lock_irqsave(&sfw_pkt_lock, flags);
	ct = lookup_ct_locked(&tup, &is_reply);
	if (ct) {
		if (is_reply)
			ct->seen_reply = true;
		is_est = is_reply || ct->seen_reply;
		ct->pkts++;
		ct->bytes += skb->len;
		ct->updated_jiffies = get_jiffies_64();
	}

	if (chain == SFW_CHAIN_PREROUTING) {
		if (ct && is_reply &&
		    (ct->nat_type == SFW_NAT_SNAT || ct->nat_type == SFW_NAT_MASQ)) {
			/* Reverse-SNAT/Masquerade on inbound reply BEFORE routing! */
			do_rewrite = true;
			rw_dst = true;
			rw_ip = ct->orig.saddr;
			rw_port = ct->orig.sport;
		} else if (ct && !is_reply && ct->nat_type == SFW_NAT_DNAT) {
			/* Subsequent packet on existing DNAT flow */
			do_rewrite = true;
			rw_dst = true;
			rw_ip = ct->reply.saddr;
			rw_port = ct->reply.sport;
		} else if (!ct) {
			/* Check live DNAT / Port-Forward rules */
			unsigned int i;
			u16 dport = ntohs(tup.dport);
			for (i = 0; i < nat_rule_cnt; i++) {
				struct sfw_nat_rule *nr = &nat_rules[i];
				if (!nr->active || nr->family != AF_INET ||
				    nr->nat_type != SFW_NAT_DNAT)
					continue;
				if (nr->proto != 0 && nr->proto != tup.proto)
					continue;
				if (!dev_matches(nr->dev_match, in_dev))
					continue;
				if (!nr->match_any &&
				    (tup.daddr & nr->match_mask) !=
				    (nr->match_net & nr->match_mask))
					continue;
				if (nr->match_port != 0 && nr->match_port != dport)
					continue;

				rw_ip = nr->target_ip;
				rw_port = nr->target_port ?
					  htons(nr->target_port) : tup.dport;
				struct sfw_tuple rep = {
					.saddr = rw_ip,
					.daddr = tup.saddr,
					.sport = rw_port,
					.dport = tup.sport,
					.proto = tup.proto,
				};
				ct = create_ct_locked(&tup, &rep, SFW_NAT_DNAT);
				if (ct) {
					ct->pkts = 1;
					ct->bytes = skb->len;
					nr->hit_flows++;
					do_rewrite = true;
					rw_dst = true;
				}
				break;
			}
		}
	}

	/* Evaluate chain filter rules using current skb header fields (post-PREROUTING DNAT!) */
	if (do_rewrite && chain == SFW_CHAIN_PREROUTING) {
		if (rewrite_ipv4_l4(skb, rw_dst, rw_ip, rw_port) < 0) {
			spin_unlock_irqrestore(&sfw_pkt_lock, flags);
			atomic64_inc(&pkt_dropped[chain]);
			return -ENOMEM;
		}
		tup.daddr = rw_ip;
		if (rw_port)
			tup.dport = rw_port;
		do_rewrite = false;
	}

	verdict = eval_chain_locked((u8)chain, &tup, in_dev, out_dev, is_est);
	if (!verdict) {
		spin_unlock_irqrestore(&sfw_pkt_lock, flags);
		atomic64_inc(&pkt_dropped[chain]);
		return -EPERM;
	}

	/* Track permitted forwarding and local traffic for stateful replies. */
	if (!ct && (chain == SFW_CHAIN_FORWARD || chain == SFW_CHAIN_OUTPUT ||
		    (chain == SFW_CHAIN_INPUT &&
		     incoming_tcp_syn(skb, skb_network_offset(skb) + ip_hdrlen(skb),
				      tup.proto)))) {
		struct sfw_tuple rep = {
			.saddr = tup.daddr,
			.daddr = tup.saddr,
			.sport = tup.dport,
			.dport = tup.sport,
			.proto = tup.proto,
		};
		ct = create_ct_locked(&tup, &rep, SFW_NAT_NONE);
		if (ct) {
			ct->pkts = 1;
			ct->bytes = skb->len;
		}
	}

	if (chain == SFW_CHAIN_OUTPUT && !is_reply) {
		/* Check local OUTPUT DNAT rules */
		unsigned int i;
		u16 dport = ntohs(tup.dport);
		for (i = 0; i < nat_rule_cnt; i++) {
			struct sfw_nat_rule *nr = &nat_rules[i];
			if (!nr->active || nr->family != AF_INET ||
			    nr->nat_type != SFW_NAT_DNAT)
				continue;
			if (nr->proto != 0 && nr->proto != tup.proto)
				continue;
			if (nr->dev_match[0] && strcmp(nr->dev_match, "*") != 0 &&
			    strcmp(nr->dev_match, "local") != 0)
				continue;
			if (!nr->match_any &&
			    (tup.daddr & nr->match_mask) !=
			    (nr->match_net & nr->match_mask))
				continue;
			if (nr->match_port != 0 && nr->match_port != dport)
				continue;

			rw_ip = nr->target_ip;
			rw_port = nr->target_port ? htons(nr->target_port) : tup.dport;
			if (ct && ct->nat_type == SFW_NAT_NONE) {
				hash_del(&ct->reply_node);
				ct->reply.saddr = rw_ip;
				ct->reply.sport = rw_port;
				ct->nat_type = SFW_NAT_DNAT;
				hash_add(ct_reply_ht, &ct->reply_node,
					 hash_tuple(&ct->reply));
			}
			nr->hit_flows++;
			do_rewrite = true;
			rw_dst = true;
			reroute = true;
			break;
		}
	}

	if (chain == SFW_CHAIN_POSTROUTING) {
		if (ct && is_reply && ct->nat_type == SFW_NAT_DNAT) {
			/* Reverse-DNAT on outbound reply to external client! */
			do_rewrite = true;
			rw_dst = false;
			rw_ip = ct->orig.daddr;
			rw_port = ct->orig.dport;
		} else if (ct && !is_reply &&
			   (ct->nat_type == SFW_NAT_SNAT ||
			    ct->nat_type == SFW_NAT_MASQ)) {
			/* Subsequent packet on existing SNAT/Masquerade flow */
			do_rewrite = true;
			rw_dst = false;
			rw_ip = ct->reply.daddr;
			rw_port = ct->reply.dport;
		} else if (!is_reply && (!ct || ct->nat_type == SFW_NAT_NONE)) {
			/* Check live SNAT / MASQUERADE rules */
			unsigned int i;
			for (i = 0; i < nat_rule_cnt; i++) {
				struct sfw_nat_rule *nr = &nat_rules[i];
				__be32 new_src;

				if (!nr->active || nr->family != AF_INET ||
				    (nr->nat_type != SFW_NAT_SNAT &&
				     nr->nat_type != SFW_NAT_MASQ))
					continue;
				if (nr->proto != 0 && nr->proto != tup.proto)
					continue;
				if (!dev_matches(nr->dev_match, out_dev))
					continue;
				if (!nr->match_any &&
				    (tup.saddr & nr->match_mask) !=
				    (nr->match_net & nr->match_mask))
					continue;

				new_src = (nr->nat_type == SFW_NAT_MASQ && out_dev) ?
					  inet_select_addr(out_dev, tup.daddr,
							   RT_SCOPE_UNIVERSE) :
					  nr->target_ip;
				if (!new_src)
					continue;

				if (!ct) {
					struct sfw_tuple rep = {
						.saddr = tup.daddr,
						.daddr = new_src,
						.sport = tup.dport,
						.dport = tup.sport,
						.proto = tup.proto,
					};
					ct = create_ct_locked(&tup, &rep,
							      nr->nat_type);
				} else {
					hash_del(&ct->reply_node);
					ct->reply.daddr = new_src;
					ct->nat_type = nr->nat_type;
					hash_add(ct_reply_ht, &ct->reply_node,
						 hash_tuple(&ct->reply));
				}
				nr->hit_flows++;
				do_rewrite = true;
				rw_dst = false;
				rw_ip = new_src;
				rw_port = tup.sport;
				break;
			}
		}
	}
	spin_unlock_irqrestore(&sfw_pkt_lock, flags);

	if (do_rewrite) {
		if (rewrite_ipv4_l4(skb, rw_dst, rw_ip, rw_port) < 0) {
			atomic64_inc(&pkt_dropped[chain]);
			return -ENOMEM;
		}
		if (reroute && reroute_output_skb(net, sk, skb) < 0) {
			atomic64_inc(&pkt_dropped[chain]);
			return -EHOSTUNREACH;
		}
	}

	atomic64_inc(&pkt_accepted[chain]);
	return 0;
}

static int sfw_ipv6_pkt_hook(unsigned int chain, struct net *net,
			     struct sock *sk, struct sk_buff *skb,
			     struct net_device *in_dev,
			     struct net_device *out_dev)
{
	struct sfw_tuple6 tup;
	struct sfw_ct6_entry *ct;
	unsigned int l4_off = sizeof(struct ipv6hdr);
	unsigned long flags;
	bool ndp_bypass = false;
	bool is_reply = false;
	bool is_est = false;
	bool do_rewrite = false;
	bool rw_dst = false;
	struct in6_addr rw_ip6 = {};
	__be16 rw_port = 0;
	bool reroute = false;
	bool verdict = true;

	if (net != &init_net || chain >= SFW_CHAIN_MAX)
		return 0;

	/* Keep the physical WAN outside the forwarding path even after policy reloads. */
	if (router_protected_forwarding && chain == SFW_CHAIN_FORWARD &&
	    !router_forward_path_allowed(in_dev, out_dev)) {
		atomic64_inc(&pkt_dropped[chain]);
		return -EPERM;
	}

	if (!extract_tuple6(skb, &tup, &l4_off, &ndp_bypass))
		return 0;

	if (ndp_bypass) {
		atomic64_inc(&pkt_accepted[chain]);
		return 0;
	}

	spin_lock_irqsave(&sfw_pkt_lock, flags);
	ct = lookup_ct6_locked(&tup, &is_reply);
	if (ct) {
		if (is_reply)
			ct->seen_reply = true;
		is_est = is_reply || ct->seen_reply;
		ct->pkts++;
		ct->bytes += skb->len;
		ct->updated_jiffies = get_jiffies_64();
	}

	if (chain == SFW_CHAIN_PREROUTING) {
		if (ct && is_reply &&
		    (ct->nat_type == SFW_NAT_SNAT || ct->nat_type == SFW_NAT_MASQ)) {
			do_rewrite = true;
			rw_dst = true;
			rw_ip6 = ct->orig.saddr;
			rw_port = ct->orig.sport;
		} else if (ct && !is_reply && ct->nat_type == SFW_NAT_DNAT) {
			do_rewrite = true;
			rw_dst = true;
			rw_ip6 = ct->reply.saddr;
			rw_port = ct->reply.sport;
		} else if (!ct) {
			unsigned int i;
			u16 dport = ntohs(tup.dport);
			for (i = 0; i < nat_rule_cnt; i++) {
				struct sfw_nat_rule *nr = &nat_rules[i];
				if (!nr->active || nr->family != AF_INET6 ||
				    nr->nat_type != SFW_NAT_DNAT)
					continue;
				if (nr->proto != 0 && nr->proto != tup.proto)
					continue;
				if (!dev_matches(nr->dev_match, in_dev))
					continue;
				if (!v6_prefix_match(&tup.daddr, &nr->match6_net,
						     nr->match6_plen,
						     nr->match_any))
					continue;
				if (nr->match_port != 0 && nr->match_port != dport)
					continue;

				rw_ip6 = nr->target_ip6;
				rw_port = nr->target_port ?
					  htons(nr->target_port) : tup.dport;
				struct sfw_tuple6 rep = {
					.saddr = rw_ip6,
					.daddr = tup.saddr,
					.sport = rw_port,
					.dport = tup.sport,
					.proto = tup.proto,
				};
				ct = create_ct6_locked(&tup, &rep, SFW_NAT_DNAT);
				if (ct) {
					ct->pkts = 1;
					ct->bytes = skb->len;
					nr->hit_flows++;
					do_rewrite = true;
					rw_dst = true;
				}
				break;
			}
		}
	}

	if (do_rewrite && chain == SFW_CHAIN_PREROUTING) {
		if (rewrite_ipv6_l4(skb, l4_off, tup.proto, rw_dst, &rw_ip6,
				    rw_port) < 0) {
			spin_unlock_irqrestore(&sfw_pkt_lock, flags);
			atomic64_inc(&pkt_dropped[chain]);
			return -ENOMEM;
		}
		tup.daddr = rw_ip6;
		if (rw_port)
			tup.dport = rw_port;
		do_rewrite = false;
	}

	verdict = eval_chain6_locked((u8)chain, &tup, in_dev, out_dev, is_est);
	if (!verdict) {
		spin_unlock_irqrestore(&sfw_pkt_lock, flags);
		atomic64_inc(&pkt_dropped[chain]);
		return -EPERM;
	}

	if (!ct && (chain == SFW_CHAIN_FORWARD || chain == SFW_CHAIN_OUTPUT ||
		    (chain == SFW_CHAIN_INPUT &&
		     incoming_tcp_syn(skb, skb_network_offset(skb) + l4_off,
				      tup.proto)))) {
		struct sfw_tuple6 rep = {
			.saddr = tup.daddr,
			.daddr = tup.saddr,
			.sport = tup.dport,
			.dport = tup.sport,
			.proto = tup.proto,
		};
		ct = create_ct6_locked(&tup, &rep, SFW_NAT_NONE);
		if (ct) {
			ct->pkts = 1;
			ct->bytes = skb->len;
		}
	}

	if (chain == SFW_CHAIN_OUTPUT && !is_reply) {
		unsigned int i;
		u16 dport = ntohs(tup.dport);
		for (i = 0; i < nat_rule_cnt; i++) {
			struct sfw_nat_rule *nr = &nat_rules[i];
			if (!nr->active || nr->family != AF_INET6 ||
			    nr->nat_type != SFW_NAT_DNAT)
				continue;
			if (nr->proto != 0 && nr->proto != tup.proto)
				continue;
			if (nr->dev_match[0] && strcmp(nr->dev_match, "*") != 0 &&
			    strcmp(nr->dev_match, "local") != 0)
				continue;
			if (!v6_prefix_match(&tup.daddr, &nr->match6_net,
					     nr->match6_plen, nr->match_any))
				continue;
			if (nr->match_port != 0 && nr->match_port != dport)
				continue;

			rw_ip6 = nr->target_ip6;
			rw_port = nr->target_port ? htons(nr->target_port) : tup.dport;
			if (ct && ct->nat_type == SFW_NAT_NONE) {
				hash_del(&ct->reply_node);
				ct->reply.saddr = rw_ip6;
				ct->reply.sport = rw_port;
				ct->nat_type = SFW_NAT_DNAT;
				hash_add(ct6_reply_ht, &ct->reply_node,
					 hash_tuple6(&ct->reply));
			}
			nr->hit_flows++;
			do_rewrite = true;
			rw_dst = true;
			reroute = true;
			break;
		}
	}

	if (chain == SFW_CHAIN_POSTROUTING) {
		if (ct && is_reply && ct->nat_type == SFW_NAT_DNAT) {
			do_rewrite = true;
			rw_dst = false;
			rw_ip6 = ct->orig.daddr;
			rw_port = ct->orig.dport;
		} else if (ct && !is_reply &&
			   (ct->nat_type == SFW_NAT_SNAT ||
			    ct->nat_type == SFW_NAT_MASQ)) {
			do_rewrite = true;
			rw_dst = false;
			rw_ip6 = ct->reply.daddr;
			rw_port = ct->reply.dport;
		} else if (!is_reply && (!ct || ct->nat_type == SFW_NAT_NONE)) {
			unsigned int i;
			for (i = 0; i < nat_rule_cnt; i++) {
				struct sfw_nat_rule *nr = &nat_rules[i];
				struct in6_addr new_src6 = {};

				if (!nr->active || nr->family != AF_INET6 ||
				    (nr->nat_type != SFW_NAT_SNAT &&
				     nr->nat_type != SFW_NAT_MASQ))
					continue;
				if (nr->proto != 0 && nr->proto != tup.proto &&
				    !(nr->proto == IPPROTO_ICMP &&
				      tup.proto == IPPROTO_ICMPV6))
					continue;
				if (!dev_matches(nr->dev_match, out_dev))
					continue;
				if (!v6_prefix_match(&tup.saddr, &nr->match6_net,
						     nr->match6_plen,
						     nr->match_any))
					continue;

				if (nr->nat_type == SFW_NAT_MASQ) {
					if (!out_dev ||
					    ipv6_dev_get_saddr(net, out_dev,
							       &tup.daddr, 0,
							       &new_src6) < 0)
						continue;
				} else {
					new_src6 = nr->target_ip6;
				}
				if (ipv6_addr_any(&new_src6))
					continue;

				if (!ct) {
					struct sfw_tuple6 rep = {
						.saddr = tup.daddr,
						.daddr = new_src6,
						.sport = tup.dport,
						.dport = tup.sport,
						.proto = tup.proto,
					};
					ct = create_ct6_locked(&tup, &rep,
							       nr->nat_type);
				} else {
					hash_del(&ct->reply_node);
					ct->reply.daddr = new_src6;
					ct->nat_type = nr->nat_type;
					hash_add(ct6_reply_ht, &ct->reply_node,
						 hash_tuple6(&ct->reply));
				}
				nr->hit_flows++;
				do_rewrite = true;
				rw_dst = false;
				rw_ip6 = new_src6;
				rw_port = tup.sport;
				break;
			}
		}
	}
	spin_unlock_irqrestore(&sfw_pkt_lock, flags);

	if (do_rewrite) {
		if (rewrite_ipv6_l4(skb, l4_off, tup.proto, rw_dst, &rw_ip6,
				    rw_port) < 0) {
			atomic64_inc(&pkt_dropped[chain]);
			return -ENOMEM;
		}
		if (reroute && reroute_output_skb6(net, sk, skb, tup.proto) < 0) {
			atomic64_inc(&pkt_dropped[chain]);
			return -EHOSTUNREACH;
		}
	}

	atomic64_inc(&pkt_accepted[chain]);
	return 0;
}

/* Honor live IPv4/IPv6 DNAT rules inside the AF_UNIX socket broker for local apps */
void sfw_apply_broker_dnat(__be32 *dst_ip, __be16 *dst_port, const char *ifname)
{
	unsigned long flags;
	unsigned int i;
	u16 dport = ntohs(*dst_port);

	spin_lock_irqsave(&sfw_pkt_lock, flags);
	for (i = 0; i < nat_rule_cnt; i++) {
		struct sfw_nat_rule *nr = &nat_rules[i];
		if (!nr->active || nr->family != AF_INET ||
		    nr->nat_type != SFW_NAT_DNAT)
			continue;
		if (nr->dev_match[0] && strcmp(nr->dev_match, "*") != 0 &&
		    (!ifname || strcmp(nr->dev_match, ifname) != 0))
			continue;
		if (!nr->match_any &&
		    (*dst_ip & nr->match_mask) != (nr->match_net & nr->match_mask))
			continue;
		if (nr->match_port != 0 && nr->match_port != dport)
			continue;
		*dst_ip = nr->target_ip;
		if (nr->target_port)
			*dst_port = htons(nr->target_port);
		nr->hit_flows++;
		atomic64_inc(&nat_translations);
		break;
	}
	spin_unlock_irqrestore(&sfw_pkt_lock, flags);
}

void sfw_apply_broker_dnat6(struct in6_addr *dst_ip6, __be16 *dst_port,
			    const char *ifname)
{
	unsigned long flags;
	unsigned int i;
	u16 dport = ntohs(*dst_port);

	spin_lock_irqsave(&sfw_pkt_lock, flags);
	for (i = 0; i < nat_rule_cnt; i++) {
		struct sfw_nat_rule *nr = &nat_rules[i];
		if (!nr->active || nr->family != AF_INET6 ||
		    nr->nat_type != SFW_NAT_DNAT)
			continue;
		if (nr->dev_match[0] && strcmp(nr->dev_match, "*") != 0 &&
		    (!ifname || strcmp(nr->dev_match, ifname) != 0))
			continue;
		if (!v6_prefix_match(dst_ip6, &nr->match6_net, nr->match6_plen,
				     nr->match_any))
			continue;
		if (nr->match_port != 0 && nr->match_port != dport)
			continue;
		*dst_ip6 = nr->target_ip6;
		if (nr->target_port)
			*dst_port = htons(nr->target_port);
		nr->hit_flows++;
		atomic64_inc(&nat_translations);
		break;
	}
	spin_unlock_irqrestore(&sfw_pkt_lock, flags);
}

/*
 * /proc/pressure_sfw/{nat,chains,conntrack,stats} Live Runtime Control
 */
static void strip_v6_brackets(char *s)
{
	size_t len = strlen(s);
	if (len >= 2 && s[0] == '[') {
		char *rb = strchr(s, ']');
		if (rb) {
			memmove(s, s + 1, (size_t)(rb - (s + 1)));
			memmove(rb - 1, rb + 1, strlen(rb + 1) + 1);
		}
	}
}

static bool parse_dual_cidr(const char *s, u16 *fam_io, bool *is_any_out,
			    __be32 *v4_net, __be32 *v4_mask,
			    struct in6_addr *v6_net, u8 *v6_plen)
{
	char buf[80], *slash;

	*is_any_out = false;
	if (strcmp(s, "*") == 0 || strcmp(s, "any") == 0) {
		*is_any_out = true;
		*v4_net = 0;
		*v4_mask = 0;
		memset(v6_net, 0, sizeof(*v6_net));
		*v6_plen = 0;
		return true;
	}

	strscpy(buf, s, sizeof(buf));
	strip_v6_brackets(buf);
	slash = strchr(buf, '/');

	if (strchr(buf, ':') != NULL) {
		unsigned int plen = 128;
		if (*fam_io && *fam_io != AF_INET6)
			return false;
		if (slash) {
			*slash++ = '\0';
			if (kstrtouint(slash, 10, &plen) < 0 || plen > 128)
				return false;
		}
		if (!in6_pton(buf, -1, v6_net->s6_addr, -1, NULL))
			return false;
		*v6_plen = (u8)plen;
		*fam_io = AF_INET6;
		return true;
	} else {
		unsigned int plen = 32;
		if (*fam_io && *fam_io != AF_INET)
			return false;
		if (slash) {
			*slash++ = '\0';
			if (kstrtouint(slash, 10, &plen) < 0 || plen > 32)
				return false;
		}
		if (!in4_pton(buf, -1, (u8 *)v4_net, -1, NULL))
			return false;
		*v4_mask = plen == 0 ? 0 : htonl(~0U << (32 - plen));
		*fam_io = AF_INET;
		return true;
	}
}

static bool parse_dual_ip(const char *s, u16 *fam_io, __be32 *v4_out,
			  struct in6_addr *v6_out)
{
	char buf[80];

	strscpy(buf, s, sizeof(buf));
	strip_v6_brackets(buf);
	if (strchr(buf, ':') != NULL) {
		if (*fam_io && *fam_io != AF_INET6)
			return false;
		if (!in6_pton(buf, -1, v6_out->s6_addr, -1, NULL))
			return false;
		*fam_io = AF_INET6;
		return true;
	} else {
		if (*fam_io && *fam_io != AF_INET)
			return false;
		if (!in4_pton(buf, -1, (u8 *)v4_out, -1, NULL))
			return false;
		*fam_io = AF_INET;
		return true;
	}
}

static u8 parse_proto(const char *s)
{
	if (strcmp(s, "tcp") == 0)    return IPPROTO_TCP;
	if (strcmp(s, "udp") == 0)    return IPPROTO_UDP;
	if (strcmp(s, "icmp") == 0)   return IPPROTO_ICMP;
	if (strcmp(s, "icmpv6") == 0 || strcmp(s, "icmp6") == 0)
		return IPPROTO_ICMPV6;
	return 0;
}

static int parse_chain_id(const char *s)
{
	if (strcmp(s, "prerouting") == 0)  return SFW_CHAIN_PREROUTING;
	if (strcmp(s, "input") == 0)       return SFW_CHAIN_INPUT;
	if (strcmp(s, "forward") == 0)     return SFW_CHAIN_FORWARD;
	if (strcmp(s, "output") == 0)      return SFW_CHAIN_OUTPUT;
	if (strcmp(s, "postrouting") == 0) return SFW_CHAIN_POSTROUTING;
	return -1;
}

static int nat_proc_show(struct seq_file *m, void *v)
{
	unsigned long flags;
	unsigned int i;

	spin_lock_irqsave(&sfw_pkt_lock, flags);
	for (i = 0; i < nat_rule_cnt; i++) {
		struct sfw_nat_rule *r = &nat_rules[i];
		const char *nt = r->nat_type == SFW_NAT_DNAT ? "DNAT" :
				 r->nat_type == SFW_NAT_SNAT ? "SNAT" : "MASQUERADE";
		if (r->family == AF_INET6) {
			seq_printf(m, "idx=%u family=inet6 type=%s proto=%u dev=%s match=[%pI6c]/%u:%u -> target=[%pI6c]:%u flows=%llu\n",
				   i, nt, r->proto, r->dev_match,
				   &r->match6_net, r->match6_plen,
				   r->match_port, &r->target_ip6,
				   r->target_port, r->hit_flows);
		} else {
			seq_printf(m, "idx=%u family=inet4 type=%s proto=%u dev=%s match=%pI4/%pI4:%u -> target=%pI4:%u flows=%llu\n",
				   i, nt, r->proto, r->dev_match,
				   &r->match_net, &r->match_mask,
				   r->match_port, &r->target_ip,
				   r->target_port, r->hit_flows);
		}
	}
	spin_unlock_irqrestore(&sfw_pkt_lock, flags);
	return 0;
}

static ssize_t nat_proc_write(struct file *file, const char __user *ubuf,
			      size_t count, loff_t *ppos)
{
	char kbuf[256], cmd[16], type_s[16], proto_s[16], dev_s[32];
	char cidr_s[80], tip_s[80];
	unsigned int mport = 0, tport = 0;
	struct sfw_nat_rule r = { .active = true };
	unsigned long flags;
	u16 fam = 0;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;
	if (count == 0 || count >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, ubuf, count))
		return -EFAULT;
	kbuf[count] = '\0';

	if (strncmp(strim(kbuf), "flush", 5) == 0) {
		spin_lock_irqsave(&sfw_pkt_lock, flags);
		nat_rule_cnt = 0;
		spin_unlock_irqrestore(&sfw_pkt_lock, flags);
		return count;
	}

	/*
	 * Formats (both IPv4 and IPv6 addresses/CIDRs supported!):
	 *   add dnat <proto> <in_dev> <dst_cidr> <dport> <new_ip> <new_port>
	 *   add snat <proto> <out_dev> <src_cidr> <snat_ip>
	 *   add masquerade <out_dev> <src_cidr>
	 */
	if (sscanf(kbuf, "%15s %15s", cmd, type_s) != 2 ||
	    strcmp(cmd, "add") != 0)
		return -EINVAL;

	if (strcmp(type_s, "dnat") == 0) {
		if (sscanf(kbuf, "add dnat %15s %31s %79s %u %79s %u",
			   proto_s, dev_s, cidr_s, &mport, tip_s, &tport) != 6)
			return -EINVAL;
		if (!parse_dual_cidr(cidr_s, &fam, &r.match_any, &r.match_net,
				     &r.match_mask, &r.match6_net,
				     &r.match6_plen) ||
		    !parse_dual_ip(tip_s, &fam, &r.target_ip, &r.target_ip6))
			return -EINVAL;
		r.family = fam ? fam : AF_INET;
		r.nat_type = SFW_NAT_DNAT;
		r.proto = parse_proto(proto_s);
		strscpy(r.dev_match, dev_s, sizeof(r.dev_match));
		r.match_port = (u16)mport;
		r.target_port = (u16)tport;
	} else if (strcmp(type_s, "snat") == 0) {
		if (sscanf(kbuf, "add snat %15s %31s %79s %79s",
			   proto_s, dev_s, cidr_s, tip_s) != 4)
			return -EINVAL;
		if (!parse_dual_cidr(cidr_s, &fam, &r.match_any, &r.match_net,
				     &r.match_mask, &r.match6_net,
				     &r.match6_plen) ||
		    !parse_dual_ip(tip_s, &fam, &r.target_ip, &r.target_ip6))
			return -EINVAL;
		r.family = fam ? fam : AF_INET;
		r.nat_type = SFW_NAT_SNAT;
		r.proto = parse_proto(proto_s);
		strscpy(r.dev_match, dev_s, sizeof(r.dev_match));
	} else if (strcmp(type_s, "masquerade") == 0 ||
		   strcmp(type_s, "masq") == 0) {
		if (sscanf(kbuf, "add %*s %31s %79s", dev_s, cidr_s) != 2)
			return -EINVAL;
		if (!parse_dual_cidr(cidr_s, &fam, &r.match_any, &r.match_net,
				     &r.match_mask, &r.match6_net,
				     &r.match6_plen))
			return -EINVAL;
		r.family = fam ? fam : AF_INET;
		r.nat_type = SFW_NAT_MASQ;
		r.proto = 0;
		strscpy(r.dev_match, dev_s, sizeof(r.dev_match));
	} else {
		return -EINVAL;
	}

	spin_lock_irqsave(&sfw_pkt_lock, flags);
	if (nat_rule_cnt >= SFW_MAX_NAT_RULES) {
		spin_unlock_irqrestore(&sfw_pkt_lock, flags);
		return -ENOSPC;
	}
	nat_rules[nat_rule_cnt++] = r;
	spin_unlock_irqrestore(&sfw_pkt_lock, flags);
	return count;
}

static int nat_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, nat_proc_show, NULL);
}

static const struct proc_ops nat_proc_ops = {
	.proc_open    = nat_proc_open,
	.proc_read    = seq_read,
	.proc_write   = nat_proc_write,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static int chains_proc_show(struct seq_file *m, void *v)
{
	unsigned long flags;
	unsigned int i;

	spin_lock_irqsave(&sfw_pkt_lock, flags);
	seq_printf(m, "policies: prerouting=%s input=%s forward=%s output=%s postrouting=%s\n",
		   chain_default_policy[0] ? "ACCEPT" : "DROP",
		   chain_default_policy[1] ? "ACCEPT" : "DROP",
		   chain_default_policy[2] ? "ACCEPT" : "DROP",
		   chain_default_policy[3] ? "ACCEPT" : "DROP",
		   chain_default_policy[4] ? "ACCEPT" : "DROP");
	for (i = 0; i < chain_rule_cnt; i++) {
		struct sfw_chain_rule *r = &chain_rules[i];
		const char *st = r->state_match == SFW_STATE_ESTABLISHED ? "established" :
				 r->state_match == SFW_STATE_NEW ? "new" : "any";
		if (r->family == AF_INET6) {
			seq_printf(m, "idx=%u family=inet6 chain=%s action=%s proto=%u in=%s out=%s src=%pI6c/%u dst=%pI6c/%u dports=%u-%u state=%s hits=%llu\n",
				   i, chain_name(r->chain),
				   r->action ? "allow" : "drop",
				   r->proto, r->in_dev, r->out_dev,
				   &r->src6_net, r->src6_plen,
				   &r->dst6_net, r->dst6_plen,
				   r->dport_min, r->dport_max, st, r->hit_pkts);
		} else {
			seq_printf(m, "idx=%u family=%s chain=%s action=%s proto=%u in=%s out=%s src=%pI4/%pI4 dst=%pI4/%pI4 dports=%u-%u state=%s hits=%llu\n",
				   i, r->family == 0 ? "any" : "inet4",
				   chain_name(r->chain),
				   r->action ? "allow" : "drop",
				   r->proto, r->in_dev, r->out_dev,
				   &r->src_net, &r->src_mask,
				   &r->dst_net, &r->dst_mask,
				   r->dport_min, r->dport_max, st, r->hit_pkts);
		}
	}
	spin_unlock_irqrestore(&sfw_pkt_lock, flags);
	return 0;
}

static ssize_t chains_proc_write(struct file *file, const char __user *ubuf,
				 size_t count, loff_t *ppos)
{
	char kbuf[320], cmd[16], ch_s[20], act_s[16], proto_s[16];
	char in_s[32], out_s[32], scidr[80], dcidr[80], state_s[20] = "any";
	unsigned int pmin = 0, pmax = 0;
	unsigned long flags;
	u16 fam = 0;
	int cid;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;
	if (count == 0 || count >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, ubuf, count))
		return -EFAULT;
	kbuf[count] = '\0';

	if (strncmp(strim(kbuf), "flush", 5) == 0) {
		spin_lock_irqsave(&sfw_pkt_lock, flags);
		chain_rule_cnt = 0;
		spin_unlock_irqrestore(&sfw_pkt_lock, flags);
		return count;
	}

	if (sscanf(kbuf, "policy %19s %15s", ch_s, act_s) == 2) {
		cid = parse_chain_id(ch_s);
		if (cid < 0)
			return -EINVAL;
		spin_lock_irqsave(&sfw_pkt_lock, flags);
		chain_default_policy[cid] =
			(strcmp(act_s, "accept") == 0 || strcmp(act_s, "allow") == 0) ? 1 : 0;
		spin_unlock_irqrestore(&sfw_pkt_lock, flags);
		return count;
	}

	if (sscanf(kbuf, "%15s %19s %15s %15s %31s %31s %79s %79s %u %u %19s",
		   cmd, ch_s, act_s, proto_s, in_s, out_s, scidr, dcidr,
		   &pmin, &pmax, state_s) < 10 || strcmp(cmd, "add") != 0)
		return -EINVAL;

	cid = parse_chain_id(ch_s);
	if (cid < 0)
		return -EINVAL;

	struct sfw_chain_rule r = {
		.active = true,
		.chain = (u8)cid,
		.action = (strcmp(act_s, "allow") == 0 || strcmp(act_s, "accept") == 0) ? 1 : 0,
		.proto = parse_proto(proto_s),
		.dport_min = (u16)pmin,
		.dport_max = (u16)pmax,
	};
	if (strcmp(state_s, "established") == 0)
		r.state_match = SFW_STATE_ESTABLISHED;
	else if (strcmp(state_s, "new") == 0)
		r.state_match = SFW_STATE_NEW;

	strscpy(r.in_dev, in_s, sizeof(r.in_dev));
	strscpy(r.out_dev, out_s, sizeof(r.out_dev));
	if (!parse_dual_cidr(scidr, &fam, &r.src_any, &r.src_net, &r.src_mask,
			     &r.src6_net, &r.src6_plen) ||
	    !parse_dual_cidr(dcidr, &fam, &r.dst_any, &r.dst_net, &r.dst_mask,
			     &r.dst6_net, &r.dst6_plen))
		return -EINVAL;
	r.family = fam; /* 0 if both src and dst are '*' -> matches both IPv4 & IPv6! */

	spin_lock_irqsave(&sfw_pkt_lock, flags);
	if (chain_rule_cnt >= SFW_MAX_CHAIN_RULES) {
		spin_unlock_irqrestore(&sfw_pkt_lock, flags);
		return -ENOSPC;
	}
	chain_rules[chain_rule_cnt++] = r;
	spin_unlock_irqrestore(&sfw_pkt_lock, flags);
	return count;
}

static int chains_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, chains_proc_show, NULL);
}

static const struct proc_ops chains_proc_ops = {
	.proc_open    = chains_proc_open,
	.proc_read    = seq_read,
	.proc_write   = chains_proc_write,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static int ct_proc_show(struct seq_file *m, void *v)
{
	struct sfw_ct_entry *ct;
	struct sfw_ct6_entry *ct6;
	unsigned long flags;
	int bkt;

	spin_lock_irqsave(&sfw_pkt_lock, flags);
	hash_for_each(ct_orig_ht, bkt, ct, orig_node) {
		const char *nt = ct->nat_type == SFW_NAT_DNAT ? "DNAT" :
				 ct->nat_type == SFW_NAT_SNAT ? "SNAT" :
				 ct->nat_type == SFW_NAT_MASQ ? "MASQUERADE" :
				 "NONE";
		seq_printf(m, "family=inet4 proto=%u state=%s nat=%s orig=%pI4:%u->%pI4:%u reply=%pI4:%u->%pI4:%u pkts=%llu bytes=%llu\n",
			   ct->orig.proto,
			   ct->seen_reply ? "ESTABLISHED" : "SYN_SENT/NEW",
			   nt,
			   &ct->orig.saddr, ntohs(ct->orig.sport),
			   &ct->orig.daddr, ntohs(ct->orig.dport),
			   &ct->reply.saddr, ntohs(ct->reply.sport),
			   &ct->reply.daddr, ntohs(ct->reply.dport),
			   ct->pkts, ct->bytes);
	}
	hash_for_each(ct6_orig_ht, bkt, ct6, orig_node) {
		const char *nt = ct6->nat_type == SFW_NAT_DNAT ? "DNAT" :
				 ct6->nat_type == SFW_NAT_SNAT ? "SNAT" :
				 ct6->nat_type == SFW_NAT_MASQ ? "MASQUERADE" :
				 "NONE";
		seq_printf(m, "family=inet6 proto=%u state=%s nat=%s orig=[%pI6c]:%u->[%pI6c]:%u reply=[%pI6c]:%u->[%pI6c]:%u pkts=%llu bytes=%llu\n",
			   ct6->orig.proto,
			   ct6->seen_reply ? "ESTABLISHED" : "SYN_SENT/NEW",
			   nt,
			   &ct6->orig.saddr, ntohs(ct6->orig.sport),
			   &ct6->orig.daddr, ntohs(ct6->orig.dport),
			   &ct6->reply.saddr, ntohs(ct6->reply.sport),
			   &ct6->reply.daddr, ntohs(ct6->reply.dport),
			   ct6->pkts, ct6->bytes);
	}
	spin_unlock_irqrestore(&sfw_pkt_lock, flags);
	return 0;
}

static int ct_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, ct_proc_show, NULL);
}

static const struct proc_ops ct_proc_ops = {
	.proc_open    = ct_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static int stats_proc_show(struct seq_file *m, void *v)
{
	unsigned int c;

	seq_printf(m, "sfw_ready: 1\n");
	seq_printf(m, "sfw_policy_gen: %llu\n",
		   (u64)atomic64_read(&sfw_policy_gen));
	seq_printf(m, "sfw_txn_active: %d\n", READ_ONCE(sfw_txn_active) ? 1 : 0);
	seq_printf(m, "sfw_txn_degraded: %d\n", READ_ONCE(sfw_txn_degraded) ? 1 : 0);
	seq_printf(m, "nat_header_rewrites: %llu\n",
		   (u64)atomic64_read(&nat_translations));
	for (c = 0; c < SFW_CHAIN_MAX; c++) {
		seq_printf(m, "chain_%s: accepted=%llu dropped=%llu\n",
			   chain_name((u8)c),
			   (u64)atomic64_read(&pkt_accepted[c]),
			   (u64)atomic64_read(&pkt_dropped[c]));
	}
	return 0;
}

static int stats_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, stats_proc_show, NULL);
}

static const struct proc_ops stats_proc_ops = {
	.proc_open    = stats_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static bool sfw_owner_alive(pid_t pid)
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

static void restore_sfw_snap_locked(const struct sfw_pkt_txn_snap *snap)
{
	memcpy(chain_default_policy, snap->default_policy_bak,
	       sizeof(chain_default_policy));
	chain_rule_cnt = snap->chain_cnt_bak;
	memcpy(chain_rules, snap->chain_bak,
	       snap->chain_cnt_bak * sizeof(chain_rules[0]));
	nat_rule_cnt = snap->nat_cnt_bak;
	memcpy(nat_rules, snap->nat_bak,
	       snap->nat_cnt_bak * sizeof(nat_rules[0]));
}

static ssize_t sfw_txn_proc_write(struct file *file, const char __user *ubuf,
				  size_t count, loff_t *ppos)
{
	char kbuf[32], *cmd;
	unsigned long flags;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;
	if (count == 0 || count >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, ubuf, count))
		return -EFAULT;
	kbuf[count] = '\0';
	cmd = strim(kbuf);

	if (strcmp(cmd, "begin") == 0) {
		struct sfw_pkt_txn_snap *snap;
		mutex_lock(&sfw_txn_lock);
		if (sfw_txn_active) {
			if (sfw_owner_alive(sfw_txn_owner_pid)) {
				mutex_unlock(&sfw_txn_lock);
				return -EBUSY;
			}
			/* Crashed loader recovery: auto-restore uncommitted snapshot */
			if (g_sfw_snap) {
				spin_lock_irqsave(&sfw_pkt_lock, flags);
				restore_sfw_snap_locked(g_sfw_snap);
				spin_unlock_irqrestore(&sfw_pkt_lock, flags);
				kvfree(g_sfw_snap);
				g_sfw_snap = NULL;
			}
			WRITE_ONCE(sfw_txn_active, false);
			sfw_txn_prepared = false;
			sfw_txn_owner_pid = 0;
		}
		snap = kvzalloc(sizeof(*snap), GFP_KERNEL);
		if (!snap) {
			mutex_unlock(&sfw_txn_lock);
			return -ENOMEM;
		}
		spin_lock_irqsave(&sfw_pkt_lock, flags);
		memcpy(snap->default_policy_bak, chain_default_policy,
		       sizeof(chain_default_policy));
		snap->chain_cnt_bak = chain_rule_cnt;
		memcpy(snap->chain_bak, chain_rules,
		       chain_rule_cnt * sizeof(chain_rules[0]));
		snap->nat_cnt_bak = nat_rule_cnt;
		memcpy(snap->nat_bak, nat_rules,
		       nat_rule_cnt * sizeof(nat_rules[0]));
		g_sfw_snap = snap;
		sfw_txn_prepared = false;
		sfw_txn_owner_pid = task_tgid_nr(current);
		WRITE_ONCE(sfw_txn_active, true);
		spin_unlock_irqrestore(&sfw_pkt_lock, flags);
		mutex_unlock(&sfw_txn_lock);
		return count;
	}

	if (strcmp(cmd, "prepare") == 0) {
		mutex_lock(&sfw_txn_lock);
		if (!sfw_txn_active || !g_sfw_snap) {
			mutex_unlock(&sfw_txn_lock);
			return -EINVAL;
		}
		sfw_txn_prepared = true;
		mutex_unlock(&sfw_txn_lock);
		return count;
	}

	if (strcmp(cmd, "commit") == 0) {
		struct sfw_pkt_txn_snap *snap;
		mutex_lock(&sfw_txn_lock);
		if (!sfw_txn_active || !g_sfw_snap) {
			mutex_unlock(&sfw_txn_lock);
			return -EINVAL;
		}
		snap = g_sfw_snap;
		g_sfw_snap = NULL;
		sfw_txn_prepared = false;
		sfw_txn_owner_pid = 0;
		WRITE_ONCE(sfw_txn_active, false);
		WRITE_ONCE(sfw_txn_degraded, false);
		atomic64_inc(&sfw_policy_gen);
		mutex_unlock(&sfw_txn_lock);
		kvfree(snap);
		return count;
	}

	if (strcmp(cmd, "abort") == 0) {
		struct sfw_pkt_txn_snap *snap;
		mutex_lock(&sfw_txn_lock);
		if (!sfw_txn_active || !g_sfw_snap) {
			mutex_unlock(&sfw_txn_lock);
			return -EINVAL;
		}
		snap = g_sfw_snap;
		spin_lock_irqsave(&sfw_pkt_lock, flags);
		restore_sfw_snap_locked(snap);
		g_sfw_snap = NULL;
		sfw_txn_prepared = false;
		sfw_txn_owner_pid = 0;
		WRITE_ONCE(sfw_txn_active, false);
		spin_unlock_irqrestore(&sfw_pkt_lock, flags);
		mutex_unlock(&sfw_txn_lock);
		kvfree(snap);
		return count;
	}

	if (strcmp(cmd, "mark_degraded") == 0) {
		WRITE_ONCE(sfw_txn_degraded, true);
		return count;
	}

	return -EINVAL;
}

static const struct proc_ops sfw_txn_proc_ops = {
	.proc_write = sfw_txn_proc_write,
	.proc_lseek = noop_llseek,
};

int sfw_nat_fwd_init(void)
{
	if (default_input_drop)
		chain_default_policy[SFW_CHAIN_INPUT] = 0;

	sfw_proc_dir = proc_mkdir("pressure_sfw", NULL);
	if (!sfw_proc_dir)
		return -ENOMEM;

	proc_create("nat", 0600, sfw_proc_dir, &nat_proc_ops);
	proc_create("chains", 0600, sfw_proc_dir, &chains_proc_ops);
	proc_create("conntrack", 0400, sfw_proc_dir, &ct_proc_ops);
	proc_create("stats", 0444, sfw_proc_dir, &stats_proc_ops);
	proc_create("txn", 0200, sfw_proc_dir, &sfw_txn_proc_ops);

	pressure_register_sfw_pkt_hook(sfw_ipv4_pkt_hook);
	pressure_register_sfw_pkt6_hook(sfw_ipv6_pkt_hook);
	pr_info("sfw: live dual-stack (IPv4 + IPv6) 5-chain packet engine + stateful NAT active\n");
	return 0;
}

void sfw_nat_fwd_exit(void)
{
	struct sfw_ct_entry *ct;
	struct sfw_ct6_entry *ct6;
	struct hlist_node *tmp;
	unsigned long flags;
	int bkt;

	pressure_register_sfw_pkt_hook(NULL);
	pressure_register_sfw_pkt6_hook(NULL);
	if (sfw_proc_dir)
		proc_remove(sfw_proc_dir);

	spin_lock_irqsave(&sfw_pkt_lock, flags);
	hash_for_each_safe(ct_orig_ht, bkt, tmp, ct, orig_node) {
		hash_del(&ct->orig_node);
		hash_del(&ct->reply_node);
		kfree(ct);
	}
	ct_count = 0;
	hash_for_each_safe(ct6_orig_ht, bkt, tmp, ct6, orig_node) {
		hash_del(&ct6->orig_node);
		hash_del(&ct6->reply_node);
		kfree(ct6);
	}
	ct6_count = 0;
	spin_unlock_irqrestore(&sfw_pkt_lock, flags);
}
