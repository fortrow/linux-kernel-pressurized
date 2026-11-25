/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SFW_PKT_H
#define _LINUX_SFW_PKT_H

#include <linux/types.h>
#include <linux/skbuff.h>

struct net;
struct sock;
struct net_device;

enum sfw_pkt_chain {
	SFW_CHAIN_PREROUTING  = 0,
	SFW_CHAIN_INPUT       = 1,
	SFW_CHAIN_FORWARD     = 2,
	SFW_CHAIN_OUTPUT      = 3,
	SFW_CHAIN_POSTROUTING = 4,
	SFW_CHAIN_MAX         = 5,
};

typedef int (*sfw_pkt_hook_t)(unsigned int chain, struct net *net,
			      struct sock *sk, struct sk_buff *skb,
			      struct net_device *in_dev,
			      struct net_device *out_dev);

#ifdef CONFIG_SECURITY_PRESSURE
int pressure_register_sfw_pkt_hook(sfw_pkt_hook_t fn);
int pressure_register_sfw_pkt6_hook(sfw_pkt_hook_t fn);
int pressure_sfw_pkt_run(unsigned int chain, struct net *net, struct sock *sk,
			 struct sk_buff *skb, struct net_device *in_dev,
			 struct net_device *out_dev);
int pressure_sfw_pkt6_run(unsigned int chain, struct net *net, struct sock *sk,
			  struct sk_buff *skb, struct net_device *in_dev,
			  struct net_device *out_dev);
bool pressure_lookup_netdev_label(int ifindex, char *label_out);
#else
static inline int pressure_sfw_pkt_run(unsigned int chain, struct net *net,
				       struct sock *sk, struct sk_buff *skb,
				       struct net_device *in_dev,
				       struct net_device *out_dev)
{
	return 0;
}
static inline int pressure_sfw_pkt6_run(unsigned int chain, struct net *net,
					struct sock *sk, struct sk_buff *skb,
					struct net_device *in_dev,
					struct net_device *out_dev)
{
	return 0;
}
#endif

#endif /* _LINUX_SFW_PKT_H */
