/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SFW_INTERNAL_H
#define _SFW_INTERNAL_H

#include <linux/types.h>
#include <linux/in6.h>
#include <linux/sfw_pkt.h>
#include <uapi/linux/sfw.h>

int sfw_nat_fwd_init(void);
void sfw_nat_fwd_exit(void);
void sfw_apply_broker_dnat(__be32 *dst_ip, __be16 *dst_port, const char *ifname);
void sfw_apply_broker_dnat6(struct in6_addr *dst_ip6, __be16 *dst_port,
			    const char *ifname);

#endif
