// SPDX-License-Identifier: GPL-2.0
/*
 * sfw: Socket & Stateful Packet/NAT Firewall CLI (Replaces Netfilter/iptables)
 *
 * Supports live runtime updates while the kernel is running across:
 *   1. AF_UNIX socket worker provenance/IP/device rules
 *   2. 5-chain packet rules (prerouting, input, forward, output, postrouting)
 *   3. Stateful NAT (DNAT port-forwarding, SNAT, dynamic MASQUERADE)
 *   4. Live stateful connection tracking (conntrack) & packet statistics
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "../../include/uapi/linux/sfw.h"

static int parse_dir(const char *s)
{
	if (strcmp(s, "bind") == 0)    return SFW_DIR_BIND;
	if (strcmp(s, "connect") == 0) return SFW_DIR_CONNECT;
	if (strcmp(s, "send") == 0)    return SFW_DIR_SEND;
	if (strcmp(s, "recv") == 0)    return SFW_DIR_RECV;
	return SFW_DIR_ANY;
}

static void dump_file(const char *path, const char *title)
{
	FILE *f = fopen(path, "r");
	char line[256];

	if (!f) {
		fprintf(stderr, "sfw: cannot open %s (%s)\n", path, strerror(errno));
		return;
	}
	if (title)
		printf("=== %s ===\n", title);
	while (fgets(line, sizeof(line), f))
		fputs(line, stdout);
	fclose(f);
}

static int write_file_str(const char *path, const char *str)
{
	int fd = open(path, O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "sfw: open %s failed: %s\n", path, strerror(errno));
		return -1;
	}
	if (write(fd, str, strlen(str)) < 0) {
		fprintf(stderr, "sfw: write %s failed: %s\n", path, strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s list | status | stats | conntrack\n"
		"  %s flush\n"
		"  %s <allow|deny> <any|bind|connect|send|recv> <pub_uid_or_0> <ip4_or_ip6> <mask4_or_plen6> <pmin> <pmax> <dev_lbl> <max_prov:0|1|2>\n"
		"  %s nat list | nat flush\n"
		"  %s nat add dnat <tcp|udp|all> <in_dev_or_*> <dst_v4_or_v6_cidr> <dport> <new_v4_or_v6_ip> <new_port>\n"
		"  %s nat add snat <tcp|udp|all> <out_dev_or_*> <src_v4_or_v6_cidr> <snat_v4_or_v6_ip>\n"
		"  %s nat add masquerade <out_dev> <src_v4_or_v6_cidr>\n"
		"  %s chain list | chain flush\n"
		"  %s chain policy <prerouting|input|forward|output|postrouting> <accept|drop>\n"
		"  %s chain add <chain> <allow|drop> <tcp|udp|icmp|icmpv6|all> <in_dev> <out_dev> <src_v4_or_v6_cidr> <dst_v4_or_v6_cidr> <pmin> <pmax> [any|new|established]\n",
		prog, prog, prog, prog, prog, prog, prog, prog, prog, prog);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "list") == 0 || strcmp(argv[1], "status") == 0) {
		dump_file("/sys/kernel/security/pressure/sfw_rules",
			  "sfw AF_UNIX Socket Worker Rules");
		if (access("/proc/pressure_sfw/chains", R_OK) == 0) {
			dump_file("/proc/pressure_sfw/chains",
				  "sfw 5-Chain Packet Rules (PREROUTING/INPUT/FORWARD/OUTPUT/POSTROUTING)");
			dump_file("/proc/pressure_sfw/nat",
				  "sfw Stateful NAT Rules (DNAT/SNAT/MASQUERADE)");
			dump_file("/proc/pressure_sfw/stats",
				  "sfw Packet & NAT Counters");
		}
		return 0;
	}

	if (strcmp(argv[1], "conntrack") == 0) {
		dump_file("/proc/pressure_sfw/conntrack",
			  "sfw Active Stateful Conntrack & NAT Sessions");
		return 0;
	}

	if (strcmp(argv[1], "stats") == 0) {
		dump_file("/proc/pressure_sfw/stats",
			  "sfw Packet & NAT Counters");
		return 0;
	}

	if (strcmp(argv[1], "nat") == 0 && argc >= 3) {
		if (strcmp(argv[2], "list") == 0) {
			dump_file("/proc/pressure_sfw/nat", "sfw Stateful NAT Rules");
			return 0;
		}
		if (strcmp(argv[2], "flush") == 0)
			return write_file_str("/proc/pressure_sfw/nat", "flush\n") < 0 ? 1 : 0;
		if (strcmp(argv[2], "add") == 0 && argc >= 6) {
			char cmd[240] = "add";
			for (int i = 3; i < argc; i++) {
				strncat(cmd, " ", sizeof(cmd) - strlen(cmd) - 1);
				strncat(cmd, argv[i], sizeof(cmd) - strlen(cmd) - 1);
			}
			strncat(cmd, "\n", sizeof(cmd) - strlen(cmd) - 1);
			if (write_file_str("/proc/pressure_sfw/nat", cmd) < 0)
				return 1;
			printf("sfw: live NAT rule added: %s", cmd);
			return 0;
		}
		usage(argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "chain") == 0 && argc >= 3) {
		if (strcmp(argv[2], "list") == 0) {
			dump_file("/proc/pressure_sfw/chains", "sfw 5-Chain Packet Rules");
			return 0;
		}
		if (strcmp(argv[2], "flush") == 0)
			return write_file_str("/proc/pressure_sfw/chains", "flush\n") < 0 ? 1 : 0;
		if (strcmp(argv[2], "policy") == 0 && argc >= 5) {
			char cmd[128];
			snprintf(cmd, sizeof(cmd), "policy %s %s\n", argv[3], argv[4]);
			if (write_file_str("/proc/pressure_sfw/chains", cmd) < 0)
				return 1;
			printf("sfw: live chain %s policy -> %s\n", argv[3], argv[4]);
			return 0;
		}
		if (strcmp(argv[2], "add") == 0 && argc >= 12) {
			char cmd[250];
			const char *st = (argc >= 13) ? argv[12] : "any";
			snprintf(cmd, sizeof(cmd),
				 "add %s %s %s %s %s %s %s %s %s %s\n",
				 argv[3], argv[4], argv[5], argv[6], argv[7],
				 argv[8], argv[9], argv[10], argv[11], st);
			if (write_file_str("/proc/pressure_sfw/chains", cmd) < 0)
				return 1;
			printf("sfw: live chain rule added to %s\n", argv[3]);
			return 0;
		}
		usage(argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "flush") == 0) {
		(void)write_file_str("/sys/kernel/security/pressure/sfw_rules", "flush\n");
		if (access("/proc/pressure_sfw/chains", W_OK) == 0) {
			(void)write_file_str("/proc/pressure_sfw/chains", "flush\n");
			(void)write_file_str("/proc/pressure_sfw/nat", "flush\n");
		}
		printf("sfw: flushed all rules\n");
		return 0;
	}

	if ((strcmp(argv[1], "allow") == 0 || strcmp(argv[1], "deny") == 0) &&
	    argc >= 9) {
		char cmd[256];
		if (argc == 9 && strchr(argv[4], '/') != NULL &&
		    strchr(argv[4], ':') != NULL) {
			/* Shorthand IPv6 CIDR: sfw allow connect 0 2001:db8::/64 80 80 dev:net_ext 1 */
			char ipbuf[80];
			snprintf(ipbuf, sizeof(ipbuf), "%s", argv[4]);
			char *slash = strchr(ipbuf, '/');
			*slash++ = '\0';
			snprintf(cmd, sizeof(cmd), "inet6 %s %d %s %s %s %s %s %s %s\n",
				 argv[1], parse_dir(argv[2]), argv[3], ipbuf,
				 slash, argv[5], argv[6], argv[7], argv[8]);
			if (write_file_str("/sys/kernel/security/pressure/sfw_rules", cmd) < 0)
				return 1;
			printf("sfw: added %s IPv6 socket rule (%s [%s]/%s:%s-%s dev=%s)\n",
			       argv[1], argv[2], ipbuf, slash, argv[5], argv[6], argv[7]);
			return 0;
		}
		if (argc >= 10) {
			if (strchr(argv[4], ':') != NULL) {
				snprintf(cmd, sizeof(cmd), "inet6 %s %d %s %s %s %s %s %s %s\n",
					 argv[1], parse_dir(argv[2]), argv[3], argv[4],
					 argv[5], argv[6], argv[7], argv[8], argv[9]);
			} else {
				snprintf(cmd, sizeof(cmd), "%s %d %s %s %s %s %s %s %s\n",
					 argv[1], parse_dir(argv[2]), argv[3], argv[4],
					 argv[5], argv[6], argv[7], argv[8], argv[9]);
			}
			if (write_file_str("/sys/kernel/security/pressure/sfw_rules", cmd) < 0)
				return 1;
			printf("sfw: added %s socket rule (%s %s:%s-%s dev=%s)\n",
			       argv[1], argv[2], argv[4], argv[6], argv[7], argv[8]);
			return 0;
		}
	}

	usage(argv[0]);
	return 1;
}
