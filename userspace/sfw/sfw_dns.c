// SPDX-License-Identifier: GPL-2.0
#include <arpa/nameser.h>
#include <resolv.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "../libpressure/libpressuresock.h"
#include "sfw_dns.h"

int sfw_resolve_ipv4(const char *host, struct in_addr *address)
{
	struct sockaddr_in dns = { .sin_family = AF_INET, .sin_port = htons(53) };
	unsigned char query[NS_PACKETSZ], reply[NS_PACKETSZ];
	char line[256], server[INET_ADDRSTRLEN];
	FILE *config = fopen("/etc/resolv.conf", "r");
	ns_msg message;
	int length, fd;

	if (!config)
		return -1;
	while (fgets(line, sizeof(line), config))
		if (sscanf(line, "nameserver %15s", server) == 1 &&
		    inet_pton(AF_INET, server, &dns.sin_addr) == 1)
			break;
	fclose(config);
	if (!dns.sin_addr.s_addr)
		return -1;

	length = res_mkquery(ns_o_query, host, ns_c_in, ns_t_a, NULL, 0,
			     NULL, query, sizeof(query));
	if (length < NS_HFIXEDSZ)
		return -1;
	fd = pg_socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;
	if (pg_connect(fd, &dns, NULL) < 0 || pg_send(fd, query, length) != length) {
		pg_close(fd);
		return -1;
	}
	length = pg_recv(fd, reply, sizeof(reply), 0);
	pg_close(fd);
	if (length < NS_HFIXEDSZ || ns_initparse(reply, length, &message) < 0 ||
	    memcmp(reply, query, 2) || !ns_msg_getflag(message, ns_f_qr) ||
	    ns_msg_getflag(message, ns_f_tc) || ns_msg_getflag(message, ns_f_rcode))
		return -1;
	for (int i = 0; i < ns_msg_count(message, ns_s_an); i++) {
		ns_rr record;

		if (ns_parserr(&message, ns_s_an, i, &record) == 0 &&
		    ns_rr_type(record) == ns_t_a && ns_rr_class(record) == ns_c_in &&
		    ns_rr_rdlen(record) == sizeof(*address)) {
			memcpy(address, ns_rr_rdata(record), sizeof(*address));
			return 0;
		}
	}
	return -1;
}
