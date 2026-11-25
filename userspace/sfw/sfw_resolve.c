// SPDX-License-Identifier: GPL-2.0
/* Resolve an IPv4 host through SFW and emit one numeric address. */
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "sfw_dns.h"

int main(int argc, char **argv)
{
	struct in_addr address;
	char result[INET_ADDRSTRLEN];
	size_t length;

	if (argc != 2)
		return 2;
	length = strlen(argv[1]);
	if (!length || length > 253 ||
	    strspn(argv[1], "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-") != length)
		return 2;

	alarm(10);
	if (inet_pton(AF_INET, argv[1], &address) != 1 &&
	    sfw_resolve_ipv4(argv[1], &address) < 0)
		return 1;
	if (!inet_ntop(AF_INET, &address, result, sizeof(result)))
		return 1;
	return puts(result) < 0 ? 1 : 0;
}
