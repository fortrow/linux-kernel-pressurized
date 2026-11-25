/* SPDX-License-Identifier: GPL-2.0 */
#ifndef PRESSURE_SFW_DNS_H
#define PRESSURE_SFW_DNS_H

#include <netinet/in.h>

int sfw_resolve_ipv4(const char *host, struct in_addr *address);

#endif
