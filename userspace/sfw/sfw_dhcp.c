// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>

#include "../../include/uapi/linux/sfw.h"
#include "../libpressure/libpressuresock.h"

#define WAN_INTERFACE "inner0"
#define DHCP_OPTIONS 240
#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67
#define DHCP_DISCOVER 1
#define DHCP_OFFER 2
#define DHCP_REQUEST 3
#define DHCP_ACK 5
#define DHCP_NAK 6

static const unsigned char cookie[] = { 99, 130, 83, 99 };

struct lease {
	uint32_t address, subnet, gateway, server, duration;
	uint32_t renew_after, rebind_after;
	unsigned char type;
};

enum exchange_state { DISCOVER, SELECT, RENEW, REBIND };

static uint32_t field32(const unsigned char *p)
{
	uint32_t value;

	memcpy(&value, p, sizeof(value));
	return value;
}

static int read_mac(unsigned char mac[6])
{
	FILE *input = fopen("/sys/class/net/" WAN_INTERFACE "/address", "r");
	unsigned int values[6];
	char line[32], tail;
	int fields;

	if (!input)
		return -1;
	fields = fgets(line, sizeof(line), input) ?
		 sscanf(line, "%2x:%2x:%2x:%2x:%2x:%2x%c", &values[0], &values[1],
			&values[2], &values[3], &values[4], &values[5], &tail) : 0;
	fclose(input);
	if (fields != 7 || tail != '\n' || strlen(line) != 18) {
		errno = EINVAL;
		return -1;
	}
	for (size_t i = 0; i < 6; i++)
		mac[i] = values[i];
	return 0;
}

static void option_address(unsigned char **out, unsigned char tag, uint32_t value)
{
	*(*out)++ = tag;
	*(*out)++ = 4;
	memcpy(*out, &value, 4);
	*out += 4;
}

static void make_request(unsigned char packet[300], const unsigned char mac[6],
			 uint32_t xid, enum exchange_state state, const struct lease *current)
{
	unsigned char *out = packet + DHCP_OPTIONS;

	memset(packet, 0, 300);
	packet[0] = 1;	/* BOOTREQUEST */
	packet[1] = 1;	/* Ethernet */
	packet[2] = 6;
	memcpy(packet + 4, &xid, sizeof(xid));
	if (state == DISCOVER || state == SELECT)
		packet[10] = 0x80;	/* Receive the initial reply by broadcast. */
	else
		memcpy(packet + 12, &current->address, sizeof(current->address));
	memcpy(packet + 28, mac, 6);
	memcpy(packet + 236, cookie, sizeof(cookie));
	*out++ = 53;
	*out++ = 1;
	*out++ = state == DISCOVER ? DHCP_DISCOVER : DHCP_REQUEST;
	*out++ = 55;
	*out++ = 5;
	*out++ = 1;	/* Subnet mask */
	*out++ = 3;	/* Router */
	*out++ = 51;	/* Lease time */
	*out++ = 58;	/* Renewal time */
	*out++ = 59;	/* Rebinding time */
	if (state == SELECT) {
		option_address(&out, 50, current->address);
		option_address(&out, 54, current->server);
	}
	*out = 255;
}

static bool unicast(uint32_t address)
{
	unsigned int first = ntohl(address) >> 24;

	return first > 0 && first < 224 && first != 127;
}

static bool parse_reply(const unsigned char *packet, size_t len, uint32_t xid,
			const unsigned char mac[6], struct lease *lease)
{
	bool seen[256] = {};

	if (len < DHCP_OPTIONS || packet[0] != 2 || packet[1] != 1 || packet[2] != 6 ||
	    field32(packet + 4) != xid || memcmp(packet + 28, mac, 6) ||
	    memcmp(packet + 236, cookie, sizeof(cookie)))
		return false;
	*lease = (struct lease){ .address = field32(packet + 16) };
	for (size_t i = DHCP_OPTIONS; i < len;) {
		unsigned int tag = packet[i++];
		unsigned int length;

		if (tag == 0)
			continue;
		if (tag == 255)
			return seen[53] && seen[54] && unicast(lease->server);
		if (i == len)
			return false;
		length = packet[i++];
		if (length > len - i)
			return false;
		switch (tag) {
		case 53:
			if (length != 1 || seen[tag])
				return false;
			lease->type = packet[i];
			break;
		case 1:
		case 3:
		case 51:
		case 54:
		case 58:
		case 59:
			if (seen[tag] || (tag == 3 ? (length < 4 || length % 4) : length != 4))
				return false;
			if (tag == 1)
				lease->subnet = field32(packet + i);
			else if (tag == 3)
				lease->gateway = field32(packet + i);
			else if (tag == 51)
				lease->duration = ntohl(field32(packet + i));
			else if (tag == 58)
				lease->renew_after = ntohl(field32(packet + i));
			else if (tag == 59)
				lease->rebind_after = ntohl(field32(packet + i));
			else
				lease->server = field32(packet + i);
			break;
		}
		seen[tag] = true;
		i += length;
	}
	return false;
}

static bool usable_lease(struct lease *lease)
{
	uint32_t host_mask = ~ntohl(lease->subnet);
	uint32_t host = ntohl(lease->address) & host_mask;
	uint32_t gateway = ntohl(lease->gateway) & host_mask;

	if (!lease->renew_after)
		lease->renew_after = lease->duration / 2;
	if (!lease->rebind_after)
		lease->rebind_after = (uint64_t)lease->duration * 7 / 8;
	return unicast(lease->address) && unicast(lease->gateway) &&
	       lease->renew_after > 0 && lease->renew_after < lease->rebind_after &&
	       lease->rebind_after < lease->duration &&
	       host_mask >= 3 && host_mask != UINT32_MAX &&
	       (host_mask & (host_mask + 1)) == 0 &&
	       (lease->address & lease->subnet) == (lease->gateway & lease->subnet) &&
	       host != 0 && host != host_mask && gateway != 0 && gateway != host_mask &&
	       lease->gateway != lease->address;
}

static int64_t monotonic_ms(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return -1;
	return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int exchange(int fd, uint32_t xid, const unsigned char mac[6],
		    enum exchange_state state, const struct lease *current,
		    struct lease *reply)
{
	struct sockaddr_in destination = {
		.sin_family = AF_INET,
		.sin_port = htons(DHCP_SERVER_PORT),
		.sin_addr.s_addr = state == RENEW ? current->server : htonl(INADDR_BROADCAST),
	};
	unsigned char request[300], packet[1536];
	int64_t start = monotonic_ms();

	if (start < 0)
		return -1;
	make_request(request, mac, xid, state, current);
	if (pg_sendto_sa(fd, request, sizeof(request), 0, (void *)&destination,
			 sizeof(destination), WAN_INTERFACE) != sizeof(request))
		return -1;
	for (;;) {
		struct sockaddr_storage source;
		const struct sockaddr_in *server = (const void *)&source;
		socklen_t source_len;
		int64_t now = monotonic_ms();
		ssize_t received;

		if (now < 0)
			return -1;
		if (now - start >= 4000) {
			errno = ETIMEDOUT;
			return -1;
		}
		received = pg_recvfrom_sa(fd, packet, sizeof(packet), SFW_FLAG_NONBLOCK,
					  &source, &source_len);
		if (received < 0) {
			if (errno != EAGAIN && errno != EINTR)
				return -1;
			nanosleep(&(struct timespec){ .tv_nsec = 100000000 }, NULL);
			continue;
		}
		if (source_len != sizeof(*server) || server->sin_family != AF_INET ||
		    server->sin_port != htons(DHCP_SERVER_PORT) ||
		    !parse_reply(packet, received, xid, mac, reply))
			continue;
		if ((state == SELECT || state == RENEW) && reply->server != current->server)
			continue;
		if (state != DISCOVER && reply->type == DHCP_NAK) {
			errno = ECONNREFUSED;
			return -1;
		}
		if (state == DISCOVER && reply->type == DHCP_OFFER && unicast(reply->address))
			return 0;
		if (state != DISCOVER && reply->type == DHCP_ACK && reply->address == current->address &&
		    usable_lease(reply))
			return 0;
	}
}

int main(int argc, char **argv)
{
	struct sockaddr_in local = {
		.sin_family = AF_INET,
		.sin_port = htons(DHCP_CLIENT_PORT),
	};
	struct lease current = {}, reply;
	enum exchange_state state = DISCOVER;
	unsigned char mac[6];
	char address[INET_ADDRSTRLEN], gateway[INET_ADDRSTRLEN], server[INET_ADDRSTRLEN];
	uint32_t xid;
	int fd, status = 1;

	if (argc == 4 && !strcmp(argv[1], "--renew") &&
	    inet_pton(AF_INET, argv[2], &current.address) == 1 && unicast(current.address) &&
	    inet_pton(AF_INET, argv[3], &current.server) == 1 && unicast(current.server)) {
		state = RENEW;
	} else if (argc == 3 && !strcmp(argv[1], "--rebind") &&
		   inet_pton(AF_INET, argv[2], &current.address) == 1 && unicast(current.address)) {
		state = REBIND;
	} else if (argc != 1) {
		fputs("Usage: sfw-dhcp [--renew ADDRESS SERVER | --rebind ADDRESS]\n", stderr);
		return 2;
	}
	if (read_mac(mac) < 0 || getrandom(&xid, sizeof(xid), 0) != sizeof(xid)) {
		perror("sfw-dhcp: client identity");
		return 1;
	}
	fd = pg_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		perror("sfw-dhcp: open SFW socket");
		return 1;
	}
	if (pg_bind(fd, &local, WAN_INTERFACE) < 0 ||
	    pg_setsockopt_int(fd, SFW_SOCKOPT_BROADCAST, 1) < 0)
		goto failed;
	if (state == DISCOVER) {
		if (exchange(fd, xid, mac, DISCOVER, NULL, &current) < 0)
			goto failed;
		state = SELECT;
	}
	if (exchange(fd, xid, mac, state, &current, &reply) < 0)
		goto failed;
	if (inet_ntop(AF_INET, &reply.address, address, sizeof(address)) &&
	    inet_ntop(AF_INET, &reply.gateway, gateway, sizeof(gateway)) &&
	    inet_ntop(AF_INET, &reply.server, server, sizeof(server))) {
		printf("%s/%d %s %u %s %u %u\n", address, __builtin_popcount(ntohl(reply.subnet)),
		       gateway, reply.duration, server, reply.renew_after, reply.rebind_after);
		status = 0;
	}
	goto out;
failed:
	status = errno == ECONNREFUSED ? 3 : 1;
	perror("sfw-dhcp: obtain WAN lease");
out:
	pg_close(fd);
	return status;
}
