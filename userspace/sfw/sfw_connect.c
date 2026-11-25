// SPDX-License-Identifier: GPL-2.0
/* Handle one HTTPS CONNECT request on an already admitted client socket. */
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../include/uapi/linux/sfw.h"
#include "../libpressure/libpressuresock.h"
#include "sfw_dns.h"

static int write_client(const void *data, size_t length)
{
	const char *bytes = data;

	while (length) {
		ssize_t count = write(STDOUT_FILENO, bytes, length);

		if (count < 0 && errno == EINTR)
			continue;
		if (count <= 0)
			return -1;
		bytes += count;
		length -= (size_t)count;
	}
	return 0;
}

static int reply(const char *message)
{
	return write_client(message, strlen(message));
}

static int read_authority(char host[254])
{
	char request[4096];
	char *authority, *version, *end;
	size_t length;

	for (size_t used = 0; used < sizeof(request) - 1; used++) {
		ssize_t count;

		do {
			count = read(STDIN_FILENO, request + used, 1);
		} while (count < 0 && errno == EINTR);
		if (count != 1 || request[used] == '\0')
			return -1;
		if (used >= 3 && !memcmp(request + used - 3, "\r\n\r\n", 4)) {
			request[used + 1] = '\0';
			goto parsed;
		}
	}
	return -1;

parsed:
	if (strncmp(request, "CONNECT ", 8))
		return -1;
	authority = request + 8;
	version = strchr(authority, ' ');
	if (!version || (strncmp(version, " HTTP/1.1\r\n", 11) &&
			 strncmp(version, " HTTP/1.0\r\n", 11)))
		return -1;
	end = memchr(authority, ':', (size_t)(version - authority));
	if (!end || version - end != 4 || memcmp(end, ":443", 4))
		return -1;
	length = (size_t)(end - authority);
	if (!length || length >= 254 ||
	    strspn(authority, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-") != length)
		return -1;
	memcpy(host, authority, length);
	host[length] = '\0';
	return 0;
}

static bool public_ipv4(struct in_addr address)
{
	uint32_t ip = ntohl(address.s_addr);
	uint32_t first = ip >> 24;

	return first != 0 && first != 10 && first != 127 && first < 224 &&
	       (ip >> 22) != (0x64400000U >> 22) &&
	       (ip >> 16) != (0xa9fe0000U >> 16) &&
	       (ip >> 20) != (0xac100000U >> 20) &&
	       (ip >> 16) != (0xc0a80000U >> 16) &&
	       (ip >> 17) != (0xc6120000U >> 17);
}

static int resolve_target(const char *host, struct in_addr *address)
{
	int fds[2], status;
	ssize_t count;
	pid_t child, waited;

	if (pipe(fds) < 0)
		return -1;
	child = fork();
	if (child == 0) {
		close(fds[0]);
		alarm(8);
		if (sfw_resolve_ipv4(host, address) < 0 ||
		    write(fds[1], address, sizeof(*address)) != sizeof(*address))
			_exit(1);
		_exit(0);
	}
	close(fds[1]);
	if (child < 0) {
		close(fds[0]);
		return -1;
	}
	do {
		count = read(fds[0], address, sizeof(*address));
	} while (count < 0 && errno == EINTR);
	close(fds[0]);
	do {
		waited = waitpid(child, &status, 0);
	} while (waited < 0 && errno == EINTR);
	return count == sizeof(*address) && waited == child &&
	       WIFEXITED(status) && !WEXITSTATUS(status) && public_ipv4(*address) ? 0 : -1;
}

static int relay(int upstream)
{
	char buffer[4096];
	struct pollfd client = { .fd = STDIN_FILENO, .events = POLLIN };
	bool from_client = true, from_upstream = true;

	alarm(60);
	while (from_client || from_upstream) {
		int upstream_events = from_upstream ? pg_poll_events(upstream) : 0;

		if (upstream_events < 0 || (upstream_events & POLLERR))
			return -1;
		if (from_upstream && (upstream_events & (POLLIN | POLLHUP))) {
			ssize_t count = pg_recv(upstream, buffer, sizeof(buffer), SFW_FLAG_NONBLOCK);

			if (count < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
				return -1;
			if (count > 0 && write_client(buffer, (size_t)count) < 0)
				return -1;
			if (count > 0)
				alarm(60);
			if (count == 0) {
				from_upstream = false;
				shutdown(STDOUT_FILENO, SHUT_WR);
			}
		}
		if (poll(&client, 1, 50) < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (client.revents & (POLLERR | POLLNVAL))
			return -1;
		if (from_client && (client.revents & (POLLIN | POLLHUP))) {
			ssize_t count = read(STDIN_FILENO, buffer, sizeof(buffer));

			if (count < 0 && errno != EINTR)
				return -1;
			for (ssize_t sent = 0; sent < count;) {
				ssize_t written = pg_send(upstream, buffer + sent, (size_t)(count - sent));

				if (written <= 0)
					return -1;
				sent += written;
				alarm(60);
			}
			if (count == 0) {
				from_client = false;
				client.fd = -1;
				if (pg_shutdown(upstream, SHUT_WR) < 0)
					return -1;
			}
		}
	}
	return 0;
}

static int handle_client(char **hosts)
{
	struct sockaddr_in remote = { .sin_family = AF_INET, .sin_port = htons(443) };
	char host[254];
	int upstream, result = 1;

	signal(SIGPIPE, SIG_IGN);
	alarm(15);
	if (read_authority(host) < 0) {
		reply("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
		return 1;
	}
	for (; *hosts; hosts++)
		if (!strcasecmp(host, *hosts))
			goto allowed;
	reply("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
	return 1;

allowed:
	if (resolve_target(host, &remote.sin_addr) == 0) {
		upstream = pg_socket(AF_INET, SOCK_STREAM, 0);
		if (upstream >= 0) {
			if (pg_connect(upstream, &remote, NULL) == 0) {
				if (reply("HTTP/1.1 200 Connection Established\r\n\r\n") == 0 &&
				    relay(upstream) == 0)
					result = 0;
				pg_close(upstream);
				return result;
			}
			pg_close(upstream);
		}
	}
	reply("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
	return 1;
}

#define MAX_CLIENTS 8
static volatile sig_atomic_t stopping;

static void stop_listener(int sig)
{
	(void)sig;
	stopping = 1;
}

static int listen_loopback(uint16_t port, char **hosts)
{
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = htons(port),
	};
	struct sigaction action = { .sa_handler = stop_listener };
	pid_t children[MAX_CLIENTS] = {};
	struct pollfd listener = { .events = POLLIN };
	int reuse = 1;
	int result = 1;

	listener.fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
	if (listener.fd < 0)
		return 1;
	if (setsockopt(listener.fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0 ||
	    bind(listener.fd, (struct sockaddr *)&address, sizeof(address)) < 0 ||
	    listen(listener.fd, MAX_CLIENTS) < 0)
		goto out;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGTERM, &action, NULL) < 0 ||
	    sigaction(SIGINT, &action, NULL) < 0)
		goto out;

	fputs("sfw-connect: listening on loopback\n", stderr);

	while (!stopping) {
		int ready = poll(&listener, 1, 250);
		int client, slot = -1;
		pid_t child;

		if (ready < 0 && errno != EINTR)
			goto out;
		for (int i = 0; i < MAX_CLIENTS; i++) {
			if (children[i] && waitpid(children[i], NULL, WNOHANG) > 0)
				children[i] = 0;
			if (!children[i])
				slot = i;
		}
		if (ready <= 0 || stopping)
			continue;
		if (!(listener.revents & POLLIN))
			goto out;
		client = accept(listener.fd, NULL, NULL);
		if (client < 0) {
			if (errno == EINTR)
				continue;
			goto out;
		}
		if (slot >= 0) {
			child = fork();
			if (child == 0) {
				signal(SIGTERM, SIG_DFL);
				signal(SIGINT, SIG_DFL);
				if (stopping)
					_exit(0);
				close(listener.fd);
				if (dup2(client, STDIN_FILENO) < 0 ||
				    dup2(client, STDOUT_FILENO) < 0)
					_exit(1);
				if (client > STDOUT_FILENO)
					close(client);
				_exit(handle_client(hosts));
			}
			if (child > 0)
				children[slot] = child;
		}
		close(client);
	}
	result = 0;

out:
	close(listener.fd);
	for (int i = 0; i < MAX_CLIENTS; i++)
		if (children[i])
			kill(children[i], SIGTERM);
	for (int i = 0; i < MAX_CLIENTS; i++)
		if (children[i])
			while (waitpid(children[i], NULL, 0) < 0 && errno == EINTR) {}
	return result;
}

int main(int argc, char **argv)
{
	if (argc >= 4 && !strcmp(argv[1], "--listen")) {
		char *end;
		long port = strtol(argv[2], &end, 10);

		if (end == argv[2] || *end || port < 1024 || port > 65535)
			return 2;
		return listen_loopback((uint16_t)port, argv + 3);
	}
	if (argc < 2 || !strcmp(argv[1], "--listen"))
		return 2;
	return handle_client(argv + 1);
}
