// SPDX-License-Identifier: GPL-2.0
/*
 * pressure_e2e_test: End-to-End Verification Helper for Pressure & sfw
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <poll.h>
#include <netinet/tcp.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>

#include "../authd/authd_proto.h"
#include "../libpressure/libpressuresock.h"

#define PUB_FD_BIT 0x40000000

static int test_fd_random(void)
{
	int fds[14];
	int monotonic_adj = 0;

	printf("[test:fd-random] uid=%u euid=%u testing random non-monotonic FDs...\n",
	       getuid(), geteuid());

	for (int i = 0; i < 10; i++) {
		char p[64];
		snprintf(p, sizeof(p), "/tmp/pg_fd_test_%d_%d", getpid(), i);
		fds[i] = open(p, O_CREAT | O_RDWR | O_TRUNC, 0600);
		if (fds[i] < 0) {
			perror("open temp file");
			return 1;
		}
		unlink(p);
	}
	for (int i = 10; i < 14; i++) {
		fds[i] = socket(AF_UNIX, SOCK_STREAM, 0);
		if (fds[i] < 0) {
			perror("socket AF_UNIX");
			return 1;
		}
	}

	for (int i = 0; i < 14; i++) {
		if ((fds[i] & PUB_FD_BIT) == 0 || fds[i] < PUB_FD_BIT) {
			fprintf(stderr, "FAIL: fd[%d]=%d missing encrypted 31-bit flag\n",
				i, fds[i]);
			return 1;
		}
		if (i > 0 && fds[i] == fds[i - 1] + 1)
			monotonic_adj++;
		for (int j = 0; j < i; j++) {
			if (fds[i] == fds[j]) {
				fprintf(stderr, "FAIL: duplicate public FD %d\n", fds[i]);
				return 1;
			}
		}
	}
	if (monotonic_adj > 1) {
		fprintf(stderr, "FAIL: FDs counted upwards!\n");
		return 1;
	}

	/* Verify read/write/lseek/fcntl/dup on encrypted public FD */
	const char *msg = "pressure-encrypted-fd-ok";
	char buf[64] = {};
	if (write(fds[0], msg, strlen(msg)) != (ssize_t)strlen(msg) ||
	    lseek(fds[0], 0, SEEK_SET) < 0 ||
	    read(fds[0], buf, sizeof(buf) - 1) != (ssize_t)strlen(msg) ||
	    strcmp(buf, msg) != 0) {
		perror("FAIL: read/write on encrypted pub_fd");
		return 1;
	}

	if (fcntl(fds[0], F_SETFD, FD_CLOEXEC) < 0 ||
	    (fcntl(fds[0], F_GETFD) & FD_CLOEXEC) == 0) {
		perror("FAIL: fcntl FD_CLOEXEC on pub_fd");
		return 1;
	}

	int dup_pub = dup(fds[0]);
	if (dup_pub < PUB_FD_BIT || dup_pub == fds[0]) {
		fprintf(stderr, "FAIL: dup() did not issue fresh random pub_fd (%d)\n",
			dup_pub);
		return 1;
	}
	close(dup_pub);

	int first_fd = fds[0];
	for (int i = 0; i < 14; i++)
		close(fds[i]);

	int reopen_fd = open("/dev/null", O_RDWR);
	if (reopen_fd < PUB_FD_BIT || reopen_fd == first_fd) {
		fprintf(stderr, "FAIL: reopened FD reused old token (%d vs %d)\n",
			reopen_fd, first_fd);
		return 1;
	}
	close(reopen_fd);

	/* Verify /proc/self/fd enumeration is blocked */
	DIR *d = opendir("/proc/self/fd");
	if (d != NULL) {
		closedir(d);
		fprintf(stderr, "FAIL: /proc/self/fd enumeration was not blocked!\n");
		return 1;
	}

	printf("[test:fd-random] PASS (sample pub_fds: 0x%x, 0x%x, 0x%x, reopen=0x%x)\n",
	       fds[0], fds[1], fds[10], reopen_fd);
	return 0;
}

static int test_write_file(const char *path, const char *content)
{
	int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd < 0) {
		perror("write_file open");
		return 1;
	}
	if (write(fd, content, strlen(content)) != (ssize_t)strlen(content)) {
		perror("write_file write");
		close(fd);
		return 1;
	}
	close(fd);
	return 0;
}

static int test_expect_open_denied(const char *path)
{
	int fd = open(path, O_RDONLY);
	if (fd >= 0) {
		close(fd);
		fprintf(stderr, "FAIL: unexpected open success on protected '%s' (uid=%u)\n",
			path, getuid());
		return 1;
	}
	printf("[test:open-denied] PASS: '%s' hard-stopped (%s) for uid=%u\n",
	       path, strerror(errno), getuid());
	return 0;
}

static int test_expect_setuid_denied(uid_t target_uid)
{
	if (setuid(target_uid) == 0) {
		fprintf(stderr, "FAIL: unauthorized setuid(%u) succeeded!\n", target_uid);
		return 1;
	}
	printf("[test:setuid-denied] PASS: unauthorized setuid(%u) hard-stopped (%s)\n",
	       target_uid, strerror(errno));
	return 0;
}

static int test_dev_lockdown(void)
{
	const char *devs[] = {
		"/dev/input/event0",
		"/dev/uinput",
		"/dev/sr0",
		"/dev/tty1",
	};
	for (size_t i = 0; i < 4; i++) {
		/* Fork per probe so 4 denied probes don't SIGKILL the parent runner at strike 3 */
		pid_t p = fork();
		if (p == 0) {
			int fd = open(devs[i], O_RDONLY);
			if (fd >= 0) {
				close(fd);
				_exit(88);
			}
			_exit(0);
		}
		int st = 0;
		waitpid(p, &st, 0);
		if (WIFEXITED(st) && WEXITSTATUS(st) == 88) {
			fprintf(stderr, "FAIL: unauthorized /dev open succeeded on %s!\n",
				devs[i]);
			return 1;
		}
	}
	/* Note: let's run mknod in a forked child in case strike count hits 3! */
	pid_t pid = fork();
	if (pid == 0) {
		if (mknod("/tmp/rogue_disk", S_IFBLK | 0666, makedev(8, 0)) == 0) {
			unlink("/tmp/rogue_disk");
			_exit(99);
		}
		_exit(0);
	}
	int st = 0;
	waitpid(pid, &st, 0);
	if (WIFEXITED(st) && WEXITSTATUS(st) == 99) {
		fprintf(stderr, "FAIL: unauthorized mknod succeeded!\n");
		return 1;
	}
	printf("[test:dev-lockdown] PASS: /dev/input/event0, /dev/uinput, /dev/sr0, /dev/tty1 & mknod all hard-stopped\n");
	return 0;
}

static int test_sfw_loopback(uint16_t port, bool check_raw_blocked)
{
	if (check_raw_blocked) {
		pid_t p = fork();
		if (p == 0) {
			int raws = socket(AF_INET, SOCK_STREAM, 0);
			if (raws >= 0) {
				close(raws);
				_exit(55);
			}
			_exit(0);
		}
		int rst = 0;
		waitpid(p, &rst, 0);
		if (WIFEXITED(rst) && WEXITSTATUS(rst) == 55) {
			fprintf(stderr, "FAIL: raw socket(AF_INET) was NOT blocked!\n");
			return 1;
		}
	}

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = htons(port),
	};
	int srv = pg_socket(AF_INET, SOCK_STREAM, 0);
	if (srv < 0) {
		perror("pg_socket server");
		return 1;
	}
	uint64_t ltok = 0;
	if (pg_bind(srv, &addr, "lo") < 0 || pg_listen(srv, &ltok) < 0) {
		perror("pg_bind/pg_listen loopback");
		pg_close(srv);
		return 1;
	}

	pid_t cpid = fork();
	if (cpid == 0) {
		usleep(50000);
		int cli = pg_socket(AF_INET, SOCK_STREAM, 0);
		if (cli < 0 || pg_connect(cli, &addr, "lo") < 0) {
			perror("pg_connect loopback");
			_exit(2);
		}
		const char *ping = "PING_SFW_UNIX";
		char reply[32] = {};
		if (pg_send(cli, ping, strlen(ping)) != (ssize_t)strlen(ping) ||
		    pg_recv(cli, reply, sizeof(reply) - 1, 0) <= 0 ||
		    strcmp(reply, "PONG_SFW_OK") != 0)
			_exit(3);
		pg_close(cli);
		_exit(0);
	}

	struct sockaddr_in peer = {};
	int acc = pg_accept(srv, ltok, &peer);
	if (acc < 0) {
		perror("pg_accept");
		pg_close(srv);
		return 1;
	}
	char inbuf[32] = {};
	if (pg_recv(acc, inbuf, sizeof(inbuf) - 1, 0) <= 0 ||
	    strcmp(inbuf, "PING_SFW_UNIX") != 0) {
		fprintf(stderr, "FAIL: unexpected loopback payload '%s'\n", inbuf);
		return 1;
	}
	const char *pong = "PONG_SFW_OK";
	pg_send(acc, pong, strlen(pong));
	pg_close(acc);
	pg_close(srv);

	int cst = 0;
	waitpid(cpid, &cst, 0);
	if (!WIFEXITED(cst) || WEXITSTATUS(cst) != 0) {
		fprintf(stderr, "FAIL: loopback client failed (status=%d)\n", cst);
		return 1;
	}

	/* Also verify unapproved external IP connect (10.99.0.1:4444) is dropped by sfw */
	pid_t bpid = fork();
	if (bpid == 0) {
		struct sockaddr_in ext = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = inet_addr("10.99.0.1"),
			.sin_port = htons(4444),
		};
		int ecli = pg_socket(AF_INET, SOCK_STREAM, 0);
		if (ecli >= 0 && pg_connect(ecli, &ext, "eth0") == 0)
			_exit(77);
		_exit(0);
	}
	int bst = 0;
	waitpid(bpid, &bst, 0);
	if (WIFEXITED(bst) && WEXITSTATUS(bst) == 77) {
		fprintf(stderr, "FAIL: sfw allowed unauthorized external IP!\n");
		return 1;
	}

	printf("[test:sfw-loopback] PASS: 127.0.0.1:%u exchanged via root AF_UNIX sfw worker; raw AF_INET & unapproved WAN blocked\n",
	       port);
	return 0;
}

static int test_sfw_loopback6(uint16_t port, bool check_raw_blocked)
{
	if (check_raw_blocked) {
		pid_t p = fork();
		if (p == 0) {
			int raws = socket(AF_INET6, SOCK_STREAM, 0);
			if (raws >= 0) {
				close(raws);
				_exit(56);
			}
			_exit(0);
		}
		int rst = 0;
		waitpid(p, &rst, 0);
		if (WIFEXITED(rst) && WEXITSTATUS(rst) == 56) {
			fprintf(stderr, "FAIL: raw socket(AF_INET6) was NOT blocked!\n");
			return 1;
		}
	}

	struct sockaddr_in6 addr6 = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
		.sin6_port = htons(port),
	};
	int srv = pg_socket(AF_INET6, SOCK_STREAM, 0);
	if (srv < 0) {
		perror("pg_socket AF_INET6 server");
		return 1;
	}
	uint64_t ltok = 0;
	if (pg_bind6(srv, &addr6, "lo") < 0 || pg_listen(srv, &ltok) < 0) {
		perror("pg_bind6/pg_listen loopback");
		pg_close(srv);
		return 1;
	}

	pid_t cpid = fork();
	if (cpid == 0) {
		usleep(50000);
		int cli = pg_socket(AF_INET6, SOCK_STREAM, 0);
		if (cli < 0 || pg_connect6(cli, &addr6, "lo") < 0) {
			perror("pg_connect6 loopback");
			_exit(2);
		}
		const char *ping = "PING_SFW_IPV6";
		char reply[32] = {};
		if (pg_send(cli, ping, strlen(ping)) != (ssize_t)strlen(ping) ||
		    pg_recv(cli, reply, sizeof(reply) - 1, 0) <= 0 ||
		    strcmp(reply, "PONG_SFW_IPV6_OK") != 0)
			_exit(3);
		pg_close(cli);
		_exit(0);
	}

	struct sockaddr_in6 peer6 = {};
	int acc = pg_accept6(srv, ltok, &peer6);
	if (acc < 0) {
		perror("pg_accept6");
		pg_close(srv);
		return 1;
	}
	char inbuf[32] = {};
	if (pg_recv(acc, inbuf, sizeof(inbuf) - 1, 0) <= 0 ||
	    strcmp(inbuf, "PING_SFW_IPV6") != 0) {
		fprintf(stderr, "FAIL: unexpected IPv6 loopback payload '%s'\n", inbuf);
		return 1;
	}
	const char *pong = "PONG_SFW_IPV6_OK";
	pg_send(acc, pong, strlen(pong));
	pg_close(acc);
	pg_close(srv);

	int cst = 0;
	waitpid(cpid, &cst, 0);
	if (!WIFEXITED(cst) || WEXITSTATUS(cst) != 0) {
		fprintf(stderr, "FAIL: IPv6 loopback client failed (status=%d)\n", cst);
		return 1;
	}

	/* Verify unapproved external IPv6 ([2001:db8::99]:4444) is dropped by sfw */
	pid_t bpid = fork();
	if (bpid == 0) {
		struct sockaddr_in6 ext6 = {
			.sin6_family = AF_INET6,
			.sin6_port = htons(4444),
		};
		inet_pton(AF_INET6, "2001:db8::99", &ext6.sin6_addr);
		int ecli = pg_socket(AF_INET6, SOCK_STREAM, 0);
		if (ecli >= 0 && pg_connect6(ecli, &ext6, "eth0") == 0)
			_exit(78);
		_exit(0);
	}
	int bst = 0;
	waitpid(bpid, &bst, 0);
	if (WIFEXITED(bst) && WEXITSTATUS(bst) == 78) {
		fprintf(stderr, "FAIL: sfw allowed unauthorized external IPv6!\n");
		return 1;
	}

	printf("[test:sfw-loopback6] PASS: [::1]:%u exchanged via root AF_UNIX sfw worker; raw AF_INET6 & unapproved WAN6 blocked\n",
	       port);
	return 0;
}

static int test_shim_loopback6(uint16_t port)
{
	struct sockaddr_in6 addr6 = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
		.sin6_port = htons(port),
	};
	int srv = socket(AF_INET6, SOCK_STREAM, 0);
	if (srv < 0) {
		perror("shim socket(AF_INET6)");
		return 1;
	}
	if (bind(srv, (struct sockaddr *)&addr6, sizeof(addr6)) < 0 ||
	    listen(srv, 4) < 0) {
		perror("shim bind/listen AF_INET6");
		close(srv);
		return 1;
	}

	pid_t cpid = fork();
	if (cpid == 0) {
		usleep(50000);
		int cli = socket(AF_INET6, SOCK_STREAM, 0);
		if (cli < 0 ||
		    connect(cli, (struct sockaddr *)&addr6, sizeof(addr6)) < 0)
			_exit(2);
		const char *msg = "SHIM_IPV6_HELLO";
		char rep[32] = {};
		if (send(cli, msg, strlen(msg), 0) <= 0 ||
		    recv(cli, rep, sizeof(rep) - 1, 0) <= 0 ||
		    strcmp(rep, "SHIM_IPV6_ACK") != 0)
			_exit(3);
		close(cli);
		_exit(0);
	}

	struct sockaddr_in6 peer6 = {};
	socklen_t plen = sizeof(peer6);
	int acc = accept(srv, (struct sockaddr *)&peer6, &plen);
	if (acc < 0) {
		perror("shim accept AF_INET6");
		close(srv);
		return 1;
	}
	char buf[32] = {};
	if (recv(acc, buf, sizeof(buf) - 1, 0) <= 0 ||
	    strcmp(buf, "SHIM_IPV6_HELLO") != 0) {
		close(acc);
		close(srv);
		return 1;
	}
	const char *ack = "SHIM_IPV6_ACK";
	send(acc, ack, strlen(ack), 0);
	close(acc);
	close(srv);

	int cst = 0;
	waitpid(cpid, &cst, 0);
	if (!WIFEXITED(cst) || WEXITSTATUS(cst) != 0)
		return 1;
	printf("[test:shim-loopback6] PASS: LD_PRELOAD libpressureshim.so transparently brokered AF_INET6 [::1]:%u over AF_UNIX\n",
	       port);
	return 0;
}

static int test_shim_udp_poll(uint16_t port)
{
	struct sockaddr_in6 srv_a6 = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
		.sin6_port = htons(port),
	};
	int srv = socket(AF_INET6, SOCK_DGRAM, 0);
	int one = 1;
	if (srv < 0) {
		perror("shim UDP socket(AF_INET6)");
		return 1;
	}
	setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	setsockopt(srv, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
	if (bind(srv, (struct sockaddr *)&srv_a6, sizeof(srv_a6)) < 0) {
		perror("shim UDP bind");
		close(srv);
		return 1;
	}

	/* Verify non-blocking O_NONBLOCK returns EAGAIN on empty UDP socket */
	fcntl(srv, F_SETFL, O_NONBLOCK);
	char nbbuf[16];
	if (recvfrom(srv, nbbuf, sizeof(nbbuf), 0, NULL, NULL) >= 0 ||
	    errno != EAGAIN) {
		fprintf(stderr, "FAIL: non-blocking UDP recvfrom did not return EAGAIN (errno=%d)\n",
			errno);
		close(srv);
		return 1;
	}
	fcntl(srv, F_SETFL, 0);

	/* Bind client to ephemeral port 0 and verify getsockname() */
	struct sockaddr_in6 cli_a6 = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
		.sin6_port = 0,
	};
	int cli = socket(AF_INET6, SOCK_DGRAM, 0);
	if (cli < 0 || bind(cli, (struct sockaddr *)&cli_a6, sizeof(cli_a6)) < 0) {
		perror("shim UDP client bind(:0)");
		close(srv);
		if (cli >= 0) close(cli);
		return 1;
	}
	struct sockaddr_in6 bound_a6 = {};
	socklen_t blen = sizeof(bound_a6);
	if (getsockname(cli, (struct sockaddr *)&bound_a6, &blen) < 0 ||
	    ntohs(bound_a6.sin6_port) == 0) {
		fprintf(stderr, "FAIL: getsockname ephemeral port failed\n");
		close(cli);
		close(srv);
		return 1;
	}

	const char *q = "DNS_QUERY_OVER_SFW_UDP";
	if (sendto(cli, q, strlen(q), 0, (struct sockaddr *)&srv_a6,
		   sizeof(srv_a6)) != (ssize_t)strlen(q)) {
		perror("shim UDP sendto");
		close(cli);
		close(srv);
		return 1;
	}

	struct pollfd pfd = { .fd = srv, .events = POLLIN };
	if (poll(&pfd, 1, 1000) <= 0 || !(pfd.revents & POLLIN)) {
		fprintf(stderr, "FAIL: shim poll(POLLIN) did not report UDP datagram ready\n");
		close(cli);
		close(srv);
		return 1;
	}

	struct sockaddr_in6 from6 = {};
	socklen_t flen = sizeof(from6);
	char rbuf[64] = {};
	if (recvfrom(srv, rbuf, sizeof(rbuf) - 1, 0,
		     (struct sockaddr *)&from6, &flen) <= 0 ||
	    strcmp(rbuf, q) != 0 ||
	    from6.sin6_port != bound_a6.sin6_port) {
		fprintf(stderr, "FAIL: shim UDP recvfrom payload/peer mismatch\n");
		close(cli);
		close(srv);
		return 1;
	}

	const char *ans = "DNS_ANSWER_OK";
	sendto(srv, ans, strlen(ans), 0, (struct sockaddr *)&from6, sizeof(from6));
	memset(rbuf, 0, sizeof(rbuf));
	if (recvfrom(cli, rbuf, sizeof(rbuf) - 1, 0, NULL, NULL) <= 0 ||
	    strcmp(rbuf, ans) != 0) {
		fprintf(stderr, "FAIL: shim UDP reply mismatch\n");
		close(cli);
		close(srv);
		return 1;
	}
	close(cli);
	close(srv);
	printf("[test:shim-udp-poll] PASS: UDPv6 sendto/recvfrom, getsockname(:%u), O_NONBLOCK, setsockopt, and poll() verified\n",
	       ntohs(bound_a6.sin6_port));
	return 0;
}

static int test_privdrop_fd(const char *daemon_name)
{
	/* Runs as root prior to privilege drop (pressure_fd_mode == 0) */
	char path[64];
	snprintf(path, sizeof(path), "/tmp/preopen_%d.dat", getpid());
	int pre_fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
	if (pre_fd < 0 || (pre_fd & PUB_FD_BIT) != 0) {
		fprintf(stderr, "FAIL: expected unencrypted pre-drop FD (got %d)\n", pre_fd);
		return 1;
	}
	unlink(path);
	if (write(pre_fd, "PREOPEN_SURVIVED", 16) != 16)
		return 1;

	/* Request daemon transition ticket from pressure-authd and drop privileges */
	struct sockaddr_un sun = { .sun_family = AF_UNIX };
	snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", AUTHD_SOCK_PATH);
	int afd = socket(AF_UNIX, SOCK_STREAM, 0);
	struct authd_request req = {
		.magic = AUTHD_PROTO_MAGIC,
		.op = AUTHD_REQ_START_DAEMON,
		.target_pid = getpid(),
	};
	struct authd_response resp = {};
	snprintf(req.username, sizeof(req.username), "%s", daemon_name);
	if (afd < 0 || connect(afd, (struct sockaddr *)&sun, sizeof(sun)) < 0 ||
	    write(afd, &req, sizeof(req)) != sizeof(req) ||
	    read(afd, &resp, sizeof(resp)) != sizeof(resp) || resp.status < 0) {
		fprintf(stderr, "FAIL: authd START_DAEMON failed\n");
		return 1;
	}
	close(afd);

	if (setresgid(resp.pub_gid, resp.pub_gid, resp.pub_gid) < 0 ||
	    setresuid(resp.pub_uid, resp.pub_uid, resp.pub_uid) < 0) {
		perror("setresuid privdrop");
		return 1;
	}

	/* 1. Pre-opened FD (< PUB_FD_BIT) must still work cleanly after privilege drop! */
	char buf[32] = {};
	if (lseek(pre_fd, 0, SEEK_SET) < 0 ||
	    read(pre_fd, buf, 16) != 16 ||
	    strcmp(buf, "PREOPEN_SURVIVED") != 0) {
		perror("FAIL: pre-opened FD failed after privilege drop");
		return 1;
	}

	/* 2. Newly opened FDs in the same process must use 31-bit Feistel encryption! */
	int post_fd = open("/dev/null", O_RDWR);
	if (post_fd < PUB_FD_BIT) {
		fprintf(stderr, "FAIL: post-drop FD was not 31-bit Feistel encrypted (%d)\n",
			post_fd);
		return 1;
	}
	close(post_fd);

	/* 3. Once pre_fd is closed, that integer slot permanently rejects unencrypted use! */
	close(pre_fd);
	pid_t cp = fork();
	if (cp == 0) {
		char c;
		if (read(pre_fd, &c, 1) >= 0)
			_exit(91);
		_exit(0);
	}
	int st = 0;
	waitpid(cp, &st, 0);
	if (WIFEXITED(st) && WEXITSTATUS(st) == 91)
		return 1;

	printf("[test:privdrop-fd] PASS: pre-opened fd=%d survived privilege drop to '%s' (uid=%u), new fd=0x%x encrypted, closed slot locked\n",
	       pre_fd, daemon_name, getuid(), post_fd);
	return 0;
}

static int test_remote_containment(void)
{
	/* Simulate running server worker (e.g. nginx/php-fpm) becoming tainted REMOTE mid-run */
	int cfd = open("/sys/kernel/security/pressure/self_confine", O_WRONLY);
	if (cfd < 0) {
		perror("open self_confine");
		return 1;
	}
	const char *cmd = "confine remote 1 subj:daemon_webd\n";
	if (write(cfd, cmd, strlen(cmd)) < 0) {
		perror("write self_confine");
		close(cfd);
		return 1;
	}
	close(cfd);

	/* 1. REMOTE worker cannot connect to localhost 127.0.0.1 via sfw */
	pid_t p1 = fork();
	if (p1 == 0) {
		struct sockaddr_in lo = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = htons(19099),
		};
		int s = pg_socket(AF_INET, SOCK_STREAM, 0);
		if (s >= 0 && pg_connect(s, &lo, "lo") == 0)
			_exit(41);
		_exit(0);
	}
	int s1 = 0;
	waitpid(p1, &s1, 0);
	if (WIFEXITED(s1) && WEXITSTATUS(s1) == 41) {
		fprintf(stderr, "FAIL: REMOTE worker connected to localhost!\n");
		return 1;
	}

	/* 1b. REMOTE worker cannot connect to IPv6 localhost [::1] via sfw either */
	pid_t p1b = fork();
	if (p1b == 0) {
		struct sockaddr_in6 lo6 = {
			.sin6_family = AF_INET6,
			.sin6_addr = IN6ADDR_LOOPBACK_INIT,
			.sin6_port = htons(19099),
		};
		int s6 = pg_socket(AF_INET6, SOCK_STREAM, 0);
		if (s6 >= 0 && pg_connect6(s6, &lo6, "lo") == 0)
			_exit(45);
		_exit(0);
	}
	int s1b = 0;
	waitpid(p1b, &s1b, 0);
	if (WIFEXITED(s1b) && WEXITSTATUS(s1b) == 45) {
		fprintf(stderr, "FAIL: REMOTE worker connected to IPv6 [::1]!\n");
		return 1;
	}

	/* 2. REMOTE worker cannot allocate W+X or anonymous executable memory */
	pid_t p2 = fork();
	if (p2 == 0) {
		void *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (m != MAP_FAILED)
			_exit(42);
		_exit(0);
	}
	int s2 = 0;
	waitpid(p2, &s2, 0);
	if (WIFEXITED(s2) && WEXITSTATUS(s2) == 42) {
		fprintf(stderr, "FAIL: REMOTE worker mapped RWX shellcode memory!\n");
		return 1;
	}

	/* 3. REMOTE worker cannot execve("/bin/sh") */
	pid_t p3 = fork();
	if (p3 == 0) {
		char *const args[] = { "/bin/sh", "-c", "exit 43", NULL };
		execve("/bin/sh", args, NULL);
		/* Expected: execve denied with EACCES */
		_exit(errno == EACCES ? 0 : 44);
	}
	int s3 = 0;
	waitpid(p3, &s3, 0);
	if (!WIFEXITED(s3) || WEXITSTATUS(s3) != 0) {
		fprintf(stderr, "FAIL: REMOTE worker execve('/bin/sh') was not blocked with EACCES (st=0x%x)!\n",
			s3);
		return 1;
	}

	/* 4. REMOTE worker cannot create AF_VSOCK (host-to-vHSM) sockets */
	pid_t p4 = fork();
	if (p4 == 0) {
		int vs = socket(AF_VSOCK, SOCK_STREAM, 0);
		if (vs >= 0) {
			close(vs);
			_exit(46);
		}
		_exit(0);
	}
	int s4 = 0;
	waitpid(p4, &s4, 0);
	if (WIFEXITED(s4) && WEXITSTATUS(s4) == 46) {
		fprintf(stderr, "FAIL: REMOTE worker created AF_VSOCK socket!\n");
		return 1;
	}

	printf("[test:remote-containment] PASS: REMOTE worker blocked from localhost sfw (v4/v6), AF_VSOCK, RWX mmap, and execve\n");
	return 0;
}

static int test_three_strikes(void)
{
	/* Ignore SIGKILL handler attempt (proving kernel force_sig(SIGKILL) is uncatchable) */
	pid_t pid = fork();
	if (pid == 0) {
		char buf[16];
		signal(SIGKILL, SIG_IGN);
		/* Strike 1: sequential integer guess */
		if (read(6, buf, sizeof(buf)) < 0) {}
		/* Strike 2: forged 31-bit token guess */
		if (read(0x45671234, buf, sizeof(buf)) < 0) {}
		/* Strike 3: third bad FD guess -> immediate kernel force_sig(SIGKILL)! */
		if (read(0x5abc9876, buf, sizeof(buf)) < 0) {}
		/* Should NEVER reach _exit(0)! */
		_exit(0);
	}

	int status = 0;
	waitpid(pid, &status, 0);
	if (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL) {
		printf("[test:3-strikes] PASS: child pid=%d terminated by kernel SIGKILL on strike #3!\n",
		       pid);
		return 0;
	}
	fprintf(stderr, "FAIL: child was not SIGKILLed on 3rd strike (status=0x%x)\n",
		status);
	return 1;
}

static int netns_tcp_server(const char *bind_ip, uint16_t port,
			    const char *expect_peer_ip)
{
	int s = socket(AF_INET, SOCK_STREAM, 0);
	int one = 1;
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = inet_addr(bind_ip),
		.sin_port = htons(port),
	};
	if (s < 0) {
		perror("netns_tcp_server socket");
		return 1;
	}
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0 ||
	    listen(s, 4) < 0) {
		perror("netns_tcp_server bind/listen");
		close(s);
		return 1;
	}
	struct sockaddr_in peer = {};
	socklen_t plen = sizeof(peer);
	int c = accept(s, (struct sockaddr *)&peer, &plen);
	if (c < 0) {
		perror("netns_tcp_server accept");
		close(s);
		return 1;
	}
	char peer_str[32];
	inet_ntop(AF_INET, &peer.sin_addr, peer_str, sizeof(peer_str));
	if (expect_peer_ip && strcmp(expect_peer_ip, "*") != 0 &&
	    strcmp(peer_str, expect_peer_ip) != 0) {
		fprintf(stderr, "FAIL: server saw peer IP %s, expected NAT IP %s\n",
			peer_str, expect_peer_ip);
		close(c);
		close(s);
		return 1;
	}
	char buf[64] = {};
	ssize_t n = recv(c, buf, sizeof(buf) - 1, 0);
	if (n > 0) {
		char reply[96];
		snprintf(reply, sizeof(reply), "ACK_FROM_%s_TO_%s", bind_ip, peer_str);
		send(c, reply, strlen(reply), 0);
	}
	close(c);
	close(s);
	return 0;
}

static int netns_tcp_client(const char *dst_ip, uint16_t port,
			    const char *expect_substr)
{
	int s = socket(AF_INET, SOCK_STREAM, 0);
	struct timeval tv = { .tv_sec = 1, .tv_usec = 500000 };
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = inet_addr(dst_ip),
		.sin_port = htons(port),
	};
	if (s < 0)
		return 1;
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		close(s);
		return 1;
	}
	const char *hello = "NAT_PROBE";
	char reply[96] = {};
	if (send(s, hello, strlen(hello), 0) <= 0 ||
	    recv(s, reply, sizeof(reply) - 1, 0) <= 0) {
		close(s);
		return 1;
	}
	close(s);
	if (expect_substr && !strstr(reply, expect_substr)) {
		fprintf(stderr, "FAIL: unexpected NAT reply '%s' (wanted '%s')\n",
			reply, expect_substr);
		return 1;
	}
	printf("[test:sfw-nat] reply='%s'\n", reply);
	return 0;
}

static int netns_tcp_server6(const char *bind_ip6, uint16_t port,
			     const char *expect_peer_ip6)
{
	int s = socket(AF_INET6, SOCK_STREAM, 0);
	int one = 1;
	struct sockaddr_in6 sin6 = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(port),
	};
	if (s < 0 || inet_pton(AF_INET6, bind_ip6, &sin6.sin6_addr) != 1) {
		perror("netns_tcp_server6 socket/pton");
		if (s >= 0)
			close(s);
		return 1;
	}
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (bind(s, (struct sockaddr *)&sin6, sizeof(sin6)) < 0 ||
	    listen(s, 4) < 0) {
		perror("netns_tcp_server6 bind/listen");
		close(s);
		return 1;
	}
	struct sockaddr_in6 peer6 = {};
	socklen_t plen = sizeof(peer6);
	int c = accept(s, (struct sockaddr *)&peer6, &plen);
	if (c < 0) {
		perror("netns_tcp_server6 accept");
		close(s);
		return 1;
	}
	char peer_str[64];
	inet_ntop(AF_INET6, &peer6.sin6_addr, peer_str, sizeof(peer_str));
	if (expect_peer_ip6 && strcmp(expect_peer_ip6, "*") != 0) {
		struct in6_addr exp6;
		if (inet_pton(AF_INET6, expect_peer_ip6, &exp6) != 1 ||
		    memcmp(&peer6.sin6_addr, &exp6, 16) != 0) {
			fprintf(stderr, "FAIL: IPv6 server saw peer %s, expected NAT66 %s\n",
				peer_str, expect_peer_ip6);
			close(c);
			close(s);
			return 1;
		}
	}
	char buf[64] = {};
	ssize_t n = recv(c, buf, sizeof(buf) - 1, 0);
	if (n > 0) {
		char reply[128];
		snprintf(reply, sizeof(reply), "ACK6_FROM_[%s]_TO_[%s]",
			 bind_ip6, peer_str);
		send(c, reply, strlen(reply), 0);
	}
	close(c);
	close(s);
	return 0;
}

static int netns_tcp_client6(const char *dst_ip6, uint16_t port,
			     const char *expect_substr)
{
	int s = socket(AF_INET6, SOCK_STREAM, 0);
	struct timeval tv = { .tv_sec = 1, .tv_usec = 500000 };
	struct sockaddr_in6 sin6 = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(port),
	};
	if (s < 0 || inet_pton(AF_INET6, dst_ip6, &sin6.sin6_addr) != 1) {
		if (s >= 0)
			close(s);
		return 1;
	}
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	if (connect(s, (struct sockaddr *)&sin6, sizeof(sin6)) < 0) {
		close(s);
		return 1;
	}
	const char *hello = "NAT66_PROBE";
	char reply[128] = {};
	if (send(s, hello, strlen(hello), 0) <= 0 ||
	    recv(s, reply, sizeof(reply) - 1, 0) <= 0) {
		close(s);
		return 1;
	}
	close(s);
	if (expect_substr && !strstr(reply, expect_substr)) {
		fprintf(stderr, "FAIL: unexpected NAT66 reply '%s' (wanted '%s')\n",
			reply, expect_substr);
		return 1;
	}
	printf("[test:sfw-nat66] reply='%s'\n", reply);
	return 0;
}

static bool fill_unix_addr(const char *ep, struct sockaddr_un *sun,
			   socklen_t *len_out)
{
	memset(sun, 0, sizeof(*sun));
	sun->sun_family = AF_UNIX;
	if (!ep || !ep[0])
		return false;
	if (ep[0] == '@') {
		size_t n = strlen(ep + 1);
		if (n == 0 || n + 1 >= sizeof(sun->sun_path))
			return false;
		sun->sun_path[0] = '\0';
		memcpy(sun->sun_path + 1, ep + 1, n);
		*len_out = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + n);
		return true;
	}
	size_t n = strlen(ep);
	if (n >= sizeof(sun->sun_path))
		return false;
	memcpy(sun->sun_path, ep, n + 1);
	*len_out = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + n + 1);
	return true;
}

static int run_expect_unix_deny(int (*fn)(void *), void *arg, const char *desc)
{
	pid_t p = fork();
	if (p < 0)
		return 1;
	if (p == 0) {
		int rc = fn(arg);
		_exit(rc == 0 ? 77 : 0);
	}
	int st = 0;
	waitpid(p, &st, 0);
	if (WIFEXITED(st) && WEXITSTATUS(st) == 77) {
		fprintf(stderr, "FAIL: AF_UNIX operation '%s' was NOT denied!\n", desc);
		return 1;
	}
	return 0;
}

static int probe_unix_sock_stream(void *arg)
{
	(void)arg;
	int s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s >= 0) {
		close(s);
		return 0;
	}
	return -1;
}

static int probe_unix_sock_dgram(void *arg)
{
	(void)arg;
	int s = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (s >= 0) {
		close(s);
		return 0;
	}
	return -1;
}

static int probe_unix_pair_stream(void *arg)
{
	(void)arg;
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
		close(sv[0]);
		close(sv[1]);
		return 0;
	}
	return -1;
}

static int probe_unix_pair_dgram(void *arg)
{
	(void)arg;
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0) {
		close(sv[0]);
		close(sv[1]);
		return 0;
	}
	return -1;
}

static int test_unix_deny_create(void)
{
	if (run_expect_unix_deny(probe_unix_sock_stream, NULL, "socket(AF_UNIX, SOCK_STREAM)") != 0 ||
	    run_expect_unix_deny(probe_unix_sock_dgram, NULL, "socket(AF_UNIX, SOCK_DGRAM)") != 0 ||
	    run_expect_unix_deny(probe_unix_pair_stream, NULL, "socketpair(AF_UNIX, SOCK_STREAM)") != 0 ||
	    run_expect_unix_deny(probe_unix_pair_dgram, NULL, "socketpair(AF_UNIX, SOCK_DGRAM)") != 0)
		return 1;
	printf("[test:unix-deny-create] PASS: unauthorized subject blocked from AF_UNIX stream/dgram & socketpair\n");
	return 0;
}

static int probe_unix_bind_ep(void *arg)
{
	const char *ep = (const char *)arg;
	struct sockaddr_un sun;
	socklen_t slen = 0;
	int s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0 || !fill_unix_addr(ep, &sun, &slen))
		return -1;
	if (ep[0] == '/')
		unlink(ep);
	int rc = bind(s, (struct sockaddr *)&sun, slen);
	close(s);
	if (rc == 0 && ep[0] == '/')
		unlink(ep);
	return rc;
}

static int probe_unix_connect_ep(void *arg)
{
	const char *ep = (const char *)arg;
	struct sockaddr_un sun;
	socklen_t slen = 0;
	int s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0 || !fill_unix_addr(ep, &sun, &slen))
		return -1;
	int rc = connect(s, (struct sockaddr *)&sun, slen);
	close(s);
	return rc;
}

static int probe_unix_sendto_ep(void *arg)
{
	const char *ep = (const char *)arg;
	struct sockaddr_un sun;
	socklen_t slen = 0;
	int s = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (s < 0 || !fill_unix_addr(ep, &sun, &slen))
		return -1;
	ssize_t n = sendto(s, "PROBE", 5, 0, (struct sockaddr *)&sun, slen);
	close(s);
	return n >= 0 ? 0 : -1;
}

static int test_unix_create_only(const char *path_stream, const char *abs_stream,
				 const char *path_dgram, const char *abs_dgram)
{
	int s1 = socket(AF_UNIX, SOCK_STREAM, 0);
	int s2 = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (s1 < 0 || s2 < 0) {
		perror("FAIL: create-only subject could not create AF_UNIX sockets");
		if (s1 >= 0) close(s1);
		if (s2 >= 0) close(s2);
		return 1;
	}
	close(s1);
	close(s2);

	if (run_expect_unix_deny(probe_unix_pair_stream, NULL, "create-only socketpair") != 0 ||
	    run_expect_unix_deny(probe_unix_bind_ep, (void *)"/tmp/probe_unauth.sock", "bind pathname") != 0 ||
	    run_expect_unix_deny(probe_unix_bind_ep, (void *)"@probe_unauth_abs", "bind abstract") != 0 ||
	    run_expect_unix_deny(probe_unix_connect_ep, (void *)path_stream, "connect pathname") != 0 ||
	    run_expect_unix_deny(probe_unix_connect_ep, (void *)abs_stream, "connect abstract") != 0 ||
	    run_expect_unix_deny(probe_unix_sendto_ep, (void *)path_dgram, "dgram sendto pathname") != 0 ||
	    run_expect_unix_deny(probe_unix_sendto_ep, (void *)abs_dgram, "dgram sendto abstract") != 0)
		return 1;

	printf("[test:unix-create-only] PASS: create-only subject created sockets but was blocked from socketpair, pathname/abstract bind/connect & dgram sendto\n");
	return 0;
}

static int test_unix_stream_server(const char *ep, const char *expect_msg,
				   const char *reply_msg, int accept_cnt)
{
	struct sockaddr_un sun;
	socklen_t slen = 0;
	struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };

	if (!fill_unix_addr(ep, &sun, &slen))
		return 1;
	if (ep[0] == '/')
		unlink(ep);
	int s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0) {
		perror("unix-stream-server socket");
		return 1;
	}
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (bind(s, (struct sockaddr *)&sun, slen) < 0 || listen(s, 8) < 0) {
		perror("unix-stream-server bind/listen");
		close(s);
		return 1;
	}
	if (ep[0] == '/')
		chmod(ep, 0666);

	for (int i = 0; i < accept_cnt; i++) {
		int c = accept(s, NULL, NULL);
		if (c < 0) {
			perror("unix-stream-server accept");
			close(s);
			return 1;
		}
		setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		char buf[128] = {};
		ssize_t n = recv(c, buf, sizeof(buf) - 1, 0);
		if (expect_msg && strcmp(expect_msg, "*") != 0) {
			if (n <= 0 || strcmp(buf, expect_msg) != 0) {
				fprintf(stderr, "FAIL: unix-stream-server('%s') got '%s' (want '%s')\n",
					ep, buf, expect_msg);
				close(c);
				close(s);
				return 1;
			}
		} else if (n < 0) {
			perror("unix-stream-server recv");
			close(c);
			close(s);
			return 1;
		}
		/* Descriptor-only probes can close the stream without a request. */
		if (n > 0 && strcmp(buf, "CLOSE_CLEAN") != 0 &&
		    reply_msg && reply_msg[0])
			send(c, reply_msg, strlen(reply_msg), MSG_NOSIGNAL);
		close(c);
	}
	close(s);
	if (ep[0] == '/')
		unlink(ep);
	return 0;
}

static int test_unix_stream_client(const char *ep, const char *send_msg,
				   const char *expect_reply)
{
	struct sockaddr_un sun;
	socklen_t slen = 0;
	struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };

	if (!fill_unix_addr(ep, &sun, &slen))
		return 1;
	int s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0) {
		perror("unix-stream-client socket");
		return 1;
	}
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (connect(s, (struct sockaddr *)&sun, slen) < 0) {
		perror("unix-stream-client connect");
		close(s);
		return 1;
	}
	if (send(s, send_msg, strlen(send_msg), 0) != (ssize_t)strlen(send_msg)) {
		perror("unix-stream-client send");
		close(s);
		return 1;
	}
	char rep[128] = {};
	ssize_t n = recv(s, rep, sizeof(rep) - 1, 0);
	close(s);
	if (n <= 0 || strcmp(rep, expect_reply) != 0) {
		fprintf(stderr, "FAIL: unix-stream-client('%s') got '%s' (want '%s')\n",
			ep, rep, expect_reply);
		return 1;
	}
	printf("[test:unix-stream-client] PASS: '%s' exchanged '%s' -> '%s'\n",
	       ep, send_msg, rep);
	return 0;
}

static int test_unix_dgram_server(const char *ep, const char *expect_msg)
{
	struct sockaddr_un sun;
	socklen_t slen = 0;
	struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };

	if (!fill_unix_addr(ep, &sun, &slen))
		return 1;
	if (ep[0] == '/')
		unlink(ep);
	int s = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("unix-dgram-server socket");
		return 1;
	}
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (bind(s, (struct sockaddr *)&sun, slen) < 0) {
		perror("unix-dgram-server bind");
		close(s);
		return 1;
	}
	if (ep[0] == '/')
		chmod(ep, 0666);

	char buf[128] = {};
	ssize_t n = recvfrom(s, buf, sizeof(buf) - 1, 0, NULL, NULL);
	close(s);
	if (ep[0] == '/')
		unlink(ep);
	if (n <= 0 || strcmp(buf, expect_msg) != 0) {
		fprintf(stderr, "FAIL: unix-dgram-server('%s') got '%s' (want '%s')\n",
			ep, buf, expect_msg);
		return 1;
	}
	printf("[test:unix-dgram-server] PASS: '%s' received authorized datagram '%s'\n",
	       ep, buf);
	return 0;
}

static int test_unix_dgram_client(const char *ep, const char *send_msg)
{
	struct sockaddr_un sun;
	socklen_t slen = 0;

	if (!fill_unix_addr(ep, &sun, &slen))
		return 1;
	int s = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("unix-dgram-client socket");
		return 1;
	}
	ssize_t n = sendto(s, send_msg, strlen(send_msg), 0,
			   (struct sockaddr *)&sun, slen);
	close(s);
	if (n != (ssize_t)strlen(send_msg)) {
		perror("unix-dgram-client sendto");
		return 1;
	}
	return 0;
}

static int test_unix_passfd_sender(const char *carrier_ep, const char *target_ep)
{
	struct sockaddr_un tsun, csun;
	socklen_t tlen = 0, clen = 0;

	if (!fill_unix_addr(target_ep, &tsun, &tlen) ||
	    !fill_unix_addr(carrier_ep, &csun, &clen))
		return 1;
	int tfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (tfd < 0 || connect(tfd, (struct sockaddr *)&tsun, tlen) < 0) {
		perror("unix-passfd-sender connect target");
		if (tfd >= 0) close(tfd);
		return 1;
	}
	int cfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (cfd < 0 || connect(cfd, (struct sockaddr *)&csun, clen) < 0) {
		perror("unix-passfd-sender connect carrier");
		close(tfd);
		if (cfd >= 0) close(cfd);
		return 1;
	}

	char dummy = 'F';
	struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
	union {
		char buf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} u;
	memset(&u, 0, sizeof(u));
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = u.buf,
		.msg_controllen = sizeof(u.buf),
	};
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &tfd, sizeof(int));

	ssize_t n = sendmsg(cfd, &msg, 0);
	/* Keep target alive briefly while receiver attempts recvmsg */
	usleep(200000);
	if (send(tfd, "CLOSE_CLEAN", 11, 0) < 0) {}
	close(cfd);
	close(tfd);
	return n > 0 ? 0 : 1;
}

static int test_unix_passfd_receiver(const char *carrier_ep)
{
	struct sockaddr_un csun;
	socklen_t clen = 0;
	struct timeval tv = { .tv_sec = 8, .tv_usec = 0 };

	if (!fill_unix_addr(carrier_ep, &csun, &clen))
		return 1;
	if (carrier_ep[0] == '/')
		unlink(carrier_ep);
	int srv = socket(AF_UNIX, SOCK_STREAM, 0);
	if (srv < 0) {
		perror("unix-passfd-receiver socket");
		return 1;
	}
	setsockopt(srv, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (bind(srv, (struct sockaddr *)&csun, clen) < 0 || listen(srv, 4) < 0) {
		perror("unix-passfd-receiver bind/listen");
		close(srv);
		return 1;
	}
	if (carrier_ep[0] == '/')
		chmod(carrier_ep, 0666);

	int cli = accept(srv, NULL, NULL);
	if (cli < 0) {
		perror("unix-passfd-receiver accept");
		close(srv);
		return 1;
	}
	setsockopt(cli, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	char dummy = 0;
	struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
	union {
		char buf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} u;
	memset(&u, 0, sizeof(u));
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = u.buf,
		.msg_controllen = sizeof(u.buf),
	};
	ssize_t n = recvmsg(cli, &msg, 0);
	int got_fd = -1;
	if (n > 0) {
		for (struct cmsghdr *cm = CMSG_FIRSTHDR(&msg); cm;
		     cm = CMSG_NXTHDR(&msg, cm)) {
			if (cm->cmsg_level == SOL_SOCKET &&
			    cm->cmsg_type == SCM_RIGHTS &&
			    cm->cmsg_len >= CMSG_LEN(sizeof(int))) {
				memcpy(&got_fd, CMSG_DATA(cm), sizeof(int));
			}
		}
	}
	close(cli);
	close(srv);
	if (carrier_ep[0] == '/')
		unlink(carrier_ep);

	if (got_fd >= 0) {
		close(got_fd);
		fprintf(stderr, "FAIL: unauthorized subject received passed AF_UNIX FD (%d) via SCM_RIGHTS!\n",
			got_fd);
		return 1;
	}
	if (n != 1 || dummy != 'F' || !(msg.msg_flags & MSG_CTRUNC)) {
		fprintf(stderr, "FAIL: expected carrier payload with SCM_RIGHTS truncated\n");
		return 1;
	}
	printf("[test:unix-passfd-deny] PASS: unauthorized SCM_RIGHTS AF_UNIX descriptor blocked by file_receive\n");
	return 0;
}

static int probe_inherited_write(void *arg)
{
	int fd = *(int *)arg;
	ssize_t n = write(fd, "HIJACK", 6);
	return n >= 0 ? 0 : -1;
}

static int probe_inherited_read(void *arg)
{
	int fd = *(int *)arg;
	char buf[16];
	ssize_t n = read(fd, buf, sizeof(buf));
	return n >= 0 ? 0 : -1;
}

static int test_unix_inherit_deny(const char *target_ep, const char *daemon_name)
{
	struct sockaddr_un tsun, asun = { .sun_family = AF_UNIX };
	socklen_t tlen = 0;

	if (!fill_unix_addr(target_ep, &tsun, &tlen))
		return 1;
	int tfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (tfd < 0 || connect(tfd, (struct sockaddr *)&tsun, tlen) < 0) {
		perror("unix-inherit-deny pre-drop connect");
		if (tfd >= 0) close(tfd);
		return 1;
	}

	snprintf(asun.sun_path, sizeof(asun.sun_path), "%s", AUTHD_SOCK_PATH);
	int afd = socket(AF_UNIX, SOCK_STREAM, 0);
	struct authd_request req = {
		.magic = AUTHD_PROTO_MAGIC,
		.op = AUTHD_REQ_START_DAEMON,
		.target_pid = getpid(),
	};
	struct authd_response resp = {};
	snprintf(req.username, sizeof(req.username), "%s", daemon_name);
	if (afd < 0 || connect(afd, (struct sockaddr *)&asun, sizeof(asun)) < 0 ||
	    write(afd, &req, sizeof(req)) != sizeof(req) ||
	    read(afd, &resp, sizeof(resp)) != sizeof(resp) || resp.status < 0) {
		fprintf(stderr, "FAIL: unix-inherit-deny authd START_DAEMON failed\n");
		close(tfd);
		if (afd >= 0) close(afd);
		return 1;
	}
	close(afd);

	if (setresgid(resp.pub_gid, resp.pub_gid, resp.pub_gid) < 0 ||
	    setresuid(resp.pub_uid, resp.pub_uid, resp.pub_uid) < 0) {
		perror("unix-inherit-deny setresuid");
		close(tfd);
		return 1;
	}

	if (run_expect_unix_deny(probe_inherited_write, &tfd, "inherited AF_UNIX write") != 0 ||
	    run_expect_unix_deny(probe_inherited_read, &tfd, "inherited AF_UNIX read") != 0) {
		close(tfd);
		return 1;
	}
	close(tfd);
	printf("[test:unix-inherit-deny] PASS: inherited AF_UNIX descriptor to '%s' blocked for '%s'\n",
	       target_ep, daemon_name);
	return 0;
}

struct router_probe_ctx {
	const char *cfg_dir;
	const char *cfg_file;
	const char *admin_sock;
};

static int probe_router_open_ro(void *arg)
{
	struct router_probe_ctx *c = (struct router_probe_ctx *)arg;
	int fd = open(c->cfg_file, O_RDONLY);
	if (fd >= 0) { close(fd); return 0; }
	return -1;
}

static int probe_router_open_rw(void *arg)
{
	struct router_probe_ctx *c = (struct router_probe_ctx *)arg;
	int fd = open(c->cfg_file, O_RDWR);
	if (fd >= 0) { close(fd); return 0; }
	return -1;
}

static int probe_router_create(void *arg)
{
	struct router_probe_ctx *c = (struct router_probe_ctx *)arg;
	char p[160];
	snprintf(p, sizeof(p), "%s/rogue_%d.conf", c->cfg_dir, getpid());
	int fd = open(p, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd >= 0) { close(fd); unlink(p); return 0; }
	return -1;
}

static int probe_router_rename(void *arg)
{
	struct router_probe_ctx *c = (struct router_probe_ctx *)arg;
	char src[96];
	snprintf(src, sizeof(src), "/tmp/rogue_ren_%d.conf", getpid());
	int fd = open(src, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd < 0)
		return -1;
	if (write(fd, "HIJACK", 6) < 0) {}
	close(fd);
	int rc = rename(src, c->cfg_file);
	unlink(src);
	return rc == 0 ? 0 : -1;
}

static int probe_router_unlink(void *arg)
{
	struct router_probe_ctx *c = (struct router_probe_ctx *)arg;
	return unlink(c->cfg_file) == 0 ? 0 : -1;
}

static int probe_router_truncate(void *arg)
{
	struct router_probe_ctx *c = (struct router_probe_ctx *)arg;
	return truncate(c->cfg_file, 0) == 0 ? 0 : -1;
}

static int probe_router_sock(void *arg)
{
	struct router_probe_ctx *c = (struct router_probe_ctx *)arg;
	struct sockaddr_un sun;
	socklen_t slen = 0;
	int s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0 || !fill_unix_addr(c->admin_sock, &sun, &slen))
		return -1;
	int rc = connect(s, (struct sockaddr *)&sun, slen);
	close(s);
	return rc == 0 ? 0 : -1;
}

static int test_router_admin_deny(const char *cfg_dir, const char *cfg_file,
				  const char *admin_sock, const char *ctx_name)
{
	struct router_probe_ctx ctx = {
		.cfg_dir = cfg_dir,
		.cfg_file = cfg_file,
		.admin_sock = admin_sock,
	};
	if (run_expect_unix_deny(probe_router_open_ro, &ctx, "router open O_RDONLY") != 0 ||
	    run_expect_unix_deny(probe_router_open_rw, &ctx, "router open O_RDWR") != 0 ||
	    run_expect_unix_deny(probe_router_create, &ctx, "router inode create") != 0 ||
	    run_expect_unix_deny(probe_router_rename, &ctx, "router rename replace") != 0 ||
	    run_expect_unix_deny(probe_router_unlink, &ctx, "router unlink") != 0 ||
	    run_expect_unix_deny(probe_router_truncate, &ctx, "router truncate") != 0 ||
	    run_expect_unix_deny(probe_router_sock, &ctx, "router admin socket") != 0) {
		fprintf(stderr, "FAIL: router admin access was not fully denied for '%s'\n",
			ctx_name);
		return 1;
	}
	printf("[test:router-admin-deny] PASS (%s): open/create/rename/unlink/truncate & admin socket all denied\n",
	       ctx_name);
	return 0;
}

static int probe_mmap_shared_write(void *arg)
{
	int fd = *(int *)arg;
	void *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (m != MAP_FAILED) {
		munmap(m, 4096);
		return 0;
	}
	return -1;
}

static int test_router_admin_allow(const char *cfg_dir, const char *cfg_file,
				   const char *admin_sock)
{
	char tmp_p[160], del_p[160], buf[64] = {};
	int fd = open(cfg_file, O_RDWR);
	if (fd < 0) {
		perror("FAIL: tty1 routeradmin open(cfg_file, O_RDWR)");
		return 1;
	}
	if (read(fd, buf, sizeof(buf) - 1) <= 0) {
		perror("FAIL: tty1 routeradmin read(cfg_file)");
		close(fd);
		return 1;
	}
	if (lseek(fd, 0, SEEK_SET) < 0 || write(fd, "ROUTER_TTY1_OK\n", 15) != 15) {
		perror("FAIL: tty1 routeradmin write(cfg_file)");
		close(fd);
		return 1;
	}

	/* Verify write-capable MAP_SHARED mapping is denied (no mmap_write granted!) */
	if (run_expect_unix_deny(probe_mmap_shared_write, &fd,
				 "router protected MAP_SHARED PROT_WRITE") != 0) {
		close(fd);
		return 1;
	}

	/* Verify inode create, atomic rename, and unlink succeed on verified tty1 */
	snprintf(tmp_p, sizeof(tmp_p), "%s/atomic_new.conf", cfg_dir);
	snprintf(del_p, sizeof(del_p), "%s/del_test.conf", cfg_dir);
	int nfd = open(tmp_p, O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (nfd < 0 || write(nfd, "ROUTER_TTY1_RENAMED\n", 20) != 20) {
		perror("FAIL: tty1 routeradmin create new file");
		if (nfd >= 0) close(nfd);
		close(fd);
		return 1;
	}
	close(nfd);
	if (rename(tmp_p, cfg_file) < 0) {
		perror("FAIL: tty1 routeradmin rename replace");
		unlink(tmp_p);
		close(fd);
		return 1;
	}
	int dfd = open(del_p, O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (dfd < 0) {
		perror("FAIL: tty1 routeradmin create del_test");
		close(fd);
		return 1;
	}
	close(dfd);
	if (unlink(del_p) < 0) {
		perror("FAIL: tty1 routeradmin unlink");
		close(fd);
		return 1;
	}

	/* Verify authorized admin AF_UNIX socket succeeds on verified tty1 */
	struct sockaddr_un sun;
	socklen_t slen = 0;
	if (!fill_unix_addr(admin_sock, &sun, &slen)) {
		close(fd);
		return 1;
	}
	int s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0 || connect(s, (struct sockaddr *)&sun, slen) < 0) {
		perror("FAIL: tty1 routeradmin connect admin_sock");
		if (s >= 0) close(s);
		close(fd);
		return 1;
	}
	char rep[64] = {};
	if (send(s, "ROUTER_RELOAD", 13, 0) != 13 ||
	    recv(s, rep, sizeof(rep) - 1, 0) <= 0 ||
	    strcmp(rep, "ROUTER_ADMIN_ACK") != 0) {
		fprintf(stderr, "FAIL: tty1 routeradmin socket RPC failed ('%s')\n", rep);
		close(s);
		close(fd);
		return 1;
	}

	/* Verify detach revocation (setsid()) revokes already-open file & socket FDs immediately! */
	pid_t dp = fork();
	if (dp == 0) {
		if (setsid() < 0)
			_exit(91);
		char b[16];
		if (read(fd, b, sizeof(b)) >= 0)
			_exit(92);
		if (write(fd, "DETACH", 6) >= 0)
			_exit(93);
		if (send(s, "DETACH", 6, 0) >= 0)
			_exit(94);
		_exit(0);
	}
	int dst = 0;
	waitpid(dp, &dst, 0);
	close(s);
	close(fd);
	if (WIFEXITED(dst) && WEXITSTATUS(dst) >= 91) {
		fprintf(stderr, "FAIL: detached child (setsid) retained tty1 authority (code=%d)!\n",
			WEXITSTATUS(dst));
		return 1;
	}

	printf("[test:router-admin-allow] PASS: verified tty1 allowed open/read/write/create/rename/unlink/admin-sock, blocked MAP_SHARED write & revoked on setsid() detach\n");
	return 0;
}

static int test_router_hold_across_logout(const char *cfg_file,
					  const char *admin_sock,
					  const char *result_file)
{
	int fd = open(cfg_file, O_RDWR);
	if (fd < 0) {
		perror("hold-across-logout open cfg_file");
		return 1;
	}
	struct sockaddr_un sun;
	socklen_t slen = 0;
	if (!fill_unix_addr(admin_sock, &sun, &slen)) {
		close(fd);
		return 1;
	}
	int s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0 || connect(s, (struct sockaddr *)&sun, slen) < 0) {
		perror("hold-across-logout connect admin_sock");
		if (s >= 0) close(s);
		close(fd);
		return 1;
	}

	/* Keep the probe alive when the controlling terminal hangs up. */
	if (signal(SIGHUP, SIG_IGN) == SIG_ERR) {
		close(s);
		close(fd);
		return 1;
	}
	pid_t bg = fork();
	if (bg < 0) {
		close(s);
		close(fd);
		return 1;
	}
	if (bg == 0) {
		/* Wait until session leader exits and press login revokes the session */
		sleep(2);
		int ok = 1;
		pid_t c1 = fork();
		if (c1 == 0) {
			char b[16];
			_exit(read(fd, b, sizeof(b)) >= 0 ? 81 : 0);
		}
		int st1 = 0;
		waitpid(c1, &st1, 0);
		if (WIFEXITED(st1) && WEXITSTATUS(st1) == 81)
			ok = 0;

		pid_t c2 = fork();
		if (c2 == 0) {
			_exit(write(fd, "AFTER_LOGOUT", 12) >= 0 ? 82 : 0);
		}
		int st2 = 0;
		waitpid(c2, &st2, 0);
		if (WIFEXITED(st2) && WEXITSTATUS(st2) == 82)
			ok = 0;

		pid_t c3 = fork();
		if (c3 == 0) {
			_exit(send(s, "AFTER_LOGOUT", 12, 0) >= 0 ? 83 : 0);
		}
		int st3 = 0;
		waitpid(c3, &st3, 0);
		if (WIFEXITED(st3) && WEXITSTATUS(st3) == 83)
			ok = 0;

		int rf = open(result_file, O_CREAT | O_WRONLY | O_TRUNC, 0644);
		if (rf >= 0) {
			const char *res = ok ? "POST_LOGOUT_REVOKED_OK\n" :
					       "POST_LOGOUT_LEAKED_FAIL\n";
			if (write(rf, res, strlen(res)) < 0) {}
			close(rf);
		}
		close(s);
		close(fd);
		_exit(ok ? 0 : 1);
	}
	/* Session leader exits immediately while background child holds open FDs */
	close(s);
	close(fd);
	return 0;
}

static int test_router_expiry(const char *cfg_file, int wait_sec)
{
	int fd = open(cfg_file, O_RDWR);
	char b[16];
	if (fd < 0 || read(fd, b, sizeof(b)) <= 0) {
		perror("router-expiry initial open/read");
		if (fd >= 0) close(fd);
		return 1;
	}
	sleep((unsigned int)wait_sec);
	if (run_expect_unix_deny(probe_inherited_read, &fd, "post-expiry read") != 0 ||
	    run_expect_unix_deny(probe_inherited_write, &fd, "post-expiry write") != 0) {
		close(fd);
		return 1;
	}
	close(fd);
	printf("[test:router-expiry] PASS: open FD on protected file revoked after %ds grant TTL expiry\n",
	       wait_sec);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2)
		return 1;
	if (strcmp(argv[1], "netns-server") == 0 && argc >= 5)
		return netns_tcp_server(argv[2], (uint16_t)atoi(argv[3]), argv[4]);
	if (strcmp(argv[1], "netns-client") == 0 && argc >= 5)
		return netns_tcp_client(argv[2], (uint16_t)atoi(argv[3]), argv[4]);
	if (strcmp(argv[1], "netns-server6") == 0 && argc >= 5)
		return netns_tcp_server6(argv[2], (uint16_t)atoi(argv[3]), argv[4]);
	if (strcmp(argv[1], "netns-client6") == 0 && argc >= 5)
		return netns_tcp_client6(argv[2], (uint16_t)atoi(argv[3]), argv[4]);
	if (strcmp(argv[1], "fd-random") == 0)
		return test_fd_random();
	if (strcmp(argv[1], "write-file") == 0 && argc >= 4)
		return test_write_file(argv[2], argv[3]);
	if (strcmp(argv[1], "expect-open-denied") == 0 && argc >= 3)
		return test_expect_open_denied(argv[2]);
	if (strcmp(argv[1], "expect-setuid-denied") == 0 && argc >= 3)
		return test_expect_setuid_denied((uid_t)strtoul(argv[2], NULL, 10));
	if (strcmp(argv[1], "dev-lockdown") == 0)
		return test_dev_lockdown();
	if (strcmp(argv[1], "sfw-loopback") == 0 && argc >= 3)
		return test_sfw_loopback((uint16_t)atoi(argv[2]),
					 argc >= 4 && strcmp(argv[3], "check-raw") == 0);
	if (strcmp(argv[1], "sfw-loopback6") == 0 && argc >= 3)
		return test_sfw_loopback6((uint16_t)atoi(argv[2]),
					  argc >= 4 && strcmp(argv[3], "check-raw") == 0);
	if (strcmp(argv[1], "shim-loopback6") == 0 && argc >= 3)
		return test_shim_loopback6((uint16_t)atoi(argv[2]));
	if (strcmp(argv[1], "shim-udp-poll") == 0 && argc >= 3)
		return test_shim_udp_poll((uint16_t)atoi(argv[2]));
	if (strcmp(argv[1], "privdrop-fd") == 0 && argc >= 3)
		return test_privdrop_fd(argv[2]);
	if (strcmp(argv[1], "hold-dev") == 0 && argc >= 4) {
		int fd = open(argv[2], O_RDONLY);
		if (fd < 0) {
			perror("hold-dev open");
			return 1;
		}
		sleep((unsigned int)atoi(argv[3]));
		close(fd);
		return 0;
	}
	if (strcmp(argv[1], "remote-containment") == 0)
		return test_remote_containment();
	if (strcmp(argv[1], "three-strikes") == 0)
		return test_three_strikes();
	if (strcmp(argv[1], "unix-deny-create") == 0)
		return test_unix_deny_create();
	if (strcmp(argv[1], "unix-create-only") == 0 && argc >= 6)
		return test_unix_create_only(argv[2], argv[3], argv[4], argv[5]);
	if (strcmp(argv[1], "unix-stream-server") == 0 && argc >= 5)
		return test_unix_stream_server(argv[2], argv[3], argv[4],
					       argc >= 6 ? atoi(argv[5]) : 1);
	if (strcmp(argv[1], "unix-stream-client") == 0 && argc >= 5)
		return test_unix_stream_client(argv[2], argv[3], argv[4]);
	if (strcmp(argv[1], "unix-dgram-server") == 0 && argc >= 4)
		return test_unix_dgram_server(argv[2], argv[3]);
	if (strcmp(argv[1], "unix-dgram-client") == 0 && argc >= 4)
		return test_unix_dgram_client(argv[2], argv[3]);
	if (strcmp(argv[1], "unix-passfd-sender") == 0 && argc >= 4)
		return test_unix_passfd_sender(argv[2], argv[3]);
	if (strcmp(argv[1], "unix-passfd-receiver") == 0 && argc >= 3)
		return test_unix_passfd_receiver(argv[2]);
	if (strcmp(argv[1], "unix-inherit-deny") == 0 && argc >= 4)
		return test_unix_inherit_deny(argv[2], argv[3]);
	if (strcmp(argv[1], "router-admin-allow") == 0 && argc >= 5)
		return test_router_admin_allow(argv[2], argv[3], argv[4]);
	if (strcmp(argv[1], "router-admin-deny") == 0 && argc >= 6)
		return test_router_admin_deny(argv[2], argv[3], argv[4], argv[5]);
	if (strcmp(argv[1], "router-hold-across-logout") == 0 && argc >= 5)
		return test_router_hold_across_logout(argv[2], argv[3], argv[4]);
	if (strcmp(argv[1], "router-expiry") == 0 && argc >= 4)
		return test_router_expiry(argv[2], atoi(argv[3]));
	return 1;
}
