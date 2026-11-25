// SPDX-License-Identifier: GPL-2.0
/*
 * press: Pressure Enforcement Application, PAM Session Launcher & Daemon Runner
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <security/pam_appl.h>

#include "../authd/authd_proto.h"
#include "../../include/uapi/linux/sfw.h"

static int write_secfs(const char *name, const char *val)
{
	char path[128];
	int fd, r;

	snprintf(path, sizeof(path), "/sys/kernel/security/pressure/%s", name);
	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -errno;
	r = (int)write(fd, val, strlen(val));
	close(fd);
	return r < 0 ? -errno : 0;
}

static int authd_rpc(const struct authd_request *req, struct authd_response *resp)
{
	struct sockaddr_un sun = { .sun_family = AF_UNIX };
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);

	if (fd < 0)
		return -errno;
	snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", AUTHD_SOCK_PATH);
	if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		int e = -errno;
		close(fd);
		return e;
	}
	if (write(fd, req, sizeof(*req)) != (ssize_t)sizeof(*req) ||
	    read(fd, resp, sizeof(*resp)) != (ssize_t)sizeof(*resp)) {
		close(fd);
		return -EIO;
	}
	close(fd);
	return resp->status;
}

#define DESKTOP_SESSION_HOOK "/usr/libexec/trimos-browser-session"

static pid_t start_desktop_hook(pid_t leader, uid_t uid)
{
	struct pressure_session_query query = { .uid = uid };
	char fd_arg[24], uid_arg[24];
	int control;
	pid_t hook = -1;

	query.pidfd = syscall(SYS_pidfd_open, leader, 0);
	if (query.pidfd < 0)
		return -1;
	control = open("/sys/kernel/security/pressure/session", O_RDONLY | O_CLOEXEC);
	if (control < 0)
		goto out;
	if (ioctl(control, PRESSURE_SESSION_CHECK, &query) < 0)
		goto close_control;
	snprintf(fd_arg, sizeof(fd_arg), "%d", query.pidfd);
	snprintf(uid_arg, sizeof(uid_arg), "%u", uid);
	hook = fork();
	if (hook == 0) {
		char *const args[] = { DESKTOP_SESSION_HOOK, fd_arg, uid_arg, NULL };
		char *const env[] = { "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };
		int input = open("/dev/null", O_RDONLY);

		if (input < 0 || dup2(input, STDIN_FILENO) < 0 ||
		    fcntl(query.pidfd, F_SETFD, 0) < 0)
			_exit(126);
		if (input != STDIN_FILENO)
			close(input);
		execve(DESKTOP_SESSION_HOOK, args, env);
		perror("press login: browser session hook");
		_exit(127);
	}
close_control:
	close(control);
out:
	close(query.pidfd);
	return hook;
}

static int pam_static_conv(int num_msg, const struct pam_message **msg,
			   struct pam_response **resp, void *appdata_ptr)
{
	const char *pw = (const char *)appdata_ptr;
	struct pam_response *reply;

	if (num_msg <= 0 || num_msg > 32)
		return PAM_CONV_ERR;
	reply = calloc((size_t)num_msg, sizeof(*reply));
	if (!reply)
		return PAM_BUF_ERR;
	for (int i = 0; i < num_msg; i++) {
		if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF ||
		    msg[i]->msg_style == PAM_PROMPT_ECHO_ON)
			reply[i].resp = strdup(pw ? pw : "");
	}
	*resp = reply;
	return PAM_SUCCESS;
}

static int read_auto_input(const char *prompt, char *input, size_t capacity)
{
	char *newline;

	fputs(prompt, stderr);
	fflush(stderr);
	if (!fgets(input, capacity, stdin) || !(newline = strchr(input, '\n')))
		return -1;
	*newline = '\0';
	return 0;
}

static int auto_label_valid(const char *label, const char *prefix)
{
	size_t len = strlen(label), prefix_len = strlen(prefix);

	return len < 32 && len > prefix_len && !strncmp(label, prefix, prefix_len) &&
	       strspn(label + prefix_len,
		      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-") ==
		      len - prefix_len;
}

static int read_auto_label(const char *prompt, const char *prefix, char label[32])
{
	char input[64];

	if (read_auto_input(prompt, input, sizeof(input)) ||
	    !auto_label_valid(input, prefix))
		return -1;
	memcpy(label, input, strlen(input) + 1);
	return 0;
}

static const struct {
	unsigned int mask;
	const char *name;
} auto_events[] = {
	{ PEV_OPEN, "open" }, { PEV_READ, "read" }, { PEV_WRITE, "write" },
	{ PEV_IOCTL, "ioctl" }, { PEV_MKNOD, "mknod" }, { PEV_EXEC, "exec" },
	{ PEV_MMAP_EXEC, "mmap_exec" }, { PEV_MMAP_WRITE, "mmap_write" },
	{ PEV_SETUID, "setuid" }, { PEV_SOCK_BIND, "sock_bind" },
	{ PEV_SOCK_CONNECT, "sock_connect" }, { PEV_SOCK_SEND, "sock_send" },
	{ PEV_SOCK_RECV, "sock_recv" }, { PEV_LOGIN, "login" },
};

static int auto_sfw(unsigned long long seq, unsigned int uid,
		    unsigned int address_bits, const char *evidence)
{
	const char *directions[] = { NULL, "bind", "connect", "send", "recv" };
	char address[INET6_ADDRSTRLEN + 1], device[32], recorded[32];
	struct in6_addr ip6;
	struct in_addr ip4 = { .s_addr = htonl(address_bits) };
	unsigned int direction, port;
	int used = 0;
	int ipv6 = !strncmp(evidence, "sfw6_dir=", 9);

	if (!uid ||
	    sscanf(evidence, ipv6 ? "sfw6_dir=%u port=%u dev=%31s%n" :
		   "sfw_dir=%u port=%u dev=%31s%n", &direction, &port, recorded, &used) != 3 ||
	    !used || evidence[used] || direction < SFW_DIR_BIND || direction > SFW_DIR_RECV ||
	    !port || port > 65535 || !strcmp(recorded, "*"))
		goto insufficient;
	if (strlen(evidence) == 47) {
		fputs("press auto: SFW device evidence may be truncated; collect a complete record\n", stderr);
		return 1;
	}
	if (ipv6) {
		if (read_auto_input("Verified full IPv6 address > ", address, sizeof(address)) ||
		    inet_pton(AF_INET6, address, &ip6) != 1 || IN6_IS_ADDR_UNSPECIFIED(&ip6) ||
		    ntohl(ip6.s6_addr32[3]) != address_bits)
			goto insufficient;
	} else if (!address_bits || !inet_ntop(AF_INET, &ip4, address, sizeof(address))) {
		goto insufficient;
	}
	if (read_auto_label("Verified network device label (dev:...) > ", "dev:", device) ||
	    (auto_label_valid(recorded, "dev:") && strcmp(recorded, device)) ||
	    !strcmp(device, "dev:none"))
		goto insufficient;
	printf("# Draft from audit event %llu. Verify UID and interface mapping with sure devices.\n"
	       "sfw_socket allow %s uid %u dst %s/%u ports %u dev %s max_prov auth_local;\n",
	       seq, directions[direction], uid, address, ipv6 ? 128 : 32, port, device);
	return fflush(stdout) == EOF ? 2 : 0;

insufficient:
	fputs("press auto: exact UID, address, port, direction, and registered network device required\n", stderr);
	return 1;
}

static int auto_policy(int argc, char **argv)
{
	const char *path = "/sys/kernel/security/pressure/audit";
	const char *seq_text, *socket_type = NULL;
	char *line = NULL, *end;
	char subject[32] = "", device[32] = "", evidence[112] = "", peer[32] = "";
	char endpoint[113], operation[16];
	unsigned int event_mask = 0, address_bits = 0, uid = 0, unix_op = 0;
	int sfw = 0, device_policy = 0, recorded_labels = 0;
	char selected_reason[40] = "";
	size_t capacity = 0;
	unsigned long long seq;
	int found = 0, failed;
	FILE *audit;

	char interactive_seq[32];
	char *interactive_args[] = { "--seq", interactive_seq };

	if (!argc) {
		fputs("Find an event with sure search, then enter its sequence > ", stderr);
		fflush(stderr);
		if (!fgets(interactive_seq, sizeof(interactive_seq), stdin) ||
		    !strchr(interactive_seq, '\n'))
			goto usage;
		*strchr(interactive_seq, '\n') = '\0';
		argc = 2;
		argv = interactive_args;
	}
	if ((argc != 2 && argc != 4) || strcmp(argv[0], "--seq") ||
	    (argc == 4 && (strcmp(argv[2], "--file") || !strcmp(argv[3], "-"))))
		goto usage;
	seq_text = argv[1];
	if (!*seq_text || strspn(seq_text, "0123456789") != strlen(seq_text))
		goto usage;
	errno = 0;
	seq = strtoull(seq_text, &end, 10);
	if (errno || *end || !seq)
		goto usage;
	if (argc == 4)
		path = argv[3];
	audit = fopen(path, "r");
	if (!audit) {
		fprintf(stderr, "press auto: cannot read %s: %s\n", path, strerror(errno));
		return 2;
	}
	while (getline(&line, &capacity, audit) >= 0) {
		unsigned long long event_seq;
		unsigned int type;
		int used = 0;
		const char *reason, *provenance, *detail;
		char reason_name[40];
		size_t detail_len;

		if (sscanf(line, "seq=%llu %n", &event_seq, &used) != 1 ||
		    !used || event_seq != seq)
			continue;
		found++;
		const char *uid_field = strstr(line + used, " pub_uid=");

		provenance = strstr(line + used, " prov=AUTH_LOCAL strike=");
		detail = strstr(line + used, " detail=");
		if (!provenance || !detail || provenance >= detail)
			continue;
		reason = strstr(provenance, " reason=");
		used = 0;
		if (!reason || reason >= detail ||
		    sscanf(reason, " reason=%39[A-Z_] val=0x%x%n",
			   reason_name, &type, &used) != 2 ||
		    !used || reason + used > detail)
			continue;
		if (reason + used != detail) {
			const char *labels = reason + used;
			int label_len = 0;

			if (sscanf(labels, " subject=%31s device=%31s%n",
				   subject, device, &label_len) != 2 ||
			    !label_len || labels + label_len > detail ||
			    !auto_label_valid(subject, "subj:") ||
			    !auto_label_valid(device, "dev:") || !strcmp(device, "dev:none"))
				continue;
			if (!strcmp(reason_name, "UNIX_SOCKET_POLICY_DENY")) {
				const char *socket_fields = labels + label_len;
				int socket_len = 0;

				if (sscanf(socket_fields, " unix_op=0x%x peer=%31s%n",
					   &unix_op, peer, &socket_len) != 2 ||
				    !socket_len || socket_fields + socket_len != detail ||
				    (strcmp(peer, "-") && !auto_label_valid(peer, "subj:")))
					continue;
			} else if (strcmp(reason_name, "POLICY_RULE_DENY") ||
				   labels + label_len != detail) {
				continue;
			}
			recorded_labels = 1;
		}
		memcpy(selected_reason, reason_name, strlen(reason_name) + 1);
		detail += sizeof(" detail=") - 1;
		detail_len = strcspn(detail, "\r\n");
		if (detail_len >= sizeof(evidence))
			continue;
		memcpy(evidence, detail, detail_len);
		evidence[detail_len] = '\0';

		if (!strcmp(reason_name, "POLICY_RULE_DENY") &&
		    type && !(type & ~PEV_ALL) && auto_label_valid(evidence, "obj:")) {
			event_mask = type;
		} else if (!strcmp(reason_name, "DEV_PROVENANCE_HARDSTOP") &&
			   auto_label_valid(evidence, "dev:")) {
			device_policy = 1;
		} else if (!strcmp(reason_name, "SFW_FIREWALL_DROP") &&
			   uid_field && uid_field < provenance) {
			const char *separator = strstr(uid_field + 1, " pub_uid=");
			unsigned int parsed_uid;
			int uid_len = 0;

			if (separator && separator < provenance)
				uid_field = separator;
			if (sscanf(uid_field, " pub_uid=%u%n", &parsed_uid, &uid_len) == 1 &&
			    uid_len && uid_field + uid_len == provenance) {
				sfw = 1;
				uid = parsed_uid;
				address_bits = type;
			}
		} else if (!strcmp(reason_name, "UNIX_SOCKET_POLICY_DENY")) {
			switch (type) {
			case SOCK_STREAM: socket_type = "stream"; break;
			case SOCK_DGRAM: socket_type = "dgram"; break;
			case SOCK_SEQPACKET: socket_type = "seqpacket"; break;
			}
		}
	}
	failed = ferror(audit);
	free(line);
	fclose(audit);
	if (failed || found != 1 || (!socket_type && !event_mask && !sfw && !device_policy)) {
		fprintf(stderr, "press auto: %s\n",
			failed ? "audit read failed" :
			found != 1 ? "expected exactly one event with that sequence" :
			"no supported scoped rule can be inferred from this event");
		if (!failed && found == 1 && *selected_reason)
			fprintf(stderr, "Reason: %s. Inspect the event with sure search.\n", selected_reason);
		return failed ? 2 : 1;
	}

	if (sfw)
		return auto_sfw(seq, uid, address_bits, evidence);
	if (device_policy) {
		fputs("The audit records the device label but omits the operation. "
		      "Seat and identity hard-stops remain enforced.\n", stderr);
		if (read_auto_label("Verified subject label (subj:...) > ", "subj:", subject) ||
		    read_auto_input("Verified device operation (open/read/write/ioctl) > ",
				    operation, sizeof(operation)) ||
		    (strcmp(operation, "open") && strcmp(operation, "read") &&
		     strcmp(operation, "write") && strcmp(operation, "ioctl"))) {
			fputs("press auto: exact subject and one verified device operation required\n", stderr);
			return 2;
		}
		printf("# Draft from audit event %llu. Confirm device identity and rule ordering.\n"
		       "allow subject %s object %s device %s events { %s } max_prov auth_local;\n",
		       seq, subject, evidence, evidence, operation);
		return fflush(stdout) == EOF ? 2 : 0;
	}

	if (!recorded_labels) {
		fprintf(stderr, "Event %llu. Confirm the subject and verified device labels from the deployment.\n",
			seq);
		if (read_auto_label("Subject label (subj:...) > ", "subj:", subject) ||
		    read_auto_label("Verified device label (dev:...) > ", "dev:", device) ||
		    strcmp(device, "dev:none") == 0) {
			fprintf(stderr, "press auto: exact subject and verified device labels required\n");
			return 2;
		}
	}
	if (socket_type) {
		if (recorded_labels) {
			const char *name;

			switch (unix_op) {
			case PUNIX_OP_CREATE: name = "create"; break;
			case PUNIX_OP_SOCKETPAIR: name = "socketpair"; break;
			case PUNIX_OP_BIND: name = "bind"; break;
			case PUNIX_OP_CONNECT: name = "connect"; break;
			case PUNIX_OP_SEND: name = "send"; break;
			case PUNIX_OP_RECV: name = "recv"; break;
			case PUNIX_OP_PASS_FD: name = "pass_fd"; break;
			default: return 2;
			}
			if (!strcmp(device, "dev:tty1_helper")) {
				fprintf(stderr, "press auto: this helper rule also requires an independently verified executable label\n");
				return 2;
			}
			if (unix_op == PUNIX_OP_PASS_FD && !strcmp(peer, "-")) {
				fprintf(stderr, "press auto: descriptor transfer requires a recorded peer label\n");
				return 2;
			}
			if (unix_op == PUNIX_OP_CREATE) {
				if (strcmp(evidence, "-") || strcmp(peer, "-"))
					return 2;
			} else if (unix_op == PUNIX_OP_SOCKETPAIR) {
				char expected[40];

				snprintf(expected, sizeof(expected), "pair:%s", subject);
				if (strcmp(evidence, expected) || strcmp(peer, subject))
					return 2;
			} else if ((evidence[0] != '/' && evidence[0] != '@' &&
				    strncmp(evidence, "pair:", 5)) || !evidence[1] ||
				   strlen(evidence) >= sizeof(evidence) - 1 ||
				   strspn(evidence, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-.@/:") != strlen(evidence)) {
				return 2;
			}
			if (unix_op == PUNIX_OP_CREATE || unix_op == PUNIX_OP_BIND) {
				if (strcmp(peer, "-"))
					return 2;
				peer[0] = '\0';
			} else if (!strcmp(peer, "-") &&
				   read_auto_label("Verified peer label (subj:...) > ", "subj:", peer)) {
				fprintf(stderr, "press auto: exact peer label required\n");
				return 2;
			}
			strcpy(operation, name);
			strcpy(endpoint, evidence);
		} else if (!strcmp(evidence, "unix_create") ||
			   !strncmp(evidence, "unix_create dev:", 16)) {
			strcpy(operation, "create");
			strcpy(endpoint, "-");
		} else {
			/* The audit detail can be truncated and does not identify the operation. */
			if ((evidence[0] != '/' && evidence[0] != '@' &&
			     strncmp(evidence, "pair:", 5)) ||
			    read_auto_input("Verified operation (bind/connect/send/recv/pass_fd) > ",
					    operation, sizeof(operation)) ||
			    (strcmp(operation, "bind") && strcmp(operation, "connect") &&
			     strcmp(operation, "send") && strcmp(operation, "recv") &&
			     strcmp(operation, "pass_fd")) ||
			    read_auto_input("Verified full endpoint (/path, @name, pair:subject) > ",
					    endpoint, sizeof(endpoint)) ||
			    strncmp(endpoint, evidence, strlen(evidence)) ||
			    (strlen(evidence) < 47 && strcmp(endpoint, evidence)) ||
			    endpoint[1] == '\0' ||
			    strspn(endpoint, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-.@/:") != strlen(endpoint)) {
				fprintf(stderr, "press auto: verified operation and exact matching endpoint required\n");
				return 2;
			}
			if (strcmp(operation, "bind") &&
			    read_auto_label("Verified peer label (subj:...) > ", "subj:", peer)) {
				fprintf(stderr, "press auto: exact peer label required\n");
				return 2;
			}
		}
	}
	printf("# Draft from audit event %llu. Verify the labels and run sure check.\n", seq);
	if (event_mask) {
		printf("allow subject %s object %s device %s events {", subject, evidence, device);
		for (size_t i = 0; i < sizeof(auto_events) / sizeof(auto_events[0]); i++)
			if (auto_events[i].mask & event_mask)
				printf(" %s", auto_events[i].name);
		puts(" } max_prov auth_local;");
	} else {
		printf("unix_socket allow subject %s type %s ops { %s } endpoint %s ",
		       subject, socket_type, operation, endpoint);
		if (*peer)
			printf("peer %s ", peer);
		printf("device %s max_prov auth_local;\n", device);
	}
	return fflush(stdout) == EOF ? 2 : 0;

usage:
	fprintf(stderr, "Usage: press auto [--seq EVENT [--file AUDIT_LOG]]\n");
	return 2;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s enforce <on|off>\n"
		"  %s boot-init\n"
		"  %s auto [--seq EVENT [--file AUDIT_LOG]]\n"
		"  %s login <user> <password|--password-stdin> <tty_path> [--rhost <ip>] -- <cmd...>\n"
		"  %s start-daemon <daemon_name> [--remote] -- <cmd...>\n"
		"  %s init-fd-crypto -- <cmd...>\n"
		"  %s exec [--origin local|remote] [--label <lbl>] [--no-fd-enc] -- <cmd...>\n",
		prog, prog, prog, prog, prog, prog, prog);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "auto") == 0)
		return auto_policy(argc - 2, argv + 2);

	if (strcmp(argv[1], "enforce") == 0 && argc >= 3) {
		const char *v = (strcmp(argv[2], "on") == 0 ||
				 strcmp(argv[2], "1") == 0) ? "1\n" : "0\n";
		int rc = write_secfs("enforce", v);
		if (rc < 0) {
			fprintf(stderr, "press: failed to set enforce: %s\n",
				strerror(-rc));
			return 1;
		}
		printf("press: enforcement %s\n", v[0] == '1' ? "ENABLED" : "DISABLED");
		return 0;
	}

	if (strcmp(argv[1], "boot-init") == 0) {
		mkdir("/run", 0755);
		mkdir("/run/pressure", 0755);
		mkdir("/run/pressure/sfw", 0755);
		printf("press: runtime directories initialized (/run/pressure/sfw)\n");
		return 0;
	}

	if (strcmp(argv[1], "login") == 0) {
		if (argc < 6) {
			usage(argv[0]);
			return 1;
		}
		const char *user = argv[2];
		const char *pass = argv[3];
		char password_input[sizeof(((struct authd_request *)0)->password)] = {};
		int password_stdin = strcmp(pass, "--password-stdin") == 0;
		const char *tty = argv[4];
		const char *rhost = "";
		const char *spoof_tty = NULL;
		const char *ttl_str = NULL;
		int use_pty = 0;
		char pty_slave[64] = "";
		int ptm_fd = -1, keep_tfd = -1;
		int idx = 5;

		while (idx < argc && strcmp(argv[idx], "--") != 0) {
			if (strcmp(argv[idx], "--rhost") == 0 && idx + 1 < argc) {
				rhost = argv[idx + 1];
				idx += 2;
			} else if (strcmp(argv[idx], "--spoof-tty") == 0 && idx + 1 < argc) {
				spoof_tty = argv[idx + 1];
				idx += 2;
			} else if (strcmp(argv[idx], "--ttl") == 0 && idx + 1 < argc) {
				ttl_str = argv[idx + 1];
				idx += 2;
			} else if (strcmp(argv[idx], "--pty") == 0) {
				use_pty = 1;
				idx++;
			} else {
				break;
			}
		}
		if (idx < argc && strcmp(argv[idx], "--") == 0)
			idx++;
		if (idx >= argc) {
			usage(argv[0]);
			return 1;
		}

		struct authd_request lreq = {
			.magic = AUTHD_PROTO_MAGIC,
			.op = AUTHD_REQ_LOOKUP,
		};
		struct authd_response lresp = {};
		snprintf(lreq.username, sizeof(lreq.username), "%s", user);
		if (authd_rpc(&lreq, &lresp) < 0) {
			fprintf(stderr, "press login: unknown user '%s'\n", user);
			return 1;
		}

		const char *real_tty = tty;
		if (use_pty || strcmp(tty, "pty") == 0) {
			ptm_fd = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
			if (ptm_fd < 0 || grantpt(ptm_fd) < 0 ||
			    unlockpt(ptm_fd) < 0 ||
			    ptsname_r(ptm_fd, pty_slave, sizeof(pty_slave)) != 0) {
				perror("press login: allocate pty");
				if (ptm_fd >= 0)
					close(ptm_fd);
				return 1;
			}
			real_tty = pty_slave;
		}
		if (real_tty[0] == '/')
			keep_tfd = open(real_tty, O_RDWR | O_NOCTTY | O_CLOEXEC);

		int ready[2] = { -1, -1 };
		pid_t hook = -1;
		bool desktop = geteuid() == 0 && !rhost[0] && password_stdin &&
			strcmp(real_tty, "/dev/tty1") == 0 && idx + 2 == argc &&
			strcmp(argv[idx], "/usr/bin/trimdesktop") == 0 &&
			strcmp(argv[idx + 1], "--pressure-session") == 0 &&
			access(DESKTOP_SESSION_HOOK, X_OK) == 0;

		if (desktop && pipe2(ready, O_CLOEXEC) < 0) {
			perror("press login: browser session notification");
			desktop = false;
		}
		pid_t child = fork();
		if (child < 0) {
			perror("fork");
			if (desktop) {
				close(ready[0]);
				close(ready[1]);
			}
			if (keep_tfd >= 0) close(keep_tfd);
			if (ptm_fd >= 0) close(ptm_fd);
			return 1;
		}
		if (child == 0) {
			if (desktop)
				close(ready[0]);
			if (keep_tfd >= 0) close(keep_tfd);
			if (ptm_fd >= 0) close(ptm_fd);

			if (setsid() < 0) {
				/* already session leader */
			}
			if (real_tty[0] == '/') {
				int c_tfd = open(real_tty, O_RDWR | O_NOCTTY);
				if (c_tfd >= 0) {
					(void)ioctl(c_tfd, TIOCSCTTY, 0);
					close(c_tfd);
				}
			}

			if (ttl_str && ttl_str[0])
				setenv("PRESSURE_LOGIN_TTL", ttl_str, 1);

			if (password_stdin) {
				size_t length;

				if (!fgets(password_input, sizeof(password_input), stdin)) {
					fprintf(stderr, "press login: unable to read password\n");
					_exit(1);
				}
				length = strlen(password_input);
				if (length < 2 || password_input[length - 1] != '\n') {
					explicit_bzero(password_input, sizeof(password_input));
					fprintf(stderr, "press login: password is empty or too long\n");
					_exit(1);
				}
				password_input[length - 1] = '\0';
				pass = password_input;
			}

			struct pam_conv conv = {
				.conv = pam_static_conv,
				.appdata_ptr = (void *)pass,
			};
			pam_handle_t *pamh = NULL;
			int prc = pam_start("pressure-login", user, &conv, &pamh);
			if (prc != PAM_SUCCESS) {
				fprintf(stderr, "pam_start failed: %d\n", prc);
				_exit(126);
			}
			pam_set_item(pamh, PAM_TTY,
				     spoof_tty ? spoof_tty : real_tty);
			if (rhost[0])
				pam_set_item(pamh, PAM_RHOST, rhost);
			pam_set_item(pamh, PAM_AUTHTOK, pass);

			prc = pam_authenticate(pamh, 0);
			if (prc != PAM_SUCCESS) {
				fprintf(stderr, "press login: PAM auth denied (%s)\n",
					pam_strerror(pamh, prc));
				pam_end(pamh, prc);
				_exit(1);
			}
			prc = pam_acct_mgmt(pamh, 0);
			if (prc != PAM_SUCCESS) {
				fprintf(stderr, "press login: PAM acct denied (%s)\n",
					pam_strerror(pamh, prc));
				pam_end(pamh, prc);
				_exit(1);
			}
			prc = pam_open_session(pamh, 0);
			if (prc != PAM_SUCCESS) {
				fprintf(stderr, "press login: PAM session rejected (%s)\n",
					pam_strerror(pamh, prc));
				pam_end(pamh, prc);
				_exit(2);
			}

			explicit_bzero(password_input, sizeof(password_input));
			pam_end(pamh, PAM_SUCCESS);

			/* Drop GID then consume one-time kernel ticket via setresuid(pub_uid)! */
			if (setresgid(lresp.pub_gid, lresp.pub_gid, lresp.pub_gid) < 0 ||
			    setresuid(lresp.pub_uid, lresp.pub_uid, lresp.pub_uid) < 0) {
				perror("press login: setresuid transition failed");
				_exit(3);
			}
			setenv("USER", user, 1);
			setenv("HOME", lresp.home_dir, 1);
			if (desktop) {
				if (write(ready[1], "1", 1) != 1)
					perror("press login: browser session notification");
				close(ready[1]);
			}
			execvp(argv[idx], &argv[idx]);
			perror("execvp");
			_exit(127);
		}

		if (desktop) {
			char authenticated;
			ssize_t received;

			close(ready[1]);
			do {
				received = read(ready[0], &authenticated, 1);
			} while (received < 0 && errno == EINTR);
			close(ready[0]);
			if (received == 1 && authenticated == '1') {
				hook = start_desktop_hook(child, lresp.pub_uid);
				if (hook < 0)
					fprintf(stderr, "press login: browser session hook unavailable\n");
			}
		}
		int status = 0;
		while (waitpid(child, &status, 0) < 0 && errno == EINTR)
			;


		/* Release TTY max_sessions lock & revoke session in kernel on logout */
		struct authd_request out_req = {
			.magic = AUTHD_PROTO_MAGIC,
			.op = AUTHD_REQ_LOGOUT,
			.target_pid = child,
		};
		struct authd_response out_resp = {};
		(void)authd_rpc(&out_req, &out_resp);
		if (hook > 0)
			while (waitpid(hook, NULL, 0) < 0 && errno == EINTR)
				;
		if (keep_tfd >= 0) close(keep_tfd);
		if (ptm_fd >= 0) close(ptm_fd);

		if (WIFSIGNALED(status))
			return 128 + WTERMSIG(status);
		return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
	}

	if (strcmp(argv[1], "start-daemon") == 0) {
		if (argc < 4) {
			usage(argv[0]);
			return 1;
		}
		const char *dname = argv[2];
		int remote = 0, idx = 3;
		if (idx < argc && strcmp(argv[idx], "--remote") == 0) {
			remote = 1;
			idx++;
		}
		if (idx < argc && strcmp(argv[idx], "--") == 0)
			idx++;
		if (idx >= argc) {
			usage(argv[0]);
			return 1;
		}

		struct authd_request req = {
			.magic = AUTHD_PROTO_MAGIC,
			.op = AUTHD_REQ_START_DAEMON,
			.target_pid = (int32_t)getpid(),
			.force_remote = (uint8_t)remote,
		};
		struct authd_response resp = {};
		snprintf(req.username, sizeof(req.username), "%s", dname);
		int rc = authd_rpc(&req, &resp);
		if (rc < 0) {
			fprintf(stderr, "press start-daemon: authd rejected '%s': %d\n",
				dname, rc);
			return 1;
		}
		if (setresgid(resp.pub_gid, resp.pub_gid, resp.pub_gid) < 0 ||
		    setresuid(resp.pub_uid, resp.pub_uid, resp.pub_uid) < 0) {
			perror("press start-daemon: setresuid failed");
			return 1;
		}
		execvp(argv[idx], &argv[idx]);
		perror("execvp");
		return 127;
	}

	if (strcmp(argv[1], "init-fd-crypto") == 0) {
		int idx = 2;
		if (idx < argc && strcmp(argv[idx], "--") == 0)
			idx++;
		if (idx >= argc) {
			usage(argv[0]);
			return 1;
		}
		if (write_secfs("self_confine", "fd_crypto_init\n") < 0) {
			perror("press init-fd-crypto");
			return 1;
		}
		execvp(argv[idx], &argv[idx]);
		perror("execvp");
		return 127;
	}

	if (strcmp(argv[1], "exec") == 0) {
		const char *origin = "local";
		const char *label = "subj:confined_app";
		int fd_enc = 1, idx = 2;

		while (idx < argc && strncmp(argv[idx], "--", 2) == 0) {
			if (strcmp(argv[idx], "--") == 0) {
				idx++;
				break;
			}
			if (strcmp(argv[idx], "--origin") == 0 && idx + 1 < argc) {
				origin = argv[idx + 1];
				idx += 2;
			} else if (strcmp(argv[idx], "--label") == 0 && idx + 1 < argc) {
				label = argv[idx + 1];
				idx += 2;
			} else if (strcmp(argv[idx], "--no-fd-enc") == 0) {
				fd_enc = 0;
				idx++;
			} else {
				break;
			}
		}
		if (idx >= argc) {
			usage(argv[0]);
			return 1;
		}
		char cmd[128];
		snprintf(cmd, sizeof(cmd), "confine %s %d %s\n",
			 origin, fd_enc, label);
		if (write_secfs("self_confine", cmd) < 0) {
			perror("press exec: self_confine");
			return 1;
		}
		execvp(argv[idx], &argv[idx]);
		perror("execvp");
		return 127;
	}

	usage(argv[0]);
	return 1;
}
