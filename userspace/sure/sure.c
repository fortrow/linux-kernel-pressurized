// SPDX-License-Identifier: GPL-2.0
/*
 * sure: Pressure Reporting, Audit Analysis & Policy Administration CLI
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/sysmacros.h>
#include <sys/xattr.h>

#include "../../include/uapi/linux/sfw.h"
#include "policy_parser.h"

static void dump_secfs(const char *node, const char *header)
{
	char path[128], line[256];
	FILE *f;

	snprintf(path, sizeof(path), "/sys/kernel/security/pressure/%s", node);
	f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "sure: cannot read %s: %s\n", path, strerror(errno));
		return;
	}
	if (header)
		printf("=== %s ===\n", header);
	while (fgets(line, sizeof(line), f))
		fputs(line, stdout);
	fclose(f);
}

static int write_secfs(const char *node, const char *line)
{
	char path[128];
	int fd, r;

	snprintf(path, sizeof(path), "/sys/kernel/security/pressure/%s", node);
	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -errno;
	r = (int)write(fd, line, strlen(line));
	close(fd);
	return r < 0 ? -errno : 0;
}

static int probe_sfw_mux_rpc(void)
{
	struct sockaddr_un sun = { .sun_family = AF_UNIX };
	struct sfw_req_hdr req = {
		.magic = SFW_PROTO_MAGIC,
		.op = SFW_OP_CLOSE,
	};
	struct sfw_resp_hdr resp = {};
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);

	if (fd < 0)
		return -1;
	snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", SFW_MUX_SOCK_PATH);
	if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		close(fd);
		return -1;
	}
	if (write(fd, &req, sizeof(req)) != (ssize_t)sizeof(req) ||
	    read(fd, &resp, sizeof(resp)) != (ssize_t)sizeof(resp) ||
	    resp.magic != SFW_PROTO_MAGIC || resp.status != 0) {
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static int check_readiness(bool require_sfw)
{
	FILE *f = fopen("/sys/kernel/security/pressure/status", "r");
	char line[256];
	int enforce = -1, txn_active = -1, txn_degraded = 0;
	unsigned long long pgen = 0;

	if (!f) {
		fprintf(stderr, "sure ready: /sys/kernel/security/pressure/status unavailable\n");
		return 1;
	}
	while (fgets(line, sizeof(line), f)) {
		sscanf(line, "enforce: %d", &enforce);
		sscanf(line, "policy_gen: %llu", &pgen);
		sscanf(line, "txn_active: %d", &txn_active);
		sscanf(line, "txn_degraded: %d", &txn_degraded);
	}
	fclose(f);

	if (enforce != 1 || txn_active != 0 || txn_degraded != 0 || pgen < 1) {
		fprintf(stderr,
			"sure ready: NOT READY (enforce=%d policy_gen=%llu txn_active=%d txn_degraded=%d)\n",
			enforce, pgen, txn_active, txn_degraded);
		return 1;
	}

	if (require_sfw) {
		struct stat st;
		if (stat(SFW_MUX_SOCK_PATH, &st) != 0 || !S_ISSOCK(st.st_mode) ||
		    probe_sfw_mux_rpc() < 0) {
			fprintf(stderr, "sure ready: NOT READY (%s broker RPC probe failed)\n",
				SFW_MUX_SOCK_PATH);
			return 1;
		}
		FILE *sf = fopen("/proc/pressure_sfw/stats", "r");
		if (!sf) {
			fprintf(stderr, "sure ready: NOT READY (/proc/pressure_sfw/stats missing)\n");
			return 1;
		}
		int sfw_rdy = 0, sfw_txn = -1, sfw_deg = 0;
		unsigned long long sgen = 0;
		while (fgets(line, sizeof(line), sf)) {
			sscanf(line, "sfw_ready: %d", &sfw_rdy);
			sscanf(line, "sfw_policy_gen: %llu", &sgen);
			sscanf(line, "sfw_txn_active: %d", &sfw_txn);
			sscanf(line, "sfw_txn_degraded: %d", &sfw_deg);
		}
		fclose(sf);
		if (sfw_rdy != 1 || sfw_txn != 0 || sfw_deg != 0 || sgen < 1) {
			fprintf(stderr,
				"sure ready: NOT READY (sfw_ready=%d sfw_policy_gen=%llu sfw_txn_active=%d sfw_txn_degraded=%d)\n",
				sfw_rdy, sgen, sfw_txn, sfw_deg);
			return 1;
		}
		printf("sure ready: OK (enforce=1 policy_gen=%llu sfw_policy_gen=%llu mux=LIVE)\n",
		       pgen, sgen);
		return 0;
	}

	printf("sure ready: OK (enforce=1 policy_gen=%llu)\n", pgen);
	return 0;
}

static bool audit_field_matches(const char *line, const char *key,
				const char *value)
{
	size_t key_len = strlen(key);
	const char *field = line;

	while (*field) {
		const char *end;

		if (strncmp(field, "detail=", 7) == 0)
			break;
		if (strncmp(field, "comm=", 5) == 0) {
			/* Kernel task names can contain spaces. */
			end = strstr(field + 5, " pub_uid=");
			while (end) {
				size_t digits = strspn(end + 9, "0123456789");

				if (digits && strncmp(end + 9 + digits, " prov=", 6) == 0)
					break;
				end = strstr(end + 1, " pub_uid=");
			}
			if (!end)
				break;
		} else {
			end = field + strcspn(field, " \t\r\n");
		}
		if ((size_t)(end - field) > key_len &&
		    strncmp(field, key, key_len) == 0 && field[key_len] == '=') {
			const char *start = field + key_len + 1;
			size_t len = end - start;

			return strlen(value) == len && memcmp(start, value, len) == 0;
		}
		if (*end != ' ')
			break;
		field = end + 1;
	}
	return false;
}

static int search_audit(int argc, char **argv)
{
	const char *path = "/sys/kernel/security/pressure/audit";
	const char *fields[] = { "comm", "pid", "ppid", "tid", "pub_uid", "reason", "action", "subject", "device", "prov" };
	const char *values[sizeof(fields) / sizeof(fields[0])] = { 0 };
	char *line = NULL;
	size_t capacity = 0;
	bool matched = false;
	FILE *input;
	int rc = 0;

	for (int arg = 0; arg < argc; arg += 2) {
		size_t index;

		if (arg + 1 == argc || !argv[arg + 1][0])
			goto usage;
		if (strcmp(argv[arg], "--file") == 0) {
			path = argv[arg + 1];
			continue;
		}
		for (index = 0; index < sizeof(fields) / sizeof(fields[0]); index++)
			if (strncmp(argv[arg], "--", 2) == 0 &&
			    strcmp(argv[arg] + 2, fields[index]) == 0)
				break;
		if (index == sizeof(fields) / sizeof(fields[0]) || values[index])
			goto usage;
		values[index] = argv[arg + 1];
	}
	input = strcmp(path, "-") == 0 ? stdin : fopen(path, "r");
	if (!input) {
		fprintf(stderr, "sure search: cannot read %s: %s\n", path, strerror(errno));
		return 2;
	}
	while (getline(&line, &capacity, input) >= 0) {
		bool include = strncmp(line, "seq=", 4) == 0;

		for (size_t i = 0; include && i < sizeof(fields) / sizeof(fields[0]); i++)
			if (values[i] && !audit_field_matches(line, fields[i], values[i]))
				include = false;
		if (include) {
			matched = true;
			if (fputs(line, stdout) == EOF) {
				rc = 2;
				break;
			}
		}
	}
	if (ferror(input) || fflush(stdout) == EOF)
		rc = 2;
	if (rc)
		fprintf(stderr, "sure search: audit I/O failed\n");
	free(line);
	if (input != stdin)
		fclose(input);
	return rc ? rc : (matched ? 0 : 1);

usage:
	fprintf(stderr, "Usage: sure search [--comm NAME] [--pid PID] [--ppid PID] [--tid TID] "
		"[--pub_uid UID] [--subject LABEL] [--device LABEL] [--prov STAGE] [--reason REASON] [--action ACTION] [--file PATH|-]\n");
	return 2;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s status\n"
		"  %s ready [--require-sfw]\n"
		"  %s report\n"
		"  %s audit\n"
		"  %s search [filters]\n"
		"  %s devices\n"
		"  %s check <policy.pr>\n"
		"  %s load <policy.pr>\n"
		"  %s dev-label <dev_path_or_netif> <label> <class_id> <local|remote> <max_sessions>\n"
		"  %s file-label <path> <label> [--local-only] [--user-private <pub_uid>] [--vault]\n"
		"  %s policy list | policy flush\n"
		"  %s policy add <allow|deny> <subj_lbl> <obj_lbl> <dev_lbl> <ev_hex> <max_prov>\n",
		prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "status") == 0) {
		dump_secfs("status", "Pressure Kernel Status");
		dump_secfs("users", "Registered Users & Daemons (Secret Kernel UIDs Redacted)");
		return 0;
	}

	if (strcmp(argv[1], "ready") == 0) {
		bool req_sfw = (argc >= 3 && strcmp(argv[2], "--require-sfw") == 0);
		return check_readiness(req_sfw);
	}

	if (strcmp(argv[1], "report") == 0 || strcmp(argv[1], "audit") == 0) {
		dump_secfs("status", "Pressure Security Summary");
		dump_secfs("audit", "Violation & 3-Strike SIGKILL Audit Log");
		return 0;
	}

	if (strcmp(argv[1], "search") == 0)
		return search_audit(argc - 2, argv + 2);

	if (strcmp(argv[1], "devices") == 0) {
		dump_secfs("devices", "Cryptographic /dev & Network Device Registry");
		return 0;
	}

	if (strcmp(argv[1], "check") == 0 && argc >= 3) {
		return sure_policy_run_file(argv[2], false);
	}

	if (strcmp(argv[1], "load") == 0 && argc >= 3) {
		return sure_policy_run_file(argv[2], true);
	}

	if (strcmp(argv[1], "rollback") == 0) {
		int r1 = write_secfs("txn", "abort\n");
		int sfd = open("/proc/pressure_sfw/txn", O_WRONLY);
		int r2 = 0;
		if (sfd >= 0) {
			if (write(sfd, "abort\n", 6) < 0)
				r2 = -errno;
			close(sfd);
		}
		printf("sure rollback: pressure=%d sfw=%d\n", r1, r2);
		return (r1 == 0 || r2 == 0) ? 0 : 1;
	}

	if (strcmp(argv[1], "dev-label") == 0 && argc >= 7) {
		const char *target = argv[2];
		const char *label = argv[3];
		unsigned int dcls = (unsigned int)strtoul(argv[4], NULL, 0);
		const char *prov = argv[5];
		unsigned int maxs = (unsigned int)strtoul(argv[6], NULL, 0);
		struct stat st;
		char cmd[192];

		if (stat(target, &st) == 0 &&
		    (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode))) {
			snprintf(cmd, sizeof(cmd), "dev %u:%u %s %u %s %u\n",
				 major(st.st_rdev), minor(st.st_rdev),
				 label, dcls, prov, maxs);
		} else {
			snprintf(cmd, sizeof(cmd), "net %s %s %u %s %u\n",
				 target, label, dcls, prov, maxs);
		}
		int rc = write_secfs("devices", cmd);
		if (rc < 0) {
			fprintf(stderr, "sure dev-label failed: %s\n", strerror(-rc));
			return 1;
		}
		printf("sure: updated device '%s' -> label=%s prov=%s max_sessions=%u\n",
		       target, label, prov, maxs);
		return 0;
	}

	if (strcmp(argv[1], "file-label") == 0 && argc >= 4) {
		const char *path = argv[2];
		const char *label = argv[3];
		uint32_t flags = 0;
		uint32_t owner_uid = 0;

		for (int i = 4; i < argc; i++) {
			if (strcmp(argv[i], "--local-only") == 0)
				flags |= PRESSURE_FILE_LOCAL_ONLY;
			else if (strcmp(argv[i], "--vault") == 0)
				flags |= PRESSURE_FILE_AUTHD_VAULT;
			else if (strcmp(argv[i], "--user-private") == 0 &&
				 i + 1 < argc) {
				flags |= PRESSURE_FILE_USER_PRIVATE;
				owner_uid = (uint32_t)strtoul(argv[++i], NULL, 10);
			}
		}

		struct pressure_xattr_disk xd = {
			.magic = PRESSURE_XATTR_MAGIC,
			.flags = flags,
			.file_pub_id = ((uint64_t)rand() << 32) | (uint64_t)rand() | 1ULL,
			.owner_pub_uid = owner_uid,
		};
		snprintf(xd.label, sizeof(xd.label), "%s", label);
		(void)setxattr(path, XATTR_NAME_PRESSURE, &xd, sizeof(xd), 0);

		char cmd[256];
		snprintf(cmd, sizeof(cmd), "%x %u %s %s\n",
			 flags, owner_uid, label, path);
		int rc = write_secfs("label_path", cmd);
		if (rc < 0) {
			fprintf(stderr, "sure file-label failed: %s\n", strerror(-rc));
			return 1;
		}
		printf("sure: labeled '%s' -> label=%s flags=0x%x owner_pub_uid=%u\n",
		       path, label, flags, owner_uid);
		return 0;
	}

	if (strcmp(argv[1], "policy") == 0 && argc >= 3) {
		if (strcmp(argv[2], "list") == 0) {
			dump_secfs("policy", "Active Event & Descriptor Policy Rules");
			dump_secfs("unix_rules", "Active AF_UNIX Socket Policy Rules");
			return 0;
		}
		if (strcmp(argv[2], "flush") == 0) {
			int rc = write_secfs("policy", "flush\n");
			if (rc < 0) {
				fprintf(stderr, "sure policy flush failed: %s\n",
					strerror(-rc));
				return 1;
			}
			printf("sure: flushed active policy rules\n");
			return 0;
		}
		if (strcmp(argv[2], "add") == 0 && argc >= 9) {
			char cmd[192];
			snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %s\n",
				 argv[3], argv[4], argv[5], argv[6], argv[7], argv[8]);
			int rc = write_secfs("policy", cmd);
			if (rc < 0) {
				fprintf(stderr, "sure policy add failed: %s\n",
					strerror(-rc));
				return 1;
			}
			printf("sure: added policy rule (%s %s -> %s)\n",
			       argv[3], argv[4], argv[5]);
			return 0;
		}
	}

	usage(argv[0]);
	return 1;
}
