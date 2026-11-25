// SPDX-License-Identifier: GPL-2.0
/*
 * pressure-authctl: User, Daemon, Password & Label CLI for pressure-authd
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "authd_proto.h"

static int authd_rpc(const struct authd_request *req, struct authd_response *resp)
{
	struct sockaddr_un sun = { .sun_family = AF_UNIX };
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);

	if (fd < 0)
		return -1;
	snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", AUTHD_SOCK_PATH);
	if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		close(fd);
		return -1;
	}
	if (write(fd, req, sizeof(*req)) != (ssize_t)sizeof(*req) ||
	    read(fd, resp, sizeof(*resp)) != (ssize_t)sizeof(*resp)) {
		close(fd);
		return -1;
	}
	close(fd);
	return resp->status;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s useradd [--daemon] <username> <password_or_-> [--label <lbl>] [--home <dir>]\n"
		"  %s useradd --password-stdin <username> [--label <lbl>] [--home <dir>]\n"
		"  %s passwd <username> <new_password>\n"
		"  %s passwd --password-stdin <username>\n"
		"  %s set-label <username> <label>\n"
		"  %s info <username>\n"
		"  %s list\n",
		prog, prog, prog, prog, prog, prog, prog);
}

static int read_password_stdin(char *password, size_t size)
{
	size_t length;

	if (!fgets(password, size, stdin)) {
		fprintf(stderr, "Unable to read password from standard input\n");
		return -1;
	}
	length = strlen(password);
	if (length < 2 || password[length - 1] != '\n') {
		explicit_bzero(password, size);
		fprintf(stderr, "Password is empty or too long\n");
		return -1;
	}
	password[length - 1] = '\0';
	return 0;
}

int main(int argc, char **argv)
{
	struct authd_request req = { .magic = AUTHD_PROTO_MAGIC };
	struct authd_response resp = {};

	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "list") == 0) {
		FILE *f = fopen("/sys/kernel/security/pressure/users", "r");
		char line[256];
		if (!f) {
			perror("open /sys/kernel/security/pressure/users");
			return 1;
		}
		while (fgets(line, sizeof(line), f))
			fputs(line, stdout);
		fclose(f);
		return 0;
	}

	if (strcmp(argv[1], "useradd") == 0) {
		int idx = 2;
		int password_stdin = 0;
		req.op = AUTHD_REQ_USERADD;
		if (idx < argc && strcmp(argv[idx], "--daemon") == 0) {
			req.is_daemon = 1;
			idx++;
		}
		if (idx < argc && strcmp(argv[idx], "--password-stdin") == 0) {
			password_stdin = 1;
			idx++;
		}
		if (idx >= argc || (!password_stdin && idx + 1 >= argc) ||
		    strlen(argv[idx]) >= sizeof(req.username)) {
			usage(argv[0]);
			return 1;
		}
		snprintf(req.username, sizeof(req.username), "%s", argv[idx++]);
		if (password_stdin) {
			if (read_password_stdin(req.password, sizeof(req.password)) < 0)
				return 1;
		} else {
			if (strcmp(argv[idx], "-") != 0)
				snprintf(req.password, sizeof(req.password), "%s", argv[idx]);
			idx++;
		}
		while (idx + 1 < argc) {
			if (strcmp(argv[idx], "--label") == 0) {
				snprintf(req.label, sizeof(req.label), "%s", argv[idx + 1]);
				idx += 2;
			} else if (strcmp(argv[idx], "--home") == 0) {
				snprintf(req.home_dir, sizeof(req.home_dir), "%s", argv[idx + 1]);
				idx += 2;
			} else {
				break;
			}
		}
		int rc = authd_rpc(&req, &resp);
		explicit_bzero(req.password, sizeof(req.password));
		if (rc < 0) {
			fprintf(stderr, "useradd failed: %d (%s)\n", rc, resp.message);
			return 1;
		}
		printf("Account '%s' provisioned: pub_uid=%u pub_gid=%u type=%s label=%s dir=%s\n",
		       req.username, resp.pub_uid, resp.pub_gid,
		       resp.is_daemon ? "daemon" : "human", resp.label, resp.home_dir);
		return 0;
	}

	if (strcmp(argv[1], "passwd") == 0 && argc >= 4) {
		int rc;

		req.op = AUTHD_REQ_PASSWD;
		if (strcmp(argv[2], "--password-stdin") == 0) {
			snprintf(req.username, sizeof(req.username), "%s", argv[3]);
			if (read_password_stdin(req.password, sizeof(req.password)) < 0)
				return 1;
		} else {
			snprintf(req.username, sizeof(req.username), "%s", argv[2]);
			snprintf(req.password, sizeof(req.password), "%s", argv[3]);
		}
		rc = authd_rpc(&req, &resp);
		explicit_bzero(req.password, sizeof(req.password));
		if (rc < 0) {
			fprintf(stderr, "passwd update failed: %d\n", rc);
			return 1;
		}
		printf("Password updated in authentication vault for '%s'.\n", req.username);
		return 0;
	}

	if (strcmp(argv[1], "set-label") == 0 && argc >= 4) {
		req.op = AUTHD_REQ_SETLABEL;
		snprintf(req.username, sizeof(req.username), "%s", argv[2]);
		snprintf(req.label, sizeof(req.label), "%s", argv[3]);
		if (authd_rpc(&req, &resp) < 0) {
			fprintf(stderr, "set-label failed: %d\n", resp.status);
			return 1;
		}
		printf("Updated enforcement label for '%s' -> %s\n", argv[2], argv[3]);
		return 0;
	}

	if (strcmp(argv[1], "info") == 0 && argc >= 3) {
		req.op = AUTHD_REQ_LOOKUP;
		snprintf(req.username, sizeof(req.username), "%s", argv[2]);
		if (authd_rpc(&req, &resp) < 0) {
			fprintf(stderr, "account '%s' not found\n", argv[2]);
			return 1;
		}
		printf("user=%s pub_uid=%u pub_gid=%u type=%s label=%s home=%s\n",
		       argv[2], resp.pub_uid, resp.pub_gid,
		       resp.is_daemon ? "daemon" : "human",
		       resp.label, resp.home_dir);
		return 0;
	}

	usage(argv[0]);
	return 1;
}
