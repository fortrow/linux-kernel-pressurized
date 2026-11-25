// SPDX-License-Identifier: GPL-2.0
/*
 * pam_pressure.so: Custom PAM Module Replacing pam_unix
 *
 * Authenticates credentials against pressure-authd's scrypt + ChaCha20-Poly1305
 * vault, checks /dev TTY max_sessions & LOCAL/REMOTE origin, and issues the
 * one-time kernel ticket mapping random userspace pub_uid -> secret kpriv_uid.
 */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include "../authd/authd_proto.h"

static void pam_cleanup_pw(pam_handle_t *pamh, void *data, int error_status)
{
	(void)pamh;
	(void)error_status;
	if (data) {
		memset(data, 0, strlen((char *)data));
		free(data);
	}
}

static int call_authd(const struct authd_request *req,
		      struct authd_response *resp)
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

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
				   int argc, const char **argv)
{
	const char *user = NULL, *authtok = NULL, *tty = NULL, *rhost = NULL;
	struct authd_request req = {
		.magic = AUTHD_PROTO_MAGIC,
		.op = AUTHD_REQ_LOGIN,
		.target_pid = 0, /* Verify password first; session ticket minted in open_session */
	};
	struct authd_response resp = {};

	(void)flags;
	(void)argc;
	(void)argv;

	if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user)
		return PAM_USER_UNKNOWN;
	if (pam_get_authtok(pamh, PAM_AUTHTOK, &authtok, NULL) != PAM_SUCCESS ||
	    !authtok)
		return PAM_AUTH_ERR;

	(void)pam_get_item(pamh, PAM_TTY, (const void **)&tty);
	(void)pam_get_item(pamh, PAM_RHOST, (const void **)&rhost);

	snprintf(req.username, sizeof(req.username), "%s", user);
	snprintf(req.password, sizeof(req.password), "%s", authtok);
	if (tty)
		snprintf(req.tty_path, sizeof(req.tty_path), "%s", tty);
	if (rhost)
		snprintf(req.rhost, sizeof(req.rhost), "%s", rhost);
	{
		const char *ttl_env = getenv("PRESSURE_LOGIN_TTL");
		if (ttl_env && ttl_env[0]) {
			unsigned long ttl_v = strtoul(ttl_env, NULL, 10);
			if (ttl_v > 0 && ttl_v <= 65535UL)
				req.reserved = (uint16_t)ttl_v;
		}
	}

	if (call_authd(&req, &resp) != 0)
		return PAM_AUTH_ERR;

	/* Stash password briefly in PAM data so open_session can request the PID ticket */
	pam_set_data(pamh, "pressure_verified_pw", strdup(authtok),
		     pam_cleanup_pw);
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
			      int argc, const char **argv)
{
	(void)pamh; (void)flags; (void)argc; (void)argv;
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
				int argc, const char **argv)
{
	const char *user = NULL;
	struct authd_request req = {
		.magic = AUTHD_PROTO_MAGIC,
		.op = AUTHD_REQ_LOOKUP,
	};
	struct authd_response resp = {};

	(void)flags; (void)argc; (void)argv;
	if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user)
		return PAM_USER_UNKNOWN;
	snprintf(req.username, sizeof(req.username), "%s", user);
	if (call_authd(&req, &resp) != 0 || resp.is_daemon)
		return PAM_ACCT_EXPIRED;
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
				   int argc, const char **argv)
{
	const char *user = NULL, *tty = NULL, *rhost = NULL, *pw = NULL;
	struct authd_request req = {
		.magic = AUTHD_PROTO_MAGIC,
		.op = AUTHD_REQ_LOGIN,
		.target_pid = (int32_t)getpid(),
	};
	struct authd_response resp = {};

	(void)flags; (void)argc; (void)argv;
	if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user)
		return PAM_SESSION_ERR;
	(void)pam_get_data(pamh, "pressure_verified_pw", (const void **)&pw);
	if (!pw)
		(void)pam_get_item(pamh, PAM_AUTHTOK, (const void **)&pw);
	if (!pw)
		return PAM_SESSION_ERR;

	(void)pam_get_item(pamh, PAM_TTY, (const void **)&tty);
	(void)pam_get_item(pamh, PAM_RHOST, (const void **)&rhost);

	snprintf(req.username, sizeof(req.username), "%s", user);
	snprintf(req.password, sizeof(req.password), "%s", pw);
	if (tty)
		snprintf(req.tty_path, sizeof(req.tty_path), "%s", tty);
	if (rhost)
		snprintf(req.rhost, sizeof(req.rhost), "%s", rhost);
	{
		const char *ttl_env = getenv("PRESSURE_LOGIN_TTL");
		if (ttl_env && ttl_env[0]) {
			unsigned long ttl_v = strtoul(ttl_env, NULL, 10);
			if (ttl_v > 0 && ttl_v <= 65535UL)
				req.reserved = (uint16_t)ttl_v;
		}
	}

	if (call_authd(&req, &resp) != 0)
		return PAM_PERM_DENIED; /* e.g. TTY max_sessions exceeded! */

	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
				    int argc, const char **argv)
{
	struct authd_request req = {
		.magic = AUTHD_PROTO_MAGIC,
		.op = AUTHD_REQ_LOGOUT,
		.target_pid = (int32_t)getpid(),
	};
	struct authd_response resp = {};

	(void)pamh; (void)flags; (void)argc; (void)argv;
	(void)call_authd(&req, &resp);
	return PAM_SUCCESS;
}
