/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _PRESSURE_AUTHD_PROTO_H
#define _PRESSURE_AUTHD_PROTO_H

#include <stdint.h>
#include <sys/types.h>

#define AUTHD_SOCK_PATH		"/run/pressure/authd.sock"
#define AUTHD_DIR_PATH		"/etc/pressure"
#define AUTHD_VAULT_PATH	"/etc/pressure/auth.vault"
#define AUTHD_KEY_PATH		"/etc/pressure/master.key"
#define AUTHD_MANIFEST_PATH	"/etc/pressure/posix.manifest"
#define AUTHD_PROTO_MAGIC	0x50415554U /* 'PAUT' */

#define AUTHD_REQ_USERADD	1
#define AUTHD_REQ_PASSWD	2
#define AUTHD_REQ_GROUPADD	3
#define AUTHD_REQ_SETLABEL	4
#define AUTHD_REQ_LOGIN		5
#define AUTHD_REQ_START_DAEMON	6
#define AUTHD_REQ_LOGOUT	7
#define AUTHD_REQ_LOOKUP	8

struct authd_request {
	uint32_t magic;
	uint32_t op;
	int32_t  target_pid;
	uint8_t  is_daemon;
	uint8_t  force_remote;
	uint16_t reserved;
	char     username[32];
	char     password[64];
	char     label[32];
	char     home_dir[96];
	char     tty_path[64];
	char     rhost[64];
};

struct authd_response {
	uint32_t magic;
	int32_t  status; /* 0 = ok, < 0 = -errno */
	uint32_t pub_uid;
	uint32_t pub_gid;
	uint8_t  is_daemon;
	uint8_t  provenance;
	char     label[32];
	char     home_dir[96];
	char     message[96];
};

#endif
