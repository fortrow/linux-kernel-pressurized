// SPDX-License-Identifier: GPL-2.0
/*
 * Declarative Pressure + sfw Policy File (.pr) Parser, Validator & Loader
 * Supports `sure check <file.pr>` (dry-run validation) and `sure load <file.pr>`.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/xattr.h>

#include "../../include/uapi/linux/sfw.h"
#include "policy_parser.h"

#define MAX_VARS	128
#define MAX_STMTS	512
#define MAX_STMT_TOKS	64
#define MAX_INC_DEPTH	8

enum pr_op_kind {
	PR_OP_ENFORCE = 1,
	PR_OP_POLICY_FLUSH,
	PR_OP_POLICY_RULE,
	PR_OP_DEV_RULE,
	PR_OP_NETDEV_RULE,
	PR_OP_FILE_LABEL,
	PR_OP_SFW_SOCK_FLUSH,
	PR_OP_SFW_SOCK_RULE,
	PR_OP_SFW_CHAIN_FLUSH,
	PR_OP_SFW_CHAIN_POLICY,
	PR_OP_SFW_CHAIN_RULE,
	PR_OP_SFW_NAT_FLUSH,
	PR_OP_SFW_NAT_RULE,
	PR_OP_UNIX_SOCK_FLUSH,
	PR_OP_UNIX_SOCK_RULE,
};

struct pr_var {
	char name[64];  /* includes leading '$' */
	char value[128];
};

struct pr_compiled_op {
	enum pr_op_kind kind;
	char src_file[128];
	int line;
	bool optional;
	uint32_t u1;
	uint32_t u2;
	char target[160];
	char label[32];
	char prov[16];
	char kern_line[320];
};

struct pr_ctx {
	struct pr_var vars[MAX_VARS];
	int var_cnt;
	struct pr_compiled_op ops[MAX_STMTS];
	int op_cnt;
};

static int set_var(struct pr_ctx *ctx, const char *name, const char *val)
{
	for (int i = 0; i < ctx->var_cnt; i++) {
		if (strcmp(ctx->vars[i].name, name) == 0) {
			snprintf(ctx->vars[i].value, sizeof(ctx->vars[i].value),
				 "%s", val);
			return 0;
		}
	}
	if (ctx->var_cnt >= MAX_VARS)
		return -1;
	snprintf(ctx->vars[ctx->var_cnt].name, sizeof(ctx->vars[0].name), "%s", name);
	snprintf(ctx->vars[ctx->var_cnt].value, sizeof(ctx->vars[0].value), "%s", val);
	ctx->var_cnt++;
	return 0;
}

static bool expand_vars(const struct pr_ctx *ctx, const char *in,
			char *out, size_t out_sz)
{
	size_t oi = 0;
	const char *p = in;

	while (*p && oi + 1 < out_sz) {
		if (*p == '$') {
			char vname[64];
			size_t vi = 0;
			vname[vi++] = *p++;
			while ((*p && (isalnum((unsigned char)*p) || *p == '_')) &&
			       vi + 1 < sizeof(vname))
				vname[vi++] = *p++;
			vname[vi] = '\0';

			const char *found = NULL;
			for (int i = 0; i < ctx->var_cnt; i++) {
				if (strcmp(ctx->vars[i].name, vname) == 0) {
					found = ctx->vars[i].value;
					break;
				}
			}
			if (!found)
				return false;
			size_t flen = strlen(found);
			if (oi + flen >= out_sz)
				return false;
			memcpy(out + oi, found, flen);
			oi += flen;
		} else {
			out[oi++] = *p++;
		}
	}
	out[oi] = '\0';
	return *p == '\0';
}

static int parse_prov_val(const char *s)
{
	if (strcmp(s, "prelogin_local") == 0 || strcmp(s, "0") == 0)
		return PRESSURE_PROV_PRELOGIN_LOCAL;
	if (strcmp(s, "auth_local") == 0 || strcmp(s, "local") == 0 ||
	    strcmp(s, "1") == 0)
		return PRESSURE_PROV_AUTH_LOCAL;
	if (strcmp(s, "remote") == 0 || strcmp(s, "2") == 0)
		return PRESSURE_PROV_REMOTE;
	return -1;
}

static int parse_dev_class(const char *s)
{
	if (strcmp(s, "pseudo_safe") == 0 || strcmp(s, "0") == 0) return PDEV_PSEUDO_SAFE;
	if (strcmp(s, "seat_tty") == 0    || strcmp(s, "1") == 0) return PDEV_SEAT_TTY;
	if (strcmp(s, "seat_input") == 0  || strcmp(s, "2") == 0) return PDEV_SEAT_INPUT;
	if (strcmp(s, "storage_blk") == 0 || strcmp(s, "3") == 0) return PDEV_STORAGE_BLK;
	if (strcmp(s, "pty") == 0         || strcmp(s, "4") == 0) return PDEV_PTY_SLAVE;
	if (strcmp(s, "net_lo") == 0      || strcmp(s, "5") == 0) return PDEV_NET_LO;
	if (strcmp(s, "net_ext") == 0     || strcmp(s, "6") == 0) return PDEV_NET_EXT;
	if (strcmp(s, "other_chr") == 0   || strcmp(s, "7") == 0) return PDEV_OTHER_CHR;
	return -1;
}

static int parse_ev_bit(const char *s, uint32_t *out)
{
	if (strcmp(s, "open") == 0)         { *out |= PEV_OPEN; return 0; }
	if (strcmp(s, "read") == 0)         { *out |= PEV_READ; return 0; }
	if (strcmp(s, "write") == 0)        { *out |= PEV_WRITE; return 0; }
	if (strcmp(s, "ioctl") == 0)        { *out |= PEV_IOCTL; return 0; }
	if (strcmp(s, "mknod") == 0)        { *out |= PEV_MKNOD; return 0; }
	if (strcmp(s, "exec") == 0)         { *out |= PEV_EXEC; return 0; }
	if (strcmp(s, "mmap_exec") == 0)    { *out |= PEV_MMAP_EXEC; return 0; }
	if (strcmp(s, "setuid") == 0)       { *out |= PEV_SETUID; return 0; }
	if (strcmp(s, "sock_bind") == 0)    { *out |= PEV_SOCK_BIND; return 0; }
	if (strcmp(s, "sock_connect") == 0) { *out |= PEV_SOCK_CONNECT; return 0; }
	if (strcmp(s, "sock_send") == 0)    { *out |= PEV_SOCK_SEND; return 0; }
	if (strcmp(s, "sock_recv") == 0)    { *out |= PEV_SOCK_RECV; return 0; }
	if (strcmp(s, "login") == 0)        { *out |= PEV_LOGIN; return 0; }
	if (strcmp(s, "proc_self_fd") == 0) { *out |= PEV_PROC_SELF_FD; return 0; }
	if (strcmp(s, "local_proxy") == 0)   { *out |= PEV_LOCAL_PROXY; return 0; }
	if (strcmp(s, "local_callback") == 0) { *out |= PEV_LOCAL_CALLBACK; return 0; }
	if (strcmp(s, "local_callback_relay") == 0) { *out |= PEV_LOCAL_CALLBACK_RELAY; return 0; }
	if (strcmp(s, "userns_nested") == 0) { *out |= PEV_USERNS_NESTED; return 0; }
	if (strcmp(s, "userns") == 0)       { *out |= PEV_USERNS; return 0; }
	if (strcmp(s, "mmap_write") == 0)   { *out |= PEV_MMAP_WRITE; return 0; }
	if (strcmp(s, "all") == 0 || strcmp(s, "*") == 0) { *out |= PEV_ALL & ~(PEV_USERNS | PEV_USERNS_NESTED | PEV_LOCAL_PROXY | PEV_PROC_SELF_FD); return 0; }
	return -1;
}

static int parse_sfw_dir(const char *s)
{
	if (strcmp(s, "any") == 0 || strcmp(s, "*") == 0) return SFW_DIR_ANY;
	if (strcmp(s, "bind") == 0)    return SFW_DIR_BIND;
	if (strcmp(s, "connect") == 0) return SFW_DIR_CONNECT;
	if (strcmp(s, "send") == 0)    return SFW_DIR_SEND;
	if (strcmp(s, "recv") == 0)    return SFW_DIR_RECV;
	return -1;
}

static int parse_unix_type(const char *s)
{
	if (strcmp(s, "any") == 0 || strcmp(s, "*") == 0 || strcmp(s, "0") == 0)
		return 0;
	if (strcmp(s, "stream") == 0)    return SOCK_STREAM;
	if (strcmp(s, "dgram") == 0)     return SOCK_DGRAM;
	if (strcmp(s, "seqpacket") == 0) return SOCK_SEQPACKET;
	return -1;
}

static int parse_unix_op_bit(const char *s, uint32_t *out)
{
	if (strcmp(s, "create") == 0)     { *out |= PUNIX_OP_CREATE; return 0; }
	if (strcmp(s, "socketpair") == 0) { *out |= PUNIX_OP_SOCKETPAIR; return 0; }
	if (strcmp(s, "bind") == 0)       { *out |= PUNIX_OP_BIND; return 0; }
	if (strcmp(s, "connect") == 0)    { *out |= PUNIX_OP_CONNECT; return 0; }
	if (strcmp(s, "send") == 0)       { *out |= PUNIX_OP_SEND; return 0; }
	if (strcmp(s, "recv") == 0)       { *out |= PUNIX_OP_RECV; return 0; }
	if (strcmp(s, "pass_fd") == 0)    { *out |= PUNIX_OP_PASS_FD; return 0; }
	if (strcmp(s, "all") == 0 || strcmp(s, "*") == 0) {
		*out |= PUNIX_OP_ALL;
		return 0;
	}
	return -1;
}

static bool valid_chain_name(const char *s)
{
	return strcmp(s, "prerouting") == 0 || strcmp(s, "input") == 0 ||
	       strcmp(s, "forward") == 0 || strcmp(s, "output") == 0 ||
	       strcmp(s, "postrouting") == 0;
}

static bool valid_proto_name(const char *s)
{
	return strcmp(s, "tcp") == 0 || strcmp(s, "udp") == 0 ||
	       strcmp(s, "icmp") == 0 || strcmp(s, "icmpv6") == 0 ||
	       strcmp(s, "icmp6") == 0 || strcmp(s, "all") == 0;
}

static bool parse_port_spec(const char *s, unsigned int *pmin, unsigned int *pmax)
{
	if (strcmp(s, "*") == 0 || strcmp(s, "any") == 0 || strcmp(s, "0") == 0) {
		*pmin = 0;
		*pmax = 0;
		return true;
	}
	const char *dash = strchr(s, '-');
	char *end = NULL;
	if (dash) {
		char b1[16];
		size_t l1 = (size_t)(dash - s);
		if (l1 == 0 || l1 >= sizeof(b1))
			return false;
		memcpy(b1, s, l1);
		b1[l1] = '\0';
		unsigned long a = strtoul(b1, &end, 10);
		if (!end || *end != '\0' || a > 65535)
			return false;
		unsigned long b = strtoul(dash + 1, &end, 10);
		if (!end || *end != '\0' || b > 65535 || a > b)
			return false;
		*pmin = (unsigned int)a;
		*pmax = (unsigned int)b;
		return true;
	}
	unsigned long p = strtoul(s, &end, 10);
	if (!end || *end != '\0' || p > 65535)
		return false;
	*pmin = (unsigned int)p;
	*pmax = (unsigned int)p;
	return true;
}

static bool validate_cidr(const char *s, int *fam_out, char *ip_out,
			  size_t ip_sz, char *mask_or_plen_out, size_t mp_sz)
{
	char buf[96];

	if (strcmp(s, "*") == 0 || strcmp(s, "any") == 0) {
		*fam_out = 0;
		snprintf(ip_out, ip_sz, "0.0.0.0");
		snprintf(mask_or_plen_out, mp_sz, "0.0.0.0");
		return true;
	}
	snprintf(buf, sizeof(buf), "%s", s);
	if (buf[0] == '[') {
		char *rb = strchr(buf, ']');
		if (!rb)
			return false;
		memmove(buf, buf + 1, (size_t)(rb - (buf + 1)));
		memmove(rb - 1, rb + 1, strlen(rb + 1) + 1);
	}
	char *slash = strchr(buf, '/');
	if (strchr(buf, ':') != NULL) {
		unsigned long plen = 128;
		struct in6_addr a6;
		if (slash) {
			char *end = NULL;
			*slash++ = '\0';
			plen = strtoul(slash, &end, 10);
			if (!end || *end != '\0' || plen > 128)
				return false;
		}
		if (inet_pton(AF_INET6, buf, &a6) != 1)
			return false;
		*fam_out = AF_INET6;
		snprintf(ip_out, ip_sz, "%s", buf);
		snprintf(mask_or_plen_out, mp_sz, "%lu", plen);
		return true;
	} else {
		unsigned long plen = 32;
		struct in_addr a4, m4;
		if (slash) {
			char *end = NULL;
			*slash++ = '\0';
			plen = strtoul(slash, &end, 10);
			if (!end || *end != '\0' || plen > 32)
				return false;
		}
		if (inet_pton(AF_INET, buf, &a4) != 1)
			return false;
		uint32_t mask_h = (plen == 0) ? 0U : (~0U << (32 - plen));
		m4.s_addr = htonl(mask_h);
		*fam_out = AF_INET;
		snprintf(ip_out, ip_sz, "%s", buf);
		if (!inet_ntop(AF_INET, &m4, mask_or_plen_out, (socklen_t)mp_sz))
			return false;
		return true;
	}
}

static bool parse_ip_and_port(const char *s, int *fam_out, char *ip_out,
			      size_t ip_sz, unsigned int *port_out)
{
	char buf[96];
	snprintf(buf, sizeof(buf), "%s", s);

	if (buf[0] == '[') {
		char *rb = strchr(buf, ']');
		if (!rb || rb[1] != ':')
			return false;
		*rb = '\0';
		struct in6_addr a6;
		if (inet_pton(AF_INET6, buf + 1, &a6) != 1)
			return false;
		char *end = NULL;
		unsigned long p = strtoul(rb + 2, &end, 10);
		if (!end || *end != '\0' || p == 0 || p > 65535)
			return false;
		*fam_out = AF_INET6;
		snprintf(ip_out, ip_sz, "%s", buf + 1);
		*port_out = (unsigned int)p;
		return true;
	}

	char *colon = strrchr(buf, ':');
	if (!colon)
		return false;
	*colon++ = '\0';
	struct in_addr a4;
	if (inet_pton(AF_INET, buf, &a4) != 1)
		return false;
	char *end = NULL;
	unsigned long p = strtoul(colon, &end, 10);
	if (!end || *end != '\0' || p == 0 || p > 65535)
		return false;
	*fam_out = AF_INET;
	snprintf(ip_out, ip_sz, "%s", buf);
	*port_out = (unsigned int)p;
	return true;
}

static int parse_file_recursive(struct pr_ctx *ctx, const char *filepath,
				int depth);

static int compile_stmt(struct pr_ctx *ctx, const char *file, int line,
			int ntok, char toks[][128])
{
	if (ntok == 0)
		return 0;

	/* 1. define $NAME = value; */
	if (strcmp(toks[0], "define") == 0) {
		if (ntok != 4 || toks[1][0] != '$' || strcmp(toks[2], "=") != 0) {
			fprintf(stderr, "%s:%d: syntax error in 'define $NAME = value;'\n",
				file, line);
			return -1;
		}
		if (set_var(ctx, toks[1], toks[3]) < 0) {
			fprintf(stderr, "%s:%d: too many variables\n", file, line);
			return -1;
		}
		return 0;
	}

	/* Expand $VARIABLES in all tokens before semantic compilation */
	for (int i = 0; i < ntok; i++) {
		if (strchr(toks[i], '$') != NULL) {
			char expanded[128];
			if (!expand_vars(ctx, toks[i], expanded, sizeof(expanded))) {
				fprintf(stderr, "%s:%d: undefined variable in '%s'\n",
					file, line, toks[i]);
				return -1;
			}
			snprintf(toks[i], 128, "%s", expanded);
		}
	}

	/* 2. include "other.pr"; */
	if (strcmp(toks[0], "include") == 0) {
		if (ntok != 2) {
			fprintf(stderr, "%s:%d: syntax error in 'include \"path.pr\";'\n",
				file, line);
			return -1;
		}
		char inc_path[256];
		if (toks[1][0] == '/') {
			snprintf(inc_path, sizeof(inc_path), "%s", toks[1]);
		} else {
			char fcopy[256];
			snprintf(fcopy, sizeof(fcopy), "%s", file);
			snprintf(inc_path, sizeof(inc_path), "%s/%s",
				 dirname(fcopy), toks[1]);
		}
		return parse_file_recursive(ctx, inc_path, MAX_INC_DEPTH);
	}

	if (ctx->op_cnt >= MAX_STMTS) {
		fprintf(stderr, "%s:%d: maximum statement count (%d) exceeded\n",
			file, line, MAX_STMTS);
		return -1;
	}

	struct pr_compiled_op *op = &ctx->ops[ctx->op_cnt];
	memset(op, 0, sizeof(*op));
	snprintf(op->src_file, sizeof(op->src_file), "%s", file);
	op->line = line;

	/* 3. set enforce <on|off|1|0>; */
	if (strcmp(toks[0], "set") == 0) {
		if (ntok != 3 || strcmp(toks[1], "enforce") != 0) {
			fprintf(stderr, "%s:%d: expected 'set enforce <on|off>;'\n",
				file, line);
			return -1;
		}
		if (strcmp(toks[2], "on") == 0 || strcmp(toks[2], "1") == 0)
			op->u1 = 1;
		else if (strcmp(toks[2], "off") == 0 || strcmp(toks[2], "0") == 0)
			op->u1 = 0;
		else {
			fprintf(stderr, "%s:%d: invalid enforce mode '%s'\n",
				file, line, toks[2]);
			return -1;
		}
		op->kind = PR_OP_ENFORCE;
		snprintf(op->kern_line, sizeof(op->kern_line), "%u\n", op->u1);
		ctx->op_cnt++;
		return 0;
	}

	/* 4. policy flush; */
	if (strcmp(toks[0], "policy") == 0 && ntok == 2 &&
	    strcmp(toks[1], "flush") == 0) {
		op->kind = PR_OP_POLICY_FLUSH;
		snprintf(op->kern_line, sizeof(op->kern_line), "flush\n");
		ctx->op_cnt++;
		return 0;
	}

	/* 5. device / netdev */
	if (strcmp(toks[0], "device") == 0 || strcmp(toks[0], "netdev") == 0) {
		bool is_net = (strcmp(toks[0], "netdev") == 0);
		if (ntok < 2) {
			fprintf(stderr, "%s:%d: missing target in %s rule\n",
				file, line, toks[0]);
			return -1;
		}
		snprintf(op->target, sizeof(op->target), "%s", toks[1]);
		int dcls = is_net ? PDEV_NET_EXT : -1;
		unsigned int max_sess = 0;
		snprintf(op->prov, sizeof(op->prov), "%s", is_net ? "remote" : "local");

		for (int i = 2; i < ntok; i++) {
			if (strcmp(toks[i], "label") == 0 && i + 1 < ntok) {
				if (strlen(toks[i + 1]) >= 32) {
					fprintf(stderr, "%s:%d: label too long\n", file, line);
					return -1;
				}
				snprintf(op->label, sizeof(op->label), "%s", toks[++i]);
			} else if (strcmp(toks[i], "class") == 0 && i + 1 < ntok) {
				dcls = parse_dev_class(toks[++i]);
				if (dcls < 0) {
					fprintf(stderr, "%s:%d: unknown device class '%s'\n",
						file, line, toks[i]);
					return -1;
				}
			} else if (strcmp(toks[i], "origin") == 0 && i + 1 < ntok) {
				const char *o = toks[++i];
				if (strcmp(o, "local") != 0 && strcmp(o, "remote") != 0) {
					fprintf(stderr, "%s:%d: origin must be local|remote\n",
						file, line);
					return -1;
				}
				snprintf(op->prov, sizeof(op->prov), "%s", o);
			} else if (strcmp(toks[i], "max_sessions") == 0 && i + 1 < ntok) {
				char *end = NULL;
				unsigned long ms = strtoul(toks[++i], &end, 10);
				if (!end || *end != '\0' || ms > 65535) {
					fprintf(stderr, "%s:%d: invalid max_sessions\n",
						file, line);
					return -1;
				}
				max_sess = (unsigned int)ms;
			} else if (strcmp(toks[i], "optional") == 0) {
				op->optional = true;
			} else {
				fprintf(stderr, "%s:%d: unexpected token '%s' in %s\n",
					file, line, toks[i], toks[0]);
				return -1;
			}
		}
		if (!op->label[0] || dcls < 0) {
			fprintf(stderr, "%s:%d: %s requires 'label' and 'class'\n",
				file, line, toks[0]);
			return -1;
		}
		op->kind = is_net ? PR_OP_NETDEV_RULE : PR_OP_DEV_RULE;
		op->u1 = (uint32_t)dcls;
		op->u2 = max_sess;
		ctx->op_cnt++;
		return 0;
	}

	/* 6. file <path> label <lbl> [flags { local_only, user_private, vault }] [owner <uid>] [optional]; */
	if (strcmp(toks[0], "file") == 0) {
		if (ntok < 4) {
			fprintf(stderr, "%s:%d: incomplete file statement\n", file, line);
			return -1;
		}
		snprintf(op->target, sizeof(op->target), "%s", toks[1]);
		uint32_t fflags = 0, owner_uid = 0;
		for (int i = 2; i < ntok; i++) {
			if (strcmp(toks[i], "label") == 0 && i + 1 < ntok) {
				if (strlen(toks[i + 1]) >= 32) {
					fprintf(stderr, "%s:%d: file label too long\n",
						file, line);
					return -1;
				}
				snprintf(op->label, sizeof(op->label), "%s", toks[++i]);
			} else if (strcmp(toks[i], "owner") == 0 && i + 1 < ntok) {
				char *end = NULL;
				unsigned long u = strtoul(toks[++i], &end, 10);
				if (!end || *end != '\0') {
					fprintf(stderr, "%s:%d: invalid owner uid\n",
						file, line);
					return -1;
				}
				owner_uid = (uint32_t)u;
			} else if (strcmp(toks[i], "flags") == 0 && i + 1 < ntok &&
				   strcmp(toks[i + 1], "{") == 0) {
				i += 2;
				while (i < ntok && strcmp(toks[i], "}") != 0) {
					if (strcmp(toks[i], ",") == 0) {
						i++;
						continue;
					}
					if (strcmp(toks[i], "local_only") == 0)
						fflags |= PRESSURE_FILE_LOCAL_ONLY;
					else if (strcmp(toks[i], "user_private") == 0)
						fflags |= PRESSURE_FILE_USER_PRIVATE;
					else if (strcmp(toks[i], "vault") == 0)
						fflags |= PRESSURE_FILE_AUTHD_VAULT;
					else if (strcmp(toks[i], "protected") == 0)
						fflags |= PRESSURE_FILE_PROTECTED;
					else {
						fprintf(stderr, "%s:%d: unknown file flag '%s'\n",
							file, line, toks[i]);
						return -1;
					}
					i++;
				}
				if (i >= ntok || strcmp(toks[i], "}") != 0) {
					fprintf(stderr, "%s:%d: unclosed flags '{'\n",
						file, line);
					return -1;
				}
			} else if (strcmp(toks[i], "optional") == 0) {
				op->optional = true;
			} else {
				fprintf(stderr, "%s:%d: unexpected token '%s' in file rule\n",
					file, line, toks[i]);
				return -1;
			}
		}
		if (!op->label[0]) {
			fprintf(stderr, "%s:%d: file statement missing 'label'\n",
				file, line);
			return -1;
		}
		op->kind = PR_OP_FILE_LABEL;
		op->u1 = fflags;
		op->u2 = owner_uid;
		ctx->op_cnt++;
		return 0;
	}

	/* 7. allow|deny subject <s|*> object <o|*> [device <d|*>] events { ... } max_prov <p>; */
	if (strcmp(toks[0], "allow") == 0 || strcmp(toks[0], "deny") == 0) {
		const char *act = toks[0];
		char subj[32] = "*", obj[32] = "*", dev[32] = "*";
		uint32_t ev_mask = 0;
		int mprov = -1;

		for (int i = 1; i < ntok; i++) {
			if (strcmp(toks[i], "subject") == 0 && i + 1 < ntok) {
				snprintf(subj, sizeof(subj), "%s", toks[++i]);
			} else if (strcmp(toks[i], "object") == 0 && i + 1 < ntok) {
				snprintf(obj, sizeof(obj), "%s", toks[++i]);
			} else if (strcmp(toks[i], "device") == 0 && i + 1 < ntok) {
				snprintf(dev, sizeof(dev), "%s", toks[++i]);
			} else if (strcmp(toks[i], "max_prov") == 0 && i + 1 < ntok) {
				mprov = parse_prov_val(toks[++i]);
				if (mprov < 0) {
					fprintf(stderr, "%s:%d: unknown max_prov '%s'\n",
						file, line, toks[i]);
					return -1;
				}
			} else if (strcmp(toks[i], "events") == 0 && i + 1 < ntok) {
				if (strcmp(toks[i + 1], "{") == 0) {
					i += 2;
					while (i < ntok && strcmp(toks[i], "}") != 0) {
						if (strcmp(toks[i], ",") == 0) {
							i++;
							continue;
						}
						if (parse_ev_bit(toks[i], &ev_mask) < 0) {
							fprintf(stderr, "%s:%d: unknown event '%s'\n",
								file, line, toks[i]);
							return -1;
						}
						i++;
					}
					if (i >= ntok || strcmp(toks[i], "}") != 0) {
						fprintf(stderr, "%s:%d: unclosed events '{'\n",
							file, line);
						return -1;
					}
				} else {
					if (parse_ev_bit(toks[++i], &ev_mask) < 0) {
						fprintf(stderr, "%s:%d: unknown event '%s'\n",
							file, line, toks[i]);
						return -1;
					}
				}
			} else {
				fprintf(stderr, "%s:%d: unexpected token '%s' in %s rule\n",
					file, line, toks[i], act);
				return -1;
			}
		}
		if (ev_mask == 0 || mprov < 0) {
			fprintf(stderr, "%s:%d: %s rule requires 'events' and 'max_prov'\n",
				file, line, act);
			return -1;
		}
		if ((ev_mask & (PEV_USERNS | PEV_USERNS_NESTED)) &&
		    ((ev_mask != PEV_USERNS && ev_mask != PEV_USERNS_NESTED) || mprov != PRESSURE_PROV_AUTH_LOCAL ||
		     strchr(subj, '*') || strchr(obj, '*') ||
		     strcmp(dev, "dev:console_tty1"))) {
			fprintf(stderr, "%s:%d: user namespace events require exact subject and object labels, dev:console_tty1, and auth_local\n",
				file, line);
			return -1;
		}
		if ((ev_mask & (PEV_LOCAL_PROXY | PEV_PROC_SELF_FD | PEV_LOCAL_CALLBACK |
				PEV_LOCAL_CALLBACK_RELAY)) &&
		    ((ev_mask != PEV_LOCAL_PROXY && ev_mask != PEV_PROC_SELF_FD &&
		      ev_mask != PEV_LOCAL_CALLBACK && ev_mask != PEV_LOCAL_CALLBACK_RELAY) ||
		     mprov != PRESSURE_PROV_AUTH_LOCAL ||
		     strncmp(subj, "subj:", 5) || !subj[5] || strchr(subj, '*') ||
		     strncmp(obj, "obj:", 4) || !obj[4] || strchr(obj, '*') ||
		     (strcmp(dev, "dev:console_tty1") && strcmp(dev, "dev:tty1_helper")))) {
			fprintf(stderr, "%s:%d: protected local socket and proc_self_fd events require separate exact subject, executable, and authenticated tty1 rules\n",
				file, line);
			return -1;
		}
		op->kind = PR_OP_POLICY_RULE;
		snprintf(op->kern_line, sizeof(op->kern_line),
			 "%.15s %s %s %s %x %d\n",
			 act, subj, obj, dev, ev_mask, mprov);
		ctx->op_cnt++;
		return 0;
	}

	/* 8. sfw_socket ... */
	if (strcmp(toks[0], "sfw_socket") == 0) {
		if (ntok == 2 && strcmp(toks[1], "flush") == 0) {
			op->kind = PR_OP_SFW_SOCK_FLUSH;
			snprintf(op->kern_line, sizeof(op->kern_line), "flush\n");
			ctx->op_cnt++;
			return 0;
		}
		if (ntok < 3 || (strcmp(toks[1], "allow") != 0 &&
				 strcmp(toks[1], "deny") != 0)) {
			fprintf(stderr, "%s:%d: expected 'sfw_socket <allow|deny|flush> ...'\n",
				file, line);
			return -1;
		}
		const char *act = toks[1];
		int dir = parse_sfw_dir(toks[2]);
		if (dir < 0) {
			fprintf(stderr, "%s:%d: unknown sfw_socket direction '%s'\n",
				file, line, toks[2]);
			return -1;
		}
		unsigned int uid = 0, pmin = 0, pmax = 0;
		char dst_s[80] = "*", dev_s[32] = "*";
		int mprov = -1;

		for (int i = 3; i < ntok; i++) {
			if (strcmp(toks[i], "uid") == 0 && i + 1 < ntok) {
				const char *us = toks[++i];
				if (strcmp(us, "*") == 0 || strcmp(us, "any") == 0)
					uid = 0;
				else {
					char *end = NULL;
					uid = (unsigned int)strtoul(us, &end, 10);
					if (!end || *end != '\0') {
						fprintf(stderr, "%s:%d: bad uid '%s'\n",
							file, line, us);
						return -1;
					}
				}
			} else if (strcmp(toks[i], "dst") == 0 && i + 1 < ntok) {
				snprintf(dst_s, sizeof(dst_s), "%s", toks[++i]);
			} else if (strcmp(toks[i], "ports") == 0 && i + 1 < ntok) {
				if (!parse_port_spec(toks[++i], &pmin, &pmax)) {
					fprintf(stderr, "%s:%d: bad port range '%s'\n",
						file, line, toks[i]);
					return -1;
				}
			} else if (strcmp(toks[i], "dev") == 0 && i + 1 < ntok) {
				snprintf(dev_s, sizeof(dev_s), "%s", toks[++i]);
			} else if (strcmp(toks[i], "max_prov") == 0 && i + 1 < ntok) {
				mprov = parse_prov_val(toks[++i]);
				if (mprov < 0) {
					fprintf(stderr, "%s:%d: bad max_prov '%s'\n",
						file, line, toks[i]);
					return -1;
				}
			} else {
				fprintf(stderr, "%s:%d: unexpected token '%s' in sfw_socket\n",
					file, line, toks[i]);
				return -1;
			}
		}
		if (mprov < 0) {
			fprintf(stderr, "%s:%d: sfw_socket requires 'max_prov'\n",
				file, line);
			return -1;
		}
		int fam = 0;
		char ip_part[96], mp_part[32];
		if (!validate_cidr(dst_s, &fam, ip_part, sizeof(ip_part),
				   mp_part, sizeof(mp_part))) {
			fprintf(stderr, "%s:%d: invalid dst CIDR '%s'\n",
				file, line, dst_s);
			return -1;
		}
		op->kind = PR_OP_SFW_SOCK_RULE;
		if (fam == AF_INET6) {
			snprintf(op->kern_line, sizeof(op->kern_line),
				 "inet6 %.15s %d %u %s %s %u %u %s %d\n",
				 act, dir, uid, ip_part, mp_part, pmin, pmax,
				 dev_s, mprov);
		} else {
			snprintf(op->kern_line, sizeof(op->kern_line),
				 "%.15s %d %u %s %s %u %u %s %d\n",
				 act, dir, uid, ip_part, mp_part, pmin, pmax,
				 dev_s, mprov);
		}
		ctx->op_cnt++;
		return 0;
	}

	/* 8b. unix_socket <flush | allow|deny ...> */
	if (strcmp(toks[0], "unix_socket") == 0) {
		if (ntok == 2 && strcmp(toks[1], "flush") == 0) {
			op->kind = PR_OP_UNIX_SOCK_FLUSH;
			snprintf(op->kern_line, sizeof(op->kern_line), "flush\n");
			ctx->op_cnt++;
			return 0;
		}
		if (ntok < 3 || (strcmp(toks[1], "allow") != 0 &&
				 strcmp(toks[1], "deny") != 0)) {
			fprintf(stderr, "%s:%d: expected 'unix_socket <allow|deny|flush> ...'\n",
				file, line);
			return -1;
		}
		const char *act = toks[1];
		char subj[32] = "*", ep[112] = "-", peer[32] = "*", dev_s[32] = "*", exe[32] = "";
		int stype = 0;
		uint32_t op_mask = 0;
		int mprov = -1;

		for (int i = 2; i < ntok; i++) {
			if (strcmp(toks[i], "subject") == 0 && i + 1 < ntok) {
				if (strlen(toks[i + 1]) >= sizeof(subj)) {
					fprintf(stderr, "%s:%d: unix_socket subject too long\n",
						file, line);
					return -1;
				}
				snprintf(subj, sizeof(subj), "%s", toks[++i]);
			} else if (strcmp(toks[i], "executable") == 0 && i + 1 < ntok) {
				const char *label = toks[++i];

				if (strncmp(label, "obj:", 4) || !label[4] ||
				    strchr(label, '*') || strlen(label) >= sizeof(exe)) {
					fprintf(stderr, "%s:%d: unix_socket executable requires an exact object label\n",
						file, line);
					return -1;
				}
				snprintf(exe, sizeof(exe), "%s", label);
			} else if (strcmp(toks[i], "type") == 0 && i + 1 < ntok) {
				stype = parse_unix_type(toks[++i]);
				if (stype < 0) {
					fprintf(stderr, "%s:%d: unknown unix_socket type '%s'\n",
						file, line, toks[i]);
					return -1;
				}
			} else if (strcmp(toks[i], "endpoint") == 0 && i + 1 < ntok) {
				const char *e = toks[++i];
				if (strcmp(e, "none") == 0)
					e = "-";
				if (strlen(e) >= sizeof(ep)) {
					fprintf(stderr, "%s:%d: unix_socket endpoint too long\n",
						file, line);
					return -1;
				}
				snprintf(ep, sizeof(ep), "%s", e);
			} else if (strcmp(toks[i], "peer") == 0 && i + 1 < ntok) {
				if (strlen(toks[i + 1]) >= sizeof(peer)) {
					fprintf(stderr, "%s:%d: unix_socket peer label too long\n",
						file, line);
					return -1;
				}
				snprintf(peer, sizeof(peer), "%s", toks[++i]);
			} else if (strcmp(toks[i], "device") == 0 && i + 1 < ntok) {
				if (strlen(toks[i + 1]) >= sizeof(dev_s)) {
					fprintf(stderr, "%s:%d: unix_socket device label too long\n",
						file, line);
					return -1;
				}
				snprintf(dev_s, sizeof(dev_s), "%s", toks[++i]);
			} else if (strcmp(toks[i], "max_prov") == 0 && i + 1 < ntok) {
				mprov = parse_prov_val(toks[++i]);
				if (mprov < 0) {
					fprintf(stderr, "%s:%d: unknown max_prov '%s'\n",
						file, line, toks[i]);
					return -1;
				}
			} else if (strcmp(toks[i], "ops") == 0 && i + 1 < ntok) {
				if (strcmp(toks[i + 1], "{") == 0) {
					i += 2;
					while (i < ntok && strcmp(toks[i], "}") != 0) {
						if (strcmp(toks[i], ",") == 0) {
							i++;
							continue;
						}
						if (parse_unix_op_bit(toks[i], &op_mask) < 0) {
							fprintf(stderr, "%s:%d: unknown unix_socket op '%s'\n",
								file, line, toks[i]);
							return -1;
						}
						i++;
					}
					if (i >= ntok || strcmp(toks[i], "}") != 0) {
						fprintf(stderr, "%s:%d: unclosed ops '{'\n",
							file, line);
						return -1;
					}
				} else {
					if (parse_unix_op_bit(toks[++i], &op_mask) < 0) {
						fprintf(stderr, "%s:%d: unknown unix_socket op '%s'\n",
							file, line, toks[i]);
						return -1;
					}
				}
			} else {
				fprintf(stderr, "%s:%d: unexpected token '%s' in unix_socket\n",
					file, line, toks[i]);
				return -1;
			}
		}
		if (op_mask == 0 || mprov < 0) {
			fprintf(stderr, "%s:%d: unix_socket requires 'ops' and 'max_prov'\n",
				file, line);
			return -1;
		}
		if ((op_mask & (PUNIX_OP_BIND | PUNIX_OP_CONNECT |
				PUNIX_OP_SEND | PUNIX_OP_RECV |
				PUNIX_OP_PASS_FD)) &&
		    strcmp(ep, "-") == 0) {
			fprintf(stderr, "%s:%d: unix_socket endpoint operation requires an explicit 'endpoint' (not '-')\n",
				file, line);
			return -1;
		}
		if (strcmp(dev_s, "dev:tty1_helper") == 0) {
			uint32_t pair_ops = PUNIX_OP_SOCKETPAIR | PUNIX_OP_SEND | PUNIX_OP_RECV;
			bool local_pair = !(op_mask & ~pair_ops) &&
					  !strncmp(ep, "pair:", 5) &&
					  !strcmp(ep + 5, subj) && !strcmp(peer, subj);
			bool chatgpt_adapter =
				!strcmp(ep, "/run/trimos/chatgpt-auth.sock") &&
				!strcmp(peer, "subj:boot") && !strcmp(subj, "subj:user_desktop") &&
				((!strcmp(exe, "obj:chatgpt_connector") && op_mask == PUNIX_OP_CONNECT) ||
				 (!strcmp(exe, "obj:chatgpt_adapter") &&
				  op_mask && !(op_mask & ~(PUNIX_OP_SEND | PUNIX_OP_RECV))));

			if (!exe[0] || strncmp(subj, "subj:", 5) || !subj[5] ||
			    strchr(subj, '*') || mprov != PRESSURE_PROV_AUTH_LOCAL ||
			    stype != SOCK_STREAM ||
			    (!local_pair && !chatgpt_adapter &&
			     (op_mask != PUNIX_OP_CREATE || strcmp(ep, "-")))) {
				fprintf(stderr, "%s:%d: tty1_helper requires an exact executable and subject, auth_local, and local stream IPC\n",
					file, line);
				return -1;
			}
		}
		op->kind = PR_OP_UNIX_SOCK_RULE;
		snprintf(op->kern_line, sizeof(op->kern_line),
			 "%.15s%s %s %d %x %s %s %s %d%s%s\n",
			 act, exe[0] ? "_exe" : "", subj, stype, op_mask, ep, peer, dev_s, mprov,
			 exe[0] ? " " : "", exe);
		ctx->op_cnt++;
		return 0;
	}

	/* 9. sfw_chain ... */
	if (strcmp(toks[0], "sfw_chain") == 0) {
		if (ntok == 2 && strcmp(toks[1], "flush") == 0) {
			op->kind = PR_OP_SFW_CHAIN_FLUSH;
			snprintf(op->kern_line, sizeof(op->kern_line), "flush\n");
			ctx->op_cnt++;
			return 0;
		}
		if (ntok == 4 && strcmp(toks[1], "policy") == 0) {
			if (!valid_chain_name(toks[2]) ||
			    (strcmp(toks[3], "accept") != 0 &&
			     strcmp(toks[3], "allow") != 0 &&
			     strcmp(toks[3], "drop") != 0)) {
				fprintf(stderr, "%s:%d: invalid sfw_chain policy\n",
					file, line);
				return -1;
			}
			op->kind = PR_OP_SFW_CHAIN_POLICY;
			snprintf(op->kern_line, sizeof(op->kern_line),
				 "policy %s %s\n", toks[2], toks[3]);
			ctx->op_cnt++;
			return 0;
		}
		if (ntok < 3 ||
		    (strcmp(toks[1], "allow") != 0 &&
		     strcmp(toks[1], "accept") != 0 &&
		     strcmp(toks[1], "drop") != 0) ||
		    !valid_chain_name(toks[2])) {
			fprintf(stderr, "%s:%d: expected 'sfw_chain <allow|drop> <chain> ...'\n",
				file, line);
			return -1;
		}
		const char *act = strcmp(toks[1], "drop") == 0 ? "drop" : "allow";
		const char *chain = toks[2];
		char proto[16] = "all", in_d[32] = "*", out_d[32] = "*";
		char src_s[80] = "*", dst_s[80] = "*", state_s[20] = "any";
		unsigned int pmin = 0, pmax = 0;

		for (int i = 3; i < ntok; i++) {
			if (strcmp(toks[i], "proto") == 0 && i + 1 < ntok) {
				snprintf(proto, sizeof(proto), "%s", toks[++i]);
				if (!valid_proto_name(proto)) {
					fprintf(stderr, "%s:%d: bad proto '%s'\n",
						file, line, proto);
					return -1;
				}
			} else if (strcmp(toks[i], "in") == 0 && i + 1 < ntok) {
				snprintf(in_d, sizeof(in_d), "%s", toks[++i]);
			} else if (strcmp(toks[i], "out") == 0 && i + 1 < ntok) {
				snprintf(out_d, sizeof(out_d), "%s", toks[++i]);
			} else if (strcmp(toks[i], "src") == 0 && i + 1 < ntok) {
				snprintf(src_s, sizeof(src_s), "%s", toks[++i]);
			} else if (strcmp(toks[i], "dst") == 0 && i + 1 < ntok) {
				snprintf(dst_s, sizeof(dst_s), "%s", toks[++i]);
			} else if (strcmp(toks[i], "dports") == 0 && i + 1 < ntok) {
				if (!parse_port_spec(toks[++i], &pmin, &pmax)) {
					fprintf(stderr, "%s:%d: bad dports '%s'\n",
						file, line, toks[i]);
					return -1;
				}
			} else if (strcmp(toks[i], "state") == 0 && i + 1 < ntok) {
				snprintf(state_s, sizeof(state_s), "%s", toks[++i]);
				if (strcmp(state_s, "any") != 0 &&
				    strcmp(state_s, "new") != 0 &&
				    strcmp(state_s, "established") != 0) {
					fprintf(stderr, "%s:%d: bad state '%s'\n",
						file, line, state_s);
					return -1;
				}
			} else {
				fprintf(stderr, "%s:%d: unexpected token '%s' in sfw_chain\n",
					file, line, toks[i]);
				return -1;
			}
		}
		int sfam = 0, dfam = 0;
		char tmp1[96], tmp2[32];
		if (!validate_cidr(src_s, &sfam, tmp1, sizeof(tmp1), tmp2, sizeof(tmp2)) ||
		    !validate_cidr(dst_s, &dfam, tmp1, sizeof(tmp1), tmp2, sizeof(tmp2)) ||
		    (sfam && dfam && sfam != dfam)) {
			fprintf(stderr, "%s:%d: invalid or mismatched src/dst CIDR (%s -> %s)\n",
				file, line, src_s, dst_s);
			return -1;
		}
		op->kind = PR_OP_SFW_CHAIN_RULE;
		snprintf(op->kern_line, sizeof(op->kern_line),
			 "add %.19s %.15s %s %s %s %s %s %u %u %s\n",
			 chain, act, proto, in_d, out_d, src_s, dst_s,
			 pmin, pmax, state_s);
		ctx->op_cnt++;
		return 0;
	}

	/* 10. sfw_nat ... */
	if (strcmp(toks[0], "sfw_nat") == 0) {
		if (ntok == 2 && strcmp(toks[1], "flush") == 0) {
			op->kind = PR_OP_SFW_NAT_FLUSH;
			snprintf(op->kern_line, sizeof(op->kern_line), "flush\n");
			ctx->op_cnt++;
			return 0;
		}
		if (ntok >= 2 && strcmp(toks[1], "masquerade") == 0) {
			char out_d[32] = "", src_s[80] = "";
			for (int i = 2; i < ntok; i++) {
				if (strcmp(toks[i], "out") == 0 && i + 1 < ntok)
					snprintf(out_d, sizeof(out_d), "%s", toks[++i]);
				else if (strcmp(toks[i], "src") == 0 && i + 1 < ntok)
					snprintf(src_s, sizeof(src_s), "%s", toks[++i]);
				else {
					fprintf(stderr, "%s:%d: unexpected '%s' in masquerade\n",
						file, line, toks[i]);
					return -1;
				}
			}
			int sfam = 0;
			char t1[96], t2[32];
			if (!out_d[0] || !src_s[0] ||
			    !validate_cidr(src_s, &sfam, t1, sizeof(t1), t2, sizeof(t2)) ||
			    sfam == 0) {
				fprintf(stderr, "%s:%d: invalid masquerade rule\n",
					file, line);
				return -1;
			}
			op->kind = PR_OP_SFW_NAT_RULE;
			snprintf(op->kern_line, sizeof(op->kern_line),
				 "add masquerade %s %s\n", out_d, src_s);
			ctx->op_cnt++;
			return 0;
		}
		if (ntok >= 2 && strcmp(toks[1], "snat") == 0) {
			char proto[16] = "all", out_d[32] = "", src_s[80] = "", to_ip[80] = "";
			for (int i = 2; i < ntok; i++) {
				if (strcmp(toks[i], "proto") == 0 && i + 1 < ntok)
					snprintf(proto, sizeof(proto), "%s", toks[++i]);
				else if (strcmp(toks[i], "out") == 0 && i + 1 < ntok)
					snprintf(out_d, sizeof(out_d), "%s", toks[++i]);
				else if (strcmp(toks[i], "src") == 0 && i + 1 < ntok)
					snprintf(src_s, sizeof(src_s), "%s", toks[++i]);
				else if (strcmp(toks[i], "to") == 0 && i + 1 < ntok)
					snprintf(to_ip, sizeof(to_ip), "%s", toks[++i]);
				else {
					fprintf(stderr, "%s:%d: unexpected '%s' in snat\n",
						file, line, toks[i]);
					return -1;
				}
			}
			int sfam = 0, tfam = 0;
			char t1[96], t2[32];
			if (!out_d[0] || !src_s[0] || !to_ip[0] ||
			    !valid_proto_name(proto) ||
			    !validate_cidr(src_s, &sfam, t1, sizeof(t1), t2, sizeof(t2)) ||
			    !validate_cidr(to_ip, &tfam, t1, sizeof(t1), t2, sizeof(t2)) ||
			    (sfam && tfam && sfam != tfam)) {
				fprintf(stderr, "%s:%d: invalid snat rule\n", file, line);
				return -1;
			}
			op->kind = PR_OP_SFW_NAT_RULE;
			snprintf(op->kern_line, sizeof(op->kern_line),
				 "add snat %s %s %s %s\n", proto, out_d, src_s, t1);
			ctx->op_cnt++;
			return 0;
		}
		if (ntok >= 2 && strcmp(toks[1], "dnat") == 0) {
			char proto[16] = "tcp", in_d[32] = "*", dst_s[80] = "*";
			char to_ep[96] = "";
			unsigned int dport = 0, new_port = 0;
			for (int i = 2; i < ntok; i++) {
				if (strcmp(toks[i], "proto") == 0 && i + 1 < ntok)
					snprintf(proto, sizeof(proto), "%s", toks[++i]);
				else if (strcmp(toks[i], "in") == 0 && i + 1 < ntok)
					snprintf(in_d, sizeof(in_d), "%s", toks[++i]);
				else if (strcmp(toks[i], "dst") == 0 && i + 1 < ntok)
					snprintf(dst_s, sizeof(dst_s), "%s", toks[++i]);
				else if (strcmp(toks[i], "dport") == 0 && i + 1 < ntok)
					dport = (unsigned int)strtoul(toks[++i], NULL, 10);
				else if (strcmp(toks[i], "to") == 0 && i + 1 < ntok)
					snprintf(to_ep, sizeof(to_ep), "%s", toks[++i]);
				else {
					fprintf(stderr, "%s:%d: unexpected '%s' in dnat\n",
						file, line, toks[i]);
					return -1;
				}
			}
			int dfam = 0, tfam = 0;
			char t1[96], t2[32], new_ip[96];
			if (!to_ep[0] || !valid_proto_name(proto) ||
			    !validate_cidr(dst_s, &dfam, t1, sizeof(t1), t2, sizeof(t2)) ||
			    !parse_ip_and_port(to_ep, &tfam, new_ip, sizeof(new_ip), &new_port) ||
			    (dfam && tfam && dfam != tfam)) {
				fprintf(stderr, "%s:%d: invalid dnat rule (use ip:port or [ipv6]:port)\n",
					file, line);
				return -1;
			}
			op->kind = PR_OP_SFW_NAT_RULE;
			snprintf(op->kern_line, sizeof(op->kern_line),
				 "add dnat %s %s %s %u %s %u\n",
				 proto, in_d, dst_s, dport, new_ip, new_port);
			ctx->op_cnt++;
			return 0;
		}
		fprintf(stderr, "%s:%d: unknown sfw_nat subcommand '%s'\n",
			file, line, toks[1]);
		return -1;
	}

	fprintf(stderr, "%s:%d: unknown statement keyword '%s'\n",
		file, line, toks[0]);
	return -1;
}

static int parse_file_recursive(struct pr_ctx *ctx, const char *filepath,
				int depth_left)
{
	if (depth_left <= 0) {
		fprintf(stderr, "%s: maximum include depth exceeded\n", filepath);
		return -1;
	}

	FILE *f = fopen(filepath, "r");
	if (!f) {
		fprintf(stderr, "sure: cannot open policy file '%s': %s\n",
			filepath, strerror(errno));
		return -1;
	}

	char toks[MAX_STMT_TOKS][128];
	int ntok = 0;
	int line = 1, stmt_line = 1;
	int c;

	while ((c = fgetc(f)) != EOF) {
		if (c == '\n') {
			line++;
			continue;
		}
		if (isspace((unsigned char)c))
			continue;
		if (c == '#') {
			while ((c = fgetc(f)) != EOF && c != '\n')
				;
			if (c == '\n')
				line++;
			continue;
		}

		if (ntok == 0)
			stmt_line = line;

		if (c == ';') {
			if (ntok > 0) {
				if (compile_stmt(ctx, filepath, stmt_line,
						 ntok, toks) < 0) {
					fclose(f);
					return -1;
				}
				ntok = 0;
			}
			continue;
		}

		if (ntok >= MAX_STMT_TOKS) {
			fprintf(stderr, "%s:%d: statement has too many tokens\n",
				filepath, stmt_line);
			fclose(f);
			return -1;
		}

		if (c == '{' || c == '}' || c == ',' || c == '=') {
			toks[ntok][0] = (char)c;
			toks[ntok][1] = '\0';
			ntok++;
			continue;
		}

		if (c == '"') {
			size_t ti = 0;
			while ((c = fgetc(f)) != EOF && c != '"') {
				if (c == '\n')
					line++;
				if (ti + 1 < 128)
					toks[ntok][ti++] = (char)c;
			}
			if (c != '"') {
				fprintf(stderr, "%s:%d: unterminated string literal\n",
					filepath, stmt_line);
				fclose(f);
				return -1;
			}
			toks[ntok][ti] = '\0';
			ntok++;
			continue;
		}

		size_t ti = 0;
		toks[ntok][ti++] = (char)c;
		while ((c = fgetc(f)) != EOF) {
			if (isspace((unsigned char)c) || c == ';' || c == '#' ||
			    c == '{' || c == '}' || c == ',' || c == '=') {
				ungetc(c, f);
				break;
			}
			if (ti + 1 < 128)
				toks[ntok][ti++] = (char)c;
		}
		toks[ntok][ti] = '\0';
		ntok++;
	}

	fclose(f);
	if (ntok > 0) {
		fprintf(stderr, "%s:%d: missing ';' at end of statement\n",
			filepath, stmt_line);
		return -1;
	}
	return 0;
}

static int write_kern_path(const char *path, const char *str)
{
	int fd = open(path, O_WRONLY);
	if (fd < 0)
		return -errno;
	ssize_t r = write(fd, str, strlen(str));
	int e = errno;
	close(fd);
	return r < 0 ? -e : 0;
}

struct file_xattr_bak {
	char path[160];
	bool had_xattr;
	struct pressure_xattr_disk old_xd;
};

static int preflight_check_ops(const struct pr_ctx *ctx, bool *uses_sfw_pkt_out)
{
	bool uses_sfw_pkt = false;

	for (int i = 0; i < ctx->op_cnt; i++) {
		const struct pr_compiled_op *op = &ctx->ops[i];
		struct stat st;

		if (op->kind == PR_OP_SFW_CHAIN_FLUSH ||
		    op->kind == PR_OP_SFW_CHAIN_POLICY ||
		    op->kind == PR_OP_SFW_CHAIN_RULE ||
		    op->kind == PR_OP_SFW_NAT_FLUSH ||
		    op->kind == PR_OP_SFW_NAT_RULE)
			uses_sfw_pkt = true;

		if (op->optional)
			continue;

		if (op->kind == PR_OP_DEV_RULE) {
			unsigned int maj = 0, min = 0;
			if (sscanf(op->target, "%u:%u", &maj, &min) != 2 &&
			    (stat(op->target, &st) != 0 ||
			     (!S_ISCHR(st.st_mode) && !S_ISBLK(st.st_mode)))) {
				fprintf(stderr, "%s:%d: preflight failed: device '%s' missing\n",
					op->src_file, op->line, op->target);
				return -1;
			}
		} else if (op->kind == PR_OP_NETDEV_RULE) {
			char sysp[220];
			snprintf(sysp, sizeof(sysp), "/sys/class/net/%s", op->target);
			if (access(sysp, F_OK) != 0) {
				fprintf(stderr, "%s:%d: preflight failed: netdev '%s' missing\n",
					op->src_file, op->line, op->target);
				return -1;
			}
		} else if (op->kind == PR_OP_FILE_LABEL) {
			if (stat(op->target, &st) != 0) {
				fprintf(stderr, "%s:%d: preflight failed: file '%s' missing\n",
					op->src_file, op->line, op->target);
				return -1;
			}
		}
	}

	if (uses_sfw_pkt && access("/proc/pressure_sfw/chains", F_OK) != 0) {
		fprintf(stderr, "sure load: preflight failed: sfw.ko not loaded (/proc/pressure_sfw/chains missing)\n");
		return 1;
	}
	if (access("/sys/kernel/security/pressure/txn", F_OK) != 0) {
		fprintf(stderr, "sure load: preflight failed: /sys/kernel/security/pressure/txn unavailable\n");
		return 1;
	}
	for (int i = 0; i < ctx->op_cnt; i++) {
		if (ctx->ops[i].kind == PR_OP_UNIX_SOCK_FLUSH ||
		    ctx->ops[i].kind == PR_OP_UNIX_SOCK_RULE) {
			if (access("/sys/kernel/security/pressure/unix_rules", F_OK) != 0) {
				fprintf(stderr, "sure load: preflight failed: /sys/kernel/security/pressure/unix_rules unavailable\n");
				return 1;
			}
			break;
		}
	}
	if ((uses_sfw_pkt || access("/proc/pressure_sfw", F_OK) == 0) &&
	    access("/proc/pressure_sfw/txn", F_OK) != 0) {
		fprintf(stderr, "sure load: preflight failed: /proc/pressure_sfw/txn unavailable\n");
		return 1;
	}
	*uses_sfw_pkt_out = uses_sfw_pkt;
	return 0;
}

/*
 * Return contract:
 *   0 = clean two-phase commit across Pressure LSM and sfw.ko
 *   1 = preflight, txn begin (-EBUSY / unavailable), or apply failure where
 *       rollback succeeded cleanly and the previous active policy is preserved
 *   2 = CRITICAL partial cross-subsystem commit or rollback failure; latches
 *       txn_degraded=1 in the kernel so `sure ready` blocks service admission
 */
static int apply_compiled_ops(const struct pr_ctx *ctx)
{
	bool uses_sfw_pkt = false, need_sfw_txn = false;
	bool lsm_txn = false, sfw_txn = false;
	bool lsm_committed = false, sfw_committed = false;
	struct file_xattr_bak *fbaks = NULL;
	int fbak_cnt = 0;
	int brc;

	if (preflight_check_ops(ctx, &uses_sfw_pkt) != 0)
		return 1;

	need_sfw_txn = uses_sfw_pkt || (access("/proc/pressure_sfw", F_OK) == 0);

	fbaks = calloc((size_t)(ctx->op_cnt ? ctx->op_cnt : 1), sizeof(*fbaks));
	if (!fbaks)
		return 1;

	brc = write_kern_path("/sys/kernel/security/pressure/txn", "begin\n");
	if (brc < 0) {
		fprintf(stderr,
			"sure load: cannot begin Pressure transaction (%s)%s -- stopped before policy edits\n",
			strerror(-brc),
			brc == -EBUSY ? " [concurrent loader active]" : "");
		free(fbaks);
		return 1;
	}
	lsm_txn = true;

	if (need_sfw_txn) {
		brc = write_kern_path("/proc/pressure_sfw/txn", "begin\n");
		if (brc < 0) {
			int arc = write_kern_path("/sys/kernel/security/pressure/txn",
						  "abort\n");
			fprintf(stderr,
				"sure load: cannot begin SFW transaction (%s)%s -- stopped before policy edits\n",
				strerror(-brc),
				brc == -EBUSY ? " [concurrent loader active]" : "");
			free(fbaks);
			if (arc < 0) {
				(void)write_kern_path("/sys/kernel/security/pressure/txn",
						      "mark_degraded\n");
				return 2;
			}
			return 1;
		}
		sfw_txn = true;
	}

	for (int i = 0; i < ctx->op_cnt; i++) {
		const struct pr_compiled_op *op = &ctx->ops[i];
		int rc = 0;

		switch (op->kind) {
		case PR_OP_ENFORCE:
			rc = write_kern_path("/sys/kernel/security/pressure/enforce",
					     op->kern_line);
			break;
		case PR_OP_POLICY_FLUSH:
		case PR_OP_POLICY_RULE:
			rc = write_kern_path("/sys/kernel/security/pressure/policy",
					     op->kern_line);
			break;
		case PR_OP_DEV_RULE: {
			char cmd[220];
			unsigned int maj = 0, min = 0;
			struct stat st;
			if (sscanf(op->target, "%u:%u", &maj, &min) == 2) {
				snprintf(cmd, sizeof(cmd), "dev %u:%u %s %u %s %u\n",
					 maj, min, op->label, op->u1, op->prov, op->u2);
			} else if (stat(op->target, &st) == 0 &&
				   (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode))) {
				snprintf(cmd, sizeof(cmd), "dev %u:%u %s %u %s %u\n",
					 major(st.st_rdev), minor(st.st_rdev),
					 op->label, op->u1, op->prov, op->u2);
			} else if (op->optional) {
				continue;
			} else {
				fprintf(stderr, "%s:%d: device '%s' not found\n",
					op->src_file, op->line, op->target);
				rc = -ENOENT;
				break;
			}
			rc = write_kern_path("/sys/kernel/security/pressure/devices", cmd);
			break;
		}
		case PR_OP_NETDEV_RULE: {
			char cmd[220];
			snprintf(cmd, sizeof(cmd), "net %s %s %u %s %u\n",
				 op->target, op->label, op->u1, op->prov, op->u2);
			rc = write_kern_path("/sys/kernel/security/pressure/devices", cmd);
			if (rc == -ENOENT && op->optional)
				rc = 0;
			break;
		}
		case PR_OP_FILE_LABEL: {
			struct stat st;
			if (stat(op->target, &st) != 0) {
				if (op->optional)
					continue;
				fprintf(stderr, "%s:%d: file '%s' not found\n",
					op->src_file, op->line, op->target);
				rc = -ENOENT;
				break;
			}

			struct file_xattr_bak *bk = &fbaks[fbak_cnt++];
			snprintf(bk->path, sizeof(bk->path), "%s", op->target);
			ssize_t xsz = getxattr(op->target, XATTR_NAME_PRESSURE,
					       &bk->old_xd, sizeof(bk->old_xd));
			bk->had_xattr = (xsz == (ssize_t)sizeof(bk->old_xd) &&
					 bk->old_xd.magic == PRESSURE_XATTR_MAGIC);

			struct pressure_xattr_disk xd = {
				.magic = PRESSURE_XATTR_MAGIC,
				.flags = op->u1,
				.file_pub_id = ((uint64_t)rand() << 32) |
					       (uint64_t)rand() | 1ULL,
				.owner_pub_uid = op->u2,
			};
			snprintf(xd.label, sizeof(xd.label), "%s", op->label);
			(void)setxattr(op->target, XATTR_NAME_PRESSURE, &xd,
				       sizeof(xd), 0);

			char cmd[256];
			snprintf(cmd, sizeof(cmd), "%x %u %s %s\n",
				 op->u1, op->u2, op->label, op->target);
			rc = write_kern_path("/sys/kernel/security/pressure/label_path", cmd);
			break;
		}
		case PR_OP_SFW_SOCK_FLUSH:
		case PR_OP_SFW_SOCK_RULE:
			rc = write_kern_path("/sys/kernel/security/pressure/sfw_rules",
					     op->kern_line);
			break;
		case PR_OP_SFW_CHAIN_FLUSH:
		case PR_OP_SFW_CHAIN_POLICY:
		case PR_OP_SFW_CHAIN_RULE:
			rc = write_kern_path("/proc/pressure_sfw/chains",
					     op->kern_line);
			break;
		case PR_OP_SFW_NAT_FLUSH:
		case PR_OP_SFW_NAT_RULE:
			rc = write_kern_path("/proc/pressure_sfw/nat",
					     op->kern_line);
			break;
		case PR_OP_UNIX_SOCK_FLUSH:
		case PR_OP_UNIX_SOCK_RULE:
			rc = write_kern_path("/sys/kernel/security/pressure/unix_rules",
					     op->kern_line);
			break;
		}

		if (rc < 0) {
			fprintf(stderr, "%s:%d: failed applying statement to kernel: %s\n",
				op->src_file, op->line, strerror(-rc));
			goto rollback;
		}
	}

	/* Phase 1: Prepare both subsystems while keeping rollback snapshots intact */
	if (sfw_txn) {
		int prc = write_kern_path("/proc/pressure_sfw/txn", "prepare\n");
		if (prc < 0) {
			fprintf(stderr, "sure load: SFW prepare failed: %s\n",
				strerror(-prc));
			goto rollback;
		}
	}
	if (lsm_txn) {
		int prc = write_kern_path("/sys/kernel/security/pressure/txn", "prepare\n");
		if (prc < 0) {
			fprintf(stderr, "sure load: Pressure prepare failed: %s\n",
				strerror(-prc));
			goto rollback;
		}
	}

	/* Phase 2: Commit Pressure LSM then SFW (in-memory pointer swaps only) */
	if (lsm_txn) {
		int crc = write_kern_path("/sys/kernel/security/pressure/txn", "commit\n");
		if (crc < 0) {
			fprintf(stderr, "sure load: Pressure commit failed: %s\n",
				strerror(-crc));
			goto rollback;
		}
		lsm_committed = true;
	}
	if (sfw_txn) {
		int crc = write_kern_path("/proc/pressure_sfw/txn", "commit\n");
		if (crc < 0) {
			fprintf(stderr,
				"sure load: SFW commit failed after Pressure commit: %s\n",
				strerror(-crc));
			goto rollback;
		}
		sfw_committed = true;
	}

	free(fbaks);
	return 0;

rollback: {
	int rb_errs = 0;
	bool partial_commit = (lsm_txn && sfw_txn &&
			       (lsm_committed != sfw_committed));

	for (int k = fbak_cnt - 1; k >= 0; k--) {
		char rcmd[256];
		if (fbaks[k].had_xattr) {
			if (setxattr(fbaks[k].path, XATTR_NAME_PRESSURE,
				     &fbaks[k].old_xd, sizeof(fbaks[k].old_xd), 0) < 0 &&
			    errno != EOPNOTSUPP)
				rb_errs++;
			snprintf(rcmd, sizeof(rcmd), "%x %u %.31s %s\n",
				 fbaks[k].old_xd.flags,
				 fbaks[k].old_xd.owner_pub_uid,
				 fbaks[k].old_xd.label, fbaks[k].path);
		} else {
			if (removexattr(fbaks[k].path, XATTR_NAME_PRESSURE) < 0 &&
			    errno != ENODATA && errno != EOPNOTSUPP)
				rb_errs++;
			snprintf(rcmd, sizeof(rcmd), "0 0 obj:unlabeled %s\n",
				 fbaks[k].path);
		}
		if (write_kern_path("/sys/kernel/security/pressure/label_path", rcmd) < 0)
			rb_errs++;
	}

	if (sfw_txn && !sfw_committed) {
		int arc = write_kern_path("/proc/pressure_sfw/txn", "abort\n");
		if (arc < 0) {
			fprintf(stderr, "sure load: SFW rollback abort failed: %s\n",
				strerror(-arc));
			rb_errs++;
		}
	}
	if (lsm_txn && !lsm_committed) {
		int arc = write_kern_path("/sys/kernel/security/pressure/txn", "abort\n");
		if (arc < 0) {
			fprintf(stderr, "sure load: Pressure rollback abort failed: %s\n",
				strerror(-arc));
			rb_errs++;
		}
	}

	free(fbaks);
	if (partial_commit || rb_errs > 0) {
		(void)write_kern_path("/sys/kernel/security/pressure/txn",
				      "mark_degraded\n");
		if (sfw_txn)
			(void)write_kern_path("/proc/pressure_sfw/txn",
					      "mark_degraded\n");
		fprintf(stderr,
			"sure load: CRITICAL: partial commit or rollback failure (lsm_committed=%d sfw_committed=%d rollback_errors=%d) -- kernel latched DEGRADED; previous policy NOT guaranteed\n",
			lsm_committed ? 1 : 0, sfw_committed ? 1 : 0, rb_errs);
		return 2;
	}

	fprintf(stderr, "sure load: transaction ABORTED cleanly -- previous active policy preserved\n");
	return 1;
}
}

int sure_policy_run_file(const char *filepath, bool apply_to_kernel)
{
	struct pr_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return 1;

	if (parse_file_recursive(ctx, filepath, MAX_INC_DEPTH) < 0) {
		free(ctx);
		return 1;
	}

	if (!apply_to_kernel) {
		printf("sure check: '%s' OK (%d validated policy operations, %d variables)\n",
		       filepath, ctx->op_cnt, ctx->var_cnt);
		free(ctx);
		return 0;
	}

	int rc = apply_compiled_ops(ctx);
	if (rc != 0) {
		free(ctx);
		return rc;
	}

	printf("sure load: applied %d policy operations from '%s'\n",
	       ctx->op_cnt, filepath);
	free(ctx);
	return 0;
}
