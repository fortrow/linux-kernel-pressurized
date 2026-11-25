// SPDX-License-Identifier: GPL-2.0
/*
 * pressure-authd: Dedicated systemd Authentication & Identity Daemon
 *
 * Coexists with distro-managed POSIX accounts (e.g., EL10 packaged service
 * users/groups) while maintaining /etc/passwd, /etc/group, and /etc/shadow:
 * - Preserves preexisting distro accounts, numeric UIDs/GIDs, GECOS/home/shell
 *   fields, /etc/group supplementary memberships, and /etc/shadow entries.
 * - Tracks Pressure-owned POSIX entries externally via the encrypted vault and
 *   kernel-locked /etc/pressure/posix.manifest (never embedding comments in
 *   /etc/{passwd,group,shadow}).
 * - Rejects name and UID/GID collisions cleanly rather than overwriting distro
 *   identities, and guarantees preexisting system accounts never gain Pressure
 *   credentials or interactive login rights.
 * - Assigns non-sequential CSPRNG 31-bit public UIDs/GIDs to all Pressure
 *   human users and daemons, paired with secret kernel-only kpriv_uid mappings.
 * - Stages /etc/passwd, /etc/group, /etc/shadow, and vault updates atomically
 *   with mkstemp + fsync + rename and crash/error rollback backups.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/sysmacros.h>
#include <stddef.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include "../../include/uapi/linux/sfw.h"
#include "authd_proto.h"

#define MAX_ACCOUNTS 128
#define PASSWORD_SALT_LEN 32
#define PASSWORD_HASH_LEN 64
#define PASSWORD_PBKDF2_ITERATIONS 600000
#define VAULT_V1 0x564c5431U
#define VAULT_V2 0x564c5432U

enum password_kdf {
	PASSWORD_NONE,
	PASSWORD_SCRYPT_V1,
	PASSWORD_PBKDF2_SHA256,
};

#define POSIX_PASSWD_PATH	"/etc/passwd"
#define POSIX_GROUP_PATH	"/etc/group"
#define POSIX_SHADOW_PATH	"/etc/shadow"

#define POSIX_BAK_PASSWD	"/etc/.pressure_bak_passwd"
#define POSIX_BAK_GROUP		"/etc/.pressure_bak_group"
#define POSIX_BAK_SHADOW	"/etc/.pressure_bak_shadow"

struct vault_account {
	uint8_t  in_use;
	uint8_t  is_daemon;
	uint8_t  password_kdf;	/* Occupies a padding byte in v1 records. */
	uint32_t pub_uid;
	uint32_t pub_gid;
	char     username[32];
	char     label[32];
	char     home_dir[96];
	uint8_t  salt[PASSWORD_SALT_LEN];
	uint8_t  pass_hash[PASSWORD_HASH_LEN];
};

_Static_assert(offsetof(struct vault_account, pub_uid) == 4 &&
	       sizeof(struct vault_account) == 268, "vault record layout changed");

struct vault_header {
	uint32_t magic;
	uint32_t count;
	uint8_t  nonce[12];
	uint8_t  tag[16];
};

struct strbuf {
	char  *data;
	size_t len;
	size_t cap;
};

static struct vault_account g_accounts[MAX_ACCOUNTS];
static char g_managed_names[MAX_ACCOUNTS][32];
static int g_managed_cnt;
static uint8_t g_master_key[32];
static volatile sig_atomic_t g_running = 1;

static void handle_sig(int sig)
{
	(void)sig;
	g_running = 0;
}

static void sb_init(struct strbuf *sb)
{
	sb->data = NULL;
	sb->len = 0;
	sb->cap = 0;
}

static void sb_free(struct strbuf *sb)
{
	free(sb->data);
	sb->data = NULL;
	sb->len = 0;
	sb->cap = 0;
}

static int sb_reserve(struct strbuf *sb, size_t extra)
{
	size_t needed, ncap;
	char *nbuf;

	if (extra > SIZE_MAX - sb->len - 1)
		return -ENOMEM;
	needed = sb->len + extra + 1;
	if (needed <= sb->cap)
		return 0;

	ncap = sb->cap ? sb->cap : 4096;
	while (ncap < needed) {
		if (ncap > SIZE_MAX / 2) {
			ncap = needed;
			break;
		}
		ncap *= 2;
	}
	nbuf = realloc(sb->data, ncap);
	if (!nbuf)
		return -ENOMEM;
	sb->data = nbuf;
	sb->cap = ncap;
	return 0;
}

static int sb_append_n(struct strbuf *sb, const char *s, size_t n)
{
	int rc = sb_reserve(sb, n);

	if (rc < 0)
		return rc;
	if (n > 0) {
		memcpy(sb->data + sb->len, s, n);
		sb->len += n;
	}
	sb->data[sb->len] = '\0';
	return 0;
}

static int sb_append_line_verbatim(struct strbuf *sb, const char *line, size_t n)
{
	int rc = sb_append_n(sb, line, n);

	if (rc < 0)
		return rc;
	if (n == 0 || line[n - 1] != '\n')
		return sb_append_n(sb, "\n", 1);
	return 0;
}

static int __attribute__((format(printf, 2, 3)))
sb_appendf(struct strbuf *sb, const char *fmt, ...)
{
	va_list ap, ap2;
	int need;
	int rc;

	va_start(ap, fmt);
	va_copy(ap2, ap);
	need = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	if (need < 0) {
		va_end(ap2);
		return -EINVAL;
	}
	rc = sb_reserve(sb, (size_t)need);
	if (rc < 0) {
		va_end(ap2);
		return rc;
	}
	vsnprintf(sb->data + sb->len, sb->cap - sb->len, fmt, ap2);
	va_end(ap2);
	sb->len += (size_t)need;
	return 0;
}

static int write_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = (const uint8_t *)buf;
	size_t off = 0;

	while (off < len) {
		ssize_t n = write(fd, p + off, len - off);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (n == 0)
			return -EIO;
		off += (size_t)n;
	}
	return 0;
}

static int read_all(int fd, void *buf, size_t len)
{
	uint8_t *p = (uint8_t *)buf;
	size_t off = 0;

	while (off < len) {
		ssize_t n = read(fd, p + off, len - off);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (n == 0)
			return -EIO;
		off += (size_t)n;
	}
	return 0;
}

static int fsync_dir(const char *dirpath)
{
	int dfd = open(dirpath, O_RDONLY | O_DIRECTORY);
	int rc = 0;

	if (dfd < 0)
		return -errno;
	if (fsync(dfd) < 0 && errno != EINVAL && errno != EROFS)
		rc = -errno;
	close(dfd);
	return rc;
}

static int copy_file_for_backup(const char *src_path, const char *dst_path,
				mode_t mode, uid_t uid, gid_t gid)
{
	int sfd = -1, dfd = -1, rc = 0;
	uint8_t buf[8192];

	sfd = open(src_path, O_RDONLY);
	if (sfd < 0)
		return -errno;
	dfd = open(dst_path, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL, 0600);
	if (dfd < 0) {
		rc = -errno;
		close(sfd);
		return rc;
	}
	for (;;) {
		ssize_t n = read(sfd, buf, sizeof(buf));

		if (n < 0) {
			if (errno == EINTR)
				continue;
			rc = -errno;
			break;
		}
		if (n == 0)
			break;
		rc = write_all(dfd, buf, (size_t)n);
		if (rc < 0)
			break;
	}
	if (rc == 0) {
		if (fchown(dfd, uid, gid) < 0) {
			/* best-effort preserve ownership on backup */
		}
		if (fchmod(dfd, mode) < 0)
			rc = -errno;
	}
	if (rc == 0 && fsync(dfd) < 0 && errno != EINVAL)
		rc = -errno;
	close(sfd);
	if (close(dfd) < 0 && rc == 0)
		rc = -errno;
	if (rc < 0)
		unlink(dst_path);
	return rc;
}

static int secfs_write(const char *node, const char *line)
{
	char path[128];
	int fd, rc;

	snprintf(path, sizeof(path), "/sys/kernel/security/pressure/%s", node);
	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -errno;
	rc = write_all(fd, line, strlen(line));
	close(fd);
	return rc;
}

static int label_kernel_path(uint32_t flags, uint32_t owner_uid,
			     const char *label, const char *path)
{
	char cmd[320];
	struct pressure_xattr_disk xd = {
		.magic = PRESSURE_XATTR_MAGIC,
		.flags = flags,
		.owner_pub_uid = owner_uid,
	};

	if (RAND_bytes((unsigned char *)&xd.file_pub_id, sizeof(xd.file_pub_id)) != 1)
		return -EIO;
	snprintf(xd.label, sizeof(xd.label), "%s", label);
	/* Best-effort xattr write (for tmpfs/ext4) + authoritative kernel blob pin */
	(void)syscall(188 /* __NR_setxattr on x86_64 */, path,
		      XATTR_NAME_PRESSURE, &xd, sizeof(xd), 0);

	snprintf(cmd, sizeof(cmd), "%x %u %s %s\n", flags, owner_uid, label, path);
	return secfs_write("label_path", cmd);
}

static bool valid_posix_username(const char *name)
{
	size_t len;

	if (!name || !name[0])
		return false;
	len = strlen(name);
	if (len >= 32 || strcmp(name, "root") == 0)
		return false;
	if (!(isalpha((unsigned char)name[0]) || name[0] == '_'))
		return false;
	for (size_t i = 1; i < len; i++) {
		unsigned char c = (unsigned char)name[i];

		if (!(isalnum(c) || c == '_' || c == '-' || c == '.'))
			return false;
	}
	return true;
}

static bool valid_passwd_field(const char *s)
{
	if (!s)
		return false;
	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;

		if (c == ':' || c == '\n' || c == '\r' || c < 0x20 || c == 0x7f)
			return false;
	}
	return true;
}

/* Pressure labels are single securityfs tokens, not POSIX fields. */
static bool valid_pressure_label(const char *label)
{
	if (!label || !label[0])
		return false;

	for (; *label; label++) {
		unsigned char c = (unsigned char)*label;

		if (c <= 0x20 || c >= 0x7f)
			return false;
	}
	return true;
}

static bool parse_colon_field_str(const char *line, int field_idx,
				  char *out, size_t out_sz)
{
	const char *p = line;
	const char *end;
	size_t n;

	if (!line || field_idx < 0 || !out || out_sz == 0)
		return false;
	for (int i = 0; i < field_idx; i++) {
		p = strchr(p, ':');
		if (!p)
			return false;
		p++;
	}
	end = strchr(p, ':');
	if (!end) {
		end = p + strlen(p);
		while (end > p && (end[-1] == '\n' || end[-1] == '\r'))
			end--;
	}
	n = (size_t)(end - p);
	if (n >= out_sz)
		n = out_sz - 1;
	memcpy(out, p, n);
	out[n] = '\0';
	return true;
}

static bool parse_colon_field_u32(const char *line, int field_idx, uint32_t *out)
{
	char buf[32];
	char *end = NULL;
	unsigned long val;

	if (!parse_colon_field_str(line, field_idx, buf, sizeof(buf)) || !buf[0])
		return false;
	if (!isdigit((unsigned char)buf[0]))
		return false;
	errno = 0;
	val = strtoul(buf, &end, 10);
	if (errno != 0 || !end || *end != '\0' || val > UINT32_MAX)
		return false;
	*out = (uint32_t)val;
	return true;
}

static struct vault_account *find_account(const char *username)
{
	for (int i = 0; i < MAX_ACCOUNTS; i++) {
		if (g_accounts[i].in_use &&
		    strcmp(g_accounts[i].username, username) == 0)
			return &g_accounts[i];
	}
	return NULL;
}

static int find_account_index(const char *username)
{
	for (int i = 0; i < MAX_ACCOUNTS; i++) {
		if (g_accounts[i].in_use &&
		    strcmp(g_accounts[i].username, username) == 0)
			return i;
	}
	return -1;
}

static bool name_in_manifest(const char *name)
{
	for (int i = 0; i < g_managed_cnt; i++) {
		if (strcmp(g_managed_names[i], name) == 0)
			return true;
	}
	return false;
}

static bool is_pressure_managed_name(const char *name)
{
	return find_account(name) != NULL || name_in_manifest(name);
}

static int load_manifest(void)
{
	FILE *f = fopen(AUTHD_MANIFEST_PATH, "r");
	char *line = NULL;
	size_t cap = 0;
	ssize_t n;

	g_managed_cnt = 0;
	if (!f) {
		if (errno == ENOENT)
			return 0;
		return -errno;
	}
	while ((n = getline(&line, &cap, f)) >= 0) {
		while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
			line[--n] = '\0';
		if (n == 0 || line[0] == '#')
			continue;
		if (!valid_posix_username(line) || name_in_manifest(line))
			continue;
		if (g_managed_cnt < MAX_ACCOUNTS) {
			snprintf(g_managed_names[g_managed_cnt],
				 sizeof(g_managed_names[g_managed_cnt]),
				 "%s", line);
			g_managed_cnt++;
		}
	}
	free(line);
	fclose(f);
	return label_kernel_path(PRESSURE_FILE_AUTHD_VAULT, 0, "obj:authd_manifest",
				 AUTHD_MANIFEST_PATH);
}

static int save_manifest_from_accounts(void)
{
	struct strbuf sb;
	char tmppath[] = "/etc/pressure/.posix.manifest.XXXXXX";
	int fd = -1, rc = 0;

	sb_init(&sb);
	for (int i = 0; i < MAX_ACCOUNTS; i++) {
		if (!g_accounts[i].in_use)
			continue;
		rc = sb_appendf(&sb, "%s\n", g_accounts[i].username);
		if (rc < 0)
			goto out;
	}

	mkdir(AUTHD_DIR_PATH, 0700);
	fd = mkstemp(tmppath);
	if (fd < 0) {
		rc = -errno;
		goto out;
	}
	if (fchmod(fd, 0600) < 0) {
		rc = -errno;
		goto out_unlink;
	}
	rc = label_kernel_path(PRESSURE_FILE_AUTHD_VAULT, 0, "obj:authd_manifest",
			       tmppath);
	if (rc < 0)
		goto out_unlink;
	if (sb.len > 0) {
		rc = write_all(fd, sb.data, sb.len);
		if (rc < 0)
			goto out_unlink;
	}
	if (fsync(fd) < 0 && errno != EINVAL) {
		rc = -errno;
		goto out_unlink;
	}
	if (close(fd) < 0) {
		fd = -1;
		rc = -errno;
		goto out_unlink;
	}
	fd = -1;

	if (rename(tmppath, AUTHD_MANIFEST_PATH) < 0) {
		rc = -errno;
		goto out_unlink;
	}
	(void)fsync_dir(AUTHD_DIR_PATH);

	g_managed_cnt = 0;
	for (int i = 0; i < MAX_ACCOUNTS; i++) {
		if (g_accounts[i].in_use && g_managed_cnt < MAX_ACCOUNTS) {
			snprintf(g_managed_names[g_managed_cnt],
				 sizeof(g_managed_names[g_managed_cnt]),
				 "%s", g_accounts[i].username);
			g_managed_cnt++;
		}
	}
	sb_free(&sb);
	return 0;

out_unlink:
	if (fd >= 0)
		close(fd);
	unlink(tmppath);
out:
	sb_free(&sb);
	return rc;
}

static int derive_scrypt_hash(const char *pass, const uint8_t *salt,
			      uint8_t *out_hash)
{
	if (EVP_PBE_scrypt(pass, strlen(pass), salt, PASSWORD_SALT_LEN,
			   16384, 8, 1, 64 * 1024 * 1024,
			   out_hash, PASSWORD_HASH_LEN) != 1)
		return -EIO;
	return 0;
}

static int derive_password_hash(const char *pass, const uint8_t *salt,
				uint8_t *out_hash, uint8_t kdf)
{
	switch (kdf) {
	case PASSWORD_SCRYPT_V1:
		return derive_scrypt_hash(pass, salt, out_hash);
	case PASSWORD_PBKDF2_SHA256:
		return PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt,
					 PASSWORD_SALT_LEN, PASSWORD_PBKDF2_ITERATIONS,
					 EVP_sha256(), PASSWORD_HASH_LEN, out_hash) == 1
		       ? 0 : -EIO;
	default:
		return -EACCES;
	}
}

static int derive_aead_key(uint8_t *out32, const uint8_t *master_key, bool legacy)
{
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	const char *salt = legacy ? "pressure-vault-v1" : "pressure-vault-v2";
	const char *info = legacy ? "chacha20-poly1305" : "aes-256-gcm";
	size_t outlen = 32;
	int ok = 0;

	if (!pctx)
		return -ENOMEM;
	if (EVP_PKEY_derive_init(pctx) > 0 &&
	    EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) > 0 &&
	    EVP_PKEY_CTX_set1_hkdf_salt(pctx, (const unsigned char *)salt, strlen(salt)) > 0 &&
	    EVP_PKEY_CTX_set1_hkdf_key(pctx, master_key, sizeof(g_master_key)) > 0 &&
	    EVP_PKEY_CTX_add1_hkdf_info(pctx, (const unsigned char *)info, strlen(info)) > 0 &&
	    EVP_PKEY_derive(pctx, out32, &outlen) > 0)
		ok = 1;
	EVP_PKEY_CTX_free(pctx);
	return ok ? 0 : -EIO;
}

static int save_vault(void)
{
	uint8_t aead_key[32];
	uint8_t *ciphertext = NULL;
	struct vault_header hdr = { .magic = VAULT_V2, .count = MAX_ACCOUNTS };
	EVP_CIPHER_CTX *ctx = NULL;
	char tmppath[] = "/etc/pressure/.auth.vault.XXXXXX";
	int len = 0, clen = 0, fd = -1, rc = -EIO;
	size_t plain_sz = sizeof(g_accounts);

	rc = derive_aead_key(aead_key, g_master_key, false);
	if (rc < 0)
		return rc;
	ciphertext = malloc(plain_sz);
	if (!ciphertext) {
		rc = -ENOMEM;
		goto out;
	}

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		rc = -ENOMEM;
		goto out;
	}
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, aead_key, NULL) != 1 ||
	    EVP_EncryptUpdate(ctx, NULL, &len, (const unsigned char *)&hdr,
			      offsetof(struct vault_header, nonce)) != 1 ||
	    EVP_EncryptUpdate(ctx, ciphertext, &len,
			      (const unsigned char *)g_accounts,
			      (int)plain_sz) != 1 ||
	    EVP_EncryptFinal_ex(ctx, ciphertext + len, &clen) != 1 ||
	    EVP_CIPHER_CTX_get_updated_iv(ctx, hdr.nonce, sizeof(hdr.nonce)) != 1 ||
	    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, hdr.tag) != 1) {
		rc = -EIO;
		goto out;
	}

	mkdir(AUTHD_DIR_PATH, 0700);
	fd = mkstemp(tmppath);
	if (fd < 0) {
		rc = -errno;
		goto out;
	}
	if (fchmod(fd, 0600) < 0) {
		rc = -errno;
		goto out_unlink;
	}
	rc = label_kernel_path(PRESSURE_FILE_AUTHD_VAULT, 0, "obj:authd_vault",
			       tmppath);
	if (rc < 0)
		goto out_unlink;
	rc = write_all(fd, &hdr, sizeof(hdr));
	if (rc < 0)
		goto out_unlink;
	rc = write_all(fd, ciphertext, plain_sz);
	if (rc < 0)
		goto out_unlink;
	if (fsync(fd) < 0 && errno != EINVAL) {
		rc = -errno;
		goto out_unlink;
	}
	if (close(fd) < 0) {
		fd = -1;
		rc = -errno;
		goto out_unlink;
	}
	fd = -1;

	if (rename(tmppath, AUTHD_VAULT_PATH) < 0) {
		rc = -errno;
		goto out_unlink;
	}
	(void)fsync_dir(AUTHD_DIR_PATH);
	rc = 0;
	goto out;

out_unlink:
	if (fd >= 0)
		close(fd);
	unlink(tmppath);
out:
	OPENSSL_cleanse(aead_key, sizeof(aead_key));
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
	free(ciphertext);
	return rc;
}

static int load_or_init_vault(void)
{
	int kfd, vfd, label_rc;

	mkdir(AUTHD_DIR_PATH, 0700);
	kfd = open(AUTHD_KEY_PATH, O_RDONLY);
	if (kfd >= 0) {
		int rrc = read_all(kfd, g_master_key, sizeof(g_master_key));

		close(kfd);
		if (rrc < 0)
			return rrc;
	} else if (errno == ENOENT) {
		char ktmp[] = "/etc/pressure/.master.key.XXXXXX";
		int wrc;

		if (RAND_bytes(g_master_key, sizeof(g_master_key)) != 1)
			return -EIO;
		kfd = mkstemp(ktmp);
		if (kfd < 0)
			return -errno;
		if (fchmod(kfd, 0600) < 0) {
			int err = -errno;

			close(kfd);
			unlink(ktmp);
			return err;
		}
		wrc = label_kernel_path(PRESSURE_FILE_AUTHD_VAULT, 0, "obj:authd_key",
					ktmp);
		if (wrc == 0)
			wrc = write_all(kfd, g_master_key, sizeof(g_master_key));
		if (wrc == 0 && fsync(kfd) < 0 && errno != EINVAL)
			wrc = -errno;
		if (close(kfd) < 0 && wrc == 0)
			wrc = -errno;
		if (wrc < 0 || rename(ktmp, AUTHD_KEY_PATH) < 0) {
			int err = wrc < 0 ? wrc : -errno;

			unlink(ktmp);
			return err;
		}
		(void)fsync_dir(AUTHD_DIR_PATH);
	} else {
		return -errno;
	}
	label_rc = label_kernel_path(PRESSURE_FILE_AUTHD_VAULT, 0, "obj:authd_key",
				     AUTHD_KEY_PATH);
	if (label_rc < 0)
		return label_rc;

	vfd = open(AUTHD_VAULT_PATH, O_RDONLY);
	if (vfd < 0) {
		if (errno != ENOENT)
			return -errno;
		memset(g_accounts, 0, sizeof(g_accounts));
		return save_vault();
	}

	uint8_t aead_key[32];
	struct vault_header hdr;
	size_t plain_sz = sizeof(g_accounts);
	uint8_t *ciphertext = malloc(plain_sz);
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int len = 0, flen = 0, rc = -EIO;

	if (ciphertext && ctx && read_all(vfd, &hdr, sizeof(hdr)) == 0 &&
	    (hdr.magic == VAULT_V1 || hdr.magic == VAULT_V2) &&
	    hdr.count == MAX_ACCOUNTS && read_all(vfd, ciphertext, plain_sz) == 0) {
		bool legacy = hdr.magic == VAULT_V1;
		const EVP_CIPHER *cipher = legacy ? EVP_chacha20_poly1305() :
						  EVP_aes_256_gcm();

		if (legacy && EVP_default_properties_is_fips_enabled(NULL)) {
			rc = -ENOTSUP;
		} else if (derive_aead_key(aead_key, g_master_key, legacy) == 0 &&
		    EVP_DecryptInit_ex(ctx, cipher, NULL, aead_key, hdr.nonce) == 1 &&
		    (legacy || EVP_DecryptUpdate(ctx, NULL, &len,
						 (const unsigned char *)&hdr,
						 offsetof(struct vault_header, nonce)) == 1) &&
		    EVP_DecryptUpdate(ctx, (unsigned char *)g_accounts, &len,
				      ciphertext, (int)plain_sz) == 1 &&
		    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, hdr.tag) == 1 &&
		    EVP_DecryptFinal_ex(ctx, (unsigned char *)g_accounts + len, &flen) == 1) {
			rc = 0;
			if (legacy) {
				for (int i = 0; i < MAX_ACCOUNTS; i++) {
					struct vault_account *acc = &g_accounts[i];

					acc->password_kdf = acc->in_use && !acc->is_daemon ?
							    PASSWORD_SCRYPT_V1 : PASSWORD_NONE;
				}
				rc = save_vault();
			}
			if (EVP_default_properties_is_fips_enabled(NULL)) {
				for (int i = 0; i < MAX_ACCOUNTS; i++) {
					if (g_accounts[i].in_use &&
					    g_accounts[i].password_kdf == PASSWORD_SCRYPT_V1) {
						rc = -ENOTSUP;
						break;
					}
				}
			}
		}
	}
	OPENSSL_cleanse(aead_key, sizeof(aead_key));
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
	free(ciphertext);
	close(vfd);
	if (rc == 0)
		rc = label_kernel_path(PRESSURE_FILE_AUTHD_VAULT, 0, "obj:authd_vault",
				       AUTHD_VAULT_PATH);
	return rc;
}

static bool posix_file_has_name(const char *path, const char *name)
{
	FILE *f = fopen(path, "r");
	char *line = NULL;
	size_t cap = 0;
	char field[64];
	bool found = false;

	if (!f)
		return false;
	while (getline(&line, &cap, f) >= 0) {
		if (parse_colon_field_str(line, 0, field, sizeof(field)) &&
		    strcmp(field, name) == 0) {
			found = true;
			break;
		}
	}
	free(line);
	fclose(f);
	return found;
}

static bool posix_id_in_use(uint32_t id)
{
	FILE *f;
	char *line = NULL;
	size_t cap = 0;
	uint32_t uid_v, gid_v;
	bool used = false;

	f = fopen(POSIX_PASSWD_PATH, "r");
	if (f) {
		while (getline(&line, &cap, f) >= 0) {
			if ((parse_colon_field_u32(line, 2, &uid_v) && uid_v == id) ||
			    (parse_colon_field_u32(line, 3, &gid_v) && gid_v == id)) {
				used = true;
				break;
			}
		}
		fclose(f);
	}
	if (!used) {
		f = fopen(POSIX_GROUP_PATH, "r");
		if (f) {
			while (getline(&line, &cap, f) >= 0) {
				if (parse_colon_field_u32(line, 2, &gid_v) &&
				    gid_v == id) {
					used = true;
					break;
				}
			}
			fclose(f);
		}
	}
	free(line);
	return used;
}

static bool id_exists(uint32_t id)
{
	if (id < 100000U || id >= 2147000000U)
		return true;
	for (int i = 0; i < MAX_ACCOUNTS; i++) {
		if (g_accounts[i].in_use &&
		    (g_accounts[i].pub_uid == id || g_accounts[i].pub_gid == id))
			return true;
	}
	return posix_id_in_use(id);
}

/* Never 1000, 1001... Always CSPRNG non-sequential 31-bit random ID */
static int generate_random_public_id(uint32_t *out)
{
	for (int tries = 0; tries < 4096; tries++) {
		uint32_t cand = 0;

		if (RAND_bytes((unsigned char *)&cand, sizeof(cand)) != 1)
			return -EIO;
		cand &= 0x7fffffffU;
		if (!id_exists(cand)) {
			*out = cand;
			return 0;
		}
	}
	return -ENOSPC;
}

/*
 * Recover from any interrupted prior atomic /etc/{passwd,group,shadow} swap
 * before validating collisions or reconciling against auth.vault.
 */
static void recover_interrupted_posix_sync(void)
{
	static const char *const targets[3] = {
		POSIX_PASSWD_PATH, POSIX_GROUP_PATH, POSIX_SHADOW_PATH
	};
	static const char *const backups[3] = {
		POSIX_BAK_PASSWD, POSIX_BAK_GROUP, POSIX_BAK_SHADOW
	};
	bool recovered = false;

	for (int i = 0; i < 3; i++) {
		if (access(backups[i], F_OK) == 0) {
			if (rename(backups[i], targets[i]) == 0) {
				fprintf(stderr,
					"pressure-authd: recovered %s from interrupted atomic update\n",
					targets[i]);
				recovered = true;
			} else {
				fprintf(stderr,
					"pressure-authd: failed to recover %s from %s: %s\n",
					targets[i], backups[i], strerror(errno));
			}
		}
	}
	if (recovered)
		(void)fsync_dir("/etc");
}

/*
 * Verify no active Pressure vault account collides in username, UID, or GID
 * with a non-Pressure distro-managed entry in /etc/passwd or /etc/group.
 */
static int check_vault_posix_collisions(char *errbuf, size_t errsz)
{
	FILE *f;
	char *line = NULL;
	size_t cap = 0;
	char name[64];
	uint32_t uid_v, gid_v;
	int rc = 0;

	f = fopen(POSIX_PASSWD_PATH, "r");
	if (f) {
		while (rc == 0 && getline(&line, &cap, f) >= 0) {
			if (!parse_colon_field_str(line, 0, name, sizeof(name)) ||
			    !name[0])
				continue;
			if (!parse_colon_field_u32(line, 2, &uid_v) ||
			    !parse_colon_field_u32(line, 3, &gid_v))
				continue;

			for (int i = 0; i < MAX_ACCOUNTS; i++) {
				const struct vault_account *acc = &g_accounts[i];

				if (!acc->in_use)
					continue;
				if (strcmp(name, acc->username) == 0) {
					if (!name_in_manifest(name) &&
					    (uid_v != acc->pub_uid ||
					     gid_v != acc->pub_gid)) {
						snprintf(errbuf, errsz,
							 "passwd name collision for '%s' (distro %u:%u vs vault %u:%u)",
							 name, uid_v, gid_v,
							 acc->pub_uid, acc->pub_gid);
						rc = -EEXIST;
						break;
					}
				} else if (!is_pressure_managed_name(name)) {
					if (uid_v == acc->pub_uid ||
					    gid_v == acc->pub_gid) {
						snprintf(errbuf, errsz,
							 "passwd ID collision between distro '%s' (%u:%u) and vault '%s' (%u:%u)",
							 name, uid_v, gid_v,
							 acc->username,
							 acc->pub_uid, acc->pub_gid);
						rc = -EEXIST;
						break;
					}
				}
			}
		}
		fclose(f);
	}
	if (rc < 0) {
		free(line);
		return rc;
	}

	f = fopen(POSIX_GROUP_PATH, "r");
	if (f) {
		while (rc == 0 && getline(&line, &cap, f) >= 0) {
			if (!parse_colon_field_str(line, 0, name, sizeof(name)) ||
			    !name[0])
				continue;
			if (!parse_colon_field_u32(line, 2, &gid_v))
				continue;

			for (int i = 0; i < MAX_ACCOUNTS; i++) {
				const struct vault_account *acc = &g_accounts[i];

				if (!acc->in_use)
					continue;
				if (strcmp(name, acc->username) == 0) {
					if (!name_in_manifest(name) &&
					    gid_v != acc->pub_gid) {
						snprintf(errbuf, errsz,
							 "group name collision for '%s' (distro gid=%u vs vault gid=%u)",
							 name, gid_v, acc->pub_gid);
						rc = -EEXIST;
						break;
					}
				} else if (!is_pressure_managed_name(name)) {
					if (gid_v == acc->pub_gid) {
						snprintf(errbuf, errsz,
							 "group GID collision between distro '%s' (%u) and vault '%s' (%u)",
							 name, gid_v,
							 acc->username, acc->pub_gid);
						rc = -EEXIST;
						break;
					}
				}
			}
		}
		fclose(f);
	}
	free(line);
	return rc;
}

static int build_merged_passwd(struct strbuf *sb)
{
	FILE *f = fopen(POSIX_PASSWD_PATH, "r");
	char *line = NULL;
	size_t cap = 0;
	ssize_t n;
	bool has_root = false;
	int rc = 0;

	if (f) {
		while ((n = getline(&line, &cap, f)) >= 0) {
			char name[64];

			if (parse_colon_field_str(line, 0, name, sizeof(name)) &&
			    name[0]) {
				if (strcmp(name, "root") == 0)
					has_root = true;
				if (is_pressure_managed_name(name))
					continue;
			}
			rc = sb_append_line_verbatim(sb, line, (size_t)n);
			if (rc < 0)
				break;
		}
		if (ferror(f) && rc == 0)
			rc = -EIO;
		free(line);
		fclose(f);
		if (rc < 0)
			return rc;
	} else if (errno != ENOENT) {
		return -errno;
	}

	if (!has_root) {
		rc = sb_append_n(sb, "root:x:0:0:root:/root:/bin/sh\n",
				 sizeof("root:x:0:0:root:/root:/bin/sh\n") - 1);
		if (rc < 0)
			return rc;
	}

	for (int i = 0; i < MAX_ACCOUNTS; i++) {
		if (!g_accounts[i].in_use)
			continue;
		rc = sb_appendf(sb, "%s:x:%u:%u:%s:%s:%s\n",
				g_accounts[i].username,
				g_accounts[i].pub_uid,
				g_accounts[i].pub_gid,
				g_accounts[i].is_daemon ? "pressure-daemon" : "pressure-user",
				g_accounts[i].home_dir,
				g_accounts[i].is_daemon ? "/bin/false" : "/bin/sh");
		if (rc < 0)
			return rc;
	}
	return 0;
}

static int build_merged_group(struct strbuf *sb)
{
	FILE *f = fopen(POSIX_GROUP_PATH, "r");
	char *line = NULL;
	size_t cap = 0;
	ssize_t n;
	bool has_root = false;
	char *preserved_members[MAX_ACCOUNTS];
	int rc = 0;

	memset(preserved_members, 0, sizeof(preserved_members));

	if (f) {
		while ((n = getline(&line, &cap, f)) >= 0) {
			char name[64];

			if (parse_colon_field_str(line, 0, name, sizeof(name)) &&
			    name[0]) {
				if (strcmp(name, "root") == 0)
					has_root = true;
				if (is_pressure_managed_name(name)) {
					int idx = find_account_index(name);

					if (idx >= 0 && !preserved_members[idx]) {
						const char *c1 = strchr(line, ':');
						const char *c2 = c1 ? strchr(c1 + 1, ':') : NULL;
						const char *c3 = c2 ? strchr(c2 + 1, ':') : NULL;

						if (c3) {
							const char *m = c3 + 1;
							size_t mlen = strlen(m);

							while (mlen > 0 &&
							       (m[mlen - 1] == '\n' ||
								m[mlen - 1] == '\r'))
								mlen--;
							if (mlen > 0) {
								preserved_members[idx] =
									strndup(m, mlen);
								if (!preserved_members[idx]) {
									rc = -ENOMEM;
									break;
								}
							}
						}
					}
					continue;
				}
			}
			rc = sb_append_line_verbatim(sb, line, (size_t)n);
			if (rc < 0)
				break;
		}
		if (ferror(f) && rc == 0)
			rc = -EIO;
		free(line);
		fclose(f);
		if (rc < 0)
			goto out;
	} else if (errno != ENOENT) {
		rc = -errno;
		goto out;
	}

	if (!has_root) {
		rc = sb_append_n(sb, "root:x:0:\n", sizeof("root:x:0:\n") - 1);
		if (rc < 0)
			goto out;
	}

	for (int i = 0; i < MAX_ACCOUNTS; i++) {
		if (!g_accounts[i].in_use)
			continue;
		rc = sb_appendf(sb, "%s:x:%u:%s\n",
				g_accounts[i].username,
				g_accounts[i].pub_gid,
				preserved_members[i] ? preserved_members[i] : "");
		if (rc < 0)
			goto out;
	}

out:
	for (int i = 0; i < MAX_ACCOUNTS; i++)
		free(preserved_members[i]);
	return rc;
}

static int build_merged_shadow(struct strbuf *sb)
{
	FILE *f = fopen(POSIX_SHADOW_PATH, "r");
	char *line = NULL;
	size_t cap = 0;
	ssize_t n;
	bool has_root = false;
	int rc = 0;

	if (f) {
		while ((n = getline(&line, &cap, f)) >= 0) {
			char name[64];

			if (parse_colon_field_str(line, 0, name, sizeof(name)) &&
			    name[0]) {
				if (strcmp(name, "root") == 0)
					has_root = true;
				if (is_pressure_managed_name(name))
					continue;
			}
			rc = sb_append_line_verbatim(sb, line, (size_t)n);
			if (rc < 0)
				break;
		}
		if (ferror(f) && rc == 0)
			rc = -EIO;
		free(line);
		fclose(f);
		if (rc < 0)
			return rc;
	} else if (errno != ENOENT) {
		return -errno;
	}

	if (!has_root) {
		rc = sb_append_n(sb, "root:!:19000:0:99999:7:::\n",
				 sizeof("root:!:19000:0:99999:7:::\n") - 1);
		if (rc < 0)
			return rc;
	}

	for (int i = 0; i < MAX_ACCOUNTS; i++) {
		if (!g_accounts[i].in_use)
			continue;
		/* Locked '!' password field: only pressure-authd vault can authenticate */
		rc = sb_appendf(sb, "%s:!:19000:0:99999:7:::\n",
				g_accounts[i].username);
		if (rc < 0)
			return rc;
	}
	return 0;
}

/*
 * Merge Pressure-managed accounts into /etc/passwd, /etc/group, and /etc/shadow
 * without clobbering distro-managed entries, using atomic staging + rollback.
 */
static int sync_posix_files(void)
{
	static const char *const targets[3] = {
		POSIX_PASSWD_PATH, POSIX_GROUP_PATH, POSIX_SHADOW_PATH
	};
	static const char *const backups[3] = {
		POSIX_BAK_PASSWD, POSIX_BAK_GROUP, POSIX_BAK_SHADOW
	};
	static const mode_t default_modes[3] = { 0644, 0644, 0600 };

	struct strbuf bufs[3];
	char tmps[3][64] = {
		"/etc/.pressure_pw_XXXXXX",
		"/etc/.pressure_gr_XXXXXX",
		"/etc/.pressure_sh_XXXXXX",
	};
	bool tmp_created[3] = { false, false, false };
	bool bak_created[3] = { false, false, false };
	bool existed[3] = { false, false, false };
	mode_t modes[3] = { 0644, 0644, 0600 };
	uid_t uids[3] = { 0, 0, 0 };
	gid_t gids[3] = { 0, 0, 0 };
	int active_cnt = 0;
	int committed = 0;
	int rc = 0;

	for (int i = 0; i < MAX_ACCOUNTS; i++) {
		if (g_accounts[i].in_use)
			active_cnt++;
	}

	/*
	 * Clean first-boot fast path: if no Pressure accounts exist and no
	 * previously managed entries need pruning, leave pristine distro
	 * /etc/{passwd,group,shadow} untouched when all three already exist
	 * with a root entry.
	 */
	if (active_cnt == 0 && g_managed_cnt == 0 &&
	    posix_file_has_name(POSIX_PASSWD_PATH, "root") &&
	    posix_file_has_name(POSIX_GROUP_PATH, "root") &&
	    posix_file_has_name(POSIX_SHADOW_PATH, "root"))
		return 0;

	for (int i = 0; i < 3; i++)
		sb_init(&bufs[i]);

	rc = build_merged_passwd(&bufs[0]);
	if (rc < 0)
		goto out_free;
	rc = build_merged_group(&bufs[1]);
	if (rc < 0)
		goto out_free;
	rc = build_merged_shadow(&bufs[2]);
	if (rc < 0)
		goto out_free;

	/* Phase 1: stage all three files in /etc, preserving original permissions/owners */
	for (int i = 0; i < 3; i++) {
		struct stat st;
		int fd;

		if (stat(targets[i], &st) == 0) {
			existed[i] = true;
			modes[i] = st.st_mode & 07777;
			uids[i] = st.st_uid;
			gids[i] = st.st_gid;
		} else if (errno == ENOENT) {
			existed[i] = false;
			modes[i] = default_modes[i];
			uids[i] = 0;
			gids[i] = 0;
		} else {
			rc = -errno;
			goto out_cleanup;
		}

		fd = mkstemp(tmps[i]);
		if (fd < 0) {
			rc = -errno;
			goto out_cleanup;
		}
		tmp_created[i] = true;

		if (bufs[i].len > 0) {
			rc = write_all(fd, bufs[i].data, bufs[i].len);
			if (rc < 0) {
				close(fd);
				goto out_cleanup;
			}
		}
		if (fchown(fd, uids[i], gids[i]) < 0) {
			/* best-effort ownership preservation */
		}
		if (fchmod(fd, modes[i]) < 0) {
			rc = -errno;
			close(fd);
			goto out_cleanup;
		}
		if (fsync(fd) < 0 && errno != EINVAL) {
			rc = -errno;
			close(fd);
			goto out_cleanup;
		}
		if (close(fd) < 0) {
			rc = -errno;
			goto out_cleanup;
		}
	}

	/* Phase 2: create durable rollback snapshots of existing live files */
	for (int i = 0; i < 3; i++) {
		unlink(backups[i]);
		if (!existed[i])
			continue;
		if (link(targets[i], backups[i]) < 0) {
			rc = copy_file_for_backup(targets[i], backups[i],
						  modes[i], uids[i], gids[i]);
			if (rc < 0)
				goto out_cleanup;
		}
		bak_created[i] = true;
	}
	(void)fsync_dir("/etc");

	/* Phase 3: atomically swap all three files; roll back on any failure */
	for (int i = 0; i < 3; i++) {
		if (rename(tmps[i], targets[i]) < 0) {
			rc = -errno;
			goto out_rollback;
		}
		tmp_created[i] = false;
		committed++;
	}

	/* Phase 4: persist Pressure-managed name manifest before discarding backups */
	rc = save_manifest_from_accounts();
	if (rc < 0)
		goto out_rollback;

	/* Phase 5: remove rollback snapshots and sync /etc */
	for (int i = 0; i < 3; i++) {
		if (bak_created[i]) {
			unlink(backups[i]);
			bak_created[i] = false;
		}
	}
	(void)fsync_dir("/etc");
	goto out_free;

out_rollback:
	for (int j = committed - 1; j >= 0; j--) {
		if (existed[j] && bak_created[j]) {
			if (rename(backups[j], targets[j]) == 0)
				bak_created[j] = false;
		} else if (!existed[j]) {
			unlink(targets[j]);
		}
	}
	(void)fsync_dir("/etc");

out_cleanup:
	for (int i = 0; i < 3; i++) {
		if (tmp_created[i])
			unlink(tmps[i]);
		if (bak_created[i])
			unlink(backups[i]);
	}
out_free:
	for (int i = 0; i < 3; i++)
		sb_free(&bufs[i]);
	return rc;
}

static int register_account_in_kernel(const struct vault_account *acc)
{
	char line[160];
	int rc;

	snprintf(line, sizeof(line), "add %u %u %s %s\n",
		 acc->pub_uid, acc->pub_gid,
		 acc->is_daemon ? "daemon" : "human", acc->label);
	rc = secfs_write("users", line);
	if (rc < 0)
		return rc;

	mkdir("/home", 0755);
	mkdir("/var", 0755);
	mkdir("/var/lib", 0755);
	mkdir(acc->home_dir, 0700);
	if (chown(acc->home_dir, acc->pub_uid, acc->pub_gid) < 0) {
		/* best-effort ownership sync */
	}

	/* Hard-stop lock directory in kernel to this user/daemon's secret kpriv_uid! */
	return label_kernel_path(PRESSURE_FILE_USER_PRIVATE |
				 (acc->is_daemon ? 0 : PRESSURE_FILE_LOCAL_ONLY),
				 acc->pub_uid, acc->label, acc->home_dir);
}

static void handle_client(int cfd)
{
	struct ucred peer = { .uid = (uid_t)-1 };
	socklen_t ulen = sizeof(peer);
	struct authd_request req;
	struct authd_response resp = { .magic = AUTHD_PROTO_MAGIC };

	getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &peer, &ulen);
	if (read(cfd, &req, sizeof(req)) != (ssize_t)sizeof(req) ||
	    req.magic != AUTHD_PROTO_MAGIC) {
		resp.status = -EINVAL;
		if (write(cfd, &resp, sizeof(resp)) < 0) {}
		return;
	}

	req.username[sizeof(req.username) - 1] = '\0';
	req.password[sizeof(req.password) - 1] = '\0';
	req.label[sizeof(req.label) - 1] = '\0';
	req.home_dir[sizeof(req.home_dir) - 1] = '\0';
	req.tty_path[sizeof(req.tty_path) - 1] = '\0';
	req.rhost[sizeof(req.rhost) - 1] = '\0';

	switch (req.op) {
	case AUTHD_REQ_USERADD: {
		int slot = -1;
		int rc;
		struct vault_account *acc;

		if (peer.uid != 0) {
			resp.status = -EPERM;
			snprintf(resp.message, sizeof(resp.message),
				 "only root may provision Pressure accounts");
			break;
		}
		if (!valid_posix_username(req.username)) {
			resp.status = -EINVAL;
			snprintf(resp.message, sizeof(resp.message),
				 "invalid or reserved POSIX username");
			break;
		}
		if ((req.home_dir[0] && !valid_passwd_field(req.home_dir)) ||
		    (req.label[0] && !valid_pressure_label(req.label))) {
			resp.status = -EINVAL;
			snprintf(resp.message, sizeof(resp.message),
				 "invalid character in home_dir or label");
			break;
		}
		if (find_account(req.username)) {
			resp.status = -EEXIST;
			snprintf(resp.message, sizeof(resp.message),
				 "Pressure account already exists");
			break;
		}
		if (posix_file_has_name(POSIX_PASSWD_PATH, req.username) ||
		    posix_file_has_name(POSIX_GROUP_PATH, req.username) ||
		    posix_file_has_name(POSIX_SHADOW_PATH, req.username)) {
			resp.status = -EEXIST;
			snprintf(resp.message, sizeof(resp.message),
				 "conflicts with existing system account or group");
			break;
		}
		for (int i = 0; i < MAX_ACCOUNTS; i++) {
			if (!g_accounts[i].in_use) {
				slot = i;
				break;
			}
		}
		if (slot < 0) {
			resp.status = -ENOSPC;
			snprintf(resp.message, sizeof(resp.message),
				 "vault account table full");
			break;
		}

		acc = &g_accounts[slot];
		memset(acc, 0, sizeof(*acc));
		acc->in_use = 1;
		acc->is_daemon = req.is_daemon ? 1 : 0;
		rc = generate_random_public_id(&acc->pub_uid);
		if (rc == 0)
			rc = generate_random_public_id(&acc->pub_gid);
		if (rc < 0) {
			OPENSSL_cleanse(acc, sizeof(*acc));
			resp.status = rc;
			snprintf(resp.message, sizeof(resp.message),
				 "failed to allocate collision-free public ID");
			break;
		}
		snprintf(acc->username, sizeof(acc->username), "%s", req.username);
		if (req.label[0])
			snprintf(acc->label, sizeof(acc->label), "%s", req.label);
		else if (acc->is_daemon)
			snprintf(acc->label, sizeof(acc->label),
				 "subj:daemon_%.19s", req.username);
		else
			snprintf(acc->label, sizeof(acc->label),
				 "subj:user_%.21s", req.username);

		if (req.home_dir[0])
			snprintf(acc->home_dir, sizeof(acc->home_dir), "%s",
				 req.home_dir);
		else if (acc->is_daemon)
			snprintf(acc->home_dir, sizeof(acc->home_dir),
				 "/var/lib/%.80s", req.username);
		else
			snprintf(acc->home_dir, sizeof(acc->home_dir),
				 "/home/%.80s", req.username);

		if (RAND_bytes(acc->salt, sizeof(acc->salt)) != 1) {
			OPENSSL_cleanse(acc, sizeof(*acc));
			resp.status = -EIO;
			snprintf(resp.message, sizeof(resp.message),
				 "CSPRNG salt generation failed");
			break;
		}
		if (!acc->is_daemon && req.password[0]) {
			acc->password_kdf = PASSWORD_PBKDF2_SHA256;
			if (derive_password_hash(req.password, acc->salt,
						 acc->pass_hash, acc->password_kdf) < 0) {
				OPENSSL_cleanse(acc, sizeof(*acc));
				resp.status = -EIO;
				snprintf(resp.message, sizeof(resp.message),
					 "password derivation failed");
				break;
			}
		}

		rc = sync_posix_files();
		if (rc < 0) {
			OPENSSL_cleanse(acc, sizeof(*acc));
			resp.status = rc;
			snprintf(resp.message, sizeof(resp.message),
				 "failed to update POSIX account files");
			break;
		}
		rc = save_vault();
		if (rc < 0) {
			OPENSSL_cleanse(acc, sizeof(*acc));
			(void)sync_posix_files();
			resp.status = rc;
			snprintf(resp.message, sizeof(resp.message),
				 "failed to persist encrypted auth vault");
			break;
		}
		rc = register_account_in_kernel(acc);
		if (rc < 0) {
			OPENSSL_cleanse(acc, sizeof(*acc));
			(void)save_vault();
			(void)sync_posix_files();
			resp.status = rc;
			snprintf(resp.message, sizeof(resp.message),
				 "failed to register account in kernel");
			break;
		}

		resp.status = 0;
		resp.pub_uid = acc->pub_uid;
		resp.pub_gid = acc->pub_gid;
		resp.is_daemon = acc->is_daemon;
		snprintf(resp.label, sizeof(resp.label), "%s", acc->label);
		snprintf(resp.home_dir, sizeof(resp.home_dir), "%s",
			 acc->home_dir);
		snprintf(resp.message, sizeof(resp.message),
			 "created random pub_uid=%u (secret kpriv_uid minted)",
			 acc->pub_uid);
		break;
	}
	case AUTHD_REQ_PASSWD: {
		struct vault_account *acc = find_account(req.username);
		uint8_t old_salt[PASSWORD_SALT_LEN];
		uint8_t old_hash[PASSWORD_HASH_LEN];
		uint8_t old_kdf;

		if (peer.uid != 0) {
			resp.status = -EPERM;
			break;
		}
		if (!acc) {
			resp.status = -ENOENT;
			break;
		}
		old_kdf = acc->password_kdf;
		memcpy(old_salt, acc->salt, sizeof(old_salt));
		memcpy(old_hash, acc->pass_hash, sizeof(old_hash));
		if (RAND_bytes(acc->salt, sizeof(acc->salt)) != 1) {
			resp.status = -EIO;
		} else {
			acc->password_kdf = PASSWORD_PBKDF2_SHA256;
			resp.status = derive_password_hash(req.password, acc->salt,
							  acc->pass_hash, acc->password_kdf);
			if (resp.status == 0)
				resp.status = save_vault();
		}
		if (resp.status < 0) {
			acc->password_kdf = old_kdf;
			memcpy(acc->salt, old_salt, sizeof(old_salt));
			memcpy(acc->pass_hash, old_hash, sizeof(old_hash));
		}
		OPENSSL_cleanse(old_salt, sizeof(old_salt));
		OPENSSL_cleanse(old_hash, sizeof(old_hash));
		break;
	}
	case AUTHD_REQ_SETLABEL: {
		struct vault_account *acc = find_account(req.username);
		char old_label[sizeof(acc->label)];

		if (peer.uid != 0 || !acc) {
			resp.status = peer.uid != 0 ? -EPERM : -ENOENT;
			break;
		}
		if (!valid_pressure_label(req.label)) {
			resp.status = -EINVAL;
			break;
		}
		memcpy(old_label, acc->label, sizeof(old_label));
		snprintf(acc->label, sizeof(acc->label), "%s", req.label);
		resp.status = save_vault();
		if (resp.status == 0)
			resp.status = register_account_in_kernel(acc);
		if (resp.status < 0) {
			memcpy(acc->label, old_label, sizeof(old_label));
			(void)save_vault();
		}
		break;
	}
	case AUTHD_REQ_LOOKUP: {
		struct vault_account *acc = find_account(req.username);
		if (!acc) {
			resp.status = -ENOENT;
			break;
		}
		resp.status = 0;
		resp.pub_uid = acc->pub_uid;
		resp.pub_gid = acc->pub_gid;
		resp.is_daemon = acc->is_daemon;
		snprintf(resp.label, sizeof(resp.label), "%s", acc->label);
		snprintf(resp.home_dir, sizeof(resp.home_dir), "%s", acc->home_dir);
		break;
	}
	case AUTHD_REQ_LOGIN: {
		struct vault_account *acc = find_account(req.username);
		uint8_t cand_hash[PASSWORD_HASH_LEN];

		if (!acc || acc->is_daemon) {
			resp.status = -EACCES;
			break;
		}
		if (derive_password_hash(req.password, acc->salt, cand_hash, acc->password_kdf) < 0 ||
		    CRYPTO_memcmp(cand_hash, acc->pass_hash, PASSWORD_HASH_LEN) != 0) {
			OPENSSL_cleanse(cand_hash, sizeof(cand_hash));
			resp.status = -EACCES;
			snprintf(resp.message, sizeof(resp.message),
				 "invalid credentials");
			break;
		}
		OPENSSL_cleanse(cand_hash, sizeof(cand_hash));

		/* If target_pid == 0, authenticate-only check (e.g. pam_sm_authenticate) */
		resp.pub_uid = acc->pub_uid;
		resp.pub_gid = acc->pub_gid;
		snprintf(resp.label, sizeof(resp.label), "%s", acc->label);
		snprintf(resp.home_dir, sizeof(resp.home_dir), "%s", acc->home_dir);

		if (req.target_pid > 0) {
			unsigned int maj = 0, min = 0;
			struct stat st;
			bool is_remote = req.force_remote || (req.rhost[0] != '\0');
			char grant_cmd[192];

			if (req.tty_path[0] && stat(req.tty_path, &st) == 0 &&
			    S_ISCHR(st.st_mode)) {
				maj = major(st.st_rdev);
				min = minor(st.st_rdev);
				if (strncmp(req.tty_path, "/dev/pts/", 9) == 0 &&
				    req.rhost[0] != '\0')
					is_remote = true;
			}
			/* Kernel independently verifies target_pid's real controlling TTY & SID */
			if (req.reserved > 0) {
				snprintf(grant_cmd, sizeof(grant_cmd),
					 "grant %d %u %s %u:%u %s %u\n",
					 req.target_pid, acc->pub_uid,
					 is_remote ? "remote" : "local",
					 maj, min, acc->label,
					 (unsigned int)req.reserved);
			} else {
				snprintf(grant_cmd, sizeof(grant_cmd),
					 "grant %d %u %s %u:%u %s\n",
					 req.target_pid, acc->pub_uid,
					 is_remote ? "remote" : "local",
					 maj, min, acc->label);
			}
			resp.status = secfs_write("auth_grant", grant_cmd);
			resp.provenance = is_remote ? PRESSURE_PROV_REMOTE :
						      PRESSURE_PROV_AUTH_LOCAL;
		} else {
			resp.status = 0;
		}
		break;
	}
	case AUTHD_REQ_START_DAEMON: {
		struct vault_account *acc = find_account(req.username);
		char grant_cmd[192];

		if (peer.uid != 0) {
			resp.status = -EPERM;
			break;
		}
		if (!acc || !acc->is_daemon || req.target_pid <= 0) {
			resp.status = -ENOENT;
			break;
		}
		snprintf(grant_cmd, sizeof(grant_cmd),
			 "grant %d %u %s 0:0 %s\n",
			 req.target_pid, acc->pub_uid,
			 req.force_remote ? "remote" : "local",
			 req.label[0] ? req.label : acc->label);
		resp.status = secfs_write("auth_grant", grant_cmd);
		resp.pub_uid = acc->pub_uid;
		resp.pub_gid = acc->pub_gid;
		resp.is_daemon = 1;
		snprintf(resp.label, sizeof(resp.label), "%s", acc->label);
		snprintf(resp.home_dir, sizeof(resp.home_dir), "%s", acc->home_dir);
		break;
	}
	case AUTHD_REQ_LOGOUT: {
		char cmd[64];
		snprintf(cmd, sizeof(cmd), "release_pid %d\n",
			 req.target_pid > 0 ? req.target_pid : (int)peer.pid);
		resp.status = secfs_write("auth_grant", cmd);
		break;
	}
	default:
		resp.status = -EINVAL;
		break;
	}

	OPENSSL_cleanse(req.password, sizeof(req.password));
	if (write(cfd, &resp, sizeof(resp)) < 0) {}
}

static bool is_fips_provider(const OSSL_PROVIDER *provider)
{
	return provider && !strcmp(OSSL_PROVIDER_get0_name(provider), "fips");
}

static bool authd_fips_ready(void)
{
	EVP_CIPHER *cipher;
	EVP_MD *digest;
	EVP_KDF *hkdf, *pbkdf2;
	EVP_MAC *hmac;
	EVP_RAND_CTX *random;
	uint8_t sample[PASSWORD_SALT_LEN], test_key[sizeof(g_master_key)];
	uint8_t verifier[PASSWORD_HASH_LEN], vault_key[32];
	bool ready;

	if (!EVP_default_properties_is_fips_enabled(NULL) ||
	    !OSSL_PROVIDER_available(NULL, "fips"))
		return false;

	cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
	digest = EVP_MD_fetch(NULL, "SHA256", NULL);
	hkdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
	pbkdf2 = EVP_KDF_fetch(NULL, "PBKDF2", NULL);
	hmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	random = RAND_get0_public(NULL);
	ready = cipher && is_fips_provider(EVP_CIPHER_get0_provider(cipher)) &&
		digest && is_fips_provider(EVP_MD_get0_provider(digest)) &&
		hkdf && is_fips_provider(EVP_KDF_get0_provider(hkdf)) &&
		pbkdf2 && is_fips_provider(EVP_KDF_get0_provider(pbkdf2)) &&
		hmac && is_fips_provider(EVP_MAC_get0_provider(hmac)) &&
		random && is_fips_provider(EVP_RAND_get0_provider(EVP_RAND_CTX_get0_rand(random))) &&
		RAND_bytes(sample, sizeof(sample)) == 1 &&
		derive_password_hash("pressure-fips-self-test", sample, verifier,
				     PASSWORD_PBKDF2_SHA256) == 0 &&
		RAND_bytes(test_key, sizeof(test_key)) == 1 &&
		derive_aead_key(vault_key, test_key, false) == 0;
	OPENSSL_cleanse(test_key, sizeof(test_key));
	OPENSSL_cleanse(vault_key, sizeof(vault_key));
	OPENSSL_cleanse(verifier, sizeof(verifier));
	OPENSSL_cleanse(sample, sizeof(sample));
	EVP_MAC_free(hmac);
	EVP_KDF_free(pbkdf2);
	EVP_KDF_free(hkdf);
	EVP_MD_free(digest);
	EVP_CIPHER_free(cipher);
	return ready;
}

int main(int argc, char **argv)
{
	bool daemonize = false, require_fips = false, check_fips = false;
	struct stat marker;
	struct sigaction sa;
	struct sockaddr_un sun = { .sun_family = AF_UNIX };
	char errbuf[192] = "";
	int sfd, rc;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--daemon") == 0)
			daemonize = true;
		else if (strcmp(argv[i], "--require-fips") == 0)
			require_fips = true;
		else if (strcmp(argv[i], "--check-fips") == 0)
			check_fips = true;
		else {
			fprintf(stderr, "Usage: pressure-authd [--daemon] [--require-fips] | --check-fips\n");
			return 1;
		}
	}
	if (lstat(AUTHD_DIR_PATH "/require-fips", &marker) == 0) {
		if (!S_ISREG(marker.st_mode) || marker.st_uid != 0 ||
		    (marker.st_mode & (S_IWGRP | S_IWOTH))) {
			fprintf(stderr, "pressure-authd: invalid require-fips marker\n");
			return 1;
		}
		require_fips = true;
	} else if (errno != ENOENT) {
		perror("pressure-authd: inspect require-fips marker");
		return 1;
	}
	if ((require_fips || check_fips) && !authd_fips_ready()) {
		fprintf(stderr, "pressure-authd: strict FIPS mode needs fips=yes and its authentication primitives from the OpenSSL FIPS provider\n");
		return 1;
	}
	if (check_fips) {
		puts("pressure-authd: FIPS provider and authentication primitives ready");
		return 0;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handle_sig;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0; /* Do not set SA_RESTART so SIGTERM interrupts accept() */
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	signal(SIGPIPE, SIG_IGN);

	if (daemonize && daemon(0, 0) < 0) {
		perror("daemon");
		return 1;
	}

	/* Claim exclusive PRESSURE_ACCT_AUTHD credential in the kernel */
	if (secfs_write("authd_register", "register\n") < 0) {
		fprintf(stderr, "pressure-authd: failed to claim kernel authd_register\n");
		return 1;
	}

	rc = load_or_init_vault();
	if (rc < 0) {
		if (rc == -ENOTSUP)
			fprintf(stderr, "pressure-authd: migrate the legacy vault and reset scrypt passwords before enabling FIPS mode\n");
		fprintf(stderr, "pressure-authd: failed to initialize authentication vault (%s)\n",
			strerror(-rc));
		return 1;
	}

	rc = load_manifest();
	if (rc < 0) {
		fprintf(stderr, "pressure-authd: failed to load POSIX manifest (%s)\n",
			strerror(-rc));
		return 1;
	}

	/* Recover any interrupted atomic /etc/{passwd,group,shadow} swap first */
	recover_interrupted_posix_sync();

	/* Refuse startup rather than clobbering colliding distro accounts/IDs */
	rc = check_vault_posix_collisions(errbuf, sizeof(errbuf));
	if (rc < 0) {
		fprintf(stderr, "pressure-authd: POSIX coexistence collision: %s\n",
			errbuf);
		return 1;
	}

	/* Reconcile Pressure-owned POSIX entries while preserving distro accounts */
	rc = sync_posix_files();
	if (rc < 0) {
		fprintf(stderr, "pressure-authd: failed to synchronize POSIX files (%s)\n",
			strerror(-rc));
		return 1;
	}

	/* Re-sync persisted Pressure accounts into kernel secret kpriv_uid table */
	for (int i = 0; i < MAX_ACCOUNTS; i++) {
		if (g_accounts[i].in_use) {
			rc = register_account_in_kernel(&g_accounts[i]);
			if (rc < 0)
				fprintf(stderr,
					"pressure-authd: warning: kernel registration failed for '%s' (%s)\n",
					g_accounts[i].username, strerror(-rc));
		}
	}

	mkdir("/run/pressure", 0755);
	unlink(AUTHD_SOCK_PATH);
	sfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sfd < 0) {
		perror("socket");
		return 1;
	}
	snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", AUTHD_SOCK_PATH);
	if (bind(sfd, (struct sockaddr *)&sun, sizeof(sun)) < 0 ||
	    chmod(AUTHD_SOCK_PATH, 0666) < 0 ||
	    listen(sfd, 32) < 0) {
		perror("bind/listen authd.sock");
		close(sfd);
		return 1;
	}

	rc = 0;
	while (g_running) {
		int cfd = accept(sfd, NULL, NULL);
		if (cfd < 0) {
			if (errno == EINTR)
				continue;
			perror("pressure-authd: accept");
			rc = 1;
			break;
		}
		handle_client(cfd);
		close(cfd);
	}

	close(sfd);
	unlink(AUTHD_SOCK_PATH);
	return rc;
}
