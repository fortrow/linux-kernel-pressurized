/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PRESSURE_VFS_H
#define _LINUX_PRESSURE_VFS_H

#include <linux/types.h>
#include <linux/siphash.h>

#define PRESSURE_PUB_FD_BIT		0x40000000U
#define PRESSURE_PUB_FD_MASK		0x3fffffffU
#define PRESSURE_MAX_PRIV_FD		16384U
#define PRESSURE_FDSLOT_PREOPENED	(1U << 0)

struct files_struct;
struct fdtable;
struct file;

struct pressure_fd_slot {
	u16 nonce;
	u16 last_nonce;
	u32 flags;
	u64 file_priv_id;
};

#ifdef CONFIG_SECURITY_PRESSURE
u32 pressure_feistel30_encrypt(const siphash_key_t *key, u32 val30);
u32 pressure_feistel30_decrypt(const siphash_key_t *key, u32 cipher30);

int pressure_vfs_encode_new_fd(struct files_struct *files, struct fdtable *fdt,
			       unsigned int priv_fd);
int pressure_vfs_decode_fd_install(struct files_struct *files,
				   struct fdtable *fdt, unsigned int fd,
				   struct file *file, unsigned int *priv_out);
int pressure_vfs_decode_fd_rcu(struct files_struct *files, unsigned int fd,
			       unsigned int *priv_out, bool *is_forged);
void pressure_vfs_release_slot(struct fdtable *fdt, unsigned int priv_fd);
void pressure_vfs_init_files_key(struct files_struct *files,
				 const struct files_struct *oldf);
void pressure_vfs_report_bad_fd(unsigned int bad_fd, int reason);
#else
static inline int pressure_vfs_encode_new_fd(struct files_struct *files,
					     struct fdtable *fdt,
					     unsigned int priv_fd)
{
	return (int)priv_fd;
}
static inline int pressure_vfs_decode_fd_install(struct files_struct *files,
						 struct fdtable *fdt,
						 unsigned int fd,
						 struct file *file,
						 unsigned int *priv_out)
{
	*priv_out = fd;
	return 0;
}
static inline int pressure_vfs_decode_fd_rcu(struct files_struct *files,
					     unsigned int fd,
					     unsigned int *priv_out,
					     bool *is_forged)
{
	*priv_out = fd;
	if (is_forged)
		*is_forged = false;
	return 0;
}
static inline void pressure_vfs_release_slot(struct fdtable *fdt,
					     unsigned int priv_fd)
{
}
static inline void pressure_vfs_init_files_key(struct files_struct *files,
					       const struct files_struct *oldf)
{
}
static inline void pressure_vfs_report_bad_fd(unsigned int bad_fd, int reason)
{
}
#endif /* CONFIG_SECURITY_PRESSURE */

#endif /* _LINUX_PRESSURE_VFS_H */
