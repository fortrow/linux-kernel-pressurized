# 01 — Upstream Linux 7.3.5 Core Patches

This document details every modification made to core upstream Linux 7.3.5 subsystems outside `security/pressure/` and `modules/sfw/`. Together, these patches total **~330 changed lines across 19 kernel files** and provide three foundational mechanisms:

1. **Randomized Non-Monotonic Public/Private File Descriptors** in `fs/file.c` and `include/linux/fdtable.h`.
2. **Per-Lookup FD Verification & `/proc/<pid>/fd` Confinement Hooks** in the LSM framework and `fs/proc/fd.c`.
3. **Zero-Netfilter Dual-Stack (IPv4 + IPv6) 5-Chain Packet Hooks** in `net/ipv4/` and `net/ipv6/`.

---

## 1. LSM Framework Registration & New Hooks

Standard Linux LSM hooks (`file_open`, `file_permission`) run at `open()` or `read()`/`write()`, but do **not** run on every raw descriptor resolution (`__fget` / `__fget_light` / socket operations) or gate `/proc/<pid>/fd` directory walks cleanly by task confinement state. Pressure adds a dedicated LSM ID and two targeted hooks:

### 1.1 `include/uapi/linux/lsm.h`
- Added [lsm.h](../include/uapi/linux/lsm.h#L68):
  ```c
  #define LSM_ID_PRESSURE 114
  ```

### 1.2 `include/linux/lsm_count.h`
- Updated [lsm_count.h](../include/linux/lsm_count.h#L105-L135) to define `PRESSURE_ENABLED` when `CONFIG_SECURITY_PRESSURE` is set and append `PRESSURE_ENABLED` to `MAX_LSM_COUNT` so static LSM hook tables size accurately at compile time.

### 1.3 `include/linux/lsm_hook_defs.h`, `include/linux/security.h`, `security/security.c`
- Declared in [lsm_hook_defs.h](../include/linux/lsm_hook_defs.h#L190-L192):
  ```c
  LSM_HOOK(int, 0, file_fd_lookup, struct file *file, unsigned int priv_fd,
           unsigned int pub_fd)
  LSM_HOOK(int, 0, proc_fd_access, struct task_struct *target)
  ```
- Declared prototypes and `!CONFIG_SECURITY` inline `return 0;` stubs in [security.h](../include/linux/security.h#L472-L474).
- Implemented and exported (`EXPORT_SYMBOL_GPL`) both dispatchers in [security.c](../security/security.c#L2395-L2406).
- Wired `security/pressure/` into [security/Kconfig](../security/Kconfig#L231) and [security/Makefile](../security/Makefile#L29).

---

## 2. VFS Public/Private Descriptor Table Architecture

### 2.1 `include/linux/pressure_vfs.h` (New Header)
Defines the boundary between `fs/file.c` and `security/pressure/fd_crypto.c` ([pressure_vfs.h](../include/linux/pressure_vfs.h#L1-L77)):
- **`PRESSURE_PUB_FD_BIT` (`0x40000000U`)**: Bit 30 marks an encrypted positive `int` public descriptor (`>= 1,073,741,824`, fitting cleanly inside signed 32-bit POSIX `int` return values).
- **`PRESSURE_PUB_FD_MASK` (`0x3fffffffU`)**: Lower 30 bits carry the SipHash Feistel ciphertext of `(nonce16 << 14) | priv_fd14`.
- **`PRESSURE_MAX_PRIV_FD` (`16384U`)**: Maximum private `fdtable` index (`2^14`) addressable inside the 14-bit slot field.
- **`struct pressure_fd_slot`**:
  ```c
  struct pressure_fd_slot {
      u16 nonce;        /* Active 16-bit non-zero random slot nonce (0 = closed) */
      u16 last_nonce;   /* Previous nonce on this slot to prevent immediate reuse */
      u32 flags;
      u64 file_priv_id; /* Secret kernel-only file_priv_id bound at fd_install() */
  };
  ```
- When `CONFIG_SECURITY_PRESSURE` is disabled, inline pass-through stubs compile to zero overhead.

### 2.2 `include/linux/fdtable.h`
Extends per-process descriptor tables ([fdtable.h](../include/linux/fdtable.h#L33-L65)):
- **`struct fdtable`**: Adds `struct pressure_fd_slot *pg_slots;` parallel to `struct file __rcu **fd`.
- **`struct files_struct`**:
  - `siphash_key_t pressure_fd_key;` — 128-bit per-`files_struct` CSPRNG key used by the Feistel cipher.
  - `u8 pressure_fd_mode;` — `0` for unconfined early-boot tasks; `1` once confined via `pam_pressure.so` (`setuid` ticket) or `press exec`.
  - `struct pressure_fd_slot pg_slots_init[NR_OPEN_DEFAULT];` — Embedded initial 64-slot array avoiding heap allocation on `fork()` for small FD tables.

### 2.3 `fs/file.c` — Complete List of Patched VFS Functions

Every VFS path that allocates, installs, duplicates, queries, or closes a file descriptor in [fs/file.c](../fs/file.c) was updated:

| Function | Line Range | Exact Change |
| :--- | :---: | :--- |
| `__free_fdtable` | [L106-L114](../fs/file.c#L106-L114) | Frees `fdt->pg_slots` via `kvfree()`. |
| `copy_fdtable` | [L158-L167](../fs/file.c#L158-L167) | Copies active `pg_slots` entries and zeroes newly expanded slots during `expand_fdtable()`. |
| `alloc_fdtable` | [L251-L263](../fs/file.c#L251-L263) | Allocates `nr * sizeof(struct pressure_fd_slot)` via `kvzalloc(..., GFP_KERNEL_ACCOUNT)`. |
| `dup_fd` | [L433-L504](../fs/file.c#L433-L504) | Initializes `newf->pg_slots_init`, copies `pressure_fd_key` + `pressure_fd_mode` via `pressure_vfs_init_files_key()`, and preserves per-slot nonces across `fork()` so inherited public FDs remain valid in child processes. |
| `init_files` | [L581-L583](../fs/file.c#L581-L583) | Points `init_files.fdtab.pg_slots` to `init_files.pg_slots_init`. |
| `alloc_fd` | [L620-L685](../fs/file.c#L620-L685) | When `pressure_fd_mode != 0`: bypasses `files->next_fd` completely, expands `fdtable` proactively when `>= 75%` full so random slot selection has ample entropy, picks a uniform random starting bit `rstart` in `[max(start, 3) .. max_fds)` via `get_random_u32_below()`, locates an unused slot via `find_next_zero_bit()`, marks it open, and returns the encrypted 31-bit public FD from `pressure_vfs_encode_new_fd()`. |
| `put_unused_fd` | [L729-L742](../fs/file.c#L729-L742) | Decodes `pub_fd -> priv_fd`, clears the slot nonce via `pressure_vfs_release_slot()`, and returns `priv_fd` to the unused bitmap. |
| `fd_install_slowpath` & `fd_install` | [L762-L835](../fs/file.c#L762-L835) | Calls `pressure_vfs_decode_fd_install()` to verify the token minted by `alloc_fd()`, bind `file_priv_id` into `pg_slots[priv_fd]`, and publish `file` into `fdt->fd[priv_fd]`. |
| `file_close_fd_locked` & `close_fd` | [L837-L876](../fs/file.c#L837-L876) | Decodes `pub_fd -> priv_fd`; if `forged` is true, records a `PVIO_BAD_FD_TOKEN` strike via `pressure_vfs_report_bad_fd(fd, 1)` before returning `-EBADF`; on valid close, rotates `last_nonce` and zeroes `nonce` so any replay of the closed `pub_fd` immediately triggers a strike. |
| `__fget` | [L1233-L1256](../fs/file.c#L1233-L1256) | RCU-decodes `pub_fd -> priv_fd` (reporting `PVIO_BAD_FD_TOKEN` on forged/stale tokens), resolves `struct file *`, and invokes `security_file_fd_lookup(file, priv_fd, fd)` so every file and socket operation enforces provenance and object hard-stops. |
| `__fget_light` | [L1331-L1364](../fs/file.c#L1331-L1364) | Routes confined tasks through `__fget()` and runs `security_file_fd_lookup()` on fast-path lookups as well. |
| `set_close_on_exec` & `get_close_on_exec` | [L1436-L1471](../fs/file.c#L1436-L1471) | Decodes `pub_fd -> priv_fd` so `fcntl(pub_fd, F_SETFD/F_GETFD, FD_CLOEXEC)` operates transparently on encrypted public descriptors. |
| `ksys_dup3`, `dup2`, & `f_dupfd` | [L1594-L1686](../fs/file.c#L1594-L1686) | Blocks `dup2`/`dup3` targeting fixed FD numbers `newfd > 2` when `pressure_fd_mode != 0` (`PVIO_FORBIDDEN_DUP2`, `-EPERM`), while allowing standard `0, 1, 2` stdio redirection (`dup()` / `F_DUPFD` allocate a fresh random encrypted `pub_fd`). |

---

## 3. `/proc/<pid>/fd` & `/proc/<pid>/fdinfo` Enumeration Lockdown

### `fs/proc/fd.c`
Even with encrypted 31-bit descriptors, allowing a confined or `REMOTE`-tainted process to call `opendir("/proc/self/fd")` would reveal active tokens. Both permission handlers in [fs/proc/fd.c](../fs/proc/fd.c) now invoke `security_proc_fd_access()`:
- **`proc_fdinfo_permission`** ([L97-L108](../fs/proc/fd.c#L97-L108))
- **`proc_fd_permission`** ([L337-L348](../fs/proc/fd.c#L337-L348))

When a confined non-`authd` or `REMOTE` task probes `/proc/<pid>/fd` or `/proc/<pid>/fdinfo`, Pressure records `PVIO_PROC_FD_ENUM` (`PROC_FD_ENUM_BLOCKED`) and returns `-EACCES`.

An authenticated local process with the POSIX descriptor ABI may enumerate its
own ordinary file table. A detached tty1 helper requires an exact
`proc_self_fd` rule for its executable and live authenticated session. Both
paths require the requester and target to be in the same thread group and share
that file table. Tokenized tables and other processes stay outside this grant.


---

## 4. Netfilter Replacement: Dual-Stack 5-Chain `sfw` Packet Hooks

`CONFIG_NETFILTER` is unset in [dev/kernel.config.fragment](../dev/kernel.config.fragment#L13). When `CONFIG_NETFILTER` is disabled, upstream `NF_HOOK(...)` macros compile directly to `okfn(...)` with zero Netfilter code in `vmlinux`. Immediately prior to each `NF_HOOK` site in the IPv4 and IPv6 stacks, lightweight RCU hooks (`pressure_sfw_pkt_run` / `pressure_sfw_pkt6_run` declared in [sfw_pkt.h](../include/linux/sfw_pkt.h)) invoke `sfw.ko` when loaded (and are no-ops when `sfw.ko` is unloaded):

| Chain Enum | IPv4 Hook Site | IPv6 Hook Site | Drop Behavior |
| :--- | :--- | :--- | :--- |
| `SFW_CHAIN_PREROUTING` (`0`) | [net/ipv4/ip_input.c](../net/ipv4/ip_input.c#L619-L623) (`ip_rcv`) & [L694-L702](../net/ipv4/ip_input.c#L694-L702) (`ip_sublist_rcv`) | [net/ipv6/ip6_input.c](../net/ipv6/ip6_input.c#L352-L373) (`ipv6_rcv`, `ip6_sublist_rcv`) | `kfree_skb(skb)` + `NET_RX_DROP` (runs **before** routing lookup so `DNAT` and reverse-`MASQUERADE` steer packets into `FORWARD` vs. `INPUT`). |
| `SFW_CHAIN_INPUT` (`1`) | [net/ipv4/ip_input.c](../net/ipv4/ip_input.c#L263-L267) (`ip_local_deliver`) | [net/ipv6/ip6_input.c](../net/ipv6/ip6_input.c#L560-L566) (`ip6_input`) | `kfree_skb(skb)` before local socket delivery. |
| `SFW_CHAIN_FORWARD` (`2`) | [net/ipv4/ip_forward.c](../net/ipv4/ip_forward.c#L163-L167) (`ip_forward`) | [net/ipv6/ip6_output.c](../net/ipv6/ip6_output.c#L700-L704) (`ip6_forward`) | `kfree_skb(skb)` with both `in_dev` (`skb->dev`) and routed `out_dev` known. |
| `SFW_CHAIN_OUTPUT` (`3`) | [net/ipv4/ip_output.c](../net/ipv4/ip_output.c#L121-L125) (`__ip_local_out`) | [net/ipv6/output_core.c](../net/ipv6/output_core.c#L117-L121) (`__ip6_local_out`) | `kfree_skb(skb)` + `-EPERM` (supports local `OUTPUT` `DNAT` + automatic re-routing). |
| `SFW_CHAIN_POSTROUTING` (`4`) | [net/ipv4/ip_output.c](../net/ipv4/ip_output.c#L444-L449) (`ip_output`) | [net/ipv6/ip6_output.c](../net/ipv6/ip6_output.c#L249-L254) (`ip6_output`) | `kfree_skb(skb)` + `-EPERM` (runs **after** routing with final `out_dev` for `SNAT`, `MASQUERADE`, and reverse-`DNAT`). |

---

## 5. Shared Kernel/Userspace UAPI Header (`include/uapi/linux/sfw.h`)

[include/uapi/linux/sfw.h](../include/uapi/linux/sfw.h) provides the single source of truth shared between `security/pressure/`, `modules/sfw/`, and `userspace/`:
- **Boot Stages**: `PRESSURE_STAGE_PRELOGIN` (`0`), `PRESSURE_STAGE_POSTLOGIN` (`1`).
- **Provenance Levels**: `PRESSURE_PROV_PRELOGIN_LOCAL` (`0`), `PRESSURE_PROV_AUTH_LOCAL` (`1`), `PRESSURE_PROV_REMOTE` (`2`).
- **Account Types**: `PRESSURE_ACCT_SYSTEM` (`0`), `PRESSURE_ACCT_HUMAN` (`1`), `PRESSURE_ACCT_DAEMON` (`2`), `PRESSURE_ACCT_AUTHD` (`3`).
- **Device Classes (`PDEV_*`)**: `PDEV_PSEUDO_SAFE` (`0`), `PDEV_SEAT_TTY` (`1`), `PDEV_SEAT_INPUT` (`2`), `PDEV_STORAGE_BLK` (`3`), `PDEV_PTY_SLAVE` (`4`), `PDEV_NET_LO` (`5`), `PDEV_NET_EXT` (`6`), `PDEV_OTHER_CHR` (`7`).
- **Event Confinement Bitmask (`PEV_*`)**: 13 distinct operations (`PEV_OPEN` through `PEV_LOGIN`, `PEV_ALL = 0x1fffU`).
- **Persistent On-Disk Extended Attribute (`security.pressure`)**: `struct pressure_xattr_disk` (`magic = 0x50525352U 'PRSR'`, `flags`, `file_pub_id`, `owner_pub_uid`, `label[32]`) with flags `PRESSURE_FILE_LOCAL_ONLY`, `PRESSURE_FILE_USER_PRIVATE`, and `PRESSURE_FILE_AUTHD_VAULT`.
- **Dual-Stack `sfw` Wire Protocol (`SFW_PROTO_MAGIC = 0x53465732U 'SFW2'`)**: `struct sfw_req_hdr`, `struct sfw_resp_hdr`, and `struct sfw_firewall_rule` supporting both `AF_INET` and `AF_INET6`.
