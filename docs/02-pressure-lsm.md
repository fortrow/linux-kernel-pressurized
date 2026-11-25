# 02 — The `pressure` Linux Security Module (`security/pressure/`)

The `pressure` LSM (`CONFIG_SECURITY_PRESSURE=y`, `LSM_ID_PRESSURE = 114`) is implemented in [security/pressure/](../security/pressure) across 5 source/header files (~2,900 lines of kernel C):

- [pressure.h](../security/pressure/pressure.h) — Security blobs, tables, audit structures, and internal APIs.
- [fd_crypto.c](../security/pressure/fd_crypto.c) — 30-bit SipHash Feistel FD cipher, audit ring, and 3-strike `SIGKILL` engine.
- [ident_policy.c](../security/pressure/ident_policy.c) — Secret `kpriv_uid` registry, one-time UID tickets, `/dev` & `net_device` cryptographic IDs, seat exclusivity, 6-tuple policy engine, and dual-stack `sfw` authorization.
- [lsm_hooks.c](../security/pressure/lsm_hooks.c) — 25 LSM hook implementations.
- [securityfs.c](../security/pressure/securityfs.c) — `/sys/kernel/security/pressure/*` interface.

---

## 1. LSM Security Blobs

Registered via `DEFINE_LSM(pressure)` with `pressure_blob_sizes` ([lsm_hooks.c](../security/pressure/lsm_hooks.c#L27-L33)):

| Kernel Object | Struct in `pressure.h` | Key Fields & Purpose |
| :--- | :--- | :--- |
| `struct cred` | `pressure_cred_blob` | `pub_uid`, `pub_gid`, secret 64-bit `kpriv_uid` & `kpriv_gid`, `session_pub_id` / `session_priv_id`, `seat_kpriv_id`, `bound_dev_kpriv_id`, `account_type`, sticky `provenance`, `confined`, `label[32]`. |
| `struct task_struct` | `pressure_task_blob` | `atomic_t strikes` (0..3 violation counter), `atomic_t remote_tainted` (lockless sticky `REMOTE` taint), `proc_pub_id` / `proc_priv_id`. |
| `struct inode` | `pressure_inode_blob` | `flags` (`PRESSURE_FILE_*`), `obj_pub_id` / secret `obj_priv_id`, `owner_pub_uid` / secret `owner_kpriv_uid`, `rdev`, `dev_class` (`PDEV_*`), `label[32]`. |
| `struct file` | `pressure_file_blob` | `file_pub_id` / secret `file_priv_id`, `opener_kpriv_uid`, `opener_provenance`. |
| `struct sock` | `pressure_sock_blob` | `sock_pub_id` / secret `sock_priv_id`, `is_sfw_worker`, `remote_tainted`. |

---

## 2. 30-Bit SipHash Feistel FD Cipher (`fd_crypto.c`)

When `pressure_enable_task_fd_crypto()` activates on a task (`files->pressure_fd_mode = 1`), every newly allocated descriptor `>= 3` is encrypted as follows ([fd_crypto.c](../security/pressure/fd_crypto.c#L48-L136)):

1. **Plaintext Construction (30 bits)**:
   - `priv_fd`: 14-bit random unused private `fdtable` index (`3 .. 16383`).
   - `nonce`: 16-bit CSPRNG non-zero integer (`1 .. 65535`), guaranteed `!= fdt->pg_slots[priv_fd].last_nonce` so closing and reopening the same underlying slot never re-emits the prior public descriptor.
   - `pt30 = (nonce << 14) | (priv_fd & 0x3fffU)`.
2. **Balanced 6-Round Feistel Bijection**:
   - Splits `pt30` into two 15-bit halves `(L, R)`.
   - Runs 6 Feistel rounds with `PRF(half15, round) = siphash_2u32(half15, round * 0x9e3779b9U, &files->pressure_fd_key) & 0x7fffU`.
   - Because `15 + 15 = 30`, the Feistel network is a **strict mathematical permutation** on `[0 .. 2^30 - 1]`: two distinct open slots can **never** collide on the same public FD.
   - Sets bit 30 (`pub_fd = 0x40000000 | cipher30`), yielding a random positive 31-bit integer in `[1073741824 .. 2147483647]`.
3. **Lockless RCU Verification (`pressure_vfs_decode_fd_rcu`)**:
   - Any descriptor `> 2` lacking `0x40000000`, decrypting to `priv_fd < 3` or `>= fdt->max_fds`, or whose `nonce != fdt->pg_slots[priv_fd].nonce` is rejected with `-EBADF` and flagged `is_forged = true`.

---

## 3. 3-Strike Audit Ring & Uncatchable `SIGKILL`

`pressure_record_violation()` ([fd_crypto.c](../security/pressure/fd_crypto.c#L234-L299)) atomically increments `pressure_task(tsk)->strikes`, appends a structured `pressure_audit_entry` to the 256-slot `audit_ring`, logs a rate-limited kernel notice, and—when `pressure_enforce == 1` and `strikes >= 3` (excluding PID 1 and `pressure-authd`)—delivers an uncatchable kernel `SIGKILL` (`force_sig(SIGKILL)` for `current`, `send_sig_info(SIGKILL, SEND_SIG_PRIV, tsk)` for remote target tasks).

### Violation Reason Codes (`enum pressure_violation_reason`)
| Code | Audit Name | Trigger Condition |
| :---: | :--- | :--- |
| 1 | `BAD_FD_TOKEN` | Sequential integer guess (`3, 4, 5...`), forged 31-bit token, or use-after-close replay. |
| 2 | `FORBIDDEN_DUP2` | Confined task calling `dup2`/`dup3` with fixed `newfd > 2`. |
| 3 | `UNAUTHORIZED_SETUID` | Calling `setuid`/`setreuid`/`setresuid`/`setgid` without a valid one-time `pressure-authd` ticket. |
| 4 | `AUTHD_VAULT_HARDSTOP` | Any process other than `pressure-authd` (even `uid=0`!) accessing `/etc/pressure/auth.vault` or `master.key`. |
| 5 | `USER_PRIVATE_DATA_HARDSTOP` | Accessing a `PRESSURE_FILE_USER_PRIVATE` file/dir without the owner's secret `kpriv_uid` (or while `REMOTE`). |
| 6 | `REMOTE_PROVENANCE_FD_BLOCK` | `REMOTE` task opening/reading/writing a `PRESSURE_FILE_LOCAL_ONLY` file or local `seat_tty`. |
| 7 | `DEV_PROVENANCE_HARDSTOP` | Unauthorized `/dev` open on `seat_input` (`/dev/input/*`, `/dev/uinput`), `storage_blk` (`/dev/sr0`, `/dev/vda`), or `net_ext`. |
| 8 | `SEAT_MAX_SESSIONS_LOCKED` | Exceeding `max_sessions` (default `1`) on `/dev/tty*` or accessing a TTY claimed by another session's `session_priv_id`. |
| 9 | `UNAUTHORIZED_MKNOD` | Confined/human/daemon/remote task attempting `mknod()` to create shadow `S_IFCHR`/`S_IFBLK` device nodes. |
| 10 | `DIRECT_IP_SOCKET_BLOCKED` | Calling `socket(AF_INET | AF_INET6 | AF_PACKET, ...)` directly instead of using the `AF_UNIX` `sfw` worker. |
| 11 | `REMOTE_EXEC_BLOCKED` | `REMOTE`-tainted task calling `execve()` without an explicit `PEV_EXEC` allow rule. |
| 12 | `REMOTE_WX_MMAP_BLOCKED` | Any `PROT_WRITE | PROT_EXEC` mapping, or executable anonymous `mmap`/`mprotect` by a `REMOTE` task. |
| 13 | `PROC_FD_ENUM_BLOCKED` | Confined or `REMOTE` task enumerating `/proc/<pid>/fd` or `/proc/<pid>/fdinfo`. |
| 14 | `SFW_FIREWALL_DROP` | `sfw` socket broker request denied by provenance, device label, UID, IP/CIDR, or port policy. |
| 15 | `POLICY_RULE_DENY` | Explicit `deny` match in the 6-tuple event policy table or unauthorized `setxattr("security.pressure")`. |

---

## 4. Secret Kernel UIDs (`kpriv_uid`), Tickets & Private Data Hard-Stops

1. **Registration (`pressure_register_user`)**: When `pressure-authd` registers an account (`pub_uid`, `pub_gid`, `human` or `daemon`, `label`), the kernel mints 64-bit random `kpriv_uid` and `kpriv_gid` secrets stored only inside `user_table` (`kpriv_uid=<SECRET>` in `/sys/kernel/security/pressure/users`).
2. **One-Time Transition Tickets (`pressure_issue_uid_ticket` / `pressure_consume_uid_ticket`)**:
   - On verified login or daemon start, `pressure-authd` writes `grant <pid> <pub_uid> <local|remote> <maj>:<min> <label>` to `auth_grant`.
   - The kernel validates TTY `max_sessions`, claims the device slot (`active_sessions++`, `owner_leader_pid = target_pid`, `owner_session_priv_id`), binds `local_seat_kpriv_id` if logging in locally on a seat TTY, and queues a 30-second one-time `pressure_uid_ticket` bound to `(target_pid, pub_uid)`.
   - When `target_pid` calls `setresuid(pub_uid, ...)`, `pressure_task_fix_setuid()` ([lsm_hooks.c](../security/pressure/lsm_hooks.c#L95-L162)) consumes the ticket, populates `ncb->kpriv_uid`, transitions `pressure_stage` from `PRELOGIN` to `POSTLOGIN` (on human local login), and activates 31-bit FD encryption!
   - Any `setuid()` without a matching ticket zeroes `ncb->kpriv_uid`, records `PVIO_UNAUTHORIZED_SETUID`, and returns `-EPERM`.
3. **Private Data Inheritance & Hard-Stops**:
   - `pressure_d_instantiate()` ([lsm_hooks.c](../security/pressure/lsm_hooks.c#L239-L274)) automatically propagates `PRESSURE_FILE_USER_PRIVATE`, `PRESSURE_FILE_LOCAL_ONLY`, `owner_pub_uid`, and `owner_kpriv_uid` from parent directories (`/home/alice`, `/var/lib/dbd`) to newly created files and subdirectories.
   - `pressure_check_inode_access()` ([ident_policy.c](../security/pressure/ident_policy.c#L617-L775)) compares `cb->kpriv_uid == ib->owner_kpriv_uid` directly—even `root` (`uid=0`) lacks Alice's or `dbd`'s `kpriv_uid` and is hard-stopped with `-EACCES`.

---

## 5. Universal `/dev` & `net_device` Confinement

- **Automatic Major/Minor Classification (`classify_default_dev`)**:
  - Block devices (`S_ISBLK`) & raw memory (`1:*` except safe pseudo minors `3,5,7,8,9,11`) $\rightarrow$ `PDEV_STORAGE_BLK` (`dev:storage_blk` / `dev:raw_mem`).
  - Safe pseudo nodes (`/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom`, `/dev/kmsg`) $\rightarrow$ `PDEV_PSEUDO_SAFE`.
  - Input peripherals (`13:*` `/dev/input/*`, `10:223` `/dev/uinput`) $\rightarrow$ `PDEV_SEAT_INPUT` (`max_sessions = 1`, requires `cb->seat_kpriv_id == local_seat_kpriv_id`).
  - Consoles & hardware/virtual TTYs (`4:*`, `5:1`) $\rightarrow$ `PDEV_SEAT_TTY` (`max_sessions = 1`, session-locked).
  - `/dev/net/tun` (`10:200`) $\rightarrow$ `PDEV_NET_EXT` (`REMOTE` provenance).
- **Network Interfaces (`pressure_netdev_notifier`)**:
  - Hooks `NETDEV_REGISTER` via `register_netdevice_notifier()`. Loopback (`lo`) gets `PDEV_NET_LO` (`LOCAL`); all external NICs (`eth0`, `veth*`, `wlan*`) get `PDEV_NET_EXT` (`REMOTE`) plus unique `dev_pub_id` / `dev_kpriv_id` pairs.
- **Automatic Session Cleanup (`pressure_task_free`)**:
  - When a session leader process exits for any reason, `pressure_task_free()` calls `pressure_release_leader_devices()` so claimed TTY `max_sessions` locks never leak.

---

## 6. `/sys/kernel/security/pressure/` Control & Reporting Files

Created in [securityfs.c](../security/pressure/securityfs.c#L504-L525):

| File | Mode | Who Can Access | Read / Write Format |
| :--- | :---: | :--- | :--- |
| `status` | `0444` | All | Key-value summary: `enforce`, `stage` (`PRELOGIN`/`POSTLOGIN`), `authd_pid`, `sfw_worker`, `policy_gen`, `txn_active`, `max_strikes`, `total_violations`, `total_sigkills`. |
| `txn` | `0200` | Local Admin | Write `begin`, `commit`, or `abort` for transactional `sure load` snapshot & rollback. |
| `enforce` | `0644` | Read: All; Write: Local Admin / `authd` | Write `0` or `1`. |
| `authd_register` | `0200` | Local Admin (one-time) | Grants `PRESSURE_ACCT_AUTHD` credential to `pressure-authd`; returns `-EBUSY` if another live PID holds it. |
| `users` | `0600` | Read: Admin/`authd`; Write: `authd` only | Write: `add <pub_uid> <pub_gid> <human\|daemon> <label>`. Read: lists users with `kpriv_uid=<SECRET>`. |
| `auth_grant` | `0200` | `authd` only | Write: `grant <pid> <pub_uid> <local\|remote> <maj>:<min> <label>` or `release_pid <pid>`. |
| `self_confine` | `0222` | Any process (monotonic confinement) | Write: `confine <local\|remote> <fd_crypto:0\|1> <label>`. |
| `label_path` | `0200` | Local Admin / `authd` | Write: `<flags_hex> <owner_pub_uid> <label> <path>` (pins kernel inode blob even on xattr-less ramfs). |
| `devices` | `0644` | Read: All; Write: Local Admin / `authd` | Write: `dev <maj:min> <label> <class> <local\|remote> <max_sess>` or `net <ifname> <label> <class> <local\|remote> <max_sess>`. |
| `policy` | `0600` | Local Admin | Write: `flush` or `<allow\|deny> <subj> <obj> <dev> <ev_hex> <max_prov>`. |
| `sfw_rules` | `0600` | Local Admin | Write: `flush`, IPv4 `<allow\|deny> <dir> <uid> <ip4> <mask4> <pmin> <pmax> <dev> <max_prov>`, or IPv6 `inet6 <allow\|deny> <dir> <uid> <ip6> <plen> <pmin> <pmax> <dev> <max_prov>`. |
| `audit` | `0400` | Local Admin / `authd` | Last 256 violation & `SIGKILL` records with boot-time millisecond timestamps. |
