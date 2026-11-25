# 06 — Build System, Initramfs, QEMU Harness & End-to-End Verification

All development, kernel compilation, module building, rootfs generation, and automated verification run out-of-tree without root privileges on the host.

---

## 1. Build Workflow

### 1.1 Kernel Configuration ([dev/kernel.config.fragment](../dev/kernel.config.fragment))
Merged atop `x86_64_defconfig` + `kvm_guest.config` into `build/.config`:
- **Disables Netfilter & SELinux**: `# CONFIG_NETFILTER is not set`, `# CONFIG_SECURITY_SELINUX is not set`.
- **Enables Pressure LSM**: `CONFIG_SECURITY_PRESSURE=y`, `CONFIG_SECURITYFS=y`, `CONFIG_LSM="landlock,lockdown,yama,loadpin,safesetid,pressure,bpf"`.
- **Enables Modules, Namespaces & Virtual Networking**: `CONFIG_MODULES=y`, `CONFIG_NET_NS=y`, `CONFIG_VETH=y`, `CONFIG_IPV6=y` (from `defconfig`).
- **Enables Xattrs, VirtIO-9p & Kernel Debugging**: `CONFIG_TMPFS_XATTR=y`, `CONFIG_EXT4_FS_SECURITY=y`, `CONFIG_9P_FS_SECURITY=y`, `CONFIG_DEBUG_INFO_DWARF5=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_GDB_SCRIPTS=y`.

### 1.2 Step-by-Step Build Commands
Run from the repository root:

```bash
# 1. Generate out-of-tree build/.config (first time or after editing fragment)
make -f dev/Makefile config

# 2. Compile patched Linux 7.3.5 bzImage, in-tree modules, and GDB scripts (uses .ccache/)
make -f dev/Makefile kernel

# 3. Compile dual-stack sfw.ko loadable kernel module and stage into dev/shared/
make -C modules/sfw

# 4. Build userspace and stage the SFW kernel module
make -C userspace
cp -f modules/sfw/sfw.ko dev/shared/sfw.ko

# 5. Pack build/initramfs.cpio.gz
make -f dev/Makefile initramfs
```

---

## 2. Initramfs & QEMU/KVM Testbed (`dev/mkinitramfs.sh`, `dev/run-qemu.sh`)

### 2.1 Initramfs Layout ([dev/mkinitramfs.sh](../dev/mkinitramfs.sh))
Builds a self-contained ~7.9 MiB `build/initramfs.cpio.gz` containing:
- BusyBox userland + `/usr/sbin/ip`, `setfattr`, `getfattr`, `capsh`, `keyctl`, `strace`.
- `pressure-authd`, `pressure-authctl`, `press`, `sure`, `sfw`, and `pressure_e2e_test` in `/usr/sbin/` along with their required `glibc`, `libcrypto`, and `libpam` shared libraries.
- `/lib/x86_64-linux-gnu/security/pam_pressure.so` and `/etc/pam.d/pressure-login`.
- `/lib/x86_64-linux-gnu/libpressureshim.so` (`LD_PRELOAD` interposer).
- Custom PID 1 `/init` mounting `proc`, `sysfs`, `devtmpfs`, `devpts`, XATTR-backed `tmpfs` (`/tmp`, `/run`, `/home`, `/var`, `/etc/pressure`), `securityfs` (`/sys/kernel/security`), and VirtIO-9p (`dev/shared` $\rightarrow$ `/mnt/host`). Because `/mnt/host` is live-shared via 9p, iterating on `sfw.ko`, userspace tools, or `.pr` policies on the host makes them immediately available in QEMU without rebuilding `bzImage`!

### 2.2 Running QEMU & Attaching GDB ([dev/run-qemu.sh](../dev/run-qemu.sh))
```bash
# Run full automated Pressure + Dual-Stack sfw + Policy Parser verification suite
./dev/run-qemu.sh --pressure-test

# Boot interactive VM console (Ctrl-A X to exit)
make -f dev/Makefile boot

# Debug kernel / LSM / sfw.ko with GDB:
# Terminal 1:
./dev/run-qemu.sh --gdb --freeze
# Terminal 2:
make -f dev/Makefile gdb
```

---

## 3. End-to-End Automated Verification Suite

Executed inside QEMU when `pressure_test=1` is passed on `/proc/cmdline` via [run_pressure_tests.sh](../userspace/tests/run_pressure_tests.sh) and [pressure_e2e_test.c](../userspace/tests/pressure_e2e_test.c):

| Stage | Test Target | What Is Asserted |
| :---: | :--- | :--- |
| **0** | LSM & Netfilter Check | `/sys/kernel/security/lsm` contains `pressure`; `/proc/sys/net/netfilter` does not exist. |
| **1** | Boot Services | `press boot-init`, `insmod sfw.ko` (`/run/pressure/sfw/mux.sock` live), `pressure-authd --daemon` (`authd_pid` registered), `press enforce on`. |
| **2** | Pre-Login Dual-Stack `sfw` + Shim | Stage is `PRELOGIN`; `127.0.0.1:19080` and `[::1]:19086` succeed via `libpressuresock`; `[::1]:19087` succeeds via `LD_PRELOAD=libpressureshim.so`; raw `socket(AF_INET)` & `socket(AF_INET6)` fail (`DIRECT_IP_SOCKET_BLOCKED`); unapproved WAN `10.99.0.1:4444` & `[2001:db8::99]:4444` fail (`SFW_FIREWALL_DROP`). |
| **2b** | Live IPv4 `FORWARD` + NAT44 | Across `lan_ns` (`10.10.1.2`) $\leftrightarrow$ router $\leftrightarrow$ `wan_ns` (`192.0.2.2` with no route to `10.10.1.0/24`): `sfw chain policy forward drop` blocks traffic; live `MASQUERADE` (`10.10.1.0/24` $\rightarrow$ `192.0.2.1`) and `DNAT` (`192.0.2.1:8088` $\rightarrow$ `10.10.1.2:9090`) succeed with `ESTABLISHED` conntrack entries. |
| **2c** | Live IPv6 `FORWARD` + NAT66 via `sure load` | Across `lan_ns` (`fd00:10::2`) $\leftrightarrow$ router $\leftrightarrow$ `wan_ns` (`fd00:20::2` with no route to `fd00:10::/64`): unapproved IPv6 TCP blocked while ICMPv6 NDP works; `sure load /tmp/live_ipv6_nat.pr` applies IPv6 rules; `NAT66 MASQUERADE` (`fd00:10::2` $\rightarrow$ `fd00:20::1`) and `NAT66 DNAT` (`[fd00:20::1]:8089` $\rightarrow$ `[fd00:10::2]:9091`) succeed. |
| **3–4** | `pressure-authd` & Vault Hard-Stop | Provisions `alice`, `bob`, `webd`, `dbd` with random `pub_uid >= 100000` and `!` in `/etc/shadow`; verifies `uid=0` outside `pressure-authd` is denied `/etc/pressure/auth.vault`. |
| **5** | PAM Login & Encrypted 31-bit FDs | `press login alice ... /dev/tty1` transitions stage to `POSTLOGIN`; 14 file/socket opens return non-monotonic collision-free `0x40000000+` tokens; `fcntl`, `dup`, close/reopen anti-replay, and `/proc/self/fd` block verified; post-login IPv4 & IPv6 `sfw` loopback verified. |
| **6** | Secret `kpriv_uid` Hard-Stops | Unauthenticated `root` (`uid=0`) and `bob` both denied `/home/alice/secret_budget.txt` and `/var/lib/dbd/records.db`; ticketless `setuid(ALICE_UID)` denied (`-EPERM`). |
| **7** | `/dev` Seat Exclusivity & Peripheral Guard | Second concurrent login on occupied `/dev/tty1` (`max_sessions=1`) rejected; `webd` daemon denied `/dev/input/event0`, `/dev/uinput`, `/dev/sr0`, `/dev/tty1`, and `mknod`. |
| **8** | `REMOTE` Containment | `REMOTE`-tainted `webd` worker denied `127.0.0.1` and `[::1]` via `sfw`, denied `PROT_WRITE\|PROT_EXEC` `mmap`, and denied `execve("/bin/sh")`. |
| **9–10** | 3-Strike Audit + `SIGKILL` | Forged FD probes `1` & `2` return `-EBADF`; strike `3` (`0x5abc9876`) triggers immediate uncatchable kernel `SIGKILL` (`WTERMSIG == SIGKILL`) and appears in `sure report`. |

---

## 4. Exporting a Standalone Kernel Patch

To generate a clean `git diff` against the pristine upstream `v7.3.5` tag:

```bash
# Kernel-only patch (excludes dev/ harness)
make -f dev/Makefile patch > ../pressure-linux-7.3.5.patch

# Full patch including dev/, modules/sfw/, userspace/, and docs/
git diff v7.3.5..HEAD > ../pressure-full-suite-7.3.5.patch
```
