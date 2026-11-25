# Linux 7.3.5 Custom Kernel, Module, LSM & Userspace Harness

## Directory Layout
- `/` — Kernel source tree tracked on branch `custom-kernel` against tag `v7.3.5` (pristine upstream baseline).
- `build/` — Out-of-tree Kbuild output (`bzImage`, `vmlinux`, modules, `initramfs.cpio.gz`). Ignored via `.git/info/exclude`.
- `dev/` — Build & QEMU/KVM development harness:
  - `Makefile` — One-command build, initramfs, boot, smoke-test, GDB, and patch export targets.
  - `kernel.config.fragment` — Kconfig fragment enabling LSMs, `securityfs`, xattrs, BTF, DWARF5, GDB scripts, VirtIO-9p, and trimming slow bare-metal drivers.
  - `mkinitramfs.sh` — Builds a fast `busybox` + `glibc` + `attr`/`libcap`/`keyctl`/`strace` initramfs with root (`uid 0`) and `tester` (`uid 1000`) accounts.
  - `run-qemu.sh` — Boots the kernel in QEMU (KVM hardware acceleration with automatic TCG fallback), mounting `dev/shared/` at `/mnt/host`.
  - `shared/` — Host-shared folder automatically mounted at `/mnt/host` inside the VM for instant testing of `.ko` modules and userspace binaries without rebuilding `initramfs`.

## Quick Commands
```bash
# Configure, compile kernel + modules, and pack initramfs
make -f dev/Makefile all

# Run automated headless QEMU boot + LSM/9p smoke test
make -f dev/Makefile smoke-test

# Boot interactive VM shell (Ctrl-A X to exit QEMU, or run 'poweroff -f')
make -f dev/Makefile boot

# Debug kernel with GDB (Terminal 1: start paused VM, Terminal 2: attach GDB)
./dev/run-qemu.sh --gdb
make -f dev/Makefile gdb

# Export pure kernel patch against upstream v7.3.5
make -f dev/Makefile patch > ../custom-kernel.patch
```
