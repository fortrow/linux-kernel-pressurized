# Helper Makefile for Patched Kernel + Modules + LSM + Userspace Development
# Usage from repo root: make -f dev/Makefile <target>

KDIR       := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
BUILD_DIR  ?= $(KDIR)/build
CCACHE_DIR ?= $(KDIR)/.ccache
JOBS       ?= $(shell nproc)

export CCACHE_DIR

.PHONY: help config menuconfig kernel modules initramfs all boot smoke-test gdb patch clean

help:
	@echo "Kernel Dev Harness Targets (make -f dev/Makefile <target>):"
	@echo "  config      Generate out-of-tree build/.config (defconfig + kvm_guest + dev fragment)"
	@echo "  menuconfig  Open interactive Kconfig menu on build/.config"
	@echo "  kernel      Compile bzImage, modules, and GDB scripts into build/ (uses ccache)"
	@echo "  initramfs   Build busybox + glibc + xattr/cap tools initramfs (build/initramfs.cpio.gz)"
	@echo "  all         Run config (if needed) + kernel + initramfs"
	@echo "  boot        Boot custom kernel interactively in QEMU/KVM (shares dev/shared -> /mnt/host)"
	@echo "  smoke-test  Boot custom kernel headlessly, verify LSMs & 9p share, and power off"
	@echo "  gdb         Attach GDB with vmlinux & kernel GDB scripts to QEMU (:1234)"
	@echo "  patch       Show clean kernel git diff against pristine v7.3.5 tag"
	@echo "  clean       Remove out-of-tree build/ artifacts"

config:
	@mkdir -p "$(BUILD_DIR)" "$(CCACHE_DIR)"
	$(MAKE) -C "$(KDIR)" O="$(BUILD_DIR)" x86_64_defconfig kvm_guest.config
	cd "$(KDIR)" && ./scripts/kconfig/merge_config.sh -m -O "$(BUILD_DIR)" \
		"$(BUILD_DIR)/.config" "$(KDIR)/dev/kernel.config.fragment"
	$(MAKE) -C "$(KDIR)" O="$(BUILD_DIR)" olddefconfig

$(BUILD_DIR)/.config:
	$(MAKE) -f "$(KDIR)/dev/Makefile" config

menuconfig: $(BUILD_DIR)/.config
	$(MAKE) -C "$(KDIR)" O="$(BUILD_DIR)" menuconfig

kernel: $(BUILD_DIR)/.config
	@mkdir -p "$(CCACHE_DIR)"
	$(MAKE) -C "$(KDIR)" O="$(BUILD_DIR)" CC="ccache gcc" -j"$(JOBS)" bzImage modules scripts_gdb

initramfs:
	"$(KDIR)/dev/mkinitramfs.sh"

all: kernel initramfs

boot:
	"$(KDIR)/dev/run-qemu.sh"

smoke-test:
	"$(KDIR)/dev/run-qemu.sh" --smoke-test

gdb:
	gdb "$(BUILD_DIR)/vmlinux" \
		-iex "add-auto-load-safe-path $(BUILD_DIR)" \
		-ex "target remote :1234"

patch:
	git -C "$(KDIR)" diff v7.3.5 -- . ':!dev'

clean:
	rm -rf "$(BUILD_DIR)"
