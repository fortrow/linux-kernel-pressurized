#!/usr/bin/env bash
set -euo pipefail

KDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-${KDIR}/build}"
STAGE_DIR="${BUILD_DIR}/initramfs_root"
OUT_INITRAMFS="${BUILD_DIR}/initramfs.cpio.gz"
SHARED_DIR="${KDIR}/dev/shared"

mkdir -p "${BUILD_DIR}" "${SHARED_DIR}"
rm -rf "${STAGE_DIR}"
mkdir -p "${STAGE_DIR}"/{bin,sbin,usr/bin,usr/sbin,etc/pam.d,etc/pressure,proc,sys,dev,tmp,run,root,home,var/lib,mnt/host,lib,lib64,lib/x86_64-linux-gnu/security}
chmod 1777 "${STAGE_DIR}/tmp"

# 1. Install static busybox and populate applet symlinks
cp /bin/busybox "${STAGE_DIR}/bin/busybox"
chmod +x "${STAGE_DIR}/bin/busybox"
for applet in $(/bin/busybox --list); do
    if [[ ! -e "${STAGE_DIR}/bin/${applet}" ]]; then
        ln -s busybox "${STAGE_DIR}/bin/${applet}"
    fi
done

# 2. Copy glibc + PAM + OpenSSL libcrypto + LSM tools and their shared libraries
copy_bin_with_libs() {
    local bin_path="$1"
    local dest_dir="$2"
    [[ -f "${bin_path}" ]] || return 0
    mkdir -p "${STAGE_DIR}${dest_dir}"
    cp -L "${bin_path}" "${STAGE_DIR}${dest_dir}/"
    ldd "${bin_path}" 2>/dev/null | awk '/=> \// {print $3} /^[[:space:]]*\// {print $1}' | while read -r lib; do
        [[ -f "${lib}" ]] || continue
        local lib_dir
        lib_dir="$(dirname "${lib}")"
        mkdir -p "${STAGE_DIR}${lib_dir}"
        cp -Ln "${lib}" "${STAGE_DIR}${lib}" 2>/dev/null || true
    done
}

for tool in /usr/bin/setfattr /usr/bin/getfattr /usr/bin/keyctl /usr/bin/strace; do
    copy_bin_with_libs "${tool}" "/usr/bin"
done
for stool in /usr/sbin/capsh /usr/sbin/getcap /usr/sbin/setcap /usr/sbin/getpcaps /usr/sbin/ip; do
    copy_bin_with_libs "${stool}" "/usr/sbin"
done

# Copy Pressure userspace binaries & PAM module if built in dev/shared
for pbin in pressure-authd pressure-authctl press sure sfw pressure_e2e_test; do
    if [[ -x "${SHARED_DIR}/${pbin}" ]]; then
        copy_bin_with_libs "${SHARED_DIR}/${pbin}" "/usr/sbin"
    fi
done
if [[ -f "${SHARED_DIR}/pam_pressure.so" ]]; then
    copy_bin_with_libs "${SHARED_DIR}/pam_pressure.so" "/lib/x86_64-linux-gnu/security"
fi
if [[ -f "${SHARED_DIR}/libpressureshim.so" ]]; then
    copy_bin_with_libs "${SHARED_DIR}/libpressureshim.so" "/lib/x86_64-linux-gnu"
fi
if [[ -d "${SHARED_DIR}/policies" ]]; then
    mkdir -p "${STAGE_DIR}/usr/share/pressure/policies"
    cp -f "${SHARED_DIR}/policies/"*.pr "${STAGE_DIR}/usr/share/pressure/policies/" 2>/dev/null || true
fi

for extra_lib in /lib/x86_64-linux-gnu/lib{attr,cap,mnl,nl-3,nl-genl-3,seccomp,keyutils,pam,crypto,dl,pthread}.so*; do
    if [[ -e "${extra_lib}" ]]; then
        cp -a "${extra_lib}" "${STAGE_DIR}/lib/x86_64-linux-gnu/" 2>/dev/null || true
    fi
done

# Install the Pressure PAM service for the guest.
install -m 0644 "${KDIR}/userspace/pam/pressure-login" "${STAGE_DIR}/etc/pam.d/pressure-login"

cat > "${STAGE_DIR}/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/sh
EOF

cat > "${STAGE_DIR}/etc/group" <<'EOF'
root:x:0:
EOF

cat > "${STAGE_DIR}/etc/shadow" <<'EOF'
root:!:19000:0:99999:7:::
EOF
chmod 600 "${STAGE_DIR}/etc/shadow"

# 4. Install compiled in-tree kernel modules if present
if [[ -f "${BUILD_DIR}/modules.order" ]]; then
    make -s -C "${KDIR}" O="${BUILD_DIR}" INSTALL_MOD_PATH="${STAGE_DIR}" modules_install
fi

# 5. Create PID 1 /init script
cat > "${STAGE_DIR}/init" <<'EOF'
#!/bin/sh
export PATH=/mnt/host:/usr/sbin:/usr/bin:/sbin:/bin

mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
mkdir -p /dev/pts /dev/shm /dev/input
mount -t devpts none /dev/pts
mount -t tmpfs -o mode=1777 none /tmp
mount -t tmpfs -o mode=0755 none /run
mount -t tmpfs -o mode=0755 none /home
mount -t tmpfs -o mode=0755 none /var
mkdir -p /var/lib /etc/pressure
mount -t tmpfs -o mode=0700 none /etc/pressure
mount -t securityfs none /sys/kernel/security 2>/dev/null || true
mount -t debugfs none /sys/kernel/debug 2>/dev/null || true

# Mount host shared directory (dev/shared -> /mnt/host) via VirtIO 9p
mount -t 9p -o trans=virtio,version=9p2000.L hostshare /mnt/host 2>/dev/null || true

hostname pressure-vm
ifconfig lo 127.0.0.1 up 2>/dev/null || true
echo 7 4 1 7 > /proc/sys/kernel/printk

echo ""
echo "============================================================"
echo " Pressure Patched Linux Kernel VM"
echo " Kernel : $(uname -sr)"
if [ -f /sys/kernel/security/lsm ]; then
    echo " LSMs   : $(cat /sys/kernel/security/lsm)"
fi
if grep -q ' /mnt/host ' /proc/mounts; then
    echo " Share  : /mnt/host (mapped to host dev/shared/)"
fi
echo "============================================================"
echo ""

if grep -q 'pressure_test=1' /proc/cmdline; then
    if /bin/sh /mnt/host/run_pressure_tests.sh; then
        echo "PRESSURE_SUITE_OK"
    else
        echo "PRESSURE_SUITE_FAIL"
    fi
    poweroff -f
    exit 0
fi

if grep -q 'autotest=1' /proc/cmdline; then
    uname -a
    [ -f /sys/kernel/security/lsm ] && echo "[autotest] Active LSMs: $(cat /sys/kernel/security/lsm)"
    grep -q ' /mnt/host ' /proc/mounts && echo "[autotest] 9p hostshare mounted at /mnt/host"
    echo "AUTOTEST_PASS"
    poweroff -f
    exit 0
fi

cd /root
exec setsid cttyhack /bin/sh
EOF
chmod +x "${STAGE_DIR}/init"

# 6. Pack cpio.gz archive with root ownership (--owner=0:0)
(
    cd "${STAGE_DIR}"
    find . -print0 | cpio --null -o --format=newc --owner=0:0 --quiet | gzip -1 > "${OUT_INITRAMFS}"
)

echo "Built initramfs: ${OUT_INITRAMFS} ($(du -h "${OUT_INITRAMFS}" | cut -f1))"
