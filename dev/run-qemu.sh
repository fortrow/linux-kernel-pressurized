#!/usr/bin/env bash
set -euo pipefail

KDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-${KDIR}/build}"
BZIMAGE="${BUILD_DIR}/arch/x86/boot/bzImage"
INITRAMFS="${BUILD_DIR}/initramfs.cpio.gz"
SHARED_DIR="${KDIR}/dev/shared"

SMOKE_TEST=0
PRESSURE_TEST=0
GDB_MODE=0
EXTRA_CMDLINE="${CMDLINE:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --smoke-test)
            SMOKE_TEST=1
            shift
            ;;
        --pressure-test)
            PRESSURE_TEST=1
            shift
            ;;
        --gdb)
            GDB_MODE=1
            shift
            ;;
        *)
            EXTRA_CMDLINE="${EXTRA_CMDLINE} $1"
            shift
            ;;
    esac
done

if [[ ! -f "${BZIMAGE}" ]]; then
    echo "Error: Kernel image not found at ${BZIMAGE}. Run 'make -f dev/Makefile kernel' first." >&2
    exit 1
fi

if [[ ! -f "${INITRAMFS}" ]]; then
    echo "Initramfs not found; building now..."
    "${KDIR}/dev/mkinitramfs.sh"
fi

mkdir -p "${SHARED_DIR}"

QEMU_ARGS=(
    -kernel "${BZIMAGE}"
    -initrd "${INITRAMFS}"
    -m "${MEMORY:-1024M}"
    -smp "${SMP:-2}"
    -nographic
    -no-reboot
    -virtfs "local,path=${SHARED_DIR},mount_tag=hostshare,security_model=mapped-xattr,id=hostshare"
)

if [[ -r /dev/kvm && -w /dev/kvm ]]; then
    QEMU_ARGS+=(-enable-kvm -cpu host)
else
    echo "Note: /dev/kvm not accessible in current environment; falling back to QEMU TCG emulation."
    QEMU_ARGS+=(-cpu max)
fi

KERNEL_CMDLINE="console=ttyS0 earlyprintk=serial,ttyS0,115200"

if [[ "${GDB_MODE}" -eq 1 ]]; then
    KERNEL_CMDLINE="${KERNEL_CMDLINE} nokaslr"
    QEMU_ARGS+=(-s -S)
fi

if [[ "${PRESSURE_TEST}" -eq 1 ]]; then
    KERNEL_CMDLINE="${KERNEL_CMDLINE} pressure_test=1 panic=-1"
    LOG_FILE="${BUILD_DIR}/pressure-test.log"
    qemu-system-x86_64 "${QEMU_ARGS[@]}" -append "${KERNEL_CMDLINE} ${EXTRA_CMDLINE}" | tee "${LOG_FILE}"
    if grep -q "PRESSURE_SUITE_OK" "${LOG_FILE}"; then
        echo "[pressure-test] SUCCESS: All Pressure LSM, authd, random FD, /dev, 3-strike SIGKILL & sfw tests passed!"
        exit 0
    else
        echo "[pressure-test] FAILED: Check ${LOG_FILE}" >&2
        exit 1
    fi
fi

if [[ "${SMOKE_TEST}" -eq 1 ]]; then
    KERNEL_CMDLINE="${KERNEL_CMDLINE} autotest=1 panic=-1"
    LOG_FILE="${BUILD_DIR}/smoke-test.log"
    qemu-system-x86_64 "${QEMU_ARGS[@]}" -append "${KERNEL_CMDLINE} ${EXTRA_CMDLINE}" | tee "${LOG_FILE}"
    if grep -q "AUTOTEST_PASS" "${LOG_FILE}"; then
        echo "[smoke-test] SUCCESS: Custom kernel booted, verified LSM & 9p share, and shut down cleanly."
        exit 0
    else
        echo "[smoke-test] FAILED: Did not observe AUTOTEST_PASS in ${LOG_FILE}." >&2
        exit 1
    fi
fi

exec qemu-system-x86_64 "${QEMU_ARGS[@]}" -append "${KERNEL_CMDLINE} ${EXTRA_CMDLINE}"
