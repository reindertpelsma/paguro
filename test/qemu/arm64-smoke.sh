#!/bin/sh
# Boot paguro.efi for aarch64 under AAVMF (qemu-system-aarch64 -M virt) and
# check it starts and runs its first stage. The full scenario runner
# (test/qemu/runner) is x86_64-only for now; this keeps the arm64 build honest.
#
# Needs: qemu-system-arm, qemu-efi-aarch64, mtools, dosfstools.
set -eu
cd "$(dirname "$0")/../.."
AAVMF=${AAVMF_DIR:-/usr/share/AAVMF}
cargo build --release -p paguro-efi --target aarch64-unknown-uefi
work=target/qemu-arm64
rm -rf "$work"; mkdir -p "$work"
# AAVMF pflash images must be exactly 64 MiB.
cp "$AAVMF/AAVMF_CODE.no-secboot.fd" "$work/code.fd"
cp "$AAVMF/AAVMF_VARS.fd" "$work/vars.fd"
truncate -s 64M "$work/code.fd" "$work/vars.fd"
esp=$work/esp.img
truncate -s 64M "$esp"
mkfs.vfat -F 32 -n ESP "$esp" >/dev/null
mmd -i "$esp" ::/EFI ::/EFI/BOOT
mcopy -i "$esp" target/aarch64-unknown-uefi/release/paguro.efi ::/EFI/BOOT/BOOTAA64.EFI
timeout 300 qemu-system-aarch64 -M virt -cpu cortex-a72 -m 512 \
    -display none -serial "file:$work/serial.log" -no-reboot -net none \
    -drive if=pflash,format=raw,readonly=on,file="$work/code.fd" \
    -drive if=pflash,format=raw,file="$work/vars.fd" \
    -drive if=none,id=esp,format=raw,file="$esp" \
    -device virtio-blk-pci,drive=esp -device virtio-rng-pci &
qpid=$!
for _ in $(seq 1 280); do
    if grep -aq -e "paguro: outcome" -e "candidate volume" "$work/serial.log" 2>/dev/null; then
        break
    fi
    sleep 1
done
kill $qpid 2>/dev/null || true
wait $qpid 2>/dev/null || true
tr -d '\r' < "$work/serial.log" | grep -a "paguro" | head -20
grep -aq "stage1 no-config" "$work/serial.log" || { echo "FAIL: loader did not run stage 1"; exit 1; }
grep -aq "Halted(Rng)" "$work/serial.log" && { echo "FAIL: no EFI_RNG_PROTOCOL"; exit 1; }
echo "PASS: arm64 loader boots and runs stage 1"
