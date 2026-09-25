#!/usr/bin/env bash
# QEMU boot tests for paguro.efi (INTERFACES.md §12, "QEMU").
#
#   test/qemu/run.sh [SCENARIO...]
#
# Builds the loader, signs a copy with the OVMF snakeoil key for the Secure
# Boot scenarios, and runs the Rust runner (test/qemu/runner), which builds
# ESP/GPT images, starts swtpm, boots OVMF and asserts on serial markers.
#
# Needs: qemu-system-x86, ovmf, swtpm, mtools, dosfstools, gdisk, sbsigntool;
# for the stage-4 scenarios also ntfs-3g (FUSE, run through `sudo -n` when
# not root), attr (setfattr), qemu-utils (qemu-img); for the aarch64 one
# qemu-system-arm and qemu-efi-aarch64 (skipped when missing).
# Uses KVM when /dev/kvm is usable, TCG otherwise (PAGURO_QEMU_ACCEL=tcg|kvm
# to force). Logs land in $PAGURO_QEMU_WORK (default target/qemu).
set -euo pipefail
cd "$(dirname "$0")/../.."

OVMF=${OVMF_DIR:-/usr/share/OVMF}
WORK=${PAGURO_QEMU_WORK:-target/qemu}
ACCEL=${PAGURO_QEMU_ACCEL:-auto}
KEYDIR=${OVMF_SNAKEOIL_DIR:-/usr/share/ovmf}

AAVMF=${AAVMF_DIR:-/usr/share/AAVMF}

cargo build --release -p paguro-efi -p paguro-probe --target x86_64-unknown-uefi
# Test-only: OVMF has no USB pointer driver; the pointer scenario boots
# this first (test/qemu/tablet-shim).
cargo build --release -p paguro-tablet-shim --target x86_64-unknown-uefi
cargo build --release -p paguro-qemu
# The BitLocker scenarios encrypt the stage-4 volume with make.sh.
cargo build --release -p paguro-harness --bin paguro-bde-write
EFI=target/x86_64-unknown-uefi/release/paguro.efi
PROBE=target/x86_64-unknown-uefi/release/probe.efi
SHIM=target/x86_64-unknown-uefi/release/tablet-shim.efi
mkdir -p "$WORK"

aa64=()
if command -v qemu-system-aarch64 >/dev/null && [ -r "$AAVMF/AAVMF_CODE.no-secboot.fd" ]; then
  cargo build --release -p paguro-efi -p paguro-probe --target aarch64-unknown-uefi
  aa64=(--efi-aa64 target/aarch64-unknown-uefi/release/paguro.efi
        --probe-aa64 target/aarch64-unknown-uefi/release/probe.efi --aavmf "$AAVMF")
else
  echo "qemu-system-aarch64 or AAVMF missing: the aarch64 scenario is skipped" >&2
fi

signed=()
if command -v sbsign >/dev/null && [ -r "$KEYDIR/PkKek-1-snakeoil.key" ]; then
  # Debian ships the snakeoil key encrypted with the passphrase "snakeoil".
  openssl pkey -in "$KEYDIR/PkKek-1-snakeoil.key" -passin pass:snakeoil \
    -out "$WORK/snakeoil.key"
  sbsign --key "$WORK/snakeoil.key" --cert "$KEYDIR/PkKek-1-snakeoil.pem" \
    --output "$WORK/paguro.signed.efi" "$EFI"
  sbsign --key "$WORK/snakeoil.key" --cert "$KEYDIR/PkKek-1-snakeoil.pem" \
    --output "$WORK/probe.signed.efi" "$PROBE"
  signed=(--efi-signed "$WORK/paguro.signed.efi" --probe-signed "$WORK/probe.signed.efi")
else
  echo "sbsign or snakeoil key missing: Secure Boot scenarios with a signed loader are skipped" >&2
fi

exec target/release/paguro-qemu --efi "$EFI" --probe "$PROBE" "${signed[@]}" "${aa64[@]}" \
  --tablet-shim "$SHIM" --ovmf "$OVMF" --work "$WORK" --accel "$ACCEL" "$@"
