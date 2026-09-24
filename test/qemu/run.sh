#!/usr/bin/env bash
# QEMU boot tests for paguro.efi (INTERFACES.md §12, "QEMU").
#
#   test/qemu/run.sh [SCENARIO...]
#
# Builds the loader, signs a copy with the OVMF snakeoil key for the Secure
# Boot scenarios, and runs the Rust runner (test/qemu/runner), which builds
# ESP/GPT images, starts swtpm, boots OVMF and asserts on serial markers.
#
# Needs: qemu-system-x86, ovmf, swtpm, mtools, dosfstools, gdisk, sbsigntool.
# Uses KVM when /dev/kvm is usable, TCG otherwise (PAGURO_QEMU_ACCEL=tcg|kvm
# to force). Logs land in $PAGURO_QEMU_WORK (default target/qemu).
set -euo pipefail
cd "$(dirname "$0")/../.."

OVMF=${OVMF_DIR:-/usr/share/OVMF}
WORK=${PAGURO_QEMU_WORK:-target/qemu}
ACCEL=${PAGURO_QEMU_ACCEL:-auto}
KEYDIR=${OVMF_SNAKEOIL_DIR:-/usr/share/ovmf}

cargo build --release -p paguro-efi --target x86_64-unknown-uefi
cargo build --release -p paguro-qemu
EFI=target/x86_64-unknown-uefi/release/paguro.efi
mkdir -p "$WORK"

signed=()
if command -v sbsign >/dev/null && [ -r "$KEYDIR/PkKek-1-snakeoil.key" ]; then
  # Debian ships the snakeoil key encrypted with the passphrase "snakeoil".
  openssl pkey -in "$KEYDIR/PkKek-1-snakeoil.key" -passin pass:snakeoil \
    -out "$WORK/snakeoil.key"
  sbsign --key "$WORK/snakeoil.key" --cert "$KEYDIR/PkKek-1-snakeoil.pem" \
    --output "$WORK/paguro.signed.efi" "$EFI"
  signed=(--efi-signed "$WORK/paguro.signed.efi")
else
  echo "sbsign or snakeoil key missing: Secure Boot scenarios with a signed loader are skipped" >&2
fi

exec target/release/paguro-qemu --efi "$EFI" "${signed[@]}" --ovmf "$OVMF" \
  --work "$WORK" --accel "$ACCEL" "$@"
