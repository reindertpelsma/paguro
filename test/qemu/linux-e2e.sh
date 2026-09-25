#!/usr/bin/env bash
# Linux end to end through paguro (DESIGN.md §3a): OVMF -> paguro.efi ->
# the UKI inside the image (or on NTFS) -> paguro-initrd -> the root from
# view A -> a marker service that checks the result and powers off.
#
#   test/qemu/linux-e2e.sh [SCENARIO...]        (default: linux-*)
#
# Environment:
#   PAGURO_KERNEL   the VM kernel (an EFI-stub bzImage)  [/boot/vmlinuz-$(uname -r)]
#   PAGURO_MODULES  its module tree                       [/lib/modules/<ver>]
#   PAGURO_KDIR     its headers, to build the modules     [$PAGURO_MODULES/build]
#   PAGURO_STUB     systemd-stub (linuxx64.efi.stub)      [fetched: systemd-boot-efi]
#   PAGURO_LINUX_CACHE  downloads (rootfs, stub)          [target/linux-cache]
#   PAGURO_QEMU_WORK    images and serial logs            [target/qemu]
#
# The root is Alpine's minirootfs (pinned, checksummed, cached) with a
# busybox-init marker service; the kernel is whatever the caller gives
# (CI: Ubuntu's generic HWE kernel, unpacked, never installed). Nothing is
# loaded into the host kernel.
#
# Needs: everything test/qemu/run.sh needs, plus cargo's
# x86_64-unknown-linux-musl target, e2fsprogs (mkfs.ext4 -d, e2fsck),
# binutils (objcopy), cpio, zstd/xz for compressed modules, curl.
set -euo pipefail
cd "$(dirname "$0")/../.."

kernel=${PAGURO_KERNEL:-/boot/vmlinuz-$(uname -r)}
moddir=${PAGURO_MODULES:-/lib/modules/$(uname -r)}
kdir=${PAGURO_KDIR:-$moddir/build}
cache=${PAGURO_LINUX_CACHE:-target/linux-cache}
work=${PAGURO_QEMU_WORK:-target/qemu}
out=$work/linux
kver=$(basename "$moddir")
mkdir -p "$cache" "$out"
cache=$(cd "$cache" && pwd)

ALPINE_VER=3.22.6
ALPINE_SHA=27694aaa55fd7a9e3ef596e0ad4eb66802308bb20172b17030cd5f4d8ae9bac2
rootfs_tgz=$cache/alpine-minirootfs-$ALPINE_VER-x86_64.tar.gz
if [ ! -s "$rootfs_tgz" ]; then
  curl -fsSL -o "$rootfs_tgz.part" \
    "https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VER%.*}/releases/x86_64/alpine-minirootfs-$ALPINE_VER-x86_64.tar.gz"
  mv "$rootfs_tgz.part" "$rootfs_tgz"
fi
echo "$ALPINE_SHA  $rootfs_tgz" | sha256sum -c --quiet

stub=${PAGURO_STUB:-}
if [ -z "$stub" ]; then
  stub=$cache/sbe/usr/lib/systemd/boot/efi/linuxx64.efi.stub
  if [ ! -s "$stub" ]; then
    (cd "$cache" && apt-get download systemd-boot-efi >/dev/null && dpkg -x systemd-boot-efi_*.deb sbe)
  fi
fi
[ -s "$stub" ] || { echo "no systemd-stub at $stub" >&2; exit 1; }

# --- builds --------------------------------------------------------------
make -s -C kernel/dm-paguro KDIR="$kdir"
make -s -C kernel/paguro-handoff KDIR="$kdir"
cargo build -q --release -p paguro-initrd --target x86_64-unknown-linux-musl
cargo build -q --release -p paguro-efi --target x86_64-unknown-uefi
cargo build -q --release -p paguro-qemu
cargo build -q --release -p paguro-harness --bin paguro-bde-write
initrd_bin=target/x86_64-unknown-linux-musl/release/paguro-initrd

# --- the test initramfs --------------------------------------------------
r=$out/initramfs
rm -rf "$r"
mkdir -p "$r"/{bin,sbin,proc,sys,dev,run,root,lib/paguro}
cp "$(command -v busybox)" "$r/bin/busybox"
file -L "$r/bin/busybox" | grep -q 'statically linked' ||
  { echo "busybox must be static (busybox-static)" >&2; exit 1; }
for a in sh mount umount insmod rmmod cat echo mkdir grep tail dmesg poweroff \
         sleep switch_root ls; do
  ln -s busybox "$r/bin/$a"
done
cp "$initrd_bin" "$r/bin/paguro-initrd"
cp test/qemu/linux/init "$r/init"
cp kernel/dm-paguro/dm-paguro.ko kernel/paguro-handoff/paguro-handoff.ko "$r/lib/paguro/"

# Modules and their dependencies, uncompressed, dependencies first; built-in
# or missing ones are skipped. An unpacked tree has no modules.dep: make one.
if [ ! -e "$moddir/modules.dep" ]; then
  depmod -b "$(cd "$moddir/../../.." && pwd)" "$kver"
fi
: > "$r/lib/paguro/order"
add_mod() {
  local rel=$1 line file d name
  line=$(grep -E "^$rel\.ko(\.zst|\.xz|\.gz)?:" "$moddir/modules.dep" | head -1) || true
  [ -n "$line" ] || return 0
  file=${line%%:*}
  for d in ${line#*:}; do add_mod "${d%.ko*}"; done
  name=$(basename "${file%.ko*}")
  grep -qx "$name" "$r/lib/paguro/order" && return 0
  case $file in
    *.zst) zstd -qdc "$moddir/$file" > "$r/lib/paguro/$name.ko" ;;
    *.xz)  xz -dc "$moddir/$file" > "$r/lib/paguro/$name.ko" ;;
    *.gz)  gzip -dc "$moddir/$file" > "$r/lib/paguro/$name.ko" ;;
    *)     cp "$moddir/$file" "$r/lib/paguro/$name.ko" ;;
  esac
  echo "$name" >> "$r/lib/paguro/order"
}
for m in drivers/md/dm-mod drivers/md/dm-crypt drivers/md/dm-zero fs/ntfs3/ntfs3 \
         drivers/block/virtio_blk drivers/virtio/virtio_pci fs/ext4/ext4 \
         fs/fat/vfat fs/nls/nls_cp437 fs/nls/nls_iso8859-1 fs/efivarfs/efivarfs \
         arch/x86/crypto/aesni-intel crypto/xts; do
  add_mod "kernel/$m"
done
(cd "$r" && find . | LC_ALL=C sort | cpio -o -H newc --quiet | gzip -1) > "$out/initramfs.img"

# --- the UKI: systemd-stub + kernel + initramfs + command line -----------
printf 'NAME="paguro test"\nID=paguro-test\n' > "$out/os-release"
printf 'console=ttyS0,115200 panic=-1 loglevel=4 rw' > "$out/cmdline"
align=$(( 0x$(objdump -p "$stub" | awk '$1 == "SectionAlignment" { print $2 }') ))
end=$(objdump -h "$stub" | awk 'NF == 7 && $1 ~ /^[0-9]+$/ { print $3, $4 }' |
      while read -r size vma; do echo $(( 0x$vma + 0x$size )); done | sort -n | tail -1)
args=()
at=$end
for s in osrel:"$out/os-release" cmdline:"$out/cmdline" linux:"$kernel" initrd:"$out/initramfs.img"; do
  name=${s%%:*} file=${s#*:}
  at=$(( (at + align - 1) / align * align ))
  args+=(--add-section ".$name=$file" --change-section-vma ".$name=$(printf 0x%x "$at")")
  at=$(( at + $(stat -Lc %s "$file") ))
done
objcopy "${args[@]}" "$stub" "$out/uki.efi"

# --- the root: Alpine minirootfs + the marker service --------------------
rf=$out/rootfs
rm -rf "$rf"
mkdir -p "$rf"
tar -xzf "$rootfs_tgz" -C "$rf" --no-same-owner 2>/dev/null
cp test/qemu/linux/marker.sh "$rf/etc/paguro-marker.sh"
printf '::sysinit:/etc/paguro-marker.sh\n' > "$rf/etc/inittab"
mkdir -p "$rf/usr/sbin" "$rf/lib/modules/$kver/extra"
cp "$initrd_bin" "$rf/usr/sbin/paguro-initrd"
cp kernel/paguro-handoff/paguro-handoff.ko "$rf/lib/modules/$kver/extra/"
echo "kernel $kver, UKI $(stat -c %s "$out/uki.efi") bytes"

# --- run -------------------------------------------------------------------
[ $# -gt 0 ] || set -- 'linux-*'
exec target/release/paguro-qemu --efi target/x86_64-unknown-uefi/release/paguro.efi \
  --ovmf "${OVMF_DIR:-/usr/share/OVMF}" --work "$work" --accel "${PAGURO_QEMU_ACCEL:-auto}" \
  --linux "$out" "$@"
