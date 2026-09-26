#!/bin/sh
# Load dm-paguro in a throwaway QEMU VM and prove the module-level semantics
# `crates/paguro-linux::image` (attach/detach/grow) relies on: view A reads
# exactly what ntfs3 itself reads off the claimed file; detach is refused
# while the device is held open and allowed once it is not, and the claim is
# gone from PG_STATUS afterwards; growth is accepted only when it is an
# append (and needs a fresh cross-check before the grown table can load,
# INTERFACES.md §10.1a), and refused — read-only — for a relocation
# (simulated the same way `kernel/dm-paguro/test/vm-test.body` does: a
# truncate is "growth" in file size but not an append). Windows is stood in
# for by writing through view C with ntfs3 read-write, exactly as
# `image::grow`'s own doc comment says to for this test.
#
# Never loads anything into the host kernel
# (kernel/dm-paguro/test/vm-test.sh's pattern: everything happens inside the
# throwaway VM this script boots).
#
#   test/vm/lifecycle.sh [KERNEL_IMAGE] [MODULE_DIR]
#
# Needs the same things kernel/dm-paguro/test/vm-test.sh does: qemu-system-x86_64
# (KVM if available, else TCG), static busybox, dmsetup, coreutils dd,
# util-linux losetup, cpio, gzip, and a built kernel/dm-paguro/tools/pgctl
# (static) and kernel/dm-paguro/dm-paguro.ko (`make -C kernel/dm-paguro &&
# make -C kernel/dm-paguro/tools pgctl`).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
top=$(cd "$here/../.." && pwd)
fix=$top/test/fixtures/ntfs
kver=$(uname -r)
kernel=${1:-/boot/vmlinuz-$kver}
moddir=${2:-/lib/modules/$kver}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
r=$work/root
# shellcheck source=/dev/null
. "$top/kernel/dm-paguro/test/vm-lib.sh"
vm_root "$r"
[ -e "$top/kernel/dm-paguro/dm-paguro.ko" ] ||
    { echo "lifecycle.sh: build the module first: make -C kernel/dm-paguro" >&2; exit 2; }
[ -x "$top/kernel/dm-paguro/tools/pgctl" ] ||
    { echo "lifecycle.sh: build pgctl first: make -C kernel/dm-paguro/tools pgctl" >&2; exit 2; }
cp "$top/kernel/dm-paguro/dm-paguro.ko" "$r/"
cp "$top/kernel/dm-paguro/tools/pgctl" "$r/bin/"
vm_modules "$moddir" drivers/md/dm-mod drivers/block/loop fs/ntfs3/ntfs3 \
    fs/fat/vfat fs/nls/nls_cp437 fs/nls/nls_iso8859-1

# The fixture, and the identities from its manifest (kernel/dm-paguro/test/vm-test.sh's
# own awk: ID_<image>_<file>="<mft-record> <mft-seq>").
gzip -dc "$fix/vol512.img.gz" > "$r/fx/vol512.img"
awk '$1 == "file" && NF == 6 && $2 !~ /^(f_|r_)/ {
         n = $3 "_" $2; gsub(/[^A-Za-z0-9]/, "_", n); print "ID_" n "=\"" $4 " " $5 "\"" }' \
    "$fix/manifest.txt" > "$r/ids"

vm_init_head > "$r/init"
cat "$here/lifecycle.body" >> "$r/init"
chmod +x "$r/init"
vm_boot "$r" "$kernel" 300 "$work/log" ""
grep -q "RESULT: ALL PASS" "$work/log"
