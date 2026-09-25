#!/bin/sh
# Load dm-paguro in a throwaway QEMU VM booting the given kernel and exercise
# it with real I/O over real NTFS volumes (test/fixtures/ntfs). Never loads
# anything into the host kernel.
#
#   test/vm-test.sh [KERNEL_IMAGE] [MODULE_DIR]
#
# Needs: qemu-system-x86_64 (KVM if available, else TCG), static busybox,
# dmsetup, coreutils dd, util-linux losetup, cpio, gzip, zstd/xz for the
# kernel's modules, and a built tools/pgctl (static). If a built
# paguro-harness is found (target/{release,debug}), the I/O-error-at-every-
# read test runs too.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
top=$(cd "$here/../../.." && pwd)
fix=$top/test/fixtures/ntfs
kver=$(uname -r)
kernel=${1:-/boot/vmlinuz-$kver}
moddir=${2:-/lib/modules/$kver}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
r=$work/root
. "$here/vm-lib.sh"
vm_root "$r"
cp "$here/../dm-paguro.ko" "$r/"
cp "$here/../tools/pgctl" "$r/bin/"
# dm, loop and ntfs3 may be modules on this kernel; ship them uncompressed.
vm_modules "$moddir" drivers/md/dm-mod drivers/block/loop fs/ntfs3/ntfs3 drivers/md/dm-log-writes \
    fs/fat/vfat fs/nls/nls_cp437 fs/nls/nls_iso8859-1

# Fixtures, identities from the manifest, and a dirty copy of vol512.
for v in vol512 vol4k vol4kn; do gzip -dc "$fix/$v.img.gz" > "$r/fx/$v.img"; done
awk '$1 == "file" && NF == 6 && $2 !~ /^(f_|r_)/ {
         n = $3 "_" $2; gsub(/[^A-Za-z0-9]/, "_", n); print "ID_" n "=\"" $4 " " $5 "\"" }' \
    "$fix/manifest.txt" > "$r/ids"
cp "$r/fx/vol512.img" "$r/fx/dirty.img"
for tok in $(awk '$2 == "f_volume_dirty" { for (i = 7; i <= NF; i++) print $i }' "$fix/manifest.txt"); do
    printf "\\$(printf %o 0x${tok#*=})" |
        dd of="$r/fx/dirty.img" bs=1 seek="${tok%=*}" conv=notrunc status=none
done
harness=""
for h in "$top/target/release/paguro-harness" "$top/target/debug/paguro-harness"; do
    [ -x "$h" ] && harness=$h && break
done
if [ -n "$harness" ]; then
    set -- $(awk '$2 == "contig.img" { print $4, $5 }' "$fix/manifest.txt")
    "$harness" ntfs-reads "$fix/vol512.img.gz" "$1" "$2" > "$r/reads"
fi

vm_init_head > "$r/init"
cat "$here/vm-test.body" >> "$r/init"
chmod +x "$r/init"
vm_boot "$r" "$kernel" 900 "$work/log" ""
grep -q "RESULT: ALL PASS" "$work/log"
