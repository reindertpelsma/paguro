#!/bin/sh
# The coexistence, growth, power-loss replay and view-C guard tests
# (test/coexist/coexist.body) in a throwaway QEMU VM. Never loads anything
# into the host kernel.
#
#   test/vm-coexist.sh [KERNEL_IMAGE] [MODULE_DIR]
#
# Environment:
#   PG_WORK     scratch directory (disks, logs); default: a fresh mktemp -d
#   PG_PHASES   default "coexist replay frag 4kn guard"
#   PG_SCALE    stress multiplier (default 1)
#   PG_REPLAY   pgreplay walk options (default "--flush-every 80 --subsets 2
#               --torn 25 --seed 1"); see pgreplay.c
#   PG_EFSCK    e2fsck the images at every Nth replayed state (default 20)
#   PG_NTFSCK   path to an ntfsck (ntfsprogs-plus) to run as well
#
# Needs: qemu-system-x86_64, static busybox, dmsetup, cpio, gzip, zstd/xz,
# python3, mkntfs, ntfsfix, sgdisk, mkfs.vfat, mkfs.ext4, e2fsck, resize2fs,
# gcc (static libc), a built dm-paguro.ko, tools/pgctl, target/release/
# paguro-harness, and for the guard phase tools/pgguard (make -C tools).
# Optional: fio, fsck.fat.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
top=$(cd "$here/../../.." && pwd)
kver=$(uname -r)
kernel=${1:-/boot/vmlinuz-$kver}
moddir=${2:-/lib/modules/$kver}
work=${PG_WORK:-}
if [ -z "$work" ]; then
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
fi
mkdir -p "$work"
r=$work/root
rm -rf "$r"
. "$here/vm-lib.sh"
vm_root "$r"

cp "$here/../dm-paguro.ko" "$r/"
cp "$here/../tools/pgctl" "$r/bin/"
for t in pgstress pgreplay; do
    gcc -static -O2 -Wall -Wextra -Werror -o "$r/bin/$t" "$here/tools/$t.c"
done
harness=$top/target/release/paguro-harness
[ -x "$harness" ] || { echo "build paguro-harness first (cargo build --release -p paguro-harness)"; exit 2; }
vm_bin "$harness" bin/paguro-harness
for b in e2fsck resize2fs ntfsfix mkntfs ntfscp; do
    vm_bin "$(command -v $b)" "sbin/$b"
done
for b in fsck.fat fio bpftool; do
    p=$(command -v $b || true)
    [ -n "$p" ] && vm_bin "$p" "sbin/$b"
done
[ -n "${PG_NTFSCK:-}" ] && vm_bin "$PG_NTFSCK" sbin/ntfsck
if [ -x "$here/../tools/pgguard" ]; then
    vm_bin "$here/../tools/pgguard" bin/pgguard
fi
cp "$here/coexist/guard.body" "$r/guard.body" 2>/dev/null || true
vm_modules "$moddir" drivers/md/dm-mod drivers/block/loop fs/ntfs3/ntfs3 \
    drivers/md/dm-log-writes drivers/md/dm-snapshot fs/ext4/ext4 fs/fat/vfat \
    fs/nls/nls_cp437 fs/nls/nls_iso8859-1 fs/nls/nls_utf8

img=$work/img
[ -e "$img/layout.env" ] || python3 "$here/coexist/mkimages.py" "$img"
cp "$img/vol512.img" "$work/vol512.img"
cp "$img/vol4kn.img" "$work/vol4kn.img"
rm -f "$work/log.img" "$work/target.img"
truncate -s "${PG_LOG_SIZE:-8G}" "$work/log.img"
truncate -s 1G "$work/target.img"
{
    cat "$img/layout.env"
    echo "SCALE=${PG_SCALE:-1}"
    echo "PHASES=\"${PG_PHASES:-coexist replay frag 4kn guard}\""
    echo "EFSCK=${PG_EFSCK:-20}"
    echo "REPLAY=\"${PG_REPLAY:---flush-every 80 --subsets 2 --torn 25 --seed 1}\""
} > "$r/layout.env"

vm_init_head > "$r/init"
cat "$here/coexist/coexist.body" >> "$r/init"
chmod +x "$r/init"

# d <file> <id> [drive options] [device options]
d() { echo "-drive file=$1,format=raw,if=none,id=$2,cache=unsafe${3:+,$3} -device virtio-blk-pci,drive=$2${4:+,$4}"; }
PG_VM_MEM=${PG_VM_MEM:-3072} vm_boot "$r" "$kernel" "${PG_TIMEOUT:-7200}" "$work/log" \
    "lsm=lockdown,capability,landlock,yama,bpf" \
    $(d "$work/vol512.img" v512) \
    $(d "$work/vol4kn.img" v4kn "" "logical_block_size=4096,physical_block_size=4096") \
    $(d "$work/log.img" vlog) \
    $(d "$work/target.img" vtgt) \
    $(d "$img/disk.vhd" vdisk readonly=on) \
    $(d "$img/bare.img" vbare readonly=on) \
    $(d "$img/disk4k.vhd" vdisk4 readonly=on) \
    $(d "$img/bare4k.img" vbare4 readonly=on) \
    $([ -e "$img/frag.img" ] && cp "$img/frag.img" "$work/frag.img" && d "$work/frag.img" vfrag "" serial=frag) \
    $([ -e "$img/guard.img" ] && cp "$img/guard.img" "$work/guard.img" && d "$work/guard.img" vguard "" serial=guard)
grep -q "RESULT: ALL PASS" "$work/log"
