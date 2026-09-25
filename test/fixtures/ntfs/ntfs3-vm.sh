#!/bin/sh
# Populate an NTFS volume through the Linux kernel's ntfs3, in a throwaway
# VM (never the host kernel), for generate.py's vol_ntfs3 fixture: ntfs3
# writes the FILE records it creates in the NTFS 3.0 layout.
#
#   ntfs3-vm.sh <volume.img> <payload.bin> <tail.bin> <out.txt> [kernel] [moddir]
#
# out.txt: "<path> <record> <sequence>" per file made.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
top=$(cd "$here/../../.." && pwd)
img=$(realpath "$1") pay=$(realpath "$2") tail=$(realpath "$3") out=$4
kver=$(uname -r)
kernel=${5:-/boot/vmlinuz-$kver}
moddir=${6:-/lib/modules/$kver}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
r=$work/root
. "$top/kernel/dm-paguro/test/vm-lib.sh"
vm_root "$r"
vm_modules "$moddir" fs/ntfs3/ntfs3
gcc -static -O2 -o "$r/bin/pgctl" "$top/kernel/dm-paguro/tools/pgctl.c"
cp "$pay" "$r/payload.bin"; cp "$tail" "$r/tail.bin"
vm_init_head > "$r/init"
cat >> "$r/init" <<'BODY'
m=/mnt
mount -t ntfs3 /dev/vda $m || { echo "FAIL: mount"; poweroff -f; }
# holes <dir> <n>: n 4 KiB files, the rest filled, every other one in disk
# order deleted: only 8-cluster holes remain free.
holes() {
    mkdir $m/$1
    i=0; while [ $i -lt $2 ]; do dd if=/dev/zero of=$m/$1/$i bs=4096 count=1 2>/dev/null; i=$((i + 1)); done
    dd if=/dev/zero of=$m/filler bs=64k 2>/dev/null; dd if=/dev/zero of=$m/filler2 bs=512 2>/dev/null
    sync
    for f in $m/$1/*; do echo "$(pgctl fiemap $f | head -1 | cut -d' ' -f1) $f"; done | sort -n |
        awk 'NR % 2 == 1 {print $2}' | xargs rm
    sync
}
unfill() { rm -f $m/filler $m/filler2; sync; }
dd if=/payload.bin of=$m/contig.img bs=64k 2>/dev/null
dd if=/payload.bin of=$m/grown.img bs=64k 2>/dev/null
echo small > $m/small.txt
mkdir $m/dir
holes a 300
dd if=/payload.bin of=$m/frag.img bs=64k 2>/dev/null
unfill
holes b 1100
# Grown into fragmented space: ntfs3 has to add extension records.
cat /tail.bin >> $m/grown.img
unfill
echo; for f in contig.img frag.img grown.img small.txt dir; do echo "ID $f $(pgctl ident $m/$f)"; done
echo "EXTENTS frag $(pgctl fiemap $m/frag.img | wc -l) grown $(pgctl fiemap $m/grown.img | wc -l)"
umount $m && echo "DONE"
poweroff -f
BODY
chmod +x "$r/init"
(cd "$r" && find . | cpio -o -H newc 2>/dev/null | gzip -1) > "$r.cpio.gz"
accel=""; [ -w /dev/kvm ] && accel="-enable-kvm -cpu host"
timeout 900 qemu-system-x86_64 $accel -m 1024 -smp 2 -nographic -no-reboot \
    -kernel "$kernel" -initrd "$r.cpio.gz" -append "console=ttyS0 quiet panic=-1" \
    -drive file="$img",format=raw,if=virtio 2>&1 | tr -d '\r' > "$work/log"
grep -q "^DONE" "$work/log" || { cat "$work/log" | tail -20; exit 1; }
grep "^EXTENTS" "$work/log" >&2
sed -n 's/^ID //p' "$work/log" > "$out"
