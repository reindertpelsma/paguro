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
mkdir -p "$r/bin" "$r/sbin" "$r/proc" "$r/sys" "$r/dev" "$r/tmp" "$r/mod" "$r/fx" "$r/mnt"

cp "$(command -v busybox)" "$r/bin/"
for a in sh mount umount insmod rmmod losetup cat poweroff grep head tail yes \
         blockdev cmp cp mkdir sed awk cut tr sleep sync truncate echo ls wc \
         printf expr seq rm stat od; do
    ln -s busybox "$r/bin/$a"
done
copy_bin() {
    cp "$1" "$r/$2"
    for l in $(ldd "$1" | grep -o '/[^ ]*'); do
        mkdir -p "$r$(dirname "$l")"; cp -L "$l" "$r$l"
    done
}
copy_bin "$(command -v dmsetup)" sbin/dmsetup
copy_bin "$(command -v dd)" bin/dd
copy_bin "$(command -v losetup)" sbin/losetup.ul	# for --sector-size
cp "$here/../dm-paguro.ko" "$r/"
cp "$here/../tools/pgctl" "$r/bin/"

# dm, loop and ntfs3 may be modules on this kernel; ship them uncompressed.
for m in drivers/md/dm-mod drivers/block/loop fs/ntfs3/ntfs3 drivers/md/dm-log-writes; do
    for ext in .ko .ko.zst .ko.xz; do
        f=$moddir/kernel/$m$ext
        [ -e "$f" ] || continue
        case $ext in
            .ko.zst) zstd -qdc "$f" > "$r/mod/$(basename "$m").ko" ;;
            .ko.xz)  xz -dc "$f" > "$r/mod/$(basename "$m").ko" ;;
            *)       cp "$f" "$r/mod/" ;;
        esac
    done
done

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

cat > "$r/init" <<'INIT'
#!/bin/sh
export PATH=/bin:/sbin
mount -t proc proc /proc; mount -t sysfs sys /sys; mount -t devtmpfs dev /dev; mount -t tmpfs tmp /tmp
fail=0
ok()  { echo "PASS: $1"; }
bad() { echo "FAIL: $1"; fail=1; }
for m in /mod/*.ko; do [ -e "$m" ] && insmod "$m"; done
INIT
cat "$here/vm-test.body" >> "$r/init"
chmod +x "$r/init"

(cd "$r" && find . | cpio -o -H newc 2>/dev/null | gzip -1) > "$work/initramfs.gz"
accel=""
[ -w /dev/kvm ] && [ -z "${PG_NO_KVM:-}" ] && accel="-enable-kvm -cpu host"	# else TCG
timeout 900 qemu-system-x86_64 $accel -m 1536 -smp 2 -nographic -no-reboot \
    -kernel "$kernel" -initrd "$work/initramfs.gz" \
    -append "console=ttyS0 quiet panic=-1" 2>&1 | tr -d '\r' | tee "$work/log" \
    | grep -E "PASS|FAIL|SKIP|RESULT|status:|BUG|Oops|WARNING|paguro"
grep -q "RESULT: ALL PASS" "$work/log"
