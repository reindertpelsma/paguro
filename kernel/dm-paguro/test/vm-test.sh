#!/bin/sh
# Load dm-paguro in a throwaway QEMU VM booting the given kernel, and check its
# behaviour with real I/O. Never loads anything into the host kernel.
#
#   test/vm-test.sh [KERNEL_IMAGE] [MODULE_DIR]
#
# Needs: qemu-system-x86_64, static busybox, dmsetup, coreutils dd, cpio, gzip.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
kver=$(uname -r)
kernel=${1:-/boot/vmlinuz-$kver}
moddir=${2:-/lib/modules/$kver}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
r=$work/root
mkdir -p "$r/bin" "$r/sbin" "$r/proc" "$r/sys" "$r/dev" "$r/tmp" "$r/mod"

cp "$(command -v busybox)" "$r/bin/"
for a in sh mount insmod losetup cat poweroff grep head yes; do ln -s busybox "$r/bin/$a"; done
copy_bin() {
    cp "$1" "$r/$2"
    for l in $(ldd "$1" | grep -o '/[^ ]*'); do
        mkdir -p "$r$(dirname "$l")"; cp -L "$l" "$r$l"
    done
}
copy_bin "$(command -v dmsetup)" sbin/dmsetup
copy_bin "$(command -v dd)" bin/dd
cp "$here/../dm-paguro.ko" "$r/"

# dm and loop may be modules on this kernel; ship them uncompressed if so.
for m in drivers/md/dm-mod drivers/block/loop; do
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

(cd "$r" && find . | cpio -o -H newc 2>/dev/null | gzip) > "$work/initramfs.gz"
accel=""
[ -w /dev/kvm ] && accel="-enable-kvm"
timeout 300 qemu-system-x86_64 $accel -m 512 -nographic -no-reboot \
    -kernel "$kernel" -initrd "$work/initramfs.gz" \
    -append "console=ttyS0 quiet panic=-1" 2>&1 | tr -d '\r' | tee "$work/log" \
    | grep -E "PASS|FAIL|RESULT|status:|BUG|Oops"
grep -q "RESULT: ALL PASS" "$work/log"
