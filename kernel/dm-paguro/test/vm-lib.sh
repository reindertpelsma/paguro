# Shared by vm-test.sh and vm-coexist.sh: build a busybox initramfs root and
# boot it in a throwaway QEMU VM. Sourced (POSIX sh). Nothing here touches
# the host kernel: modules are only copied into the VM's initramfs.

# vm_root <dir>: busybox, its applets, dmsetup, coreutils dd, util-linux
# losetup (for --sector-size) and the usual mount points.
vm_root() {
    r=$1
    mkdir -p "$r/bin" "$r/sbin" "$r/proc" "$r/sys" "$r/dev" "$r/tmp" "$r/mod" "$r/fx" "$r/mnt" "$r/etc"
    cp "$(command -v busybox)" "$r/bin/"
    for a in sh mount umount insmod rmmod losetup cat poweroff grep head tail yes \
             blockdev cmp cp mkdir sed awk cut tr sleep sync truncate echo ls wc \
             printf expr seq rm stat od find du tar xargs env date sort uniq mv \
             ln touch chmod kill test [ df md5sum dmesg basename dirname true false; do
        [ -e "$r/bin/$a" ] || ln -s busybox "$r/bin/$a"
    done
    vm_bin "$(command -v dmsetup)" sbin/dmsetup
    vm_bin "$(command -v dd)" bin/dd
    vm_bin "$(command -v losetup)" sbin/losetup.ul
}

# vm_bin <host-binary> <path-in-root>: the binary and its shared libraries.
vm_bin() {
    mkdir -p "$r/$(dirname "$2")"
    cp "$1" "$r/$2"
    for l in $(ldd "$1" 2>/dev/null | grep -o '/[^ ]*'); do
        [ -e "$r$l" ] && continue
        mkdir -p "$r$(dirname "$l")"; cp -L "$l" "$r$l"
    done
}

# vm_modules <moddir> <module>...: each module (kernel/-relative path without
# extension) and everything it depends on (modules.dep), uncompressed, into
# /mod, with /mod/order listing them dependencies first. Missing or built-in
# modules are skipped.
vm_modules() {
    md=$1; shift
    : > "$r/mod/order"
    # An unpacked (dpkg -x) module tree has no modules.dep: make one there.
    if [ ! -e "$md/modules.dep" ]; then
        depmod -b "$(cd "$md/../../.." && pwd)" "$(basename "$md")" ||
            { echo "vm_modules: no modules.dep in $md and depmod failed" >&2; return 1; }
    fi
    for m in "$@"; do vm_module_dep "$md" "kernel/$m"; done
}

vm_module_dep() {
    md=$1; rel=$2
    line=$(grep -E "^$rel\.ko(\.zst|\.xz|\.gz)?:" "$md/modules.dep" 2>/dev/null | head -1)
    [ -n "$line" ] || return 0
    file=${line%%:*}
    for d in ${line#*:}; do vm_module_dep "$md" "${d%.ko*}"; done
    name=$(basename "${file%.ko*}")
    grep -qx "$name" "$r/mod/order" && return 0
    case $file in
        *.zst) zstd -qdc "$md/$file" > "$r/mod/$name.ko" ;;
        *.xz)  xz -dc "$md/$file" > "$r/mod/$name.ko" ;;
        *.gz)  gzip -dc "$md/$file" > "$r/mod/$name.ko" ;;
        *)     cp "$md/$file" "$r/mod/$name.ko" ;;
    esac
    echo "$name" >> "$r/mod/order"
}

# The first lines of every /init: mounts, ok/bad, modules in dependency order.
vm_init_head() {
    cat <<'INIT'
#!/bin/sh
export PATH=/bin:/sbin
mount -t proc proc /proc; mount -t sysfs sys /sys; mount -t devtmpfs dev /dev; mount -t tmpfs tmp /tmp
fail=0
ok()  { echo "PASS: $1"; }
bad() { echo "FAIL: $1"; fail=1; }
for m in $(cat /mod/order); do insmod "/mod/$m.ko"; done
INIT
}

# vm_boot <root> <kernel> <timeout-s> <log> <append> [qemu args...]
vm_boot() {
    root=$1 kernel=$2 tmo=$3 log=$4 append=$5; shift 5
    (cd "$root" && find . | cpio -o -H newc 2>/dev/null | gzip -1) > "$root.cpio.gz"
    accel=""
    [ -w /dev/kvm ] && [ -z "${PG_NO_KVM:-}" ] && accel="-enable-kvm -cpu host"	# else TCG
    timeout "$tmo" qemu-system-x86_64 $accel -m "${PG_VM_MEM:-1536}" -smp 2 -nographic -no-reboot \
        -kernel "$kernel" -initrd "$root.cpio.gz" \
        -append "console=ttyS0 quiet panic=-1 $append" "$@" 2>&1 | tr -d '\r' > "$log" &
    qpid=$!
    tail -f "$log" --pid=$qpid 2>/dev/null |
        grep --line-buffered -E "PASS|FAIL|SKIP|RESULT|status:|BUG|Oops|WARNING|paguro|INFO|pgstress:|CORRUPT|DEBUG" || true
    wait $qpid
}
