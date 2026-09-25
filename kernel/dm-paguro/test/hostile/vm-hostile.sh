#!/bin/sh
# /dev/paguro, the dm table lines and /dev/paguro-handoff as a hostile caller
# sees them (INTERFACES §12.0), in a throwaway VM on a debug kernel
# (build-kernel.sh: KASAN + UBSAN + lockdep + kmemleak, or KCSAN). Never
# loads anything into the host kernel.
#
#   test/hostile/vm-hostile.sh <kernel-out-dir>     (bzImage, build/, version)
#
# Environment: PG_HOSTILE_SECS (churn/race seconds, default 30),
# PG_HOSTILE_FUZZ (random ioctls, default 200000).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
dmp=$(cd "$here/../.." && pwd)
top=$(cd "$dmp/../.." && pwd)
kout=$(cd "$1" && pwd)
flavour=$(awk '{print $2}' "$kout/version")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
. "$dmp/test/vm-lib.sh"

# The modules, built against the debug kernel (in a copy: the tree's own
# objects belong to whatever kernel it was last built for).
for m in dm-paguro paguro-handoff; do
    mkdir -p "$work/$m"
    src=$dmp; [ $m = paguro-handoff ] && src=$top/kernel/paguro-handoff
    cp "$src"/*.c "$src"/*.h "$src"/Kbuild "$work/$m/" 2>/dev/null || true
    make -s -C "$kout/build" M="$work/$m" modules
done
gcc -static -O2 -Wall -Wextra -Werror -pthread -o "$work/pghostile" "$here/pghostile.c"
make -s -C "$dmp/tools" pgctl

boot() { # boot <name> <body> [qemu args...]
    name=$1 body=$2; shift 2
    r=$work/$name
    vm_root "$r"
    : > "$r/mod/order"	# everything the tests need is built in
    cp "$work/dm-paguro/dm-paguro.ko" "$work/paguro-handoff/paguro-handoff.ko" "$r/"
    cp "$work/pghostile" "$dmp/tools/pgctl" "$r/bin/"
    gzip -dc "$top/test/fixtures/ntfs/vol512.img.gz" > "$r/fx/vol512.img"
    awk '$1 == "file" && NF == 6 && $3 == "vol512.img" && $2 !~ /^(f_|r_)/ {
             n = $2; gsub(/[^A-Za-z0-9]/, "_", n); print "ID_" n "=\"" $4 " " $5 "\"" }' \
        "$top/test/fixtures/ntfs/manifest.txt" > "$r/ids"
    {
        echo "FLAVOUR=$flavour SECS=${PG_HOSTILE_SECS:-30} FUZZ=${PG_HOSTILE_FUZZ:-200000}"
    } > "$r/env"
    vm_init_head > "$r/init"
    cat "$here/common.body" "$here/$body" >> "$r/init"
    chmod +x "$r/init"
    PG_VM_MEM=${PG_VM_MEM:-4096} vm_boot "$r" "$kout/bzImage" "${PG_TIMEOUT:-3600}" "$work/$name.log" \
        "kmemleak=on hung_task_timeout_secs=60 loglevel=4" "$@"
    cp "$work/$name.log" "${PG_HOSTILE_LOGS:-$work}/$name.log" 2>/dev/null || true
    grep -q "RESULT: ALL PASS" "$work/$name.log"
}

rc=0
boot ctl ctl.body || rc=1
# The handoff module needs an EFI boot: OVMF, no paguro loader (so no
# handoff table), systab= garbage and the real one.
ovmf=${PG_OVMF:-/usr/share/OVMF/OVMF_CODE_4M.fd}
if [ -e "$ovmf" ]; then
    cp "${PG_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}" "$work/vars.fd"
    boot handoff handoff.body \
        -drive if=pflash,format=raw,readonly=on,file="$ovmf" \
        -drive if=pflash,format=raw,file="$work/vars.fd" || rc=1
else
    echo "SKIP: handoff (no OVMF at $ovmf)"
fi
exit $rc
