#!/bin/sh
# The root's marker service (busybox init, sysinit): proves the root came
# up through paguro and reports what the runner asserts on, then powers off.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
mount -t devtmpfs dev /dev 2>/dev/null
say() { echo "PAGURO-LINUX: $*" > /dev/console; }
bad() { say "CHECK FAILED: $*"; }
root=$(awk '$2 == "/" { d = $1 } END { print d }' /proc/mounts)
say "root=$root up"
# The root's device chain, top to bottom, by device-mapper name.
dev=$(mountpoint -d /)
chain=""
while [ -n "$dev" ]; do
    s=/sys/dev/block/$dev
    [ -r "$s/dm/name" ] || break
    chain="$chain $(cat "$s/dm/name")"
    dev=$(cat "$s"/slaves/*/dev 2>/dev/null | head -1)
done
say "chain:$chain"
paguro-initrd status | while read -r l; do say "status $l"; done
# The handoff: the device is gone, and the firmware copy is zeroed — a new
# load of the reader finds nothing to take.
[ -e /dev/paguro-handoff ] && bad "/dev/paguro-handoff still present"
ko=$(ls /lib/modules/*/extra/paguro-handoff.ko 2>/dev/null | head -1)
if insmod "$ko" systab="$(paguro-initrd systab)" 2>/dev/null; then
    bad "the handoff could be read twice"
    rmmod paguro_handoff
elif dmesg | grep -q "paguro-handoff: the handoff was already consumed"; then
    say "handoff consumed and zeroed"
else
    bad "reloading paguro-handoff failed for another reason"
fi
if grep -q ' / ext4 ro[, ]' /proc/mounts; then
    if touch /paguro-write-test 2>/dev/null; then
        bad "a read-only root accepted a write"
    else
        say "root read-only (write refused)"
    fi
else
    mkdir -p /var/lib/paguro
    n=$(cat /var/lib/paguro/boots 2>/dev/null || echo 0)
    n=$((n + 1))
    echo "$n" > /var/lib/paguro/boots
    if [ "$n" = 1 ]; then
        # 8 MiB of known data, written once, verified on later boots.
        seq 1 1000000 > /var/lib/paguro/data
        md5sum /var/lib/paguro/data | cut -d' ' -f1 > /var/lib/paguro/data.md5
    elif [ "$(md5sum /var/lib/paguro/data | cut -d' ' -f1)" = "$(cat /var/lib/paguro/data.md5)" ]; then
        say "data from boot 1 intact"
    else
        bad "data from boot 1 changed"
    fi
    sync
    say "boot count $n"
fi
sync
mount -o remount,ro / 2>/dev/null
say "done"
poweroff -f
