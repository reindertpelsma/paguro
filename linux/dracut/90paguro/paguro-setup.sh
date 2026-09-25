#!/bin/sh
# initqueue/settled: build the root once the disks are there.
[ -e /dev/paguro-root ] && return 0
[ -c /dev/paguro-handoff ] || return 0
for m in dm-paguro dm-crypt dm-zero ntfs3 vfat nls_cp437 nls_iso8859-1 efivarfs; do
    modprobe -q "$m" 2> /dev/null
done
mkdir -p /run/paguro
# The root is linked at /dev/paguro-root, read-only at the device when
# Windows is dirty or hibernated.
ok=0
paguro-initrd setup --env /run/paguro/root.env && ok=1
# Consumed and wiped either way; nothing is left for the module to hold.
rmmod paguro_handoff 2> /dev/null
[ "$ok" = 1 ] || die "paguro: could not build the root from the handoff"
