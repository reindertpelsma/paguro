#!/bin/sh
# paguro-vm's --tripwire-hook for split-e2e.sh: view B lives in L2, where
# nbdkit holds it, so the tripwire is set on nbdkit there. The host QEMU's
# NBD client stalls rather than fails when nbdkit dies (reconnect-delay),
# and the test stops the host QEMU, standing in for the product's QEMU being
# the process the module kills.
#   tripwire-hook.sh on <host qemu pid> | off      (PAGURO_SHARE: L2's /share)
set -eu
q=${PAGURO_SHARE:?}/q
case $1 in
    on) cmd='dmsetup message paguro-vmdisk-b 0 tripwire $(cat /run/nbd.pid)' ;;
    off) cmd='dmsetup message paguro-vmdisk-b 0 tripwire off' ;;
    *) exit 2 ;;
esac
n=hook-$(date +%s%N)-$$
printf '%s\n' "$cmd" > "$q/$n.sh.tmp" && mv "$q/$n.sh.tmp" "$q/$n.sh"
for _ in $(seq 100); do
    [ -e "$q/$n.rc" ] && break
    sleep 0.3
done
[ -e "$q/$n.rc" ] || { echo "tripwire-hook: L2 did not answer" >&2; exit 1; }
cat "$q/$n.out" >&2
exit "$(cat "$q/$n.rc")"
