#!/usr/bin/env bash
# The product topology in one Linux VM: the paguro host stack AND the
# Windows VM inside L2 (Windows nested one level deeper), so paguro-vm
# launch runs where the module runs — the disk is /dev/mapper/paguro-vmdisk
# itself (host_device), the private link a tap moved into netns paguro, vsock
# a vhost-vsock device. Slower than split-e2e.sh; it proves the paths that
# one cannot (a tap and vhost need the Linux side's kernel).
#
#   test/vm/nested-e2e.sh           (environment as split-e2e.sh)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib.sh
. "$here/lib.sh"

WIN_DISK=${PAGURO_WIN_DISK:-/var/tmp/paguro-vm/win-bde.qcow2}
RP_FILE=${PAGURO_WIN_RECOVERY:-/data/paguro-work/vm/recovery-password.txt}
VOLUME_GUID=${PAGURO_WIN_VOLUME_GUID:-5241b9de-5ba4-4523-8a88-2253f46ef21f}
PART=${PAGURO_WIN_PARTITION:-/dev/vda3}
IMAGE=${PAGURO_WIN_IMAGE:-paguro/linux.img}
WIN_KEY=${WINVM_KEY:-/var/tmp/winvm/keys/id_ed25519}
SSH_PORT=${PAGURO_NESTED_SSH_PORT:-2226}
export PAGURO_L2_MEM=${PAGURO_L2_MEM:-7680} PAGURO_L2_SCOPE_MAX=${PAGURO_L2_SCOPE_MAX:-8G}
export PAGURO_L2_NESTED=1 PAGURO_L2_EXTRA_FWD="hostfwd=tcp:127.0.0.1:$SSH_PORT-:$SSH_PORT"
RES=$VMWORK/nested-results.txt
: > "$RES"
fails=0
pass() { echo "PASS: $*" | tee -a "$RES"; }
fail() { echo "FAIL: $*" | tee -a "$RES"; fails=$((fails + 1)); }
result() { echo "RESULT $1: $2" | tee -a "$RES"; }
expect() {
    local v; v=$(grep -aE -m1 -- "$3" <<<"$2" || head -1 <<<"$2")
    if grep -aqE -- "$3" <<<"$2"; then pass "$1: $v"; else fail "$1: $v (want /$3/)"; fi
}
wssh() { ${WSSH_TIMEOUT:+timeout "$WSSH_TIMEOUT"} ssh -i "$WIN_KEY" -p "$SSH_PORT" -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10 -o ServerAliveInterval=15 \
            paguro@127.0.0.1 "$@"; }
trap 'l2_stop || true' EXIT

say "build"
l2_build
l2_root "$VMWORK/l2root" >/dev/null

say "L2: the host stack, then Windows inside it"
l2_start "$WIN_DISK"
cp "$RP_FILE" "$SHARE/rp.txt"
l2 "set -e
test -e /dev/kvm && echo kvm: yes
paguro-vm unlock --partition $PART --recovery-password-file /share/rp.txt --vmk-out /run/vmk --volume-add > /run/vol
mount -t ntfs3 -o ro /dev/mapper/paguro-plain /mnt/p
pgctl ident /mnt/p/$IMAGE > /run/ident
pgctl fiemap /mnt/p/$IMAGE > /share/fiemap
umount /mnt/p
pgctl claim \$(tail -1 /run/vol) \$(cat /run/ident) raw > /run/claim
pgctl crosscheck-list \$(cat /run/claim) /share/fiemap
mount -t vfat -o ro /dev/vda1 /mnt/esp
mkdir -p /run/paguro/vm /run/paguro/win
paguro-vm prepare --disk /dev/vda --partition $PART --volume-guid $VOLUME_GUID \
    --volume-id \$(tail -1 /run/vol) --vmk-file /run/vmk --esp-dir /mnt/esp --work /run/paguro/vm > /dev/null
umount /mnt/esp
(setsid paguro-vm launch --work /run/paguro/win --disk-dev /dev/mapper/paguro-vmdisk --bus ahci \
    --nat-hostfwd tcp:0.0.0.0:$SSH_PORT-:22 --hostonly tap:paguro0 --vsock-cid 3 --memory 5120 --cpus 2 \
    --driver-timeout 0 --bek-unplug-after 60 --ovmf-code /usr/share/OVMF/OVMF_CODE_4M.fd \
    --ovmf-vars-template /usr/share/OVMF/OVMF_VARS_4M.fd \
    -- -qmp unix:/run/paguro/win/qmp-test.sock,server=on,wait=off > /share/nested-launch.log 2>&1 &)
sleep 15; cat /share/nested-launch.log" | tee "$VMWORK/nested-setup.txt"
expect "L2 has KVM (Windows nests one level down)" "$(cat "$VMWORK/nested-setup.txt")" '^kvm: yes'

say "Windows (nested) boots from /dev/mapper/paguro-vmdisk"
t0=$(date +%s)
shot() { l2 "paguro-vm qmp --socket /run/paguro/win/qmp-test.sock '{\"execute\":\"screendump\",\"arguments\":{\"filename\":\"/share/$1\",\"format\":\"png\"}}'" >/dev/null 2>&1 || true; }
for i in $(seq 240); do
    sleep 10
    [ $((i % 30)) = 3 ] && shot "nested-boot-$i.png"
    wssh 'echo up' 2>/dev/null | grep -aq up && break
done
wssh 'echo up' 2>/dev/null | grep -aq up || { shot nested-failed.png; die "nested Windows did not come up"; }
result "nested boot to SSH" "$(( $(date +%s) - t0 )) s"
sleep 60
shot nested-desktop.png
out=$(wssh 'manage-bde -status C: & bcdedit /enum {current} | findstr testsigning & fltmc filters' 2>&1 | tr -d '\r')
echo "$out" > "$VMWORK/nested-guest.txt"
expect "nested: BitLocker on, the session's external key" "$(grep -a 'Protection Status' <<<"$out")" 'Protection On'
expect "nested: testsigning" "$out" 'testsigning +Yes'
expect "nested: PaguroFlt attached" "$out" 'PaguroFlt +1 '
out=$(wssh 'powershell -NoProfile -Command "Get-PnpDevice -PresentOnly | Where-Object FriendlyName -match ''VirtIO Socket|VirtIO Serial|VirtIO Ethernet'' | ForEach-Object { $_.Status + '' '' + $_.FriendlyName }"' 2>&1 | tr -d '\r')
echo "$out" >> "$VMWORK/nested-guest.txt"
expect "nested: vsock device" "$out" 'OK VirtIO Socket'
out=$(l2 "cat /share/nested-launch.log; /sbin/ip -n paguro -brief link; /sbin/ip -brief link | grep -c paguro0 || true")
echo "$out" > "$VMWORK/nested-l2.txt"
expect "nested: QEMU's tap moved into netns paguro by the launcher" "$out" 'link: paguro0 in netns paguro'
expect "nested: BEK read and unplugged" "$out" 'BEK: removed from the guest'
wssh 'shutdown /s /t 0' >/dev/null 2>&1 || true
for _ in $(seq 60); do l2 "test -e /run/paguro/win/qemu.pid" >/dev/null 2>&1 || break; sleep 5; done
out=$(l2 "cat /share/nested-launch.log | tail -3; paguro-vm teardown --work /run/paguro/vm 2>&1; pgctl status")
echo "$out" >> "$VMWORK/nested-l2.txt"
expect "nested: QEMU exited cleanly" "$out" 'QEMU exited: exit status: 0'
l2_stop
cp "$SHARE"/nested-*.png "$VMWORK/shots/" 2>/dev/null || true

say "results"
cat "$RES"
[ "$fails" = 0 ] && echo "RESULT: ALL PASS" || { echo "RESULT: $fails FAILED"; exit 1; }
