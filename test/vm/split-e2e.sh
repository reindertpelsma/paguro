#!/usr/bin/env bash
# The user's own BitLocker Windows, booted as a VM through the paguro disk
# stack (DESIGN.md §4.3, §4.5, §6 "The VM boot") — split across two VMs
# because this host never loads paguro's modules:
#
#   L2 (Linux, the host's kernel):  the Windows disk as /dev/vda
#       paguro-vm unlock --volume-add   stand-in for the initrd: dm-crypt
#                                       volume, PG_VOLUME_ADD (FVE reserved)
#       pgctl claim                     the image file on C: (view B's EIO)
#       paguro-vm prepare               substitute + .BEK, synthetic ESP,
#                                       view B, /dev/mapper/paguro-vmdisk
#       qemu-nbd                        exports it
#   host: paguro-vm launch --nbd ...    Windows on it: host identity, the
#                                       .BEK stick (unplugged once read),
#                                       every write logged (Q24)
#
# then: guest checks, the private link (§5c) and /mnt/c over it (§5b
# Mode 1), BitLocker operations in the guest (absorbed, §6), the EIO
# probe; after shutdown, L2 proves nothing reached BitLocker's sectors or
# the image, and a native boot (TPM, no marker) of the same disk shows
# native Windows unaffected.
#
#   test/vm/split-e2e.sh
#
# Environment (defaults are this repo's local test setup, see README.md):
#   PAGURO_WIN_DISK          BitLocker'd Windows qcow2 (never modified)
#   PAGURO_WIN_RECOVERY      file with its recovery password
#   PAGURO_WIN_VOLUME_GUID   C:'s GPT partition GUID
#   PAGURO_WIN_PARTITION     C:'s partition in L2 (/dev/vda3)
#   PAGURO_WIN_IMAGE         a file on C: to claim (paguro/linux.img)
#   PAGURO_WIN_VARS, PAGURO_WIN_TPM   native boot's OVMF vars and swtpm state
#   PAGURO_VM_WORK           big files (/data/paguro-work/vm/run)
#   PAGURO_Q1=1              also §11 Q1-Q3: writes into the image and a
#                            relocation of it from the guest (q1-probe.ps1)
#   PAGURO_Q1_KILL=1         end the session by killing QEMU, not a shutdown
#                            (Q3's "arbitrary interruption")
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib.sh
. "$here/lib.sh"

WIN_DISK=${PAGURO_WIN_DISK:-/var/tmp/paguro-vm/win-bde.qcow2}
RP_FILE=${PAGURO_WIN_RECOVERY:-/data/paguro-work/vm/recovery-password.txt}
VOLUME_GUID=${PAGURO_WIN_VOLUME_GUID:-5241b9de-5ba4-4523-8a88-2253f46ef21f}
PART=${PAGURO_WIN_PARTITION:-/dev/vda3}
IMAGE=${PAGURO_WIN_IMAGE:-paguro/linux.img}
NATIVE_VARS=${PAGURO_WIN_VARS:-/var/tmp/paguro-vm/win-bde-vars.fd}
NATIVE_TPM=${PAGURO_WIN_TPM:-$HOME/.cache/winvm-swtpm-vm/win-bde-tpm}
WIN_KEY=${WINVM_KEY:-/var/tmp/winvm/keys/id_ed25519}
SSH_PORT=${PAGURO_WIN_SSH_PORT:-2224}
NATIVE_SSH_PORT=$((SSH_PORT + 1))
WIN=$VMWORK/win
SHOTS=$VMWORK/shots
RES=$VMWORK/results.txt
PHASES=$VMWORK/phases.txt
vm=$top/target/release/paguro-vm
W=$top/test/winvm/winvm
mkdir -p "$VMWORK" "$WIN" "$SHOTS"
: > "$RES"
: > "$PHASES"
fails=0

result() { echo "RESULT $1: $2" | tee -a "$RES"; }
pass() { echo "PASS: $*" | tee -a "$RES"; }
fail() { echo "FAIL: $*" | tee -a "$RES"; fails=$((fails + 1)); }
expect() { # name value pattern
    local v; v=$(grep -aE -m1 -- "$3" <<<"$2" || head -1 <<<"$2")
    if grep -aqE -- "$3" <<<"$2"; then pass "$1: $v"; else fail "$1: $v (want /$3/)"; fi
}
wssh() { ${WSSH_TIMEOUT:+timeout "$WSSH_TIMEOUT"} ssh -i "$WIN_KEY" -p "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR -o ConnectTimeout=5 -o ServerAliveInterval=15 paguro@127.0.0.1 "$@"; }
wscp() { scp -i "$WIN_KEY" -P "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR "$@"; }
check() { grep -a -m1 "^CHECK $1: " "$2" | sed "s/^CHECK $1: //" || true; }
# The write log's entry count: a phase boundary for q24.py.
phase() { echo "$1 $(python3 "$here/q24.py" --count "$VMWORK/writes.log")" >> "$PHASES"; }
shim() { # winvm (screen, keys) against the launcher's second QMP socket
    [ -L "$VMWORK/winshim/run" ] && rm -f "$VMWORK/winshim/run"
    mkdir -p "$VMWORK/winshim/run"
    ln -sfn "$(dirname "$WIN_KEY")" "$VMWORK/winshim/keys"
    ln -sfn "$WIN/qmp-test.sock" "$VMWORK/winshim/run/qmp.sock"
    ln -sfn "$WIN/qemu.pid" "$VMWORK/winshim/run/qemu.pid"
    WINVM_DIR=$VMWORK/winshim WINVM_SSH_PORT=$SSH_PORT "$W" "$@"
}
cleanup() {
    [ -e "$WIN/qemu.pid" ] && kill "$(cat "$WIN/qemu.pid")" 2>/dev/null || true
    l2_stop || true
}
trap cleanup EXIT

say "build"
l2_build
(cd "$top" && CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-2} cargo build -q --release -p paguro-vm)
l2_root "$VMWORK/l2root" >/dev/null

say "L2: the paguro host stack"
l2_start "$WIN_DISK"
cp "$RP_FILE" "$SHARE/rp.txt"
l2 "set -e
paguro-vm unlock --partition $PART --recovery-password-file /share/rp.txt --vmk-out /run/vmk --volume-add > /run/vol
mount -t ntfs3 -o ro /dev/mapper/paguro-plain /mnt/p
pgctl ident /mnt/p/$IMAGE > /run/ident
pgctl fiemap /mnt/p/$IMAGE > /share/fiemap
umount /mnt/p
pgctl claim \$(tail -1 /run/vol) \$(cat /run/ident) raw > /run/claim
pgctl crosscheck-list \$(cat /run/claim) /share/fiemap
mount -t vfat -o ro /dev/vda1 /mnt/esp
mkdir -p /run/paguro/vm
paguro-vm prepare --disk /dev/vda --partition $PART --volume-guid $VOLUME_GUID \
    --volume-id \$(tail -1 /run/vol) --vmk-file /run/vmk --esp-dir /mnt/esp --work /run/paguro/vm > /dev/null
umount /mnt/esp
cp /run/paguro/vm/session.json /run/paguro/vm/bek.img /run/paguro/vm/table.txt /share/
pgctl status" | tee "$VMWORK/l2-setup.txt"
python3 - "$SHARE/session.json" "$SHARE/fiemap" "$PART" > "$SHARE/hash.sh" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
print("set -e")
for (st, n, _), name in zip(s["owned"], s["owned_names"]):
    print(f"echo {name} $(dd if={sys.argv[3]} bs=512 skip={st} count={n} 2>/dev/null | sha256sum | cut -c1-16)")
for i, l in enumerate(open(sys.argv[2])):
    st, n = l.split()
    print(f"echo image-extent-{i} $(dd if={sys.argv[3]} bs=512 skip={st} count={n} 2>/dev/null | sha256sum | cut -c1-16)")
PY
l2 "sh /share/hash.sh" > "$VMWORK/pre-hashes.txt"
result "owned ranges" "$(python3 -c "import json;s=json.load(open('$SHARE/session.json'));print(', '.join(f'{n}@{a}+{l}' for (a,l,_),n in zip(s['owned'],s['owned_names'])))")"
v0=$(python3 -c "import json;print(json.load(open('$SHARE/session.json'))['volume_at']//512)")
read -r img_start img_len < "$SHARE/fiemap"
out=$(l2 "dd if=/dev/mapper/paguro-vmdisk of=/dev/null bs=512 skip=$((v0 + img_start)) count=8 iflag=direct 2>&1 | head -1
dd if=/dev/mapper/paguro-vmdisk of=/dev/null bs=512 skip=$((v0 + img_start + img_len)) count=8 iflag=direct 2>&1 | tail -1
dd if=/dev/mapper/paguro-vmdisk of=/dev/null bs=512 skip=$((v0 + img_start - 8)) count=8 iflag=direct 2>&1 | tail -1") || true
expect "view B: the image's first sectors through paguro-vmdisk" "$(sed -n 1p <<<"$out")" 'Input/output error'
expect "view B: the sectors after it" "$(sed -n 2p <<<"$out")" '8\+0 records out'
expect "view B: the sectors before it" "$(sed -n 3p <<<"$out")" '8\+0 records out'
out=$(l2 "dmsetup create paguro-c-try --table \"0 \$(blockdev --getsz $PART) paguro-volume \$(tail -1 /run/vol) c\" 2>&1; echo rc=\$?") || true
expect "view C refused while view B is loaded" "$(tail -1 <<<"$out")" 'rc=[1-9]'
md0=$(python3 -c "import json;s=json.load(open('$SHARE/session.json'));print([a for (a,l,_),n in zip(s['owned'],s['owned_names']) if n=='metadata-0'][0])")
out=$(l2 "dd if=/dev/mapper/paguro-vmdisk bs=512 skip=$((v0 + md0)) count=128 2>/dev/null > /run/served-md0
dd if=$PART bs=512 skip=$md0 count=128 2>/dev/null > /run/raw-md0
head -c 8 /run/served-md0; echo; cmp -s /run/served-md0 /run/raw-md0 && echo same || echo substituted")
expect "the guest is served substituted metadata, not the disk's" "$(tr '\n' ' ' <<<"$out")" '-FVE-FS- substituted'
vol_sectors=$(python3 -c "import json;print(json.load(open('$SHARE/session.json'))['volume_bytes']//512)")
out=$(l2 "mkdir -p /mnt/bek /mnt/bde /mnt/dis
mount -o loop,ro /run/paguro/vm/bek.img /mnt/bek && bek=\$(ls /mnt/bek/*.BEK)
dmsetup create paguro-vmc --readonly --table \"0 $vol_sectors linear /dev/mapper/paguro-vmdisk $v0\" && dmsetup mknodes
bdeinfo -s \$bek /dev/mapper/paguro-vmc 2>&1 | grep -aE 'Is locked|Number of key protectors|External key' | tr -s ' \t' ' '
bdemount -s \$bek /dev/mapper/paguro-vmc /mnt/bde && echo libbde \$(dd if=/mnt/bde/bde1 bs=1 skip=3 count=8 2>/dev/null) && umount /mnt/bde
dislocker-fuse -V /dev/mapper/paguro-vmc -f \$bek -- /mnt/dis >/dev/null 2>&1 && echo dislocker \$(dd if=/mnt/dis/dislocker-file bs=1 skip=3 count=8 2>/dev/null) && umount /mnt/dis
dmsetup remove paguro-vmc; umount /mnt/bek" 2>&1) || true
echo "$out" > "$VMWORK/oracles-real.txt"
expect "libbde opens the real volume through the stack with the session's .BEK" "$(grep -a '^libbde' <<<"$out")" '^libbde NTFS$'
expect "dislocker too" "$(grep -a '^dislocker' <<<"$out")" '^dislocker NTFS$'
l2 "(setsid qemu-nbd --persistent --shared=4 --export-name=vmdisk --format=raw --cache=none --aio=native \
    --bind=0.0.0.0 --port=10809 /dev/mapper/paguro-vmdisk > /share/qemu-nbd.log 2>&1 & echo \$! > /run/nbd.pid); sleep 1" >/dev/null

say "Windows: paguro-vm launch"
# The host workloads' memory.max (DESIGN.md §4.5), on a scratch cgroup
# with nothing in it: the plumbing, without touching the real host's.
HOSTCG=/sys/fs/cgroup/paguro-vm-e2e-host
rmdir "$HOSTCG" 2>/dev/null || true
mkdir "$HOSTCG"
rm -f "$WIN/vars.fd"
(cd "$WIN" && "$vm" launch --work "$WIN" --nbd "127.0.0.1:$L2_NBD_PORT/vmdisk" --bek "$SHARE/bek.img" \
    --bus ahci --nat-hostfwd "tcp:127.0.0.1:$SSH_PORT-:22" --hostonly "socket:$VMWORK/paguro0.sock" \
    --no-vsock --record-writes "$VMWORK/writes.log" --memory 6144 --cpus 4 --scope-memory-max 8G \
    --driver-timeout 300 --bek-unplug-after 30 --host-cgroup "$HOSTCG" \
    -- -qmp "unix:$WIN/qmp-test.sock,server=on,wait=off" > "$VMWORK/launch.log" 2>&1) &
t0=$(date +%s)
for i in $(seq 90); do
    sleep 10
    [ "$i" = 3 ] && shim screenshot "$SHOTS/01-boot.png" >/dev/null 2>&1 || true
    wssh 'echo up' 2>/dev/null | grep -aq up && break
done
wssh 'echo up' 2>/dev/null | grep -aq up || { shim screenshot "$SHOTS/boot-failed.png" || true; die "Windows did not come up"; }
result "boot to SSH" "$(( $(date +%s) - t0 )) s"
result "host workloads' memory.max while the VM runs" "$(cat "$HOSTCG/memory.max") ($(grep -a 'memory:' "$VMWORK/launch.log" | tr '\n' ' '))"
# The driver gate: the report on the agent port, before the timeout.
wscp "$here/agent-report.ps1" paguro@127.0.0.1:C:/winvm/
wssh 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\winvm\agent-report.ps1' 2>&1 | tr -d '\r' > "$VMWORK/agent.txt" || true
tail -1 "$VMWORK/agent.txt"
sleep 3
expect "the launcher's driver gate saw the report" "$(grep -a 'driver:' "$VMWORK/launch.log")" 'reported after'
phase boot
shim wait-screen 240 --stable 10 >/dev/null 2>&1 || true
shim screenshot "$SHOTS/02-desktop.png" >/dev/null
grep -a 'BEK' "$VMWORK/launch.log" | tee -a "$RES" || true

say "guest checks"
wscp "$here/guest-checks.ps1" "$here/eio-probe.ps1" "$here/q1-probe.ps1" paguro@127.0.0.1:C:/winvm/
wssh 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\winvm\guest-checks.ps1' | tr -d '\r' > "$VMWORK/guest-checks.txt"
g=$VMWORK/guest-checks.txt
expect "BitLocker protection in the VM" "$(check bitlocker.protection "$g")" '^On$'
expect "the session's external key is a protector" "$(check bitlocker.protectors "$g")" "ExternalKey=\\{$(python3 -c "import json;print(json.load(open('$SHARE/session.json'))['bek_name'][:-4])")\\}"
expect "testsigning (synthetic ESP only)" "$(check bcd.testsigning "$g")" 'Yes'
expect "the minifilter is loaded and attached" "$(check minifilter "$g")" '^PaguroFlt 1 '
expect "SMBIOS type 11 marker" "$(check smbios.oemstrings "$g")" 'paguro-vm/1'
host_uuid=$("$vm" identity | python3 -c "import json,sys;print(json.load(sys.stdin)['uuid'] or '')")
expect "SMBIOS UUID = the host's" "$(check smbios.uuid "$g" | tr A-Z a-z)" "^${host_uuid}\$"
host_mac=$("$vm" identity | python3 -c "import json,sys;print((json.load(sys.stdin)['mac'] or '').replace(':','-').upper())")
expect "the NAT adapter carries the host's MAC" "$(grep -a '^CHECK nic\.' "$g" | tr '\n' ' ')" "$host_mac"
expect "no WinRE, three partitions" "$(grep -ac '^CHECK partition\.' "$g")" '^3$'
expect "no TPM in the VM" "$(check tpm "$g")" '^0$'
expect "a guest write lands" "$(check write.file "$g")" '^paguro-vm '
result "guest facts" "$(grep -aE '^CHECK (cpu|hypervisor.present|smbios.vendor|disk.0|winre|secureboot|activation|disk.errors):' "$g" | sed 's/^CHECK //' | tr '\n' ';')"
# The same, on the desktop: an elevated console (Run dialog, ctrl+shift+enter).
shim key win-r >/dev/null; sleep 4
shim type 'cmd /k manage-bde -status C: & bcdedit /enum {current} | findstr testsigning & fltmc filters' >/dev/null
shim key ctrl-shift-ret >/dev/null
sleep 20
shim screenshot "$SHOTS/03-console.png" >/dev/null

say "the private link (§5c): /mnt/c (§5b Mode 1) and L: over it"
l2 "paguro-vm link --ifname \$(sed -n 's/.*link=//p' /share/l2-nics)" >/dev/null
python3 -c "import secrets;print(secrets.token_urlsafe(24))" > "$SHARE/smb-secret"
python3 -c "import secrets;print(secrets.token_urlsafe(24))" > "$SHARE/host-secret"
# The Linux side's Samba first (L:), then the Windows side.
out=$(l2 "mkdir -p /mnt/l/alpine && echo 'hello from the Linux side' > /mnt/l/alpine/hello.txt && chown -R 1000:1000 /mnt/l
paguro-vm samba --root /mnt/l --state /run/paguro/samba --secret-file /share/host-secret && echo samba-up" 2>&1) || true
echo "$out" > "$VMWORK/samba.txt"
expect "Samba in netns paguro" "$(tail -1 <<<"$out")" 'samba-up'
"$vm" windows-provision > "$VMWORK/provision.ps1"
wscp "$VMWORK/provision.ps1" paguro@127.0.0.1:C:/winvm/provision.ps1
out=$(wssh "powershell -NoProfile -ExecutionPolicy Bypass -File C:\\winvm\\provision.ps1 -SmbSecret $(cat "$SHARE/smb-secret") -HostSecret $(cat "$SHARE/host-secret")" 2>&1 | tr -d '\r') || true
echo "$out" > "$VMWORK/provision.txt"
expect "Windows side of the link provisioned" "$(grep -a 'private link' <<<"$out")" 'private link ready'
out=$(l2 "paguro-vm mount-c --target /mnt/c --secret-file /share/smb-secret && ls /mnt/c/paguro && cat /mnt/c/paguro/written-in-vm.txt && grep ' /mnt/c ' /proc/mounts" 2>&1) || true
echo "$out" > "$VMWORK/mnt-c.txt"
expect "/mnt/c: C: over SMB from the VM, mounted inside netns paguro" "$(tr '\n' ' ' <<<"$out")" 'written-in-vm.txt.*paguro-vm .*//169.254.244.2/paguro-c /mnt/c cifs'
out=$(l2 "/sbin/ip -n paguro -brief addr; /sbin/ip -brief addr | grep -c 169.254.244 || true") || true
expect "the link exists only in netns paguro" "$(tr '\n' ' ' <<<"$out")" 'paguro0 +UP +169.254.244.1/30.* 0 *$'
l2 "umount /mnt/c" >/dev/null || true
# Over SSH the user's credential vault is out of reach (key logon), so the
# test connects with the credential given; the agent, in the user's
# session, uses the mapping the provisioning saved.
out=$(wssh "net use \\\\169.254.244.1\\l /user:paguro $(cat "$SHARE/host-secret") & type \\\\169.254.244.1\\l\\alpine\\hello.txt" 2>&1 | tr -d '\r') || true
echo "$out" >> "$VMWORK/samba.txt"
expect "L: from Windows over the link" "$(tr '\n' ' ' <<<"$out")" 'hello from the Linux side'
l2 "tail -30 /run/paguro/samba/log.smbd; dmesg | grep -i cifs | tail -5" >> "$VMWORK/samba.txt" 2>&1 || true

say "BitLocker in the guest (absorbed, §6; Q24)"
phase link
wssh 'manage-bde -protectors -disable C:' > "$VMWORK/bde-suspend.txt" 2>&1 || true
expect "suspend in the session (clear key)" "$(wssh 'manage-bde -status C:' | tr -d '\r' | grep -a 'Protection Status')" 'Protection Off'
phase suspend
wssh 'manage-bde -protectors -enable C:' > "$VMWORK/bde-resume.txt" 2>&1 || true
result "resume in the session" "$(wssh 'manage-bde -status C:' | tr -d '\r' | grep -a 'Protection Status' | tr -s ' ') / $(tr -d '\r' < "$VMWORK/bde-resume.txt" | grep -av '^$' | tail -2 | tr '\n' ' ')"
phase resume
out=$(wssh 'manage-bde -protectors -add C: -RecoveryPassword' | tr -d '\r')
rid=$(grep -aoE '\{[0-9A-F-]{36}\}' <<<"$out" | head -1)
result "protector added in the session" "$rid"
phase add-protector
[ -n "$rid" ] && wssh "manage-bde -protectors -delete C: -id $rid" > /dev/null 2>&1 || true
phase delete-protector

say "S3 suspend and resume (Q24)"
wssh 'powercfg /a' 2>&1 | tr -d '\r' > "$VMWORK/powercfg.txt"
# Only the "are available" section counts (it ends where "are not" starts).
states=$(sed -n '/ are available/,/ are not available/p' "$VMWORK/powercfg.txt")
if grep -aq 'Standby (S3)' <<<"$states"; then
    phase before-s3
    (wssh 'rundll32.exe powrprof.dll,SetSuspendState 0,1,0' >/dev/null 2>&1 &)
    st=""
    for _ in $(seq 60); do
        st=$(qmp "$WIN/qmp-test.sock" '{"execute":"query-status"}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["return"]["status"])')
        [ "$st" = suspended ] && break
        sleep 2
    done
    expect "the guest suspends to S3" "$st" '^suspended$'
    phase suspended
    sleep 10
    qmp "$WIN/qmp-test.sock" '{"execute":"system_wakeup"}' >/dev/null
    for _ in $(seq 60); do wssh 'echo up' 2>/dev/null | grep -aq up && break; sleep 3; done
    expect "and resumes" "$(wssh 'manage-bde -status C:' 2>&1 | tr -d '\r' | grep -a 'Lock Status')" 'Unlocked'
    phase resumed
else
    result "S3" "not offered by the guest: $(sed -n '/Standby (S3)/,/^$/p' "$VMWORK/powercfg.txt" | tr '\n\t' '  ' | tr -s ' ')"
fi

say "the image from the guest (view B's EIO)"
out=$(WSSH_TIMEOUT=900 wssh 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\winvm\eio-probe.ps1' 2>&1 | tr -d '\r') || true
echo "$out" > "$VMWORK/eio.txt"
expect "an ordinary file reads" "$(check eio.hosts <(echo "$out"))" '^read '
expect "the image's clusters do not" "$(check eio.linux.img <(echo "$out"))" '^error: '
result "I/O errors reported to the guest" "$(grep -ao 'disk: [0-9]* I/O error' "$VMWORK/launch.log" | tail -1)"
phase eio

if [ "${PAGURO_Q1:-0}" = 1 ]; then
    say "§11 Q1-Q3: writes into the image and its relocation, from the guest"
    out=$(WSSH_TIMEOUT=2400 wssh 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\winvm\q1-probe.ps1' 2>&1 | tr -d '\r') || true
    echo "$out" > "$VMWORK/q1.txt"
    grep -a -E '^(CHECK q1\.|EVENT )' <<<"$out" | sed 's/^CHECK q1\./RESULT q1 /' | tee -a "$RES"
    expect "Q1/Q2: the image's extents are unchanged in the guest's own view" "$(check q1.extents-unchanged <(echo "$out"))" '^yes'
    expect "Q1/Q2: ... and after the optimiser" "$(check q1.extents-unchanged-after-defrag <(echo "$out"))" '^yes'
    phase q1
    shim screenshot "$SHOTS/03-q1.png" >/dev/null 2>&1 || true
fi

say "shutdown"
qpid=$(cat "$WIN/qemu.pid")
if [ "${PAGURO_Q1_KILL:-0}" = 1 ]; then
    # Q3: no shutdown, no flush — whatever NTFS held stays unwritten.
    kill -9 "$qpid" 2>/dev/null || true
    result "session end" "QEMU killed (PAGURO_Q1_KILL)"
else
    wssh 'shutdown /s /t 0' >/dev/null 2>&1 || true
fi
for _ in $(seq 60); do [ -e "/proc/$qpid" ] || break; sleep 5; done
sleep 3
grep -aE 'BEK|driver|disk:|QEMU exited|memory' "$VMWORK/launch.log" | tee -a "$RES" || true
expect "memory.max restored after the VM" "$(cat "$HOSTCG/memory.max")" '^max$'
rmdir "$HOSTCG" 2>/dev/null || true
phase shutdown

say "Q24: what Windows wrote to BitLocker's sectors"
python3 "$here/q24.py" "$VMWORK/writes.log" "$SHARE/session.json" --phases "$PHASES" | tee "$VMWORK/q24.txt"

say "L2: nothing reached the disk's BitLocker sectors or the image"
l2 "kill \$(cat /run/nbd.pid); sleep 1; paguro-vm absorbed --work /run/paguro/vm" > "$VMWORK/absorbed.json" || true
result "absorbed (buffer vs served)" "$(cat "$VMWORK/absorbed.json")"
l2 "sh /share/hash.sh" > "$VMWORK/post-hashes.txt"
if cmp -s "$VMWORK/pre-hashes.txt" "$VMWORK/post-hashes.txt"; then
    pass "every BitLocker-owned sector and the image's extents unchanged on disk ($(wc -l < "$VMWORK/pre-hashes.txt") ranges)"
else
    fail "on-disk ranges changed: $(diff "$VMWORK/pre-hashes.txt" "$VMWORK/post-hashes.txt" | tr '\n' ' ')"
fi
out=$(l2 "paguro-vm teardown --work /run/paguro/vm 2>&1; pgctl status
dmsetup create paguro-c-try --table \"0 \$(blockdev --getsz $PART) paguro-volume \$(tail -1 /run/vol) c\" && echo view-c-loads && dmsetup remove paguro-c-try
mount -t ntfs3 -o ro /dev/mapper/paguro-plain /mnt/p && cat /mnt/p/paguro/written-in-vm.txt; umount /mnt/p") || true
echo "$out" | tee "$VMWORK/l2-post.txt"
expect "view C loads once view B is gone" "$out" 'view-c-loads'
expect "the guest's file is on the volume" "$out" '^paguro-vm '
l2_stop

say "native boot of the same disk (TPM, no marker)"
nat=$VMWORK/native
rm -rf "$nat" && mkdir -p "$nat"
ln -s "$VMWORK/l2disk.qcow2" "$nat/base.qcow2"
cp "$NATIVE_VARS" "$nat/base-vars.fd"
ln -s "$(dirname "$WIN_KEY")" "$nat/keys"
ntpm=$HOME/.cache/winvm-swtpm-e2e
rm -rf "$ntpm" && mkdir -p "$ntpm" && cp -a "$NATIVE_TPM" "$ntpm/base-tpm"
export WINVM_DIR=$nat WINVM_TPM_DIR=$ntpm WINVM_SSH_PORT=$NATIVE_SSH_PORT WINVM_MEM=6G
"$W" start --timeout 600 >/dev/null
SSH_PORT=$NATIVE_SSH_PORT
out=$(wssh 'manage-bde -protectors -get C: & manage-bde -status C: & bcdedit /enum {current} | findstr testsigning & fltmc filters & type C:\paguro\written-in-vm.txt' | tr -d '\r')
echo "$out" > "$VMWORK/native.txt"
if [ "${PAGURO_Q1:-0}" = 1 ]; then
    # Q3: native Windows after the refused writes (and, with PAGURO_Q1_KILL,
    # the interruption): the dirty bit, an online scan, the image's extents.
    wscp "$here/q1-probe.ps1" paguro@127.0.0.1:C:/winvm/ || true
    q3=$(WSSH_TIMEOUT=1200 wssh 'fsutil dirty query C: & chkdsk C: /scan & fsutil file queryextents C:\paguro\linux.img' 2>&1 | tr -d '\r') || true
    echo "$q3" > "$VMWORK/q3-native.txt"
    result "Q3 native: dirty bit" "$(grep -a -m1 -i 'dirty' <<<"$q3")"
    result "Q3 native: chkdsk /scan" "$(grep -a -m1 -i -E 'found no problems|found problems|errors found' <<<"$q3")"
    result "Q3 native: bad sectors" "$(grep -a -m1 -i 'bad sectors' <<<"$q3")"
    result "Q3 native: image extents" "$(grep -a -i 'VCN' <<<"$q3" | tr '\n' ' ')"
fi
"$W" screenshot "$SHOTS/04-native.png" >/dev/null
"$W" stop >/dev/null
expect "native: TPM unseals (booted without a prompt), protection on" "$(grep -a 'Protection Status' <<<"$out")" 'Protection On'
if grep -aq 'External Key' <<<"$out"; then fail "native: the session's external key persisted"; else pass "native: no external key (the substitute was session-only)"; fi
if grep -aq 'PaguroFlt' <<<"$out"; then fail "native: PaguroFlt loaded"; else pass "native: PaguroFlt not loaded (test-signed, testsigning off natively)"; fi
expect "native: the file written in the VM" "$out" 'paguro-vm '

say "results"
cat "$RES"
[ "$fails" = 0 ] && echo "RESULT: ALL PASS" || { echo "RESULT: $fails FAILED"; exit 1; }
