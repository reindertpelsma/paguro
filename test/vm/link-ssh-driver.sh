#!/bin/sh
# Runs once, inside the throwaway VM `test/vm/link-ssh.sh` builds, as the
# systemd unit `paguro-link-ssh-test.service`. Prints PASS:/FAIL:/RESULT:
# lines the host script greps for, then powers off.
exec >/dev/console 2>&1
set -u
export PATH=/usr/local/bin:/bin:/sbin:/usr/bin:/usr/sbin
FAIL=0
ok()  { echo "PASS: $1"; }
bad() { echo "FAIL: $1"; FAIL=1; }

STATE=/etc/paguro/link
UNITDIR=/etc/systemd/system

# `paguro0`, inside netns paguro, first: in production this is the VM
# launcher's job (`paguro_vm::net::attach_link`, moving the tap in and
# addressing it) and normally already done by the time `paguro link setup`
# runs; the socket unit binds 169.254.244.1 inside that namespace, so the
# address must exist there before (or logically "at the same time as") the
# socket starts, not after.
echo "-- wiring a second netns as \"Windows\", and the link's own address --"
/sbin/ip netns add winclient || bad "ip netns add winclient"
/sbin/ip link add vethw type veth peer name vethh || bad "veth"
# `paguro link setup` (below) also does this (idempotently); done here first
# so paguro0 can be addressed before the socket unit tries to bind it.
/sbin/ip netns add paguro 2>/dev/null
/sbin/ip link set vethh netns paguro || bad "vethh -> netns paguro"
/sbin/ip -n paguro link set vethh name paguro0 || bad "rename to paguro0"
/sbin/ip -n paguro addr add 169.254.244.1/30 dev paguro0 || bad "address the link"
/sbin/ip -n paguro link set paguro0 up
/sbin/ip -n paguro link set lo up
/sbin/ip link set vethw netns winclient || bad "vethw -> netns winclient"
/sbin/ip netns exec winclient ip addr add 169.254.244.2/30 dev vethw || bad "address winclient"
/sbin/ip netns exec winclient /sbin/ip link set vethw up
/sbin/ip netns exec winclient /sbin/ip link set lo up

HOSTNS=$(readlink /proc/1/ns/net)
LINKNS=$(/sbin/ip netns exec paguro readlink /proc/self/ns/net)
if [ "$HOSTNS" = "$LINKNS" ]; then
    bad "test setup is broken: the host and netns paguro are the same namespace"
else
    ok "netns paguro ($LINKNS) is not the host namespace ($HOSTNS)"
fi

echo "-- paguro link setup --"
paguro link setup --user root --state-dir "$STATE" --unit-dir "$UNITDIR" \
    --sshd /usr/sbin/sshd || bad "link setup"

ssh-keygen -q -t ed25519 -N '' -C windows -f /root/winkey || bad "windows keypair"
paguro link setup --user root --state-dir "$STATE" --unit-dir "$UNITDIR" \
    --sshd /usr/sbin/sshd --windows-key /root/winkey.pub ||
    bad "link setup (with the windows key)"

grep -q 'from="169.254.244.2"' "$STATE/authorized_keys" ||
    bad "authorized_keys: no from= restriction on the windows key"

systemctl is-active --quiet paguro-ssh.socket && ok "paguro-ssh.socket is active" || {
    bad "paguro-ssh.socket did not come up"
    echo "-- debug: /sbin/ip netns list --"; /sbin/ip netns list; ls -la /run/netns
    echo "-- debug: systemctl status paguro-ssh.socket --"
    systemctl status --no-pager -l paguro-ssh.socket 2>&1
    echo "-- debug: sshd_config --"; cat "$STATE/sshd_config" 2>&1
}

SSH='ssh -o LogLevel=ERROR -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=5'

echo "-- the real login --"
OUT=$(/sbin/ip netns exec winclient $SSH -i /root/winkey root@169.254.244.1 \
    'readlink /proc/self/ns/net && whoami' 2>&1)
RC=$?
if [ $RC -eq 0 ]; then
    GOTNS=$(echo "$OUT" | sed -n 1p)
    WHO=$(echo "$OUT" | sed -n 2p)
    [ "$GOTNS" = "$HOSTNS" ] && ok "the shell runs in the HOST namespace ($GOTNS)" ||
        bad "the shell's namespace is $GOTNS, expected the host's ($HOSTNS); netns paguro is $LINKNS"
    [ "$WHO" = root ] && ok "logged in as root" || bad "unexpected whoami: $WHO"
else
    bad "ssh with the valid key failed (rc=$RC): $OUT"
fi

echo "-- refusals --"
ssh-keygen -q -t ed25519 -N '' -C intruder -f /root/badkey || bad "intruder keypair"
OUT=$(/sbin/ip netns exec winclient $SSH -i /root/badkey root@169.254.244.1 true 2>&1)
[ $? -ne 0 ] && ok "a key not in authorized_keys is refused" ||
    bad "the wrong key was accepted: $OUT"

OUT=$(/sbin/ip netns exec winclient ssh -o BatchMode=yes -o ConnectTimeout=5 \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    root@169.254.244.1 true 2>&1)
[ $? -ne 0 ] && ok "password authentication is refused" ||
    bad "password authentication was accepted: $OUT"

# The private link's /30 has only two usable addresses (.1 and .2), so a
# third address on the same segment does not exist to test against; the
# meaningful "wrong origin" case is the wrong namespace entirely — the
# HOST's own default namespace, which has no route to 169.254.244.0/30 at
# all, since that address lives only inside netns paguro.
OUT=$($SSH -i /root/winkey -o ConnectTimeout=3 root@169.254.244.1 true 2>&1)
[ $? -ne 0 ] && ok "unreachable from the host's own namespace" ||
    bad "reachable from the wrong namespace: $OUT"

echo "RESULT: $([ "$FAIL" -eq 0 ] && echo PASS || echo FAIL)"
# No poweroff.target in this minimal image (see test/vm/link-ssh.sh); busybox's
# own poweroff halts the VM directly.
poweroff -f
