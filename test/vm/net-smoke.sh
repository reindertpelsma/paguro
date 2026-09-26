#!/bin/bash
# test/vm/net-smoke.sh — the VM's LAN (DESIGN.md §5c), without Windows.
#
# A tiny busybox guest (host kernel, a throwaway initramfs — see
# kernel/dm-paguro/test/vm-lib.sh's vm_root, reused here) is booted with a
# tap exactly as `paguro-vm launch --net tap` configures it, and paguro's
# *production* code (`paguro-vm net-up`, i.e. lan.rs/dhcp.rs — the same
# nftables generator and DHCP server `launch` uses) sets up the host side:
# the tap's address, the `inet paguro` nftables table, DNS, Docker/firewalld
# coexistence, and the DHCP lease.
#
# Two passes, each its own QEMU/tap/net-up (paguro-vm's `--dmz` is fixed for
# a whole `launch` session, never toggled live, so this mirrors reality
# rather than reconfiguring networking under a running guest):
#
#   pass 1 (--dmz off): a routed LAN host (a netns that merely adds a route
#     for the VM's subnet through this host, on neither the tap nor the WAN
#     interface) must not reach the VM, and neither must the WAN side.
#   pass 2 (--dmz on): DHCP, DNS, TCP egress, the DMZ ladder (an unlisted
#     port reaches the guest; 445/22/80 do not) — and the same routed-LAN
#     host must *still* not reach the VM: turning the DMZ on for the WAN
#     interface must never open a hole for a host that simply routes the
#     VM's subnet through us on some other link.
#
# The DMZ's "LAN interface" and the routed-LAN-host's link are both private
# veth pairs this script creates and removes (never the host's real
# uplink): this is a shared lab host, so nftables DNAT/DROP for a lab test
# never touches its real public/LAN NIC. Everything this script creates is
# uniquely named and torn down by the trap below, even on failure.

set -u
top=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
# shellcheck source=/dev/null
. "$top/kernel/dm-paguro/test/vm-lib.sh"

WORK=${PAGURO_NET_SMOKE_WORK:-/data/paguro-work/target-vm-net/net-smoke}
TARGET_DIR=${CARGO_TARGET_DIR:-/data/paguro-work/target-vm-net}
TAG=$$
LAN_IF="pgtapsmk$((TAG % 10000))"
WAN_IF="pgwsmk$((TAG % 10000))h"
PEER_IF="pgwsmk$((TAG % 10000))p"
NETNS="pgwsmk$((TAG % 10000))"
SUBNET=198.19.249.0/24
GUEST_IP=198.19.249.2
HOST_IP=198.19.249.1
WAN_HOST_IP=10.250.77.1
WAN_PEER_IP=10.250.77.2
ROUTED_HOST_IF="pgrtsmk$((TAG % 10000))h"
ROUTED_PEER_IF="pgrtsmk$((TAG % 10000))p"
ROUTED_NETNS="pgrtsmk$((TAG % 10000))"
ROUTED_HOST_IP=10.250.88.1
ROUTED_PEER_IP=10.250.88.2
GUEST_MAC=52:54:00:5a:5b:5c
DMZ_OPEN_PORT=18734
DMZ_NEVER_PORT=445
DMZ_LINUX_PORT=80   # this host really listens here (see below): proves the
                     # dynamic linux_ports exclusion, not just the static one
PEER_HTTP_PORT=8080
UNIT="pgvm-net-smoke-$TAG"

fail=0
say() { printf '\n### %s\n' "$*"; }
ok()  { echo "PASS: $1"; }
bad() { echo "FAIL: $1"; fail=1; }

QEMU_PID=""
NETUP_PID=""
PEER_HTTPD_PID=""
VM=""
IP_FORWARD_BEFORE=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "?")

# stop_netup / stop_qemu: used both between passes and at final cleanup.
stop_netup() {
    [ -n "$NETUP_PID" ] || return 0
    kill -0 "$NETUP_PID" 2>/dev/null || { NETUP_PID=""; return 0; }
    kill -TERM "$NETUP_PID" 2>/dev/null
    for _ in $(seq 30); do kill -0 "$NETUP_PID" 2>/dev/null || break; sleep 0.3; done
    kill -0 "$NETUP_PID" 2>/dev/null && kill -KILL "$NETUP_PID" 2>/dev/null
    NETUP_PID=""
}
stop_qemu() {
    [ -n "$QEMU_PID" ] || return 0
    kill -0 "$QEMU_PID" 2>/dev/null || { QEMU_PID=""; return 0; }
    kill -TERM "$QEMU_PID" 2>/dev/null
    for _ in $(seq 20); do kill -0 "$QEMU_PID" 2>/dev/null || break; sleep 0.3; done
    kill -0 "$QEMU_PID" 2>/dev/null && kill -KILL "$QEMU_PID" 2>/dev/null
    QEMU_PID=""
}

cleanup() {
    say "cleanup"
    stop_netup
    stop_qemu
    if [ -n "$PEER_HTTPD_PID" ]; then
        kill "$PEER_HTTPD_PID" 2>/dev/null || true
    fi
    # A safety net in case net-up's own guard didn't run (e.g. -KILL above):
    # idempotent, and must leave nothing behind either way.
    [ -n "$VM" ] && "$VM" net-down --tap "$LAN_IF" >/dev/null 2>&1
    ip link delete "$LAN_IF" >/dev/null 2>&1 || true
    ip netns delete "$NETNS" >/dev/null 2>&1 || true
    ip link delete "$WAN_IF" >/dev/null 2>&1 || true
    ip netns delete "$ROUTED_NETNS" >/dev/null 2>&1 || true
    ip link delete "$ROUTED_HOST_IF" >/dev/null 2>&1 || true

    say "verifying cleanup"
    ip link show "$LAN_IF" >/dev/null 2>&1 && bad "tap $LAN_IF still present" || ok "tap $LAN_IF is gone"
    nft list table inet paguro >/dev/null 2>&1 && bad "nft table inet paguro still present" || ok "nft table inet paguro is gone"
    ip netns list 2>/dev/null | grep -q "^$NETNS" && bad "netns $NETNS still present" || ok "netns $NETNS is gone"
    ip link show "$WAN_IF" >/dev/null 2>&1 && bad "veth $WAN_IF still present" || ok "veth $WAN_IF is gone"
    ip netns list 2>/dev/null | grep -q "^$ROUTED_NETNS" && bad "netns $ROUTED_NETNS still present" || ok "netns $ROUTED_NETNS is gone"
    ip link show "$ROUTED_HOST_IF" >/dev/null 2>&1 && bad "veth $ROUTED_HOST_IF still present" || ok "veth $ROUTED_HOST_IF is gone"
    now=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "?")
    [ "$now" = "$IP_FORWARD_BEFORE" ] && ok "ip_forward restored ($now)" || bad "ip_forward is $now, was $IP_FORWARD_BEFORE"
    if iptables -C DOCKER-USER -i "$LAN_IF" -j ACCEPT 2>/dev/null; then
        bad "DOCKER-USER still has a rule for $LAN_IF"
    else
        ok "DOCKER-USER has no rule for $LAN_IF"
    fi
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "$LAN_IF"; then
        bad "ufw still has a rule mentioning $LAN_IF"
    else
        ok "ufw has no rule mentioning $LAN_IF"
    fi

    if [ "$fail" = 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fi
    exit "$fail"
}
trap cleanup EXIT INT TERM

say "build paguro-vm (release)"
(cd "$top" && CARGO_TARGET_DIR="$TARGET_DIR" cargo build -q --release -p paguro-vm) || { bad "build"; exit 1; }
VM="$TARGET_DIR/release/paguro-vm"
[ -x "$VM" ] || { bad "no $VM"; exit 1; }

say "the fake LAN: a private veth pair ($WAN_IF / $PEER_IF), never the host's real NIC"
ip link show "$WAN_IF" >/dev/null 2>&1 && { bad "$WAN_IF already exists (stale from a previous run?)"; exit 1; }
ip netns list 2>/dev/null | grep -q "^$NETNS" && { bad "netns $NETNS already exists"; exit 1; }
ip link add "$WAN_IF" type veth peer name "$PEER_IF" || { bad "veth add"; exit 1; }
ip netns add "$NETNS" || { bad "netns add"; exit 1; }
ip link set "$PEER_IF" netns "$NETNS"
ip addr add "$WAN_HOST_IP/30" dev "$WAN_IF"
ip link set "$WAN_IF" up
ip netns exec "$NETNS" ip addr add "$WAN_PEER_IP/30" dev "$PEER_IF"
ip netns exec "$NETNS" ip link set "$PEER_IF" up
ip netns exec "$NETNS" ip link set lo up
ok "veth pair up: host $WAN_HOST_IP, peer $WAN_PEER_IP"

say "a routed LAN host: a second netns that merely routes the VM's subnet through this host (never DNAT'd, never the WAN interface)"
ip link show "$ROUTED_HOST_IF" >/dev/null 2>&1 && { bad "$ROUTED_HOST_IF already exists (stale from a previous run?)"; exit 1; }
ip netns list 2>/dev/null | grep -q "^$ROUTED_NETNS" && { bad "netns $ROUTED_NETNS already exists"; exit 1; }
ip link add "$ROUTED_HOST_IF" type veth peer name "$ROUTED_PEER_IF" || { bad "routed veth add"; exit 1; }
ip netns add "$ROUTED_NETNS" || { bad "routed netns add"; exit 1; }
ip link set "$ROUTED_PEER_IF" netns "$ROUTED_NETNS"
ip addr add "$ROUTED_HOST_IP/30" dev "$ROUTED_HOST_IF"
ip link set "$ROUTED_HOST_IF" up
ip netns exec "$ROUTED_NETNS" ip addr add "$ROUTED_PEER_IP/30" dev "$ROUTED_PEER_IF"
ip netns exec "$ROUTED_NETNS" ip link set "$ROUTED_PEER_IF" up
ip netns exec "$ROUTED_NETNS" ip link set lo up
# The whole point of the bug under test: this host adds a route for the
# VM's subnet via us, on an interface that is neither the tap nor the WAN —
# nothing about our own nftables state should ever let it reach the VM.
ip netns exec "$ROUTED_NETNS" ip route add "$SUBNET" via "$ROUTED_HOST_IP" dev "$ROUTED_PEER_IF"
ok "routed-LAN-host netns up: host $ROUTED_HOST_IP, peer $ROUTED_PEER_IP, routes $SUBNET via us"

say "the fallback local HTTP server (peer netns): TCP-egress target (DESIGN.md-sanctioned when there's no real path out)"
mkdir -p "$WORK/www"
echo "paguro-net-smoke-peer-http" > "$WORK/www/index.html"
ip netns exec "$NETNS" busybox httpd -f -p "$PEER_HTTP_PORT" -h "$WORK/www" &
PEER_HTTPD_PID=$!

say "the guest: a busybox root with udhcpc/wget/nslookup/nc, host kernel (reused for both passes)"
rm -rf "$WORK/root"
vm_root "$WORK/root"
r=$WORK/root
vm_bin "$(command -v ip)" sbin/ip
for a in udhcpc wget nslookup nc httpd; do [ -e "$r/bin/$a" ] || ln -s busybox "$r/bin/$a"; done
mkdir -p "$r/etc/udhcpc"
cat > "$r/etc/udhcpc/script" <<'EOF'
#!/bin/sh
[ "$1" = bound ] || [ "$1" = renew ] || exit 0
ip addr flush dev "$interface" 2>/dev/null
ip addr add "$ip/24" dev "$interface"
ip link set "$interface" up
[ -n "${router:-}" ] && ip route replace default via "$router" dev "$interface"
: > /etc/resolv.conf
for d in ${dns:-}; do echo "nameserver $d" >> /etc/resolv.conf; done
{
    echo "DHCP_IP=$ip"
    echo "DHCP_ROUTER=${router:-}"
    echo "DHCP_DNS=${dns:-}"
} > /run/dhcp-result
EOF
chmod +x "$r/etc/udhcpc/script"
for p in $DMZ_OPEN_PORT $DMZ_NEVER_PORT $DMZ_LINUX_PORT 22; do
    mkdir -p "$r/www$p"
    echo "PAGURO-GUEST-$p" > "$r/www$p/index.html"
done
vm_init_head > "$r/init"
cat >> "$r/init" <<EOF
mkdir -p /run
ip link set eth0 up
udhcpc -i eth0 -s /etc/udhcpc/script -n -q -t 10 -T 2 -A 3 && ok "dhcp lease" || bad "dhcp lease"
. /run/dhcp-result 2>/dev/null
echo "GUEST: ip=\$DHCP_IP router=\$DHCP_ROUTER dns=\$DHCP_DNS"
[ "\$DHCP_IP" = "$GUEST_IP" ] && ok "dhcp gave $GUEST_IP" || bad "dhcp gave \$DHCP_IP, wanted $GUEST_IP"
nslookup example.com >/tmp/ns.out 2>&1
if grep -qE 'Address.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' /tmp/ns.out && ! grep -q "can't resolve" /tmp/ns.out; then
    ok "dns resolves example.com"
else
    bad "dns did not resolve example.com"
fi
cat /tmp/ns.out
if wget -q -T 5 -O- http://$WAN_PEER_IP:$PEER_HTTP_PORT/ | grep -q paguro-net-smoke-peer-http; then
    ok "tcp egress reached the peer's http server"
else
    bad "tcp egress to the peer's http server failed"
fi
for p in $DMZ_OPEN_PORT $DMZ_NEVER_PORT $DMZ_LINUX_PORT 22; do
    httpd -f -p \$p -h /www\$p &
done
sleep 1
echo GUEST-READY
# Repeated for the rest of this boot: every fresh outbound connection's
# reply must keep working throughout — the "established,related" rule.
( for i in \$(seq 1 6); do
      sleep 3
      if wget -q -T 3 -O- http://$WAN_PEER_IP:$PEER_HTTP_PORT/ | grep -q paguro-net-smoke-peer-http; then
          echo "EGRESS-OK \$i"
      else
          echo "EGRESS-FAIL \$i"
      fi
  done ) &
sleep 30
poweroff -f
EOF
chmod +x "$r/init"
(cd "$r" && find . | cpio -o -H newc 2>/dev/null | gzip -1) > "$r.cpio.gz"

KERNEL="/boot/vmlinuz-$(uname -r)"
LOG="$WORK/serial.log"

# boot_pass_qemu: a fresh QEMU (fresh tap, since QEMU itself creates it),
# waiting until the tap exists.
boot_pass_qemu() {
    : > "$LOG"
    rm -f "$WORK/qemu.pid"
    XDG_RUNTIME_DIR=/run/user/0 systemd-run --user --scope --unit="$UNIT-$1" -p MemoryMax=1G -p MemorySwapMax=0 -- \
        qemu-system-x86_64 -name pgvm-net-smoke -machine q35,accel=kvm -cpu host -smp 2 -m 512 \
        -nographic -no-reboot -kernel "$KERNEL" -initrd "$r.cpio.gz" \
        -append "console=ttyS0 quiet panic=-1" \
        -netdev tap,id=nat,ifname="$LAN_IF",script=no,downscript=no,vhost=on \
        -device virtio-net-pci,netdev=nat,id=natdev,mac=$GUEST_MAC \
        -pidfile "$WORK/qemu.pid" \
        > "$LOG" 2>&1 &
    disown
    for _ in $(seq 100); do [ -s "$WORK/qemu.pid" ] && break; sleep 0.2; done
    QEMU_PID=$(cat "$WORK/qemu.pid" 2>/dev/null || echo "")
    [ -n "$QEMU_PID" ] || { bad "qemu ($1) did not start; see $LOG"; return 1; }
    for _ in $(seq 100); do ip link show "$LAN_IF" >/dev/null 2>&1 && break; sleep 0.2; done
    ip link show "$LAN_IF" >/dev/null 2>&1 || { bad "tap $LAN_IF never appeared ($1)"; return 1; }
    ok "qemu up (pid $QEMU_PID, pass $1), tap $LAN_IF exists"
}

# start_pass_netup <label> [--dmz]: production net-up, waiting for "ready".
start_pass_netup() {
    local label=$1; shift
    "$VM" net-up --tap "$LAN_IF" --wan "$WAN_IF" --subnet "$SUBNET" --mac "$GUEST_MAC" "$@" \
        > "$WORK/net-up-$label.log" 2>&1 &
    NETUP_PID=$!
    for _ in $(seq 100); do grep -q "net-up: ready" "$WORK/net-up-$label.log" 2>/dev/null && break; sleep 0.2; done
    if grep -q "net-up: ready" "$WORK/net-up-$label.log" 2>/dev/null; then
        ok "net-up ($label) ready"
    else
        bad "net-up ($label) did not become ready"
        cat "$WORK/net-up-$label.log"
        return 1
    fi
    cat "$WORK/net-up-$label.log"
}

wait_guest_ready() {
    for _ in $(seq 200); do grep -q "GUEST-READY" "$LOG" 2>/dev/null && break; sleep 0.3; done
    grep -q "GUEST-READY" "$LOG" || { bad "guest never became ready"; tail -60 "$LOG"; return 1; }
}

# ---------------------------------------------------------------------------
# Pass 1: --dmz off. A routed LAN host (and the WAN side) must not reach the
# VM at all — the baseline the fix (oifname tap: established/related or a
# DMZ'd connection only, else drop) is supposed to guarantee unconditionally.

say "PASS 1: --dmz off"
boot_pass_qemu off || exit 1
start_pass_netup off || exit 1
wait_guest_ready || exit 1
tail -n +1 "$LOG" | grep -E "PASS:|FAIL:|GUEST:" || true
grep -q "^FAIL:" "$LOG" && fail=1

say "routed LAN host, --dmz off: a route to the VM's subnet through us must not reach it"
if ip netns exec "$ROUTED_NETNS" curl -s --max-time 3 "http://$GUEST_IP:$DMZ_OPEN_PORT/" 2>/dev/null | grep -q "PAGURO-GUEST-$DMZ_OPEN_PORT"; then
    bad "a routed LAN host reached the VM directly (dmz off)"
else
    ok "a routed LAN host did not reach the VM directly (dmz off)"
fi
say "WAN side, --dmz off: an otherwise-forwardable port must not reach the VM either"
if ip netns exec "$NETNS" curl -s --max-time 3 "http://$WAN_HOST_IP:$DMZ_OPEN_PORT/" 2>/dev/null | grep -q "PAGURO-GUEST-$DMZ_OPEN_PORT"; then
    bad "an unlisted port reached the guest with --dmz off"
else
    ok "an unlisted port did not reach the guest with --dmz off"
fi

say "end of pass 1: tearing down this QEMU/net-up before pass 2"
stop_netup
stop_qemu
for _ in $(seq 30); do ip link show "$LAN_IF" >/dev/null 2>&1 || break; sleep 0.2; done
ip link show "$LAN_IF" >/dev/null 2>&1 && bad "tap $LAN_IF still present after pass 1" || ok "tap $LAN_IF is gone after pass 1"
nft list table inet paguro >/dev/null 2>&1 && bad "nft table inet paguro still present after pass 1" || ok "nft table gone after pass 1"

# ---------------------------------------------------------------------------
# Pass 2: --dmz on. Everything pass 1 checked must still hold (turning the
# DMZ on for the WAN interface must never open a hole for the routed-LAN
# path), plus the full DHCP/DNS/egress/DMZ-ladder proof.

say "PASS 2: --dmz on"
boot_pass_qemu on || exit 1
start_pass_netup on --dmz || exit 1
wait_guest_ready || exit 1
tail -n +1 "$LOG" | grep -E "PASS:|FAIL:|GUEST:" || true
grep -q "^FAIL:" "$LOG" && fail=1

say "DMZ, from the peer netns (the fake external LAN client)"
open_ok=0
for _ in $(seq 5); do
    if ip netns exec "$NETNS" curl -s --max-time 3 "http://$WAN_HOST_IP:$DMZ_OPEN_PORT/" 2>/dev/null | grep -q "PAGURO-GUEST-$DMZ_OPEN_PORT"; then
        open_ok=1
        break
    fi
    sleep 1
done
if [ "$open_ok" = 1 ]; then
    ok "an unlisted port ($DMZ_OPEN_PORT) is DMZ'd to the guest"
else
    bad "an unlisted port ($DMZ_OPEN_PORT) did not reach the guest"
    echo "DEBUG: nft after failed attempt:"
    nft list table inet paguro
    echo "DEBUG: DOCKER-USER after:"
    iptables -vnL DOCKER-USER
    echo "DEBUG: ip route get $GUEST_IP from $WAN_PEER_IP iif $WAN_IF:"
    ip route get "$GUEST_IP" from "$WAN_PEER_IP" iif "$WAN_IF" 2>&1
    echo "DEBUG: dmesg tail:"
    dmesg | tail -8
fi
if ip netns exec "$NETNS" curl -s --max-time 3 "http://$WAN_HOST_IP:$DMZ_NEVER_PORT/" 2>/dev/null | grep -q "PAGURO-GUEST-$DMZ_NEVER_PORT"; then
    bad "port $DMZ_NEVER_PORT (never-forward) reached the guest"
else
    ok "port $DMZ_NEVER_PORT (never-forward) did not reach the guest"
fi
if ip netns exec "$NETNS" curl -s --max-time 3 "http://$WAN_HOST_IP:22/" 2>/dev/null | grep -q "PAGURO-GUEST-22"; then
    bad "port 22 reached the guest"
else
    ok "port 22 did not reach the guest"
fi
if ip netns exec "$NETNS" curl -s --max-time 3 "http://$WAN_HOST_IP:$DMZ_LINUX_PORT/" 2>/dev/null | grep -q "PAGURO-GUEST-$DMZ_LINUX_PORT"; then
    bad "port $DMZ_LINUX_PORT (Linux listens here) reached the guest instead of the host"
else
    ok "port $DMZ_LINUX_PORT (Linux listens here) did not reach the guest"
fi

say "routed LAN host, --dmz on: turning the DMZ on must not open a hole for the routed path"
if ip netns exec "$ROUTED_NETNS" curl -s --max-time 3 "http://$GUEST_IP:$DMZ_OPEN_PORT/" 2>/dev/null | grep -q "PAGURO-GUEST-$DMZ_OPEN_PORT"; then
    bad "a routed LAN host reached the VM directly (dmz on) on a port that IS DMZ'd from the WAN side"
else
    ok "a routed LAN host did not reach the VM directly (dmz on)"
fi

say "the guest's own outbound connections kept getting their replies throughout this pass"
sleep 4
egress_log=$(grep -E "EGRESS-OK|EGRESS-FAIL" "$LOG" || true)
echo "$egress_log"
if [ -n "$egress_log" ] && ! grep -q "EGRESS-FAIL" <<<"$egress_log" && grep -q "EGRESS-OK" <<<"$egress_log"; then
    ok "the VM's own outbound connections kept working (established,related, not the DMZ)"
else
    bad "an outbound connection's reply did not get through"
fi

kill "$PEER_HTTPD_PID" 2>/dev/null || true
# cleanup() (the EXIT trap) does the rest and prints RESULT: PASS|FAIL.
