#!/bin/sh
# Proves the Linux side of the private link's SSH (DESIGN.md §5c "Shells,
# the same command both ways", "Windows -> Linux"), WITHOUT Windows:
#
#   paguro-ssh.socket   [Socket] ListenStream=169.254.244.1:22
#                       NetworkNamespacePath=/run/netns/paguro, Accept=yes
#     -- hands each connection to --
#   paguro-ssh@.service [Service] ExecStart=sshd -i -e -f <our sshd_config>
#
# `NetworkNamespacePath=` is a property of the *socket unit* alone — the
# whole point of this design (a plain `sshd -D` started with `ip netns exec
# paguro` would give shells cut off from the network) — so proving it needs
# a real systemd, not just `ip netns`/`unshare` plumbing. `systemd-nspawn`
# and `debootstrap` are not installed here and are not added (no host
# package changes), so this boots a **throwaway QEMU VM** (the host's own
# kernel, never loaded on the host) whose initramfs runs the host's own
# `systemd`/`sshd`/`ssh` binaries copied in verbatim (the same `vm_bin`
# technique `kernel/dm-paguro/test/vm-lib.sh` already uses for busybox +
# dm-paguro) as PID 1 — the most faithful option available without
# installing anything: real systemd, real `NetworkNamespacePath`, real
# `sshd`, and it never touches the host's own systemd instance or its
# `/etc/ssh`.
#
# Inside that one VM: `paguro link setup` (this installation's own
# generated units/keys/sshd_config), a second netns "winclient" playing
# Windows at 169.254.244.2 over a veth, a login with the right key (its
# shell's `/proc/self/ns/net` must equal the HOST namespace, not netns
# `paguro`'s), then the refusals: a wrong key, password auth, and a
# connection attempted from the wrong namespace entirely (the host's own —
# unreachable, since 169.254.244.1 exists only inside netns `paguro`).
#
#   test/vm/link-ssh.sh [KERNEL_IMAGE]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
top=$(cd "$here/../.." && pwd)
kver=$(uname -r)
kernel=${1:-/boot/vmlinuz-$kver}
work=${PAGURO_LINKSSH_WORK:-$(mktemp -d)}
mkdir -p "$work"
[ -n "${PAGURO_LINKSSH_WORK:-}" ] || trap 'rm -rf "$work"' EXIT
r=$work/root

# shellcheck source=kernel/dm-paguro/test/vm-lib.sh
. "$top/kernel/dm-paguro/test/vm-lib.sh"

say() { printf '\n### %s\n' "$*"; }
die() { echo "FAIL: $*" >&2; exit 1; }

say "building paguro (musl, static)"
(cd "$top" && CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-2} \
    cargo build -q --release -p paguro-linux --target x86_64-unknown-linux-musl)
TARGET_DIR=${CARGO_TARGET_DIR:-$top/target}
PAGURO_BIN=$TARGET_DIR/x86_64-unknown-linux-musl/release/paguro
[ -x "$PAGURO_BIN" ] || die "paguro not built at $PAGURO_BIN"

say "building the root: busybox + iproute2 + a real systemd/sshd/ssh"
rm -rf "$r"
vm_root "$r"
rm -f "$r/bin/ip"
vm_bin "$(command -v ip)" sbin/ip
# Not in vm_root's applet list; `ip netns exec` execvp()s this by name and
# (unlike busybox's own shell) does not fall back to busybox's standalone
# applet dispatch.
ln -sf busybox "$r/bin/readlink"
vm_bin "$(command -v timeout)" bin/timeout.real
ln -sf timeout.real "$r/bin/timeout"
# `veth` (the "Windows" netns's other half) is a module on this kernel.
vm_modules "/lib/modules/$kver" drivers/net/veth

# systemd itself (its shared libs, ldd-resolved, land at the same absolute
# paths as the host — that's what makes systemd's own internal library
# lookups (libsystemd-core/-shared) resolve unchanged).
vm_bin /usr/lib/systemd/systemd usr/lib/systemd/systemd
# Split out of PID 1 since systemd 256 (CVE-hardening): every service is
# actually forked/exec'd by this helper, not by systemd itself.
vm_bin /usr/lib/systemd/systemd-executor usr/lib/systemd/systemd-executor
vm_bin /usr/bin/systemctl usr/bin/systemctl
ln -sf ../../usr/bin/systemctl "$r/bin/systemctl"
vm_bin /usr/sbin/sshd usr/sbin/sshd
# OpenSSH 9.8+ split privilege separation into re-exec'd helper binaries
# (sshd-session, sshd-auth, ...) sshd -i needs; copy the lot rather than
# chasing each one as it turns up missing.
mkdir -p "$r/usr/lib/openssh"
for f in /usr/lib/openssh/sshd-session /usr/lib/openssh/sshd-auth; do
    [ -x "$f" ] && vm_bin "$f" "usr/lib/openssh/$(basename "$f")"
done
vm_bin /usr/bin/ssh usr/bin/ssh
vm_bin /usr/bin/ssh-keygen usr/bin/ssh-keygen

# Libraries only ever dlopen'd (glibc's NSS modules; systemd's own optional
# libmount/libkmod/libapparmor) so `ldd` on any binary never lists them.
copy_lib() {
    [ -e "$r$1" ] && return 0
    mkdir -p "$r$(dirname "$1")"
    cp -L "$1" "$r$1" 2>/dev/null || return 0
    for l in $(ldd "$1" 2>/dev/null | grep -o '/[^ ]*'); do copy_lib "$l"; done
}
for l in libnss_files.so.2 libmount.so.1 libblkid.so.1 libkmod.so.2 libapparmor.so.1; do
    copy_lib "/usr/lib/x86_64-linux-gnu/$l"
done
cp "$PAGURO_BIN" "$r/usr/local/bin/paguro" 2>/dev/null || {
    mkdir -p "$r/usr/local/bin"
    cp "$PAGURO_BIN" "$r/usr/local/bin/paguro"
}

# Only the handful of systemd vendor targets this boot actually needs to
# reach multi-user.target (written out explicitly, not copied wholesale
# from the host's /usr/lib/systemd/system: that directory is really the
# whole *distro's* vendor units — dbus, systemd-networkd, grub, cloud-init,
# NetworkManager, gettys, ... — none of which this rootfs ships the
# binaries for, so enabling them (even transitively, via the host's own
# preset/.wants symlinks) means unit start failures repeatedly retried).
# `RequiresMountsFor=/var /var/tmp` in basic.target is satisfied by their
# being plain directories on the already-mounted root; everything else
# below is a soft (Wants) dependency.
mkdir -p "$r/usr/lib/systemd/system" "$r/var" "$r/var/tmp" "$r/root" "$r/run/netns" "$r/etc/systemd/system"
ln -sfn /run "$r/var/run"
cat > "$r/usr/lib/systemd/system/sysinit.target" <<'EOF'
[Unit]
Description=System Initialization
EOF
cat > "$r/usr/lib/systemd/system/basic.target" <<'EOF'
[Unit]
Description=Basic System
Requires=sysinit.target
Wants=sockets.target
After=sysinit.target sockets.target
RequiresMountsFor=/var /var/tmp
EOF
cat > "$r/usr/lib/systemd/system/multi-user.target" <<'EOF'
[Unit]
Description=Multi-User System
Requires=basic.target
After=basic.target
AllowIsolate=yes
EOF
cat > "$r/usr/lib/systemd/system/sockets.target" <<'EOF'
[Unit]
Description=Socket Units
EOF

printf 'root:x:0:0:root:/root:/bin/sh\nsshd:x:100:65534:sshd privsep user:/run/sshd:/usr/sbin/nologin\nnobody:x:65534:65534::/nonexistent:/bin/false\n' > "$r/etc/passwd"
printf 'root:x:0:\nnogroup:x:65534:\n' > "$r/etc/group"
printf 'passwd: files\ngroup: files\nshadow: files\n' > "$r/etc/nsswitch.conf"
mkdir -p "$r/usr/lib"
printf 'NAME=paguro-link-ssh-test\nID=paguro-test\n' > "$r/usr/lib/os-release"
ln -sf ../usr/lib/os-release "$r/etc/os-release"
: > "$r/etc/shadow"
ln -sfn /proc/mounts "$r/etc/mtab"

# Force multi-user (server) rather than the compiled-in default, which
# would pull in a display manager we don't have.
ln -sf /usr/lib/systemd/system/multi-user.target "$r/etc/systemd/system/default.target"

# The test driver: one oneshot service, run once multi-user.target (i.e.
# `paguro-ssh.socket` and friends can already be started) is reachable.
cp "$here/link-ssh-driver.sh" "$r/usr/local/bin/paguro-link-ssh-driver.sh"
chmod +x "$r/usr/local/bin/paguro-link-ssh-driver.sh"
cat > "$r/etc/systemd/system/paguro-link-ssh-test.service" <<'EOF'
[Unit]
Description=paguro link-ssh.sh test driver
After=multi-user.target
[Service]
Type=oneshot
ExecStart=/usr/local/bin/paguro-link-ssh-driver.sh
StandardOutput=journal+console
StandardError=journal+console
EOF
mkdir -p "$r/etc/systemd/system/multi-user.target.wants"
ln -sf ../paguro-link-ssh-test.service \
    "$r/etc/systemd/system/multi-user.target.wants/paguro-link-ssh-test.service"

cat > "$r/init" <<'EOF'
#!/bin/sh
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
mount -t tmpfs -o mode=755 run /run
mkdir -p /run/netns
mkdir -p /run/sshd
for m in $(cat /mod/order 2>/dev/null); do insmod "/mod/$m.ko"; done
exec /usr/lib/systemd/systemd
EOF
chmod +x "$r/init"

say "booting (console=ttyS0; the driver's PASS/FAIL/RESULT lines are the test)"
log=$work/serial.log
vm_boot "$r" "$kernel" 90 "$log" "console=ttyS0"
fails=$(grep -c '^FAIL:' "$log" || true)
grep -q '^RESULT: PASS$' "$log" || fails=$((fails + 1))
if [ "$fails" -eq 0 ]; then
    echo
    echo "link-ssh.sh: PASS"
else
    echo
    tail -60 "$log"
    die "$fails failure(s) — see the log above"
fi
