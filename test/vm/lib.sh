# Shared by test/vm/*.sh (bash). The Linux side of the VM path runs in a
# throwaway QEMU VM ("L2") with the host's own kernel: dm-paguro and every
# other module load there, never on the host. Windows runs in a second VM
# launched by `paguro-vm launch`, its disk the L2's
# /dev/mapper/paguro-vmdisk exported over NBD.
#
# Big files go under $PAGURO_VM_WORK (default /data/paguro-work/vm/run).

top=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
VMWORK=${PAGURO_VM_WORK:-/data/paguro-work/vm/run}
SHARE=$VMWORK/share
L2_NBD_PORT=${PAGURO_VM_NBD_PORT:-10809}
export XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}

say() { printf '\n### %s\n' "$*"; }
die() { echo "FAIL: $*" >&2; exit 1; }

# The host-built pieces: paguro-vm (static), dm-paguro against the host
# kernel's headers, pgctl (static).
l2_build() {
    (cd "$top" && CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-2} cargo build -q --release -p paguro-vm \
        --target x86_64-unknown-linux-musl)
    make -s -C "$top/kernel/dm-paguro" >/dev/null 2>&1 || make -C "$top/kernel/dm-paguro"
    make -s -C "$top/kernel/dm-paguro/tools" pgctl
}

# l2_root <dir>: busybox root with the host stack's tools.
l2_root() {
    local r=$1 kver; kver=$(uname -r)
    rm -rf "$r"
    # shellcheck source=/dev/null
    . "$top/kernel/dm-paguro/test/vm-lib.sh"
    vm_root "$r"
    for a in ip sleep ls mkdir sha256sum hexdump xxd cut tr find sort head tail; do
        [ -e "$r/bin/$a" ] || ln -s busybox "$r/bin/$a"
    done
    rm -f "$r/bin/ip"
    vm_bin "$(command -v ip)" sbin/ip
    vm_bin "$(command -v qemu-nbd)" bin/qemu-nbd
    # The RemoteApp phase relays RDP into netns paguro (split-e2e.sh).
    command -v socat >/dev/null && vm_bin "$(command -v socat)" bin/socat
    # The split test's NBD server: nbdkit answers a failed read with an error
    # on that request and keeps the connection (qemu-nbd drops it, which a
    # client holding requests across reconnects then retries forever).
    vm_bin "$(command -v nbdkit)" bin/nbdkit
    vm_bin /usr/lib/x86_64-linux-gnu/nbdkit/plugins/nbdkit-file-plugin.so \
        usr/lib/x86_64-linux-gnu/nbdkit/plugins/nbdkit-file-plugin.so
    vm_bin "$(command -v bdeinfo)" bin/bdeinfo
    vm_bin "$(command -v bdemount)" bin/bdemount
    vm_bin "$(command -v dislocker-metadata)" bin/dislocker-metadata
    vm_bin "$(command -v dislocker-fuse)" bin/dislocker-fuse
    vm_bin "$(command -v ntfsls)" bin/ntfsls
    vm_bin "$(command -v ntfscat)" bin/ntfscat
    vm_bin "$(command -v sha256sum)" bin/sha256sum.gnu
    # Samba for L: (DESIGN.md §5c), when an extracted `samba` package is at
    # hand (apt-get download samba; dpkg -x ... $PAGURO_SAMBA_ROOT): smbd
    # from it, its libraries from there and the host (samba-libs).
    local sroot=${PAGURO_SAMBA_ROOT:-/data/paguro-work/vm/samba-debs/root}
    if [ -x "$sroot/usr/sbin/smbd" ]; then
        local lib=/usr/lib/x86_64-linux-gnu/samba
        LD_LIBRARY_PATH=$sroot$lib:$lib vm_bin "$sroot/usr/sbin/smbd" sbin/smbd
        vm_bin "$(command -v smbpasswd)" bin/smbpasswd
        mkdir -p "$r$lib"
        cp -a "$lib/." "$r$lib/"
        cp -a "$sroot$lib/." "$r$lib/"
        for l in $(LD_LIBRARY_PATH=$sroot$lib:$lib ldd "$sroot/usr/sbin/smbd" | grep -o '/[^ ]*'); do
            [ -e "$r$l" ] || { mkdir -p "$r$(dirname "$l")"; cp -L "$l" "$r$l"; }
        done
    fi
    # nested-e2e.sh: QEMU, OVMF and KVM in L2 too.
    if [ -n "${PAGURO_L2_NESTED:-}" ]; then
        vm_bin "$(command -v qemu-system-x86_64)" bin/qemu-system-x86_64
        mkdir -p "$r/usr/share/qemu" "$r/usr/share/OVMF" "$r/usr/share/seabios"
        cp -a /usr/share/qemu/. "$r/usr/share/qemu/"
        cp -a /usr/share/seabios/. "$r/usr/share/seabios/" 2>/dev/null || true
        cp /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/OVMF/OVMF_VARS_4M.fd "$r/usr/share/OVMF/"
    fi
    cp "$top/target/x86_64-unknown-linux-musl/release/paguro-vm" "$r/bin/"
    cp "$top/kernel/dm-paguro/tools/pgctl" "$r/bin/"
    vm_modules "/lib/modules/$kver" drivers/md/dm-crypt drivers/md/dm-zero fs/ntfs3/ntfs3 \
        fs/9p/9p net/9p/9pnet_virtio fs/smb/client/cifs arch/x86/crypto/aesni-intel \
        drivers/md/dm-log-writes fs/nls/nls_utf8 fs/nls/nls_cp437 fs/nls/nls_iso8859-1 \
        crypto/cmac crypto/ccm ${PAGURO_L2_NESTED:+arch/x86/kvm/kvm-amd arch/x86/kvm/kvm-intel \
        drivers/vhost/vhost_vsock}
    cp "$top/kernel/dm-paguro/dm-paguro.ko" "$r/mod/"
    vm_init_head > "$r/init"
    cat "$top/test/vm/l2-init.body" >> "$r/init"
    chmod +x "$r/init"
    printf 'root:x:0:0::/root:/bin/sh\npaguro:x:1000:1000::/mnt/l:/bin/false\nnobody:x:65534:65534::/nonexistent:/bin/false\n' > "$r/etc/passwd"
    printf 'root:x:0:\npaguro:x:1000:\nnogroup:x:65534:\n' > "$r/etc/group"
    (cd "$r" && find . | cpio -o -H newc 2>/dev/null | gzip -1) > "$r.cpio.gz"
}

# l2_start <windows-disk.qcow2>: boot L2 with the Windows disk (a fresh
# overlay of it) as virtio-blk, the share, NBD forwarded to the host, and
# the private link's far end listening on $VMWORK/paguro0.sock.
l2_start() {
    local base=$1 kver; kver=$(uname -r)
    mkdir -p "$SHARE" && rm -rf "${SHARE:?}"/*
    rm -f "$VMWORK/l2disk.qcow2" "$VMWORK/paguro0.sock"
    qemu-img create -q -f qcow2 -F qcow2 -b "$base" "$VMWORK/l2disk.qcow2"
    systemd-run --user --scope --collect -p MemoryMax=${PAGURO_L2_SCOPE_MAX:-4G} -- \
      qemu-system-x86_64 -name paguro-l2 -machine q35,accel=kvm -cpu host -smp 2 -m ${PAGURO_L2_MEM:-2560} \
        -nographic -no-reboot -kernel "/boot/vmlinuz-$kver" -initrd "$VMWORK/l2root.cpio.gz" \
        -append "console=ttyS0 quiet panic=-1" \
        -drive if=none,id=wd,file="$VMWORK/l2disk.qcow2",format=qcow2,cache=writeback,discard=unmap \
        -device virtio-blk-pci,drive=wd,serial=PAGURO-TEST-DISK \
        -netdev user,id=nat,hostfwd=tcp:127.0.0.1:$L2_NBD_PORT-:10809${PAGURO_L2_EXTRA_FWD:+,$PAGURO_L2_EXTRA_FWD} \
        -device virtio-net-pci,netdev=nat,mac=52:54:00:12:34:56 \
        -netdev stream,id=link,server=on,addr.type=unix,addr.path="$VMWORK/paguro0.sock" \
        -device virtio-net-pci,netdev=link,mac=02:70:67:00:00:01 \
        -virtfs local,path="$SHARE",mount_tag=share,security_model=none,id=share \
        -qmp unix:"$VMWORK/l2-qmp.sock",server=on,wait=off -pidfile "$VMWORK/l2.pid" \
        > "$VMWORK/l2-serial.log" 2>&1 &
    for _ in $(seq 120); do [ -e "$SHARE/l2-ready" ] && return 0; sleep 1; done
    tail -30 "$VMWORK/l2-serial.log"
    die "L2 did not come up"
}

# l2 <shell text>: run it in L2, print its output, return its status.
l2() {
    local n; n=$(printf '%03d' $(( $(ls "$SHARE/q" | grep -c '\.sh$') + 1 )))
    printf '%s\n' "$*" > "$SHARE/q/$n.sh.tmp" && mv "$SHARE/q/$n.sh.tmp" "$SHARE/q/$n.sh"
    while [ ! -e "$SHARE/q/$n.rc" ]; do sleep 0.3; done
    cat "$SHARE/q/$n.out"
    return "$(cat "$SHARE/q/$n.rc")"
}

l2_stop() {
    [ -e "$SHARE/q" ] && echo poweroff -f > "$SHARE/q/$(printf '%03d' $(( $(ls "$SHARE/q" | grep -c '\.sh$') + 1 ))).sh"
    local pid; pid=$(cat "$VMWORK/l2.pid" 2>/dev/null) || return 0
    for _ in $(seq 30); do kill -0 "$pid" 2>/dev/null || return 0; sleep 1; done
    kill "$pid" 2>/dev/null || true
}

qmp() { # socket json...
    python3 - "$@" <<'PY'
import json, socket, sys
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); f = s.makefile('rwb')
def rd():
    while True:
        m = json.loads(f.readline())
        if 'event' not in m:
            return m
rd(); f.write(b'{"execute":"qmp_capabilities"}\n'); f.flush(); rd()
for c in sys.argv[2:]:
    f.write(c.encode() + b'\n'); f.flush(); print(json.dumps(rd()))
PY
}

screenshot() { # qmp-socket out.png
    qmp "$1" "{\"execute\":\"screendump\",\"arguments\":{\"filename\":\"$2\",\"format\":\"png\"}}" >/dev/null
}
