#!/bin/bash
# dracut module: the same steps as the initramfs-tools hook
# shellcheck disable=SC2154  # $kernel, $moddir: set by dracut
# (linux/initramfs-tools). Refuses an initramfs without dm-paguro for the
# kernel it is built for (INTERFACES.md §11.6).

check() {
    require_binaries paguro-initrd || return 1
    return 0
}

depends() {
    echo dm rootfs-block
}

installkernel() {
    local m
    for m in dm-paguro paguro-handoff; do
        if ! modinfo -k "$kernel" "$m" > /dev/null 2>&1; then
            derror "paguro: $m is not built for kernel $kernel; refusing to build an initramfs that cannot find its root"
            return 1
        fi
    done
    hostonly='' instmods dm-paguro paguro-handoff dm-crypt dm-zero ntfs3 vfat \
        nls_cp437 nls_iso8859-1 efivarfs
}

install() {
    inst_binary /usr/sbin/paguro-initrd
    inst_hook cmdline 90 "$moddir/paguro-cmdline.sh"
    inst_hook initqueue/settled 90 "$moddir/paguro-setup.sh"
}
