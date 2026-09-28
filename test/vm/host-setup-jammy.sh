#!/usr/bin/env bash
# Prepares an Ubuntu 22.04 (jammy) KVM host -- a rented cloud VM, say --
# for test/winvm and test/vm (split-e2e.sh). Idempotent; run as root.
#
# 22.04 ships several things the rig has outgrown, each learnt the hard way:
#   OVMF 2022.02    its "non-secboot" OVMF_CODE_4M.fd still enforces Secure
#                   Boot with MS keys enrolled, so testsigning cannot be set
#                   (edk2 2023.11-7 dropped Secure Boot from it): 24.04's ovmf
#   QEMU 6.2        no `-netdev stream` (7.2+): QEMU 9.2 from source, with
#                   slirp (winvm's user networking) and PNG (screendumps)
#   busybox 1.30    no `dd iflag=direct` in L2: 24.04's busybox-static
#   libbde, dislocker  too old for the session's external key: current
#                   sources, with an rpath so L2's minimal root finds their
#                   libraries (mbedTLS 3 for dislocker)
# plus the musl target paguro's L2 binaries build for, and a user manager
# for root (winvm starts QEMU with `systemd-run --user`).
#
# Change QEMU *before* building the BitLocker test image
# (test/vm/make-bde-image.sh): its TPM seal covers the NIC's option ROM.
set -euxo pipefail
export HOME=${HOME:-/root} DEBIAN_FRONTEND=noninteractive
umask 022
J=${JOBS:-$(nproc)}
SRC=${PAGURO_HOST_SRC:-/data/src}
mkdir -p "$SRC"

apt-get update -qq
apt-get install -y -qq git curl build-essential pkg-config clang llvm cmake \
    "linux-headers-$(uname -r)" qemu-utils swtpm swtpm-tools genisoimage mtools dosfstools \
    gdisk ntfs-3g attr e2fsprogs dmsetup cpio zstd socat nbdkit nbd-client fuse3 \
    samba-common-bin samba-libs python3-numpy python3-pil python3-tomli python3-venv \
    unzip p7zip-full jq xz-utils binutils musl-tools ninja-build flex bison \
    libglib2.0-dev libpixman-1-dev libslirp-dev libseccomp-dev libcap-ng-dev libaio-dev \
    liburing-dev libcurl4-openssl-dev libzstd-dev libnuma-dev libfdt-dev zlib1g-dev libpng-dev \
    openssh-client openssh-server autoconf automake libtool autopoint gettext libfuse3-dev ruby-dev

deb24() { # package version: install 24.04's build of an arch-independent or static package
    local url=$1 f=$SRC/$(basename "$1")
    [ -f "$f" ] || curl -fsSL -o "$f" "$url"
    dpkg -i "$f"
}
deb24 http://archive.ubuntu.com/ubuntu/pool/main/e/edk2/ovmf_2024.02-2ubuntu0.9_all.deb
deb24 http://archive.ubuntu.com/ubuntu/pool/main/b/busybox/busybox-static_1.36.1-6ubuntu3.1_amd64.deb

if ! /usr/local/bin/qemu-system-x86_64 --version 2>/dev/null | grep -q 'version 9.2'; then
    cd "$SRC"
    [ -f qemu-9.2.4.tar.xz ] || curl -fsSL -O https://download.qemu.org/qemu-9.2.4.tar.xz
    rm -rf qemu-9.2.4 && tar xf qemu-9.2.4.tar.xz && cd qemu-9.2.4
    ./configure --prefix=/usr/local --target-list=x86_64-softmmu --enable-kvm --enable-slirp \
        --enable-png --enable-curl --enable-linux-aio --enable-linux-io-uring --enable-seccomp \
        --enable-tools --disable-docs --disable-werror >/dev/null
    make -j"$J" >/dev/null && make install >/dev/null
fi

if ! /usr/local/bin/bdeinfo -V 2>/dev/null | grep -q 20260916; then
    cd "$SRC"
    curl -fsSL -o libbde.tar.gz https://github.com/libyal/libbde/releases/download/20260916/libbde-alpha-20260916.tar.gz
    rm -rf libbde && mkdir libbde && tar xf libbde.tar.gz -C libbde --strip-components=1 && cd libbde
    ./configure --prefix=/usr/local --enable-shared LDFLAGS="-Wl,-rpath,/usr/local/lib" >/dev/null
    make -j"$J" >/dev/null && make install >/dev/null && ldconfig
fi

if [ ! -x /usr/local/bin/dislocker-fuse ]; then
    cd "$SRC"
    rm -rf mbedtls && git clone -q --depth 1 --branch v3.6.4 https://github.com/Mbed-TLS/mbedtls.git && cd mbedtls
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DUSE_SHARED_MBEDTLS_LIBRARY=On -DENABLE_TESTING=Off \
        -DENABLE_PROGRAMS=Off . >/dev/null && make -j"$J" >/dev/null && make install >/dev/null && ldconfig
    cd "$SRC" && rm -rf dislocker && git clone -q https://github.com/Aorimn/dislocker.git && cd dislocker
    git checkout -q "$(git rev-list -1 --before=2025-09-08 HEAD)"
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_PREFIX_PATH=/usr/local . >/dev/null
    make -j"$J" >/dev/null && make install >/dev/null && ldconfig
fi

[ -x "$HOME/.cargo/bin/cargo" ] || curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
"$HOME/.cargo/bin/rustup" target add x86_64-unknown-linux-musl

# Samba for L2 (test/vm/lib.sh, PAGURO_SAMBA_ROOT's default).
S=/data/paguro-work/vm/samba-debs
mkdir -p "$S" && cd "$S"
ls samba_*.deb >/dev/null 2>&1 || apt-get download samba
[ -x root/usr/sbin/smbd ] || dpkg -x samba_*.deb root

loginctl enable-linger root
hash -r
qemu-system-x86_64 --version | head -1
echo HOST-SETUP-DONE
