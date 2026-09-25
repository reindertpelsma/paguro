#!/bin/sh
# A debug kernel for the hostile-interface tests (INTERFACES §12.0): a
# pinned longterm kernel.org release, defconfig + kvm_guest + one of
#
#   kasan   KASAN (generic), UBSAN, lockdep (PROVE_LOCKING), kmemleak,
#           DEBUG_ATOMIC_SLEEP, list/sg/refcount debugging
#   kcsan   KCSAN (data races), lockdep
#
# (KASAN and KCSAN exclude each other.) Builds bzImage, the modules the VM
# needs as built-ins, and an external-module build tree for dm-paguro and
# paguro-handoff.
#
#   build-kernel.sh <kasan|kcsan> <outdir>      -> <outdir>/{bzImage,build/}
set -eu
flavour=$1
out=$(mkdir -p "$2" && cd "$2" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
VER=6.18.53
SHA=4d6fba95c2244b08a7b4144a4d38b9be4fb31abb5e7682ae40bb5cb11374cfe0
tar=${PG_KERNEL_CACHE:-$out/..}/linux-$VER.tar.xz
[ -s "$tar" ] || curl -fsSL -o "$tar" "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$VER.tar.xz"
echo "$SHA  $tar" | sha256sum -c --quiet
src=$out/src
if [ ! -d "$src" ]; then
    mkdir -p "$src"
    tar -xJf "$tar" -C "$src" --strip-components=1
fi
cd "$src"
make -s defconfig
make -s kvm_guest.config
scripts/kconfig/merge_config.sh -m -O . .config "$here/common.config" "$here/$flavour.config" > /dev/null
make -s olddefconfig
for opt in $(grep -h '^CONFIG_.*=y' "$here/common.config" "$here/$flavour.config" | cut -d= -f1); do
    grep -q "^$opt=y" .config || { echo "build-kernel: $opt did not stick" >&2; exit 1; }
done
make -s -j"$(nproc)" bzImage modules
cp arch/x86/boot/bzImage "$out/bzImage"
rm -rf "$out/build"
# The tree an external module needs (scripts/package/install-extmod-build).
srctree=. MAKE=make CC=gcc HOSTCC=gcc SRCARCH=x86 KCONFIG_CONFIG=.config \
    sh scripts/package/install-extmod-build "$out/build"
echo "$VER $flavour" > "$out/version"
