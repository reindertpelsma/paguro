#!/usr/bin/env bash
# The BitLocker'd Windows that test/vm/split-e2e.sh boots (README.md
# "Inputs"), built reproducibly from the winvm base image (test/winvm):
#
#   an overlay on the base -> C: shrunk to 21 GiB, NetKVM and the test-signed
#   minifilter installed, C:\paguro\linux.img (64 MiB, allocated, valid data
#   to the end), testsigning off in the native BCD -> reboot -> BitLocker on
#   C: (recovery password protector, TPM, full encryption) -> wait for 100%
#
# Leaves (never committed; the evaluation licence):
#   $OUT/win-bde.qcow2       the disk (an overlay on the base, by real path)
#   $OUT/win-bde-vars.fd     its native OVMF variables
#   $TPM_OUT                 its swtpm state (the TPM protector lives here)
#   $OUT/win-bde.env         PAGURO_WIN_* for split-e2e.sh (sourced by it)
#   $RP_OUT                  the recovery password
# and makes the base and the new disk immutable (chattr +i): a stray `ln -sf`
# or `rm` onto them fails instead of destroying hours of work.
#
#   test/vm/make-bde-image.sh            (as root; KVM, swtpm, qemu-img)
#
# Inputs (environment, with defaults):
#   PAGURO_WINVM_BASE_DIR   the winvm build (base.qcow2, base-vars.fd, keys/)
#   PAGURO_BDE_INPUTS       NetKVM/ and minifilter/ (the CI artifact
#                           `paguro-minifilter`: pkg/Release, paguro-test.cer)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
W=$here/../winvm/winvm

BASE_DIR=${PAGURO_WINVM_BASE_DIR:-/data/paguro-work/winvm}
INPUTS=${PAGURO_BDE_INPUTS:-/data/paguro-work/bde-inputs}
OUT=${PAGURO_BDE_OUT:-/var/tmp/paguro-vm}
TPM_OUT=${PAGURO_BDE_TPM_OUT:-$HOME/.cache/winvm-swtpm-vm/win-bde-tpm}
RP_OUT=${PAGURO_BDE_RP_OUT:-/data/paguro-work/vm/recovery-password.txt}
BUILD=${PAGURO_BDE_BUILD:-/data/paguro-work/bde-build}
SIZE_GIB=${PAGURO_BDE_C_GIB:-21}

base=$(realpath "$BASE_DIR/base.qcow2")
[ -f "$base" ] || { echo "no winvm base at $BASE_DIR/base.qcow2 (test/winvm/winvm build)" >&2; exit 1; }
for f in "$INPUTS/NetKVM/w11/amd64/netkvm.inf" "$INPUTS/minifilter/pkg/Release/paguro_flt.inf" "$INPUTS/minifilter/paguro-test.cer"; do
    [ -f "$f" ] || { echo "missing input $f" >&2; exit 1; }
done
if [ -e "$OUT/win-bde.qcow2" ]; then
    echo "$OUT/win-bde.qcow2 exists; remove it deliberately first (chattr -i, rm)" >&2
    exit 1
fi

# A private harness directory: the base is linked FROM here, never the
# other way round; nothing under $BASE_DIR is written.
rm -rf "$BUILD" && mkdir -p "$BUILD"
ln -s "$base" "$BUILD/base.qcow2"
cp "$BASE_DIR/base-vars.fd" "$BUILD/base-vars.fd"
ln -s "$(realpath "$BASE_DIR/keys")" "$BUILD/keys"
export WINVM_DIR=$BUILD WINVM_SSH_PORT=${PAGURO_BDE_SSH_PORT:-2250}
export WINVM_TPM_DIR=$HOME/.cache/winvm-swtpm-bde
rm -rf "$WINVM_TPM_DIR" && mkdir -p "$WINVM_TPM_DIR"
cp -a "${WINVM_BASE_TPM:-$HOME/.cache/winvm-swtpm/base-tpm}" "$WINVM_TPM_DIR/base-tpm"
export XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/0}
trap '"$W" stop --force >/dev/null 2>&1 || true' EXIT

say() { printf '\n### %s\n' "$*"; }

say "prepare: shrink C:, drivers, the image file, testsigning off"
"$W" start --timeout 900 >/dev/null
"$W" ssh 'mkdir C:\bde 2>nul & exit 0' >/dev/null
for src in "$INPUTS/NetKVM" "$INPUTS/minifilter" "$here/make-bde-prepare.ps1" "$here/make-bde-encrypt.ps1"; do
    "$W" scp -r "$src" ":C:/bde/" >/dev/null
done
"$W" ssh "powershell -NoProfile -ExecutionPolicy Bypass -File C:\\bde\\make-bde-prepare.ps1 -SizeGiB $SIZE_GIB" | tr -d '\r'
"$W" stop --timeout 300 >/dev/null

say "encrypt (a fresh boot, so the TPM protector seals testsigning off)"
"$W" start --keep --timeout 900 >/dev/null
out=$("$W" ssh 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\bde\make-bde-encrypt.ps1' | tr -d '\r')
echo "$out"
rp=$(grep -ao 'BDE_RECOVERY [0-9-]*' <<<"$out" | awk '{print $2}')
guid=$(grep -ao 'BDE_GUID [0-9a-fA-F-]*' <<<"$out" | awk '{print tolower($2)}')
[ -n "$rp" ] && [ -n "$guid" ] || { echo "encryption did not report a recovery password and a GUID" >&2; exit 1; }
"$W" ssh 'rmdir /s /q C:\bde' >/dev/null || true
"$W" stop --timeout 300 >/dev/null

say "export"
mkdir -p "$OUT" "$(dirname "$TPM_OUT")" "$(dirname "$RP_OUT")"
ov=$BUILD/run/overlay.qcow2
# The overlay names its backing file through $BUILD's link: name the real one.
qemu-img rebase -u -F qcow2 -b "$base" "$ov"
mv "$ov" "$OUT/win-bde.qcow2"
cp "$BUILD/run/vars.fd" "$OUT/win-bde-vars.fd"
rm -rf "$TPM_OUT" && cp -a "$WINVM_TPM_DIR/run/state" "$TPM_OUT"
printf '%s\n' "$rp" > "$RP_OUT"
chmod 600 "$RP_OUT"
cat > "$OUT/win-bde.env" <<EOF
# Written by test/vm/make-bde-image.sh on $(date -Iseconds); sourced by split-e2e.sh.
PAGURO_WIN_DISK=$OUT/win-bde.qcow2
PAGURO_WIN_VARS=$OUT/win-bde-vars.fd
PAGURO_WIN_TPM=$TPM_OUT
PAGURO_WIN_RECOVERY=$RP_OUT
PAGURO_WIN_VOLUME_GUID=$guid
WINVM_KEY=$(realpath "$BASE_DIR/keys")/id_ed25519
EOF
chattr +i "$base" "$OUT/win-bde.qcow2"
rm -rf "$BUILD" "$WINVM_TPM_DIR"
trap - EXIT
echo "win-bde: $OUT/win-bde.qcow2 (C: $guid), recovery password in $RP_OUT; base and disk immutable"
