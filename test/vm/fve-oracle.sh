#!/usr/bin/env bash
# DESIGN.md §11 Q10: the substituted FVE metadata round-trips through two
# independent readers. For each generated BitLocker volume (make.sh), the
# substitute from `paguro-vm fve` is applied to a copy of it; libbde
# (bdemount -s) and dislocker (dislocker-file -f) must open the copy with
# the new .BEK and return exactly the expected decrypted view — and the
# volume's own protector must still open it.
#
#   test/vm/fve-oracle.sh [WORKDIR]
#
# Needs what test/fixtures/bde/make.sh needs (ntfs-3g, libbde-utils,
# dislocker, FUSE) and mkntfs. Never touches a kernel module.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
work=${1:-$(mktemp -d)}
mkdir -p "$work"
unmount() { fusermount -u "$1" 2>/dev/null || umount "$1" 2>/dev/null || true; }
trap 'unmount "$work/mnt"; [ -n "${1:-}" ] || rm -rf "$work"' EXIT
cargo build -q --release --manifest-path "$root/Cargo.toml" -p paguro-vm -p paguro-harness \
  --bin paguro-vm --bin paguro-bde-write
vm=$root/target/release/paguro-vm
export PAGURO_BDE_WRITE=$root/target/release/paguro-bde-write

plain=$work/plain.img
rm -f "$plain"
truncate -s 64M "$plain"
mkntfs -F -Q -q -s 512 "$plain" >/dev/null 2>&1
printf 'paguro fve oracle\n' > "$work/hello.txt"
ntfscp -q "$plain" "$work/hello.txt" hello.txt
plain4k=$work/plain4k.img
rm -f "$plain4k"
truncate -s 64M "$plain4k"
mkntfs -F -Q -q -s 4096 "$plain4k" >/dev/null 2>&1

pass=0 fail=0
check() { # name input make.sh-options...
  local name=$1 in=$2; shift 2
  local v=$work/$name.img out=$work/$name.fve copy=$work/$name.sub.img
  "$root/test/fixtures/bde/make.sh" "$in" "$v" --no-verify "$@" >/dev/null
  local vmk; vmk=$(awk '$1=="vmk" {print $2}' "$v.keys")
  cp --sparse=always "$v" "$copy"
  rm -rf "$out"
  "$vm" fve --volume "$v" --vmk-hex "$vmk" --out "$out" --apply "$copy" > "$out.json"
  local bek; bek=$(ls "$out"/*.BEK)
  local enc; enc=$(awk '$1=="encrypted-size" {print $2}' "$v.keys")
  local ok=1
  # dislocker: the new external key
  if dislocker-file -V "$copy" -f "$bek" "$work/dis.img" >/dev/null 2>&1; then
    local n; n=$(stat -c %s "$work/dis.img")
    [ "$n" -ge "$enc" ] && cmp -s -n "$n" "$work/dis.img" "$v.expect" || { echo "  dislocker: view differs"; ok=0; }
  else
    echo "  dislocker: could not open with the .BEK"; ok=0
  fi
  rm -f "$work/dis.img"
  # libbde: the new external key
  mkdir -p "$work/mnt"
  if bdemount -s "$bek" "$copy" "$work/mnt" </dev/null >/dev/null 2>&1; then
    cmp -s "$work/mnt/bde1" "$v.expect" || { echo "  libbde: view differs"; ok=0; }
    unmount "$work/mnt"
  else
    echo "  libbde: could not open with the .BEK"; ok=0
  fi
  # the volume's own protector still opens the substitute
  local rp; rp=$(awk '$1=="recovery" {print $2}' "$v.keys")
  if [ -n "$rp" ]; then
    if bdemount -r "$rp" "$copy" "$work/mnt" </dev/null >/dev/null 2>&1; then
      cmp -s "$work/mnt/bde1" "$v.expect" || { echo "  libbde (recovery): view differs"; ok=0; }
      unmount "$work/mnt"
    else
      echo "  libbde: the recovery password no longer opens it"; ok=0
    fi
  fi
  # and dislocker lists the new protector, by its GUID
  local g; g=$(sed -n 's/.*"protector":"\([^"]*\)".*/\1/p' "$out.json")
  local md; md=$(dislocker-metadata -V "$copy" 2>/dev/null || true)
  grep -q "GUID: '$g'" <<<"$md" || { echo "  dislocker-metadata: $g not listed"; ok=0; }
  if [ $ok = 1 ]; then echo "PASS $name"; pass=$((pass+1)); else echo "FAIL $name"; fail=$((fail+1)); fi
  rm -f "$v" "$copy" "$v.expect"
}

check xts128-recovery "$plain" --recovery auto --seed 1
check xts256-recovery "$plain" --recovery auto --cipher xts256 --seed 2
check xts128-4k "$plain4k" --recovery auto --seed 3
check xts128-password "$plain" --password paguro --seed 4
check xts128-partial "$plain" --recovery auto --encrypted-size 16777216 --seed 5
check xts128-validation-v1 "$plain" --recovery auto --validation-v1 --seed 6
echo "RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ]
