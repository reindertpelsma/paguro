#!/usr/bin/env bash
# Turn a plain NTFS image into a BitLocker volume, the way Windows lays one
# out, and prove it with two independent readers.
#
#   test/fixtures/bde/make.sh <plain-ntfs.img> <out.img> [options]
#
# Options (passed to paguro-bde-write, see its --help):
#   --password PW            password protector
#   --recovery auto|DIGITS   recovery-password protector (auto: from --seed)
#   --clear-key              clear-key protector (BitLocker "suspended")
#   --startup-key FILE.BEK   startup-key protector, key written to FILE.BEK
#   --cipher xts128|xts256   default xts128
#   --encrypted-size BYTES   partially encrypted: plaintext from here on
#   --validation-v1          Windows 7-style validation (CRC only, no hash)
#   --seed N                 keys, salts and nonces (deterministic output)
#   --keys FILE              where to write the keys (default: <out>.keys)
#   --no-verify              skip the libbde/dislocker check
#
# The NTFS gets four new root files, FVE2.* — three 64 KiB metadata regions
# and the 8 KiB relocated boot-sector copy — exactly as Windows reserves
# them inside the filesystem, so the filesystem stays consistent. The input
# is not modified. At least one protector is required; with no protector
# option, --password paguro is used.
#
# Also written: <out>.expect, the decrypted view every reader must return
# (the input with the four reserved regions zeroed), and <out>.keys.
#
# Needs: ntfs-3g (ntfscp, ntfsinfo), cargo; for verification libbde-utils
# (bdemount) and dislocker (dislocker-file), and FUSE.
set -euo pipefail

usage() { sed -n '2,/^set -e/p' "$0" | sed -e 's/^# \{0,1\}//' -e '/^set -e/d'; exit 2; }
[ $# -ge 2 ] || usage
in=$1 out=$2
shift 2

root=$(cd "$(dirname "$0")/../../.." && pwd)
verify=1 keys="$out.keys"
pass=() protector=0
while [ $# -gt 0 ]; do
  case $1 in
    --no-verify) verify=0 ;;
    --keys) keys=$2; shift ;;
    --password|--recovery|--startup-key) protector=1; pass+=("$1" "$2"); shift ;;
    --clear-key) protector=1; pass+=("$1") ;;
    --validation-v1) pass+=("$1") ;;
    --cipher|--encrypted-size|--seed) pass+=("$1" "$2"); shift ;;
    -h|--help) usage ;;
    *) echo "make.sh: unknown option $1" >&2; exit 2 ;;
  esac
  shift
done
[ "$protector" = 1 ] || pass+=(--password paguro)

[ "$(dd if="$in" bs=1 skip=3 count=8 status=none)" = "NTFS    " ] \
  || { echo "make.sh: $in is not an NTFS volume" >&2; exit 1; }

work=$(mktemp -d)
unmount() { fusermount -u "$1" 2>/dev/null || umount "$1" 2>/dev/null; }
trap 'unmount "$work/mnt" || true; rm -rf "$work"' EXIT
cp --sparse=always "$in" "$work/plain.img"

# Reserve the regions as ordinary (non-resident, contiguous) files.
cluster=$(ntfsinfo -m "$work/plain.img" 2>/dev/null | awk '/Cluster Size:/ {print $3; exit}')
reserve() { # name bytes -> byte offset of its single run
  head -c "$2" /dev/urandom > "$work/r"
  ntfscp -q -f "$work/plain.img" "$work/r" "$1" >/dev/null 2>&1 \
    || { echo "make.sh: no room for $1 on the NTFS" >&2; exit 1; }
  local runs
  runs=$(ntfsinfo -v -F "/$1" "$work/plain.img" 2>/dev/null \
    | awk '/Runlist:/ {f=1; next} f && /^\t\t\t0x/ {print $2} /Total runs/ {f=0}')
  [ "$(echo "$runs" | wc -l)" = 1 ] && [ -n "$runs" ] \
    || { echo "make.sh: $1 is fragmented on the NTFS" >&2; exit 1; }
  echo $(( runs * cluster ))
}
guid='{e40ad34d-dae9-4bc7-95bd-b16218c10f72}'
m1=$(reserve "FVE2.$guid.1" 65536)
m2=$(reserve "FVE2.$guid.2" 65536)
m3=$(reserve "FVE2.$guid.3" 65536)
rl=$(reserve "FVE2.{24e6f0ae-6a00-4f73-984b-75ce9942852d}" 8192)

writer="$root/target/release/paguro-bde-write"
if [ -z "${PAGURO_BDE_WRITE:-}" ]; then
  cargo build -q --release --manifest-path "$root/Cargo.toml" -p paguro-harness --bin paguro-bde-write
else
  writer=$PAGURO_BDE_WRITE
fi
"$writer" --input "$work/plain.img" --output "$out" --expect "$out.expect" --keys "$keys" \
  --metadata "$m1,$m2,$m3" --reloc "$rl" "${pass[@]}"

[ "$verify" = 1 ] || exit 0

# Both oracles must decrypt it to exactly the expected view.
key_of() { awk -v k="$1" '$1==k {print $2}' "$keys"; }
pw=$(key_of password) rp=$(key_of recovery)
if [ -n "$rp" ]; then dis=(-p"$rp"); bde=(-r "$rp")
elif [ -n "$pw" ]; then dis=(-u"$pw"); bde=(-p "$pw")
elif [ -n "$(key_of clear-key)" ]; then dis=(--clearkey); bde=()
else bek=$(key_of startup-key); dis=(-f "$bek"); bde=(-s "$bek")
fi
dislocker-file -V "$out" "${dis[@]}" "$work/dislocker.img" >/dev/null 2>&1 \
  || { echo "make.sh: dislocker could not decrypt $out" >&2; exit 1; }
# dislocker exposes only encrypted_size (rounded up to 8 KiB) of a
# partially encrypted volume; libbde (below) checks the plaintext tail.
dsz=$(stat -c %s "$work/dislocker.img")
[ "$dsz" -ge "$(key_of encrypted-size)" ] \
  || { echo "make.sh: dislocker returned only $dsz bytes" >&2; exit 1; }
cmp -s -n "$dsz" "$work/dislocker.img" "$out.expect" \
  || { echo "make.sh: dislocker's decryption differs from the expected view" >&2; exit 1; }
mkdir "$work/mnt"
bdemount "${bde[@]}" "$out" "$work/mnt" </dev/null >/dev/null \
  || { echo "make.sh: bdemount could not open $out" >&2; exit 1; }
cmp -s "$work/mnt/bde1" "$out.expect" \
  || { echo "make.sh: libbde's decryption differs from the expected view" >&2; exit 1; }
unmount "$work/mnt"
ntfsinfo -m "$out.expect" >/dev/null 2>&1 \
  || { echo "make.sh: the decrypted view is not a valid NTFS" >&2; exit 1; }
echo "make.sh: $out verified by dislocker and libbde"
