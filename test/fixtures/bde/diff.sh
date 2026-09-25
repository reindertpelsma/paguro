#!/usr/bin/env bash
# Differential test of paguro's BitLocker reader against libbde and
# dislocker (INTERFACES.md §12.2 "three implementations agree").
#
#   test/fixtures/bde/diff.sh [--update]
#
# 1. Windows-made volumes (windows/bitlk-images.tar.xz from cryptsetup, and
#    dfvfs's bdetogo.raw when it can be fetched): our metadata must match
#    bdeinfo's; our decryption of the whole volume must equal dislocker's
#    and libbde's byte for byte (and cryptsetup's recorded SHA-256), with
#    every key the fixture has; volumes we refuse must be refused with the
#    error the manifest names.
# 2. Generated volumes (make.sh over mkntfs images, 512/4096-byte sectors,
#    XTS-128/256, every protector kind, partially encrypted): make.sh proves
#    each against both oracles; ours must equal the same expected view.
#
# --update rewrites windows/manifest.txt and windows/*.sparse (the
# metadata-level fixtures `cargo test` uses) from the live oracles.
#
# Needs: libbde-utils, dislocker, ntfs-3g, FUSE, xz, cargo, curl (optional).
# The oracles must be Ubuntu 26.04's or newer (libbde 20240502, dislocker
# 0.7.3+git20250907): 24.04's libbde 20190102 cannot open XTS-256 or
# partially encrypted volumes and its dislocker crashes on several of these.
set -euo pipefail

root=$(cd "$(dirname "$0")/../../.." && pwd)
fx=$root/test/fixtures/bde
work=${PAGURO_BDE_WORK:-$root/target/bde-diff}
update=0
[ "${1:-}" = --update ] && update=1

# PAGURO_BDE_PREBUILT=1: the binaries are already built (CI runs this
# script as root, for FUSE, without a toolchain on root's PATH).
[ -n "${PAGURO_BDE_PREBUILT:-}" ] || cargo build -q --release --manifest-path "$root/Cargo.toml" \
  -p paguro-harness --bin paguro-bde-read --bin paguro-bde-write
R=$root/target/release/paguro-bde-read
export PAGURO_BDE_WRITE=$root/target/release/paguro-bde-write

rm -rf "$work"
mkdir -p "$work/mnt"
unmount() { fusermount -u "$1" 2>/dev/null || umount "$1" 2>/dev/null; }
trap 'unmount "$work/mnt" || true' EXIT
fails=0
pass() { echo "  ok   $*"; }
fail() { echo "  FAIL $*"; fails=$((fails + 1)); }
sha() { sha256sum < "$1" | cut -c1-64; }

# bdeinfo's view, normalised to the manifest's key=value lines. The volume
# fields come out in ours_fields' order whatever order bdeinfo prints them
# in (20190102, Ubuntu 24.04's, prints the method before the identifier;
# 20240502 after); protectors keep bdeinfo's order, which is the metadata's.
bdeinfo_fields() { # image [bdeinfo key options...]
  local img=$1; shift
  bdeinfo "$@" "$img" </dev/null 2>/dev/null | awk -F'\t+: ' '
    /Volume identifier/ {vid=$2; hv=1}
    /Encryption method/ {meth=$2; hm=1}
    /^\tDescription/ {desc=$2; hd=1}
    /^\tIdentifier/ {id=$2}
    /^\tType/ {prot = prot "protector=" $2 " " id "\n"}
    END {
      if (hv) print "volume_id=" vid
      if (hm) print "method=" meth
      if (hd) print "description=" desc
      printf "%s", prot
    }' || true
}
ours_fields() { # image
  "$R" --input "$1" --info | awk -F'\t: ' '
    /^Volume identifier/ {print "volume_id=" $2}
    /^Encryption method/ {print "method=" $2}
    /^Description/ {print "description=" $2}
    /^Identifier/ {id=$2}
    /^Type/ {print "protector=" $2 " " id}'
}

oracle_decrypt() { # image out-dis out-bde dislocker-opts... -- bdemount-opts...
  local img=$1 od=$2 ob=$3; shift 3
  local dis=() bde=()
  while [ "$1" != -- ]; do dis+=("$1"); shift; done; shift
  bde=("$@")
  rm -f "$od" "$ob"
  dislocker-file -V "$img" "${dis[@]}" "$od" >/dev/null 2>&1 || rm -f "$od"
  if bdemount "${bde[@]}" "$img" "$work/mnt" </dev/null >/dev/null 2>&1; then
    cp "$work/mnt/bde1" "$ob"; unmount "$work/mnt"
  fi
}

manifest=$work/manifest.txt
: > "$manifest"

echo "== Windows-made volumes"
tar xJf "$fx/windows/bitlk-images.tar.xz" -C "$work"
imgs=$work/bitlk-images
cfg() { awk -v s="[$1]" -v k="$2" '$0==s{f=1;next} /^\[/{f=0} f && index($0,k"=")==1 {sub(/^[^=]*=/,""); print}' "$imgs/images.conf"; }
names=$(sed -n 's/^\[\(.*\)\]$/\1/p' "$imgs/images.conf")
if [ -z "${PAGURO_BDE_OFFLINE:-}" ] && curl -sfL -o "$work/bdetogo.raw" \
    https://raw.githubusercontent.com/log2timeline/dfvfs/64fde7c153ae63983d18c5f446bdc0ce3ef796ba/test_data/bdetogo.raw \
    && [ "$(sha "$work/bdetogo.raw")" = ed7982a1f9263e4e54889fea1fa74112d12fea0a0aa7cd8f84fc6f03198ae71b ]; then
  names="$names dfvfs-bdetogo"
fi

for n in ${PAGURO_BDE_ONLY:-$names}; do
  if [ "$n" = dfvfs-bdetogo ]; then
    img=$work/bdetogo.raw pw=bde-TEST rp= want= bek= clear=
  else
    img=$imgs/$n.img pw=$(cfg "$n" PW) rp=$(cfg "$n" RP) want=$(cfg "$n" SHA256SUM)
    bek= clear=
    sk=$(cfg "$n" SK_VMK_GUID); [ -n "$sk" ] && bek=$imgs/${sk^^}.BEK
    [ -n "$(cfg "$n" CLEARKEY_VMK_GUID)" ] && clear=1
  fi
  echo "-- $n"
  # Every key the fixture has: "ours-option|dislocker-option|bdemount-option".
  keys=()
  [ -n "$pw" ] && keys+=("--password $pw|-u$pw|-p $pw")
  [ -n "$rp" ] && keys+=("--recovery $rp|-p$rp|-r $rp")
  rp2=$(cfg "$n" RP2 2>/dev/null || true); [ -n "$rp2" ] && keys+=("--recovery $rp2|-p$rp2|-r $rp2")
  [ -n "$bek" ] && keys+=("--startup-key $bek|-f$bek|-s $bek")
  [ -n "$clear" ] && keys+=("--clear-key|--clearkey|")

  # Metadata: ours against bdeinfo (which needs a key to open the volume).
  first=${keys[0]}
  IFS='|' read -r -a k <<< "$first"
  read -r -a bopt <<< "${k[2]:-}"
  bdeinfo_fields "$img" "${bopt[@]}" > "$work/bi.txt"
  if ours_fields "$img" > "$work/oi.txt" 2>"$work/oi.err"; then
    if [ -s "$work/bi.txt" ]; then
      diff -u "$work/bi.txt" "$work/oi.txt" > "$work/idiff" && pass "metadata = bdeinfo" \
        || { fail "metadata differs from bdeinfo"; cat "$work/idiff"; }
    else
      pass "metadata parsed (bdeinfo cannot open this volume)"
    fi
  else
    pass "metadata refused: $(cat "$work/oi.err")"
  fi

  refused= agreed=
  for key in "${keys[@]}"; do
    IFS='|' read -r -a k <<< "$key"
    read -r -a oopt <<< "${k[0]}"; read -r -a dopt <<< "${k[1]}"; read -r -a bopt <<< "${k[2]:-}"
    oracle_decrypt "$img" "$work/d.img" "$work/b.img" "${dopt[@]}" -- "${bopt[@]}"
    ds=$([ -s "$work/d.img" ] && sha "$work/d.img" || echo -)
    bs=$([ -s "$work/b.img" ] && sha "$work/b.img" || echo -)
    if "$R" --input "$img" "${oopt[@]}" --output "$work/o.img" 2>"$work/o.err"; then
      os=$(sha "$work/o.img")
      if [ "$os" = "$ds" ] && [ "$os" = "$bs" ] && { [ -z "$want" ] || [ "$os" = "$want" ]; }; then
        pass "${oopt[0]}: whole volume = dislocker = libbde${want:+ = cryptsetup} (${os:0:16})"
        agreed=$os
      elif [ "$bs" = - ] && [ "$os" = "$ds" ] && [ "$os" = "$want" ]; then
        # libbde tries only the first recovery-password protector.
        pass "${oopt[0]}: whole volume = dislocker = cryptsetup (${os:0:16}); libbde cannot open with this key"
      else
        fail "${oopt[0]}: ours $os, dislocker $ds, libbde $bs, cryptsetup ${want:--}"
      fi
    else
      refused=$(sed 's/^paguro-bde-read: //' "$work/o.err")
      pass "${oopt[0]}: refused ($refused); dislocker ${ds:0:12}, libbde ${bs:0:12}"
    fi
  done

  if [ "$update" = 1 ]; then
    "$R" --input "$img" --sparse "$fx/windows/$n.sparse" 2>/dev/null || true
    {
      echo "[$n]"
      echo "size=$(stat -c %s "$img")"
      [ -n "$pw" ] && echo "password=$pw"
      [ -n "$rp" ] && echo "recovery=$rp"
      [ -n "$rp2" ] && echo "recovery=$rp2"
      [ -n "$bek" ] && { cp "$bek" "$fx/windows/"; echo "startup_key=$(basename "$bek")"; }
      [ -n "$clear" ] && echo "clear_key=1"
      if [ -n "$agreed" ]; then
        echo "sha256=$agreed"
        # The boot sectors as the oracles return them (relocated, decrypted).
        echo "boot_sha256=$(head -c 8192 "$work/d.img" | sha256sum | cut -c1-64)"
      fi
      [ -n "$refused" ] && echo "refused=$refused"
      cat "$work/bi.txt"
      echo
    } >> "$manifest"
  fi
done
[ "$update" = 1 ] && cp "$manifest" "$fx/windows/manifest.txt"

echo "== Generated volumes (make.sh, verified by dislocker and libbde)"
mkplain() { # size sector-size out
  truncate -s "$1" "$3"
  mkntfs -q -F -f -s "$2" -c "$(( $2 > 4096 ? $2 : 4096 ))" -L paguro "$3" >/dev/null 2>&1
  printf 'paguro BitLocker fixture\n' > "$work/hello.txt"
  ntfscp -q "$3" "$work/hello.txt" hello.txt
}
mkplain 64M 512 "$work/p512.img"
mkplain 64M 4096 "$work/p4k.img"
cases=(
  "p512 --password pässwörd --recovery auto --seed 1"
  "p512 --password pw --cipher xts256 --seed 2"
  "p4k --recovery auto --seed 3"
  "p4k --clear-key --cipher xts256 --seed 4"
  "p512 --startup-key @BEK --seed 5"
  "p512 --password pw --encrypted-size 33554432 --seed 6"
  "p4k --password pw --encrypted-size 41943040 --validation-v1 --seed 7"
  "p512 --password pw --recovery auto --clear-key --encrypted-size 34603520 --seed 8"
  "p4k --startup-key @BEK --cipher xts256 --password pw --seed 9"
)
i=0
for c in "${cases[@]}"; do
  i=$((i + 1))
  read -r -a a <<< "$c"
  plain=${a[0]}; opts=("${a[@]:1}")
  opts=("${opts[@]/@BEK/$work/g$i.bek}")
  echo "-- g$i: ${opts[*]}"
  if ! "$fx/make.sh" "$work/$plain.img" "$work/g$i.img" "${opts[@]}" >"$work/make.log" 2>&1; then
    fail "make.sh: $(cat "$work/make.log")"; continue
  fi
  pass "$(tail -1 "$work/make.log" | sed 's/^make.sh: //')"
  keys=$work/g$i.img.keys
  kv() { awk -v k="$1" '$1==k {print $2}' "$keys"; }
  ok=()
  [ -n "$(kv password)" ] && ok+=("--password $(kv password)")
  [ -n "$(kv recovery)" ] && ok+=("--recovery $(kv recovery)")
  [ -n "$(kv clear-key)" ] && ok+=("--clear-key")
  [ -n "$(kv startup-key)" ] && ok+=("--startup-key $(kv startup-key)")
  for o in "${ok[@]}"; do
    read -r -a oo <<< "$o"
    if "$R" --input "$work/g$i.img" "${oo[@]}" --output "$work/o.img" 2>"$work/o.err" \
        && cmp -s "$work/o.img" "$work/g$i.img.expect"; then
      pass "${oo[0]}: ours = expected view (= dislocker = libbde)"
    else
      fail "${oo[0]}: ours differs or failed: $(cat "$work/o.err")"
    fi
  done
  bdeinfo_fields "$work/g$i.img" $([ -n "$(kv password)" ] && echo -p "$(kv password)") \
    $([ -z "$(kv password)" ] && [ -n "$(kv recovery)" ] && echo -r "$(kv recovery)") \
    $([ -z "$(kv password)$(kv recovery)" ] && [ -n "$(kv startup-key)" ] && echo -s "$(kv startup-key)") \
    > "$work/bi.txt"
  ours_fields "$work/g$i.img" > "$work/oi.txt"
  diff -u "$work/bi.txt" "$work/oi.txt" > "$work/idiff" && pass "metadata = bdeinfo" \
    || { fail "metadata differs from bdeinfo"; cat "$work/idiff"; }
done

echo
if [ "$fails" -ne 0 ]; then
  echo "diff.sh: $fails failure(s)"
  exit 1
fi
echo "diff.sh: all agree"
