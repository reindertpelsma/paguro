#!/usr/bin/env bash
# Reproduce themes/default/fonts/*.ttf: Inter 4.1 (SIL OFL 1.1), subset to
# what the loader can show — Latin-1 plus the punctuation, arrows and bullet
# the strings use. build.rs rasterises from these at build time; nothing of
# the font file reaches paguro.efi.
#
# Needs: curl, unzip, sha256sum, pyftsubset (python3 fonttools).
set -euo pipefail
cd "$(dirname "$0")/../default/fonts"

URL=https://github.com/rsms/inter/releases/download/v4.1/Inter-4.1.zip
SHA256=9883fdd4a49d4fb66bd8177ba6625ef9a64aa45899767dde3d36aa425756b11e
UNICODES="U+0020-007E,U+00A0-00FF,U+2013-2014,U+2018-2019,U+201C-201D,U+2022,U+2026,U+2190-2193,U+2212"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -sSL -o "$tmp/inter.zip" "$URL"
echo "$SHA256  $tmp/inter.zip" | sha256sum -c -
unzip -q -o "$tmp/inter.zip" -d "$tmp"
cp "$tmp/LICENSE.txt" OFL.txt
for w in Regular SemiBold; do
  pyftsubset "$tmp/extras/ttf/Inter-$w.ttf" \
    --unicodes="$UNICODES" \
    --layout-features='' --no-hinting --desubroutinize \
    --name-IDs='*' --name-languages='*' \
    --output-file="Inter-$w.ttf"
done
ls -l
