#!/bin/sh
# Smoke test of the Windows test VM: boot a fresh overlay, check the OS and
# test signing, screenshot the desktop, cross-build paguro.exe and run
# `status --json` on it, then install and exercise the test-signed minifilter
# from the windows workflow's `paguro-minifilter` artifact.
#
#   test/winvm/smoke.sh [<run-id>]      # run id of a successful `windows` run
#                                       # (default: the latest one on main)
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
W="$HERE/winvm"
DIR=${WINVM_DIR:-/data/paguro-work/winvm}
SHOTS="$DIR/shots"
mkdir -p "$SHOTS"
say() { printf '\n### %s\n' "$*"; }

say "minifilter artifact"
RUN=${1:-$(gh run list -R reindertpelsma/paguro --workflow windows.yml --branch main \
    --status success -L 1 --json databaseId -q '.[0].databaseId')}
MF="$DIR/artifacts/minifilter-$RUN"
[ -d "$MF" ] || gh run download "$RUN" -R reindertpelsma/paguro -n paguro-minifilter -D "$MF"
echo "run $RUN -> $MF"

say "paguro.exe (x86_64-pc-windows-msvc, cargo-xwin)"
(cd "$REPO" && cargo xwin build -p paguro-win --release --target x86_64-pc-windows-msvc)
EXE="$REPO/target/x86_64-pc-windows-msvc/release/paguro.exe"

say "boot"
"$W" start
trap '"$W" stop' EXIT
"$W" ssh ver
"$W" ssh "bcdedit | findstr testsigning"
"$W" ssh "bcdedit | findstr testsigning" | grep -q Yes
"$W" wait-screen 120 --stable 5 >/dev/null || true
"$W" screenshot "$SHOTS/smoke-desktop.png"

say "paguro.exe status --json"
"$W" ssh "mkdir C:\\winvm\\t 2>nul & exit 0"
"$W" scp "$EXE" :C:/winvm/t/paguro.exe
"$W" ssh "C:\\winvm\\t\\paguro.exe status --json" | tee "$DIR/logs/smoke-status.json"
grep -q '"paguro-cli/1"' "$DIR/logs/smoke-status.json"

say "the same, typed into a console on the desktop"
"$W" key win-r
sleep 2
"$W" type "cmd /k C:\\winvm\\t\\paguro.exe status" --enter
sleep 5
"$W" screenshot "$SHOTS/smoke-paguro-status.png"

say "minifilter"
"$W" ssh "rmdir /s /q C:\\winvm\\mf 2>nul & mkdir C:\\winvm\\mf"
"$W" scp -r "$MF/pkg" :C:/winvm/mf/
"$W" scp -r "$MF/test" :C:/winvm/mf/
"$W" scp "$HERE/minifilter-test.ps1" :C:/winvm/mf/
"$W" ssh "powershell -NoProfile -ExecutionPolicy Bypass -File C:\\winvm\\mf\\minifilter-test.ps1" \
    | tee "$DIR/logs/smoke-minifilter.log"
"$W" key win-r
sleep 2
"$W" type "cmd /k fltmc filters"
"$W" key ctrl-shift-ret   # Run dialog: elevated (no prompt for admins on this VM)
sleep 4
"$W" screenshot "$SHOTS/smoke-fltmc.png"
say "smoke passed; screenshots in $SHOTS"
