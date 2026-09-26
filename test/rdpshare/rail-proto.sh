#!/usr/bin/env bash
# Prototype test for paguro's RAIL server (windows/rail-agent): proves that
# an RDP server built on FreeRDP 3's SERVER libraries, running inside the
# signed-in Windows session, can present individual Windows app windows
# (RAIL / RemoteApp) to a stock Linux xfreerdp3 as separate native Linux
# windows, with a token instead of a Windows password.
#
# See docs/DESIGN.md Sec.5c and /data/paguro-work/rdp-auth-research.md for
# the surrounding design context, and windows/rail-agent/README (build
# recipe) for how rail-agent.exe is produced.
#
# Requires the winvm harness (see /workspace/paguro-vm/test/winvm/README.md)
# and its exact env vars per the project's hard rules -- this script does
# not create/link/copy/move/delete anything in $WINVM_DIR except via the
# harness itself.
#
# Usage: test/rdpshare/rail-proto.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
AGENT_DIR="$REPO_ROOT/windows/rail-agent"
EVIDENCE_DIR="${EVIDENCE_DIR:-/data/paguro-work/rail-build/evidence}"
W="/workspace/paguro-vm/test/winvm/winvm"
TOKEN="railproto-$(date +%s)"
PORT=3392

export WINVM_DIR="${WINVM_DIR:-/data/paguro-work/winvm-arming}"
export WINVM_SSH_PORT="${WINVM_SSH_PORT:-2240}"
export WINVM_TPM_DIR="${WINVM_TPM_DIR:-$HOME/.cache/winvm-swtpm-arming}"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/0}"
export WINVM_EXTRA_FWD="hostfwd=tcp:127.0.0.1:${PORT}-:${PORT}"

mkdir -p "$EVIDENCE_DIR"

log() { echo "[rail-proto] $*"; }
fail() { echo "[rail-proto] FAIL: $*" >&2; exit 1; }

# --- 0. build (idempotent; the Makefile links against the pre-built
#      FreeRDP-for-Windows libraries under /data/paguro-work/rail-build) ---
log "building rail-agent.exe"
make -C "$AGENT_DIR" >/tmp/rail-agent-build.log 2>&1 \
  || fail "build failed, see /tmp/rail-agent-build.log"
[[ -f "$AGENT_DIR/rail-agent.exe" ]] || fail "rail-agent.exe missing after build"

# --- 1. start the VM (tolerate "already running": a previous run of this
#        script, or an interactive debugging session, may have left it up) ---
log "starting winvm"
"$W" start || "$W" status | grep -q '"running": true' \
  || fail "winvm is not running and would not start"

# --- 2. deploy the agent + a scheduled task that runs it interactively ---
log "deploying rail-agent.exe"
"$W" ssh "mkdir C:\\rail-agent" || true
"$W" scp "$AGENT_DIR/rail-agent.exe" :C:/rail-agent/rail-agent.exe
"$W" ssh "del C:\\rail-agent\\out.log" || true
"$W" ssh "del C:\\rail-agent\\rail-agent-server.crt C:\\rail-agent\\rail-agent-server.key" || true
# Prototype note: a real deployment needs a firewall rule (or a signed/
# properly-scoped install) -- an eval VM's default Windows Firewall silently
# drops the inbound connection otherwise (see windows/rail-agent/README).
"$W" ssh "netsh advfirewall firewall add rule name=PaguroRailAgent dir=in action=allow protocol=TCP localport=${PORT}" || true
"$W" ssh "schtasks /create /tn PaguroRailAgent /tr \"cmd /c cd /d C:\\rail-agent && rail-agent.exe --token ${TOKEN} > C:\\rail-agent\\out.log 2>&1\" /sc onstart /ru paguro /it /f"
"$W" ssh "schtasks /end /tn PaguroRailAgent" || true
sleep 1
"$W" ssh "schtasks /run /tn PaguroRailAgent"
sleep 3

FP="$("$W" ssh "type C:\\rail-agent\\out.log" | grep -o 'cert fingerprint (sha256): .*' | sed 's/cert fingerprint (sha256): //' | tr -d '\r')"
[[ -n "$FP" ]] || fail "could not read the agent's certificate fingerprint from out.log"
log "agent listening, cert fingerprint: $FP"

# --- 3. wrong token: must be refused ---
log "test (d): wrong token is refused"
if timeout 15 xvfb-run -a xfreerdp3 /v:127.0.0.1:${PORT} /u:paguro /p:not-the-token \
     /cert:fingerprint:sha256:"$FP" /sec:tls /log-level:INFO /app:program:notepad.exe \
     >/tmp/rail-proto-wrongtoken.log 2>&1; then
  fail "connection with the WRONG token was not refused (unexpected success)"
fi
grep -q "wrong token\|BIO_read retries exceeded\|Connection reset" /tmp/rail-proto-wrongtoken.log \
  || log "warning: refusal happened but the expected log marker wasn't found; check /tmp/rail-proto-wrongtoken.log"
"$W" ssh "type C:\\rail-agent\\out.log" | grep -q "REFUSED: wrong token" \
  || fail "server-side log does not show the REFUSED line for the bad token"
log "  ok: wrong token refused (server logged REFUSED, client's connection was torn down)"

# --- 4. correct token + RAIL exec: a separate X11 window must appear ---
log "test (a): correct token + /app:program:notepad.exe -> a separate host window"
export DISPLAY=:50
export XAUTHORITY=/data/paguro-work/rail-build/xauth/Xauthority
rm -f "$XAUTHORITY"; touch "$XAUTHORITY"
pkill -x Xvfb 2>/dev/null || true
sleep 1
Xvfb :50 -screen 0 1280x1024x24 -nolisten tcp -auth "$XAUTHORITY" >/tmp/rail-proto-xvfb.log 2>&1 &
XVFB_PID=$!
sleep 2

nohup timeout 180 xfreerdp3 /v:127.0.0.1:${PORT} /u:paguro /p:"${TOKEN}" \
  /cert:fingerprint:sha256:"$FP" /sec:tls /log-level:INFO /app:program:notepad.exe /w:800 /h:600 \
  >/tmp/rail-proto-client.log 2>&1 &
CLIENT_PID=$!
sleep 6

xwininfo -root -tree > /tmp/rail-proto-tree1.txt 2>&1 || true
cat /tmp/rail-proto-tree1.txt
grep -qi "Notepad" /tmp/rail-proto-tree1.txt || fail "no separate X11 window titled like '...Notepad' found"
NOTEPAD_WID="$(xdotool search --name 'Notepad' | head -1)"
[[ -n "$NOTEPAD_WID" ]] || fail "xdotool could not find the Notepad window"
log "  ok: separate X11 window for Notepad found (id $NOTEPAD_WID)"
xwd -root -out /tmp/rail-proto-01.xwd && convert /tmp/rail-proto-01.xwd "$EVIDENCE_DIR/01-rail-windows.png"

# --- 5. type into the Notepad window; verify via UI Automation over the VM's
#        interactive session (SSH alone cannot see the interactive desktop) ---
log "test (b): typing changes real Notepad content (verified via UI Automation)"
xdotool windowfocus "$NOTEPAD_WID"
sleep 1
xdotool key ctrl+a
MARKER="railproto-$(date +%s)"
xdotool type --delay 60 "$MARKER"
sleep 1
xwd -root -out /tmp/rail-proto-02.xwd && convert /tmp/rail-proto-02.xwd "$EVIDENCE_DIR/02-typed.png"

"$W" scp "$HERE/read_notepad.ps1" :C:/rail-agent/read_notepad.ps1
"$W" ssh "schtasks /create /tn PaguroReadNotepad /tr \"cmd /c powershell -ExecutionPolicy Bypass -File C:\\rail-agent\\read_notepad.ps1 > C:\\rail-agent\\readback.txt 2>&1\" /sc onstart /ru paguro /it /f" || true
"$W" ssh "schtasks /run /tn PaguroReadNotepad"
for _ in 1 2 3 4 5; do
  sleep 2
  "$W" ssh "type C:\\rail-agent\\readback.txt" > "$EVIDENCE_DIR/notepad-readback.txt" 2>&1 || true
  grep -q "$MARKER" "$EVIDENCE_DIR/notepad-readback.txt" && break
done
cat "$EVIDENCE_DIR/notepad-readback.txt"
grep -q "$MARKER" "$EVIDENCE_DIR/notepad-readback.txt" \
  || fail "UI Automation readback does not contain the text we typed via the RAIL window"
log "  ok: readback matches what was typed through the X11 window"

# --- 6. a second app (RAIL exec via a scheduled task standing in for a
#        second client-side exec, since stock xfreerdp3 only auto-execs the
#        one program named on its own command line -- see windows/rail-agent
#        README's RAIL-maturity notes) must appear as a second window ---
log "test (c): a second app gets its own separate window"
"$W" ssh "schtasks /create /tn PaguroLaunchCalc /tr calc.exe /sc onstart /ru paguro /it /f" || true
"$W" ssh "schtasks /run /tn PaguroLaunchCalc"
sleep 3
xwininfo -root -tree > /tmp/rail-proto-tree2.txt 2>&1 || true
cat /tmp/rail-proto-tree2.txt
grep -qi "Calculator" /tmp/rail-proto-tree2.txt || fail "no separate X11 window for Calculator found"
log "  ok: Calculator is a separate X11 window alongside Notepad"
xwd -root -out /tmp/rail-proto-03.xwd && convert /tmp/rail-proto-03.xwd "$EVIDENCE_DIR/03-two-apps.png"

log "ALL CHECKS PASSED. Evidence saved under $EVIDENCE_DIR"

kill "$CLIENT_PID" 2>/dev/null || true
kill "$XVFB_PID" 2>/dev/null || true
