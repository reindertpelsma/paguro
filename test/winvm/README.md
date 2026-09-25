# winvm: local Windows 11 test VM

A reusable Windows 11 VM on a Linux/KVM host, driven over QMP (screen,
keyboard, mouse) and SSH (commands, file copy). It is for testing the Windows
side of paguro (`paguro.exe`, the minifilter, later the WinUI 3 app with
FlaUI) without a Windows machine.

**Licence: the image is a Windows 11 Enterprise *evaluation* copy for local
testing only. Never commit, upload or publish the ISO, the qcow2 images or any
file derived from them.** Everything large lives in `$WINVM_DIR`
(default `/data/paguro-work/winvm`), never in the repo.

## What the base image contains

- Windows 11 Enterprise 25H2 evaluation, x64 en-US (build 26200.6584),
  streamed from Microsoft's Evaluation Center link and checked against the
  SHA-256 in Microsoft's `Verify-Download-Win11-Enterprise.pdf`
  (`a61adeab…e535e7b9`). Nothing is stored locally: QEMU reads the ISO over
  HTTPS during the install (`--iso PATH` uses a local copy instead).
- q35, OVMF with Microsoft keys enrolled (`OVMF_VARS_4M.ms.fd`), swtpm TPM 2.0,
  AHCI disk (TRIM → qcow2 discard), e1000e network (inbox drivers only),
  usb-tablet for absolute mouse input. 8 GB RAM, 4 vCPUs.
- Local administrator `paguro`, auto-logon, UAC without prompts, no lock
  screen, no sleep. Password: `$WINVM_DIR/keys/password`.
- OpenSSH Server (Win32-OpenSSH MSI), key auth with
  `$WINVM_DIR/keys/id_ed25519`; the default shell is `cmd.exe`.
- `bcdedit /set testsigning on`.
- .NET 8 SDK (8.0.425), Windows App SDK 1.8 runtime (WinUI 3). FlaUI comes
  from NuGet in the tests themselves (the VM has internet via user-mode NAT).
- Windows Update: no automatic updates (policy), quality updates deferred
  30 days, feature updates 365 days; Store auto-download off; no device
  encryption.

## Secure Boot and test signing

Windows refuses `testsigning` while Secure Boot is enforced. The build
therefore installs **with Secure Boot on** (Windows 11 setup checks, the MS
keys in the variable store), then boots once with Secure Boot off to set
`testsigning`. `winvm start` boots with Secure Boot **off** by default (the
non-secboot OVMF build, same variable store), so test-signed drivers load;
`winvm start --secure-boot` enforces it (and test-signed drivers then do not
load).

## Host requirements

`qemu-system-x86_64` with `qemu-block-extra` (the HTTPS block driver), OVMF
(`/usr/share/OVMF/*_4M*`), `swtpm`, `genisoimage`, `ssh`/`scp`, Python 3 with
`numpy` and `Pillow` (only for `wait-screen`). The VM runs in a transient
systemd user scope with `MemoryMax=10G`; set `XDG_RUNTIME_DIR` if your shell
has none (the tool defaults it to `/run/user/$UID`).

swtpm's AppArmor profile only lets it write under `$HOME`, so the TPM state
(tiny) lives in `~/.cache/winvm-swtpm` (`$WINVM_TPM_DIR`).

## Commands

```
winvm build [--iso PATH|URL] [--skip-verify] [--force]   # ~1 h, unattended
winvm start [--keep] [--secure-boot] [--vnc N] [--no-wait]
winvm stop [--force]
winvm status
winvm ssh [<cmd ...>]                # cmd.exe command line, or an interactive shell
winvm scp [-r] <src> <dst>           # guest side prefixed with ':' e.g. :C:/winvm/
winvm screenshot <out.png>
winvm type <text> [--enter]          # ASCII, US layout
winvm key <combo> [<combo> ...]      # ctrl-alt-delete, win-r, alt-f4, ret, esc ...
winvm click <x> <y> [--button right] [--double]
winvm wait-screen <seconds>          # wait until the screen stops changing
winvm wait-screen <template.png>     # wait until the template appears; prints its centre
```

`start` always boots from a **fresh overlay** (`run/overlay.qcow2` on top of the
read-only `base.qcow2`, plus fresh copies of the UEFI variables and TPM state),
so every run starts from the clean image. `--keep` reuses the previous
overlay. `start` returns once SSH answers (about 1 min).

`stop` sends an ACPI power-off, then QMP `quit`, then SIGTERM to the recorded
QEMU pid; it never kills by name.

Environment: `WINVM_DIR`, `WINVM_SSH_PORT` (2222), `WINVM_MEM` (8G),
`WINVM_CPUS` (4), `WINVM_TPM_DIR`.

## Layout of `$WINVM_DIR`

```
base.qcow2  base-vars.fd          the clean image (read-only) and its UEFI variables
run/        overlay.qcow2, vars.fd, qmp.sock, qemu.pid, serial.log, qemu.log
keys/       id_ed25519(.pub), password
payload/    installers put on the config ISO (hash-pinned in winvm)
shots/      screenshots
logs/       build.log, build-serial.log (first-logon setup progress via COM1)
```

## Example: paguro.exe and the minifilter

```sh
W=test/winvm/winvm
$W start
$W ssh ver
$W ssh "bcdedit | findstr testsigning"
$W screenshot /data/paguro-work/winvm/shots/desktop.png

cargo xwin build -p paguro-win --release --target x86_64-pc-windows-msvc
$W ssh mkdir C:\\winvm\\t
$W scp target/x86_64-pc-windows-msvc/release/paguro.exe :C:/winvm/t/
$W ssh C:\\winvm\\t\\paguro.exe --json status

# minifilter: the `paguro-minifilter` artifact of the windows workflow
# (test-signed pkg/ + test/pgflt_test.exe); see smoke.sh for the full sequence
$W stop
```

`smoke.sh` runs the whole smoke sequence (boot, `ver`, testsigning, a
desktop screenshot, `paguro.exe status --json`, the minifilter inert and
active tests).

## Files

- `winvm` – the tool (Python 3, stdlib; numpy/Pillow for `wait-screen`)
- `autounattend.xml` – unattended install (`@PASSWORD@` filled in at build)
- `winvm-setup.ps1` – first-logon setup, then power-off
- `smoke.sh` – smoke test
