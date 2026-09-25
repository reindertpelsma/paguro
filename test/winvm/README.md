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
  encryption. The NIC is unplugged (QMP `set_link`) from the install until the
  first-logon script starts, so OOBE's "Checking for updates" adds nothing.
- The evaluation is activated online at the end of the build (`slmgr /ato`):
  it is valid for **90 days from the build** (`slmgr /xpr` shows the date);
  after that, rebuild. An unactivated evaluation reports "grace time expired".

The first build took about 75 min on a loaded 4-core host (Windows Setup
about 60 min with the ISO streamed over HTTPS, first-logon setup 13 min,
the testsigning boot 1 min). The base image is about 11 GiB (12 GiB with
`--no-compress`; compressed roughly half, but the compression needs that much
free space next to the install image while it runs).

## Secure Boot and test signing

Windows refuses `testsigning` while Secure Boot is enforced. The build
therefore installs **with Secure Boot on** (Windows 11 setup checks, the MS
keys in the variable store), then boots once with Secure Boot off to set
`testsigning`. `winvm start` boots with Secure Boot **off** by default (the
non-secboot OVMF build, same variable store), so test-signed drivers load;
`winvm start --secure-boot` enforces it (and test-signed drivers then do not
load).

## WSL2 inside the VM (third level of virtualization)

Works, with one change: boot with `WINVM_CPU=host` (plain host CPU model, no
Hyper-V enlightenments). Tested on an AMD EPYC host with `kvm_amd nested=1`:
`wsl --install --no-distribution` (WSL 2.7.14; it must run from the desktop,
over SSH the inbox `wsl.exe` stub only prints "not installed"), reboot, then
`wsl --import` of an Alpine minirootfs and `wsl -d alpine -- uname -a` runs the
WSL2 kernel (6.18.33.2-microsoft-standard-WSL2, 4 CPUs, ~4 GB). WSL prints
"Nested virtualization is not supported on this machine" but runs anyway.
With the default enlightened CPU model, the guest reached the desktop with the
hypervisor enabled and then hung (vCPUs spinning, no SSH). Expect the WSL2
path to be slow; it is for functional tests, not timing.

WSL is not in the base image: install it in an overlay (`start`, then the
steps above, `start --keep` afterwards).

## Findings from the first smoke run

- `cargo xwin build -p paguro-win --release --target x86_64-pc-windows-msvc`
  links the CRT dynamically; on a clean Windows 11 `paguro.exe` then exits
  `0xC0000135` (VCRUNTIME140.dll not found) without printing anything. With
  `RUSTFLAGS="-C target-feature=+crt-static"` it runs (`smoke.sh` does this).
  The hosted CI runner hides this because Visual Studio is installed there.
- Run unelevated from the desktop, `paguro status` reports `secure boot: null`
  and `minifilter: not loaded` while PaguroFlt is loaded (elevated over SSH it
  reports both correctly).
- `Import-Certificate` into `LocalMachine\Root` fails with E_ACCESSDENIED over
  SSH; `certutil -addstore` works.

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
winvm build [--iso PATH|URL] [--skip-verify] [--force]   # ~75 min, unattended
winvm start [--keep] [--secure-boot] [--paguro-vm] [--vnc N] [--no-wait]
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
`WINVM_CPUS` (4), `WINVM_CPU` (QEMU `-cpu`; `host` for WSL2), `WINVM_TPM_DIR`.

`start --paguro-vm` adds the SMBIOS type 11 `paguro-vm/1` OEM string, so the
minifilter's release build loads active.

`build --resume [--disk IMG] [--no-compress]` finishes a build whose phase 1
is running or done (for example after moving the install image to another
disk with a live `blockdev-snapshot-sync`/`drive-mirror` when space ran out).

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

RUSTFLAGS="-C target-feature=+crt-static" \
  cargo xwin build -p paguro-win --release --target x86_64-pc-windows-msvc
$W ssh mkdir C:\\winvm\\t
$W scp target/x86_64-pc-windows-msvc/release/paguro.exe :C:/winvm/t/
$W ssh C:\\winvm\\t\\paguro.exe status --json

# drive the desktop: Win+R, an elevated console, a screenshot, a click
$W key win-r; $W type "cmd /k fltmc filters"; $W key ctrl-shift-ret
$W wait-screen 30; $W screenshot /tmp/fltmc.png; $W click 1091 145

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
- `minifilter-test.ps1` – runs on the VM: trust the CI test certificate,
  install, load inert + `pgflt_test inert`, load active + `pgflt_test active`
