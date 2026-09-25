# paguro

> **Linux and Windows on one machine, seamlessly — both ways.** Install Linux
> like an application, next to the Windows you already have. Whichever one you
> boot, the other one's apps are right there on your desktop: Linux apps in
> Windows, Windows apps in Linux. Nothing repartitioned, nothing reinstalled,
> and Windows' own boot left exactly as it was.

*Paguroidea: the hermit crabs. They occupy a shell they did not build, leave its
structure unaltered, and can move out without damaging it.*

## One desktop, both operating systems

The idea is simple: pick the OS you want to sit in, and keep using your apps
from the other one without thinking about where they live.

| You booted | You also get |
|---|---|
| **Windows** | your Linux apps in ordinary Windows windows, through WSL2 and WSLg (or GWSL) — running from the same Linux installation you boot natively |
| **Linux**, on the metal | your Windows apps as ordinary Linux windows, WinBoat-style — from **your own Windows installation**, the one you also boot natively, running as a VM with GPU acceleration |

Same apps, same files, same installations — just a different one in charge of
the hardware. Reboot into Linux when you want native Linux performance, into
Windows when something needs bare metal (anti-cheat, vendor tools), and keep
working with both either way. paguro keeps its footprint small: Windows' boot
path, BitLocker configuration and partition table are never modified, and
uninstalling is deleting a handful of files.

## What you get

- **Space shared with Windows, not carved from it.** Linux lives in image files
  on your Windows drive, so it draws from the same free space: no partition
  sized up front, no starving one side to feed the other. An image grows when
  it needs to.
- **As many distributions as you like.** Each is a file. Trying one out is
  creating a file; removing it is deleting one — not repartitioning, twice.
- **Your Windows, both ways.** The same installation boots natively and runs as
  a GPU-accelerated VM under Linux, its apps in ordinary windows.
- **Windows can reach Linux**, even on a single-disk laptop: the image is a file
  that WSL2 mounts, which a Linux partition on the Windows disk never is.
- **Your WSL2 distributions on the metal**, as they are.
- **BitLocker keeps working** without recovery-key prompts: Windows' boot path
  is never touched.

## Status

Work in progress; nothing here is ready for a real machine. Built and tested so
far, in QEMU and in CI:

- **the loader** (`paguro.efi`, x86_64 and aarch64): configuration check, PCR 12
  ratchet, TPM sealing and unsealing (swtpm), finding a disk image on NTFS,
  publishing it read-only so the firmware's own FAT driver binds it, and
  starting the next UEFI image from inside it; recovery with a file browser; a
  themed graphical UI with text mode, tested without firmware;
- **the kernel module's trusted core** (~800 lines of dependency-free C),
  differential-tested against a Rust reference, fuzzed, model-checked with
  CBMC, and run in a VM against real NTFS volumes;
- in progress: BitLocker unlock, the Windows command-line tools and minifilter,
  and the coexistence and power-loss tests.

The design is [`docs/DESIGN.md`](docs/DESIGN.md); the exact contracts between
components are [`docs/INTERFACES.md`](docs/INTERFACES.md).

## How it works, in one paragraph

Linux lives in an image file on the Windows NTFS volume — anywhere, and more
than one. A small UEFI loader (`paguro.efi`, beside Windows Boot Manager, never
replacing it) unlocks BitLocker, finds the image, and starts the next boot
stage from it: a UKI, systemd-boot, or the distribution's own shim and GRUB. In
Linux, a kernel module exposes the image as a block device and refuses every
other access to its sectors, so the same Windows installation can run as a VM
over the rest of the volume — or be mounted natively — without ever being able
to move or overwrite Linux. Windows stays the default boot and never learns
paguro exists; uninstall is a handful of deletions and a reboot.

## Layout

| Path | What | Runs in |
|---|---|---|
| `crates/paguro-core` ([README](crates/paguro-core/README.md)) | every format and parser: NTFS, VHD, GPT, FAT32, BitLocker metadata, `paguro.ini`, seals, handoff, TPM responses | everywhere — `no_std`, no alloc |
| `crates/paguro-crypto` ([README](crates/paguro-crypto/README.md)) | key derivation, XTS-AES, AES-CCM, BitLocker's stretch | everywhere — `no_std`, symmetric only |
| `crates/paguro-boot` ([README](crates/paguro-boot/README.md)) | the loader's stage machine behind a platform trait | UEFI, and the host for tests |
| `crates/paguro-efi` ([README](crates/paguro-efi/README.md)) | the UEFI adapter: firmware calls, GOP, block device publishing | UEFI (x86_64, aarch64) |
| `crates/paguro-ui` ([README](crates/paguro-ui/README.md)), `paguro-theme` ([README](crates/paguro-theme/README.md)), `paguro-ui-preview` ([README](crates/paguro-ui-preview/README.md)) | the loader's UI renderer, the build-time theme compiler, a preview tool | UEFI / build / host |
| `themes/` | themes: layout, colours, fonts, images, strings | build time |
| `crates/paguro-initrd` ([README](crates/paguro-initrd/README.md)) | builds the views, writes seals, records PCRs | the initrd |
| `crates/paguro-win` ([README](crates/paguro-win/README.md)) | the Windows command-line tool | Windows |
| `crates/paguro-harness` ([README](crates/paguro-harness/README.md)) | differential and model tests, the BitLocker test-volume writer | Linux host |
| `kernel/dm-paguro` | the enforcement module (C) | Linux kernel |
| `windows/minifilter` | clean refusals in Windows (C/WDK) | Windows kernel |
| `test/qemu` ([README](test/qemu/runner/README.md)), `test/uefi-probe` ([README](test/uefi-probe/README.md)), `test/fixtures` | QEMU scenarios, the probe payload, disk fixtures | Linux host |
| `fuzz/` ([README](fuzz/README.md)) | fuzz targets for every parser | Linux host |

**The trusted core is one module we write.** Its runtime logic is a few hundred
lines of dependency-free C, compiled into userspace too and differential-tested
against the Rust reference in `paguro-core`.

**Language rule: Rust by default, C where the platform's interface is C** — the
device-mapper target and the Windows minifilter.

## Build

```sh
cargo test                                                   # all logic, incl. mock boots
cargo run --release -p paguro-harness -- 100000              # C-vs-Rust differential checks
cargo build --release -p paguro-efi --target x86_64-unknown-uefi
test/qemu/run.sh                                             # the loader under OVMF + swtpm
test/qemu/arm64-smoke.sh                                     # the loader under AAVMF
make -C kernel/dm-paguro && kernel/dm-paguro/test/vm-test.sh # the module, in a VM
cargo run -p paguro-ui-preview -- --all --out-dir target/ui-gallery   # render every screen
```

## Rules the code must keep

- **The loader never writes to disk** and never chainloads Windows (`BootNext` +
  reset instead). It implements no asymmetric cryptography.
- **The kernel module's request path is a range test and nothing else** — no
  cipher, no key, and no NTFS parsing on I/O. NTFS is parsed only when an image
  is claimed and again when it grows: the module re-reads the file's record
  itself to confirm the new extents (after the writer — ntfs3 natively, or the
  guest with its volume flushed — has made them durable), and never takes
  them from userspace.
- **Every parser is hardened**, whatever stage it runs in. Fixed capacity, no
  allocation from on-disk content, reject rather than tolerate.
- **No authentication tag, no convenience check** on wrapped keys.
- **Install only adds.** Nothing existing — partition table, BitLocker
  configuration, BCD — is ever modified.
- **Never break Windows booting, never leak the BitLocker key, never corrupt
  a disk.** Everything else ranks below these.

## Licence

paguro is dual-licensed under **Apache-2.0 OR GPL-2.0-only**
([`LICENSE-APACHE`](LICENSE-APACHE), [`LICENSE-GPL-2.0`](LICENSE-GPL-2.0)), at
your option. The GPL-2.0 option exists for compatibility: Apache-2.0 cannot be
combined with GPL-2.0-only code (such as the Linux kernel), so anyone who needs
to can take the code under GPL-2.0 instead.

Exceptions:

- the Linux kernel module (`kernel/dm-paguro`) is **GPL-2.0**, as Linux
  requires; its dependency-free core (`pg_range`, `pg_claim`, `pg_ntfs`) and
  the uapi header are dual **GPL-2.0 OR MIT** so userspace tests and tools can
  share them;
- bundled third-party material keeps its own licence, stated next to it (the
  Inter font under the SIL OFL, test fixtures under their sources' licences).
