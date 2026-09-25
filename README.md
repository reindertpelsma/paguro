# paguro

> **Your existing Windows, both ways.** Install Linux like an application, use
> the Windows you already have from inside it as a VM, and keep a completely
> ordinary native Windows boot for whatever needs bare metal — with nothing
> repartitioned and nothing reinstalled.

*Paguroidea: the hermit crabs. They occupy a shell they did not build, leave its
structure unaltered, and can move out without damaging it.*

**Status: design only.** Architecturally mature, experimentally unproven. The
design is [`docs/DESIGN.md`](docs/DESIGN.md); this repository is the skeleton it
will be built into. Nothing here touches a real disk yet.

## How it works, in one paragraph

Linux lives in a fixed-VHD image file on the Windows NTFS volume — anywhere, and
more than one. A small UEFI loader (`paguro.efi`, beside Windows Boot Manager,
never replacing it) unlocks BitLocker, finds the image, and boots a UKI from it.
In Linux, a kernel module exposes the image as a block device and refuses every
other access to its sectors, so the same Windows installation can run as a VM
over the rest of the volume — or be mounted natively — without ever being able
to move or overwrite Linux. Windows stays the default boot and never learns
paguro exists; uninstall is six deletions and a reboot.

## Where to start

The design is explicit that **the first artifact is not paguro — it is the
storage torture harness** (§1b, §11 Q1–Q3): a sacrificial NTFS volume, a Windows
VM, and a block layer refusing exactly what the module would refuse, then
defrag, `chkdsk`, shrink, conversion and power loss at every write boundary. If
NTFS can be driven into an unrecoverable state, the design stops there.

## Layout

| Path | What | Design | Runs in |
|---|---|---|---|
| `crates/paguro-core` | range test, NTFS runlist decoder, fixed-VHD, `paguro.ini` grammar, seal-file layouts, bounded FVE walk | §2, §4.3, §6 | everywhere — `no_std`, no deps, no alloc |
| `crates/paguro-crypto` | the §6 key-derivation chain, `bitlocker_stretch` | §6 | everywhere — `no_std`, symmetric only |
| `crates/paguro-efi` | the loader: the four-stage contract | §4.1 | UEFI (`x86_64-unknown-uefi`) |
| `crates/paguro-initrd` | build the views, write seals, record PCRs | §4.3, §6 | the initrd |
| `crates/paguro-win` | Restart into Linux, pre-flight, repair hook | §4.6, §7 | Windows |
| `crates/paguro-harness` | the storage torture harness; today a model check of the range test and a C-vs-Rust differential test | §11 | Linux host |
| `kernel/dm-paguro` | the enforcement module: a device-mapper target (C) | §4.3 | Linux kernel |
| `windows/minifilter` | clean refusals in the guest (C/WDK) | §4.4 | Windows kernel |

**The trusted core is one module we write**, a few hundred lines of C. Its
runtime logic, `pg_range.c`, is compiled into userspace too and
differential-tested against the Rust specification `paguro-core/src/range.rs`;
the module itself is loaded in a throwaway QEMU VM in CI and exercised with real
I/O.

**Language rule: Rust by default, C where the platform's interface is C** — the
device-mapper target and the Windows minifilter. Both are thin; the logic they
run is specified and tested in Rust.

## Build

```sh
cargo test                                                     # all pure logic
cargo run -p paguro-harness -- 1000000                         # model + C-vs-Rust checks
cargo build -p paguro-efi --target x86_64-unknown-uefi         # the loader
make -C kernel/dm-paguro && kernel/dm-paguro/test/vm-test.sh   # module, in a VM
```

Boot the loader under OVMF (it stops at the unimplemented stage 1):

```sh
mkdir -p esp/EFI/BOOT
cp target/x86_64-unknown-uefi/debug/paguro.efi esp/EFI/BOOT/BOOTX64.EFI
cp /usr/share/OVMF/OVMF_VARS_4M.fd vars.fd
qemu-system-x86_64 -machine q35 -m 256 -nographic -net none \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive if=pflash,format=raw,file=vars.fd \
  -drive format=raw,file=fat:rw:esp
```

## Rules the code must keep

- **The loader never writes to disk** and never chainloads Windows (`BootNext` +
  reset instead). It implements no asymmetric cryptography.
- **The kernel module's request path is a range test and nothing else** — no
  cipher, no key, no NTFS parsing after load.
- **Every parser is hardened**, whatever stage it runs in. Fixed capacity, no
  allocation from on-disk content, reject rather than tolerate.
- **No authentication tag, no convenience check** on wrapped keys.
- **Install only adds.** Nothing existing — partition table, BitLocker
  configuration, BCD — is ever modified.

## Licence

paguro is licensed under the **Apache License 2.0** ([`LICENSE`](LICENSE)),
except:

- the Linux kernel module (`kernel/dm-paguro`) is **GPL-2.0**, as Linux
  requires; its dependency-free core (`pg_range`, `pg_claim`, `pg_ntfs`) and
  the uapi header are dual **GPL-2.0 OR MIT** so userspace tests and tools can
  share them;
- bundled third-party material keeps its own licence, stated next to it (the
  Inter font under the SIL OFL, test fixtures under their sources' licences).
