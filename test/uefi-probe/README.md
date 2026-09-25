# paguro-probe

`probe.efi` — a tiny UEFI app the QEMU scenarios chain into instead of a real
UKI, to prove the handoff end to end without needing a full Linux boot.
`no_std`, `#![no_main]`. Runs under UEFI (started by `paguro.efi` the same
way a UKI would be).

## Its place in paguro

Loaded by [`paguro-efi`](../../crates/paguro-efi) at the end of stage 4, in
place of the next real boot stage, from
[`test/qemu/runner`](../qemu/runner) scenarios. Depends on
[`paguro-core`](../../crates/paguro-core) for the handoff table format. See
[`docs/INTERFACES.md`](../../docs/INTERFACES.md) §8 ("Loader → initrd
handoff") for the configuration table it reads, and §3.2 for the synthetic
block device it opens `SimpleFileSystem` on.

On its serial console (every line prefixed `PAGURO-PROBE:`), it proves:

1. how it was started — `LoadedImage.DeviceHandle`'s device path (paguro's
   synthetic block device), or that it has none (an `efi_file` loaded from a
   buffer);
2. that the device is usable — it opens `SimpleFileSystem` on its own
   `DeviceHandle` and prints `\probe.txt` from its own FAT32;
3. what paguro handed off — the handoff configuration table's `IMAGE`
   records, `STATE` flags and rung.

Then it returns.

## Modules

Single `main.rs`; no submodules.

## Invariants

- `no_std`, `#![no_main]` — a minimal UEFI app, not linked into `paguro.efi`.
- Test-only: it exists so QEMU scenarios can assert on the handoff without a
  real distribution kernel/initrd.
- Every diagnostic line is prefixed `PAGURO-PROBE:` so `test/qemu/runner`'s
  serial-log assertions can distinguish it from `paguro.efi`'s own output.

## Build & test

```sh
cargo build --release -p paguro-probe --target x86_64-unknown-uefi
cargo clippy -p paguro-efi -p paguro-probe --target x86_64-unknown-uefi -- -D warnings
cargo clippy -p paguro-efi -p paguro-probe --target aarch64-unknown-uefi -- -D warnings
```

Built and exercised as part of `.github/workflows/loader.yml`'s `test` job
(clippy) and the `qemu` job (booted by the stage-4 scenarios).
