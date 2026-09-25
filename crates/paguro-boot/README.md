# paguro-boot

The loader's logic as a stage machine, generic over a `Platform` trait so the
same code runs under UEFI (`paguro-efi`) and in the mock-boot tests on a Linux
host. `no_std`, no allocation (every buffer lives in `Buffers`, placed by the
caller — pages under UEFI, the heap in tests), `#![forbid(unsafe_code)]`.

## Its place in paguro

This is the loader's brain; [`paguro-efi`](../paguro-efi) is a thin adapter
around it (`Platform` implemented over the `uefi` crate), and
`test/qemu/runner` and `paguro-win` reuse pieces of it (the TPM client,
BitLocker unlock) so the loader and Windows share one implementation. Depends
on [`paguro-core`](../paguro-core) (formats) and
[`paguro-crypto`](../paguro-crypto) (primitives); depended on by `paguro-efi`,
`paguro-ui`, `paguro-win`, `paguro-harness`, and `test/qemu/runner`. See
[`docs/DESIGN.md`](../../docs/DESIGN.md) §4.1 ("Custom UEFI bootloader") and
§6 (the key-derivation ladder) for the four-stage execution contract this
crate implements (`Machine::go`): read and verify `paguro.ini`, parse and
taint PCR 12, unlock the volume through its seals, locate the boot entry's
disks and hand off to the next image — recovery skips straight to a
sentinel PCR-12 cap without ever parsing the configuration.

## Modules

| module | purpose |
|---|---|
| `machine` | the stage machine itself — `Machine::go` is the contract above, every branch a mock-boot test |
| `platform` | what the stage machine needs from firmware (`Platform` trait), nothing more |
| `volume` | partition discovery (GPT walk, BitLocker/NTFS probe) and the FVE-metadata side of unlocking |
| `bde` | stage 3's BitLocker reader: protectors → VMK → FVEK, the decrypted view |
| `stage4` | the unlocked volume's NTFS, the boot entry's disks, and starting the next UEFI image |
| `tpm` | the TPM conversation for the `tpm`/PIN-bypass rungs and provisioning `TPM2_Create` |
| `ui` | what every front end shares: key model, text-entry editor, list navigation |
| `keymap` | keyboard layouts at boot (US-physical key → configured layout) |
| `vt100` | keys decoded from a serial console's bytes |

## Invariants

- `no_std`, no allocation, `#![forbid(unsafe_code)]`.
- Recovery never parses the configuration; PCR 12 is capped first.
- Every stage-machine branch has a mock-boot test (`Platform` implemented in
  memory: fake variables, a fake TPM).

## Build & test

```sh
cargo test -p paguro-boot
cargo test -p paguro-boot --test swtpm -- --nocapture   # real swtpm, not mocked
cargo test -p paguro-boot --test bde_stage4              # BitLocker + stage 4
cargo clippy -p paguro-boot --all-targets -- -D warnings
```

Covered by `.github/workflows/loader.yml` (fmt/clippy/test, swtpm, BitLocker
jobs) and `arm64.yml` (aarch64 under qemu-user, including swtpm).
