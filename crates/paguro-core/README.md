# paguro-core

Pure, dependency-free logic shared by the loader, the kernel module and
userspace: every on-disk format paguro reads or writes, and the parsers for
them. `no_std`, no allocation, `forbid(unsafe_code)`. It runs everywhere —
compiled into `paguro-efi` (UEFI), the Linux initrd, `paguro-win`, and as the
Rust specification the C kernel module's core is differential-tested against.

## Its place in paguro

The dependency-free centre of the workspace: [`paguro-crypto`](../paguro-crypto)
supplies the primitives its formats wrap; [`paguro-boot`](../paguro-boot),
[`paguro-efi`](../paguro-efi), [`paguro-initrd`](../../crates/paguro-initrd),
[`paguro-win`](../paguro-win) and [`paguro-harness`](../paguro-harness) all
build on it directly. See [`docs/DESIGN.md`](../../docs/DESIGN.md) §5.5 ("The
trusted core — one module") for why this crate exists as ordinary, testable
functions over byte slices, and [`docs/INTERFACES.md`](../../docs/INTERFACES.md)
for the exact format each module implements.

## Modules

| group | modules | purpose |
|---|---|---|
| enforcement | `range`, `runlist` | §4.3 — the runtime range test and the one NTFS parse at module load; the specification the C core mirrors |
| disk formats | `vhd`, `disk`, `gpt`, `fat` | §2, §4.2 — fixed-VHD, disk detection, GPT, read-only FAT32 |
| NTFS | `ntfs` | boot-entry lookup, the loader's own reads |
| BitLocker | `fve`, `bde` | §6 — bounded FVE metadata walk, volume header/protectors/sector map |
| config & handoff | `config`/`ini`, `seal`, `bootstrap`, `handoff` | §6 — `paguro.ini`, seal files, boot-variable bootstrap, loader→initrd handoff |
| identifiers | `guid` | GUIDs used throughout |
| TPM | `tpm` | request/response marshalling |
| display/input | `edid`, `vt100` | §13.2a — preferred resolution, serial VT100 decoding |
| Windows-side data | `efisig`, `smbios`, `hwid` | §11.6, §11.5 — signature lists, DMI strings, hardware IDs/modaliases |
| pre-flight | `recorded`, `tcglog` | §4.6 — what Linux recorded, the TCG log's PCR 7 prefix |
| shared | `bytes` | byte-slice helpers used across the above |

## Invariants

- `no_std`, no allocation, `#![forbid(unsafe_code)]`.
- Every parser is hardened: fixed capacity, reject rather than tolerate
  malformed input, no panics on attacker-controlled data.
- Every parser has a fuzz target under [`fuzz/`](../../fuzz) — see that
  README for which target covers which module.
- `range` is the specification the C kernel module's core is
  differential-tested against (`paguro-harness`); keeping the two in sync is
  load-bearing for DESIGN.md §5.5's testability argument.

## Build & test

```sh
cargo test -p paguro-core
cargo clippy -p paguro-core --all-targets -- -D warnings
```

Run as part of `.github/workflows/loader.yml` (fmt/clippy/test job) and
`.github/workflows/ci.yml`. The real-volume NTFS tests are gated by
`cargo test -p paguro-core --test ntfs_dir` (loader.yml checks they didn't
silently skip).
