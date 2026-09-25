# fuzz

`cargo-fuzz` (libFuzzer) targets for every parser paguro exposes to
attacker-controlled bytes: on-disk formats, BitLocker metadata, the loader's
handoff and UI input, and the external formats the Windows tool reads. Runs
on a Linux host, nightly Rust only (`cargo-fuzz` needs `-Z` flags the pinned
stable toolchain doesn't have) — deliberately its own Cargo workspace
(`[workspace] members = ["."]`) so it doesn't drag nightly requirements into
the main build.

## Its place in paguro

Depends on [`paguro-core`](../crates/paguro-core) and
[`paguro-boot`](../crates/paguro-boot) directly; the `ntfs_diff` target also
builds the C core (`kernel/dm-paguro/pg_range.c`, `pg_claim.c`, `pg_ntfs.c`,
via `build.rs`) to differential-fuzz it against the Rust specification. See
[`docs/INTERFACES.md`](../docs/INTERFACES.md) §12 ("Testing contract") — "every
parser is fuzzed" is a project rule (see the root
[`README.md`](../README.md)), and this crate is where that's discharged.
`paguro-harness` generates seed corpora for several targets
(`ntfs-seeds`/`payload-seeds`).

## Targets, by area

| area (INTERFACES §) | targets |
|---|---|
| NTFS core (§10.1, §12) | `ntfs_file`, `runlist`, `ntfs_diff` (C vs Rust) |
| Loader parsers (§3, §4, §8, §9, §12) | `ini_config`, `seal`, `fve`, `bde_metadata`, `bde_unlock`, `gpt`, `disk`, `fat_dir`, `handoff`, `bootstrap`, `tpm_response`, `tpm_client` |
| Loader UI input (§13.2a) | `edid`, `vt100` |
| Loader's NTFS names (§3.2, §13.4) | `ntfs_index`, `ntfs_lookup` |
| Windows tool's inputs (§11.5, §11.6; DESIGN §4.6) | `win_formats` |

## Invariants

- Every parser reachable from an untrusted source (disk contents, BitLocker
  metadata, serial/EDID input, boot variables) has a target here.
- `ntfs_diff` compares the C core and the Rust specification on the same
  input — same result, same error, same sector reads — not just each in
  isolation.
- Round-trippable formats (`win_formats`'s targets) must round-trip exactly,
  not just fail to crash.

## Build & test

```sh
cargo install cargo-fuzz --locked
cd fuzz
cargo +nightly fuzz run ini_config corpus/ini_config -- -max_total_time=60
cargo +nightly fuzz run ntfs_diff corpus/ntfs_diff ../kernel/dm-paguro/test/fuzz/corpus/{ntfs,payload} \
  -- -dict=../kernel/dm-paguro/test/fuzz/ntfs.dict -max_len=131072
```

Every target here runs 60 s per push/PR (longer nightly): the loader's
parsers in `.github/workflows/loader.yml`'s `fuzz` matrix, the NTFS-core
targets plus the C-side equivalents in `kernel.yml`'s `fuzz` matrix, and
`win_formats` in `windows.yml`'s `linux` job.
