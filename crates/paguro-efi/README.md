# paguro-efi

`paguro.efi`, the loader binary itself: a thin `Platform` implementation over
the `uefi` crate plus `main`. `no_std`, `#![no_main]`. Runs under UEFI
(x86_64 and aarch64; the code is architecture-neutral). This is the only
crate in the workspace where `unsafe` is used (firmware calls, page
placement) rather than forbidden.

## Its place in paguro

Started by a distribution's signed shim, beside Windows Boot Manager, never
replacing it (see [`docs/DESIGN.md`](../../docs/DESIGN.md) §4.1). All of the
decision logic is [`paguro-boot`](../paguro-boot)'s `run`; this crate converts
UEFI types, bounds reads, and reports failures as values. Rendering is
[`paguro-ui`](../paguro-ui), compiled in from `themes/` at build time via
[`paguro-theme`](../paguro-theme). Exercised end to end by
`test/qemu/runner` under OVMF/AAVMF with swtpm — see
[`docs/INTERFACES.md`](../../docs/INTERFACES.md) §12.

## Modules

| module | purpose |
|---|---|
| `platform` | `Platform` over the `uefi` crate — the only place firmware is touched; opens protocols per call, closes on return |
| `blockio` | publishes a boot entry's disk file as a synthetic, read-only `EFI_BLOCK_IO_PROTOCOL` (§3.2) |
| `console` | text consoles: the diagnostic log, ConOut as text-UI sink, serial mirrors (§13.2a) |
| `front` | `Frontend` over displays, ConOut, serial consoles and input, following the configured display mode |
| `gop` | every GOP display at its own preferred mode, one frame per distinct resolution |
| `input` | input from every console at once: firmware keyboard, serial (VT100), pointers |

## Invariants

- **Never writes to disk** — firmware variables only.
- **Never chainloads Windows** — "Start Windows" is `BootNext` + reset.
- **No asymmetric cryptography** — shim verifies the UKI, not this binary.
- The theme is compiled in; no PNG, TOML or font parser is linked, and no
  attacker-authored display data is parsed here.
- SBAT metadata is embedded (`sbat.csv`) for shim's revocation scheme; bump
  the `paguro` generation to revoke older builds after a security fix.

## Build & test

```sh
cargo build --release -p paguro-efi --target x86_64-unknown-uefi
cargo build --release -p paguro-efi --target aarch64-unknown-uefi
cargo clippy -p paguro-efi --target x86_64-unknown-uefi -- -D warnings
test/qemu/run.sh          # boot it under OVMF + swtpm
test/qemu/arm64-smoke.sh  # boot it under AAVMF
```

Covered by `.github/workflows/loader.yml` (`efi`, `languages`, `qemu` jobs)
and `arm64.yml` (`boot` job).
