# paguro-ui

The loader's graphical (and text) front end: layout, a software rasteriser,
and the prompt loop that drives them from input. `no_std`, no allocation, no
`unsafe`, integer arithmetic only. Runs under UEFI as part of `paguro.efi`,
and on the host for tests, the golden-image suite, and
[`paguro-ui-preview`](../paguro-ui-preview).

## Its place in paguro

```
(Screen, View, Theme, width×height) --layout--> DrawList --paint--> Canvas (BGRA)
```

Depends on [`paguro-boot`](../paguro-boot) (screen/input types) and
[`paguro-core`](../paguro-core); its `build.rs` depends on
[`paguro-theme`](../paguro-theme) to compile a `themes/<name>/` directory
(`PAGURO_THEME`, `PAGURO_LANG`) into statics. Used by `paguro-efi` (the GOP is
its `driver::Display`) and `paguro-ui-preview`. See
[`docs/INTERFACES.md`](../../docs/INTERFACES.md) §13 for the rendering
contract, screens, and the text-mode fallback.

## Modules

| module | purpose |
|---|---|
| `layout` | pure layout into a fixed-capacity `DrawList` |
| `draw` | the draw list itself: rectangles, image blits, text runs |
| `canvas` | the software rasteriser; every write clipped to the buffer and the clip rect |
| `driver` | the prompt loop over a `Display` (the GOP in `paguro-efi`, a memory buffer in tests) and text-console fallback |
| `theme` | the compiled-in theme as data — pre-rasterised, pre-decoded; nothing here parses |
| `builtin` | the actual compiled-in theme/variants, `include!`d from `build.rs` output |
| `strings` | the string catalogue, generated from `paguro_theme::spec::STRINGS` |
| `text` | measuring, fitting and wrapping text with a pre-rasterised font |
| `textui` | the same screens laid out on an 80×24 character grid (§13.2a text mode) |
| `pointer` | the pointer as a pure state machine (§13.2b) |
| `display` | choosing each display's graphics mode from GOP + EDID (§13.2a) |
| `fixtures` | named screens in representative states, for the preview tool and golden tests only (dropped by the linker in the loader) |

## Invariants

- `no_std`, no allocation, no `unsafe`, integer arithmetic only.
- Every canvas write is clipped — no draw call can touch memory outside the
  buffer regardless of its arguments.
- No PNG, TOML or font parser exists in this crate: everything that parses
  those formats runs in `paguro-theme` at build time.

## Build & test

```sh
cargo test -p paguro-ui --test golden --test layout_prop
PAGURO_LANG=nl cargo test -p paguro-ui --test golden --test layout_prop   # per language
cargo clippy -p paguro-efi -p paguro-probe --target x86_64-unknown-uefi -- -D warnings
```

Covered by `.github/workflows/loader.yml`'s `test` job and the `languages`
matrix (`en nl de fr es`).
