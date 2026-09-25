# paguro-theme

The build-time half of the loader's theme: validates a `themes/<name>/`
directory and emits Rust source for `paguro-ui` to `include!`. Host-only —
runs inside `paguro-ui`'s `build.rs`; nothing here reaches `paguro.efi` except
the statics it writes.

## Its place in paguro

A theme is `themes/<name>/`: `theme.toml`, `images/*.png`, `fonts/*.ttf`,
`strings/<lang>.toml`, optional `variants/*.toml`. This crate writes
pre-rasterised glyph alpha maps per text style/scale step, pre-decoded
premultiplied BGRA images per scale step, a resolved layout table per screen
kind, and the string table (literal + placeholder parts) — everything
[`paguro-ui`](../paguro-ui) then only reads as statics. See
[`docs/INTERFACES.md`](../../docs/INTERFACES.md) §13.1 and
[`docs/DESIGN.md`](../../docs/DESIGN.md) §4.2 ("Theme — compiled in,
extensible at build time"). [`paguro-ui-preview`](../paguro-ui-preview)
exercises the same compiled output for theme authors.

## Modules

| module | purpose |
|---|---|
| `spec` | the resolved output types (`STRINGS` etc.) `paguro-ui` includes |
| (crate root) | parsing `theme.toml`/`strings/*.toml` (`serde`/`toml`), PNG decoding (`png`), font rasterisation (`fontdue`), and code generation |

## Invariants

- Host-only build tool: a panic here fails the build — already where every
  invalid theme input ends up — and this code never ships in the loader.
- **Everything that parses PNG, TOML or TTF runs here**, on the build host;
  the loader (`paguro-ui`/`paguro-efi`) contains none of those parsers.
- Every error names the offending file and key, and fails the build rather
  than falling back to a default.

## Build & test

```sh
cargo test -p paguro-theme
cargo build -p paguro-efi --target x86_64-unknown-uefi   # exercises it via build.rs
```

Exercised indirectly by every `paguro-ui`/`paguro-efi` build in
`.github/workflows/loader.yml` (the `test`, `efi` and `languages` jobs all
invoke this crate through `build.rs`).
