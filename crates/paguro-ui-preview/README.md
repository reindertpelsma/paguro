# paguro-ui-preview

Renders the loader's screens to PNG (or an 80×24 text grid on stdout) on the
host, with the theme compiled into this build. A tool for theme authors and
translators, not something the loader ships. Runs on the host (Linux/macOS/
Windows dev machine).

## Its place in paguro

Links [`paguro-boot`](../paguro-boot) and [`paguro-ui`](../paguro-ui) exactly
as `paguro-efi` does, but drives `paguro-ui`'s `builtin` theme/`fixtures`
module directly instead of firmware — so a theme change shows up as an image
without building or booting the loader. See
[`docs/INTERFACES.md`](../../docs/INTERFACES.md) §13.

```sh
cargo run -p paguro-ui-preview -- --screen unlock --res 1920x1080 --theme light --out x.png
cargo run -p paguro-ui-preview -- --all [--out-dir DIR] [--res WxH ...] [--theme NAME ...] [--lang CODE ...]
cargo run -p paguro-ui-preview -- --all --screens unlock,browse-esp --lang de --lang fr
cargo run -p paguro-ui-preview -- --screen unlock --text          # the text UI, on stdout
cargo run -p paguro-ui-preview -- --list
PAGURO_THEME=mytheme cargo run -p paguro-ui-preview -- --all
```

`--screen`/`--screens` take fixture names (`--list` prints them), `--theme` a
compiled-in variant (`dark`, `light`, `dark-contrast`, `light-contrast`, …),
`--lang` a compiled-in language. `--cursor X,Y` draws the pointer's cursor.

## Modules

Single `main.rs`; no submodules of its own — it composes `paguro_ui::builtin`,
`draw`, `fixtures`, `pointer`, `textui` and `render` directly.

## Invariants

- Host tool only — not linked into `paguro.efi`.
- Renders exactly what `paguro-ui::render` would draw under firmware, so a
  preview is representative of the real loader output.

## Build & test

```sh
cargo build -p paguro-ui-preview
cargo run -p paguro-ui-preview -- --all --out-dir target/ui-gallery   # render every screen
```

No dedicated CI job; built as part of the workspace `cargo build`/`cargo
test` in `.github/workflows/ci.yml`.
