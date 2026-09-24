# Loader themes

The loader's look — colours, fonts, sizes, layout, images and every string —
is compiled into `paguro.efi` (INTERFACES.md §13.1, DESIGN.md §4.2 "Theme —
compiled in"). The loader contains no PNG, TOML or font parser: at build time
`crates/paguro-theme` validates a theme directory and emits Rust statics
(pre-rasterised glyphs per text style and scale, pre-decoded premultiplied
images per scale, a resolved layout per screen, the strings), which
`crates/paguro-ui` renders.

```sh
PAGURO_THEME=default PAGURO_LANG=en cargo build --release -p paguro-efi --target x86_64-unknown-uefi
PAGURO_THEME=path/to/mytheme cargo run -p paguro-ui-preview -- --all --out-dir /tmp/gallery
cargo run -p paguro-ui-preview -- --list
cargo run -p paguro-ui-preview -- --screen unlock --res 1920x1080 --theme high-contrast --out x.png
```

`PAGURO_THEME` is a directory name under `themes/` or a path (default
`default`); `PAGURO_LANG` picks `strings/<lang>.toml` (default `en`). A theme
that fails validation fails the build with a message naming the file and key.
Changing the theme changes the binary, so PCR 4 moves and machines re-seal —
deliberately (DESIGN.md §4.2).

## Layout of a theme

```text
themes/<name>/
  theme.toml            everything below
  variants/*.toml       compiled-in alternates (high contrast, large text…),
                        each overlaying theme.toml; F2 cycles them at run time
  images/*.png          any PNG; scaled at build time to each scale step
  fonts/*.ttf           TrueType/OpenType, rasterised at build time
  strings/<lang>.toml   every user-visible string
```

## `theme.toml`

Every length is in **reference pixels**. The loader computes
`s = min(width / reference.w, height / reference.h)` and uses the largest
entry of `scales` not above `s` (the smallest entry when all are above), so
the UI keeps its proportions from 640×480 to 3840×2160. Each scale entry is
rasterised at build time — each one costs binary size.

### `[theme]`

| key | meaning |
|---|---|
| `name` | `[A-Za-z0-9_-]+`; a variant must set its own |
| `description` | free text |
| `reference` | `[w, h]`, the design size |
| `scales` | 1–8 strictly increasing factors in 0.25–4 |

### `[fonts]`

`name = "fonts/File.ttf"`: fonts the text styles refer to.

### `[text]` — text styles

One entry per style, all required: `brand` (the name), `title`, `body`,
`label` (list rows, action labels), `detail` (row details), `field` (typed
text), `hint` (key hints), `key` (key caps), `banner` (the unattested banner
and messages).

```toml
label = { font = "regular", size = 20, line = 28, charset = "latin1" }
```

`size` and `line` (line height) are reference pixels. Every style carries
the characters of the strings drawn in it, digits and a few separators;
`charset` adds printable ASCII (`"ascii"`) or all of Latin-1 (`"latin1"`).
`label` and `field` must be `latin1` (they show file names and typed text),
`detail` at least `ascii` (it shows the default UEFI path). Two styles with
identical settings share their glyphs in the binary. Characters missing from
a font are drawn as `?`; a character a *string* needs but the font lacks is a
build error.

### `[colors]`

All roles are required, as `"#rrggbb"`: `background`, `text`, `muted`,
`faint` (disabled rows, placeholders), `accent`, `surface` (rows, fields),
`surface_selected`, `border`, `border_focus`, `cursor`, `key_border`,
`key_text`, `banner_background`, `banner_text`, `toast_background`,
`toast_text`.

### `[images]`

```toml
logo = { file = "images/logo.png", size = [40, 40] }
```

`size` is the drawn size in reference pixels; the build resamples the PNG
(premultiplied area average) for every scale step.

### `[options]`

| key | meaning |
|---|---|
| `bullet` | one character shown per hidden secret character |
| `ellipsis` | one character ending cut text |
| `selection` | how the chosen list row is marked: `bar`, `fill` or `outline` |
| `scale_bias` | use this many scale steps more than the screen calls for (large text; no extra glyphs) |

### `[layout]`, `[primitive.<name>]`, `[screen.<name>]`

`[layout]` holds the defaults for every screen. `[primitive.<name>]`
(`list`, `field`, `message`) and then `[screen.<name>]` (`unlock`, `secret`,
`recovery_key`, `path`, `message`, `volumes`, `browser`, `disk`)
override any subset of its keys, table by table:

```toml
[primitive.message]
content = { max_width = 620 }

[screen.unlock]
show_hints = false
decorations = [{ image = "logo", anchor = "bottom-right", offset = [0, 0] }]
```

| key | meaning |
|---|---|
| `margin` | `[vertical, horizontal]` around the frame |
| `show_logo`, `show_name`, `show_hints` | frame elements on/off |
| `brand` | `{ anchor, offset, logo, gap }`: the logo (an `[images]` name, optional) and the name |
| `banner` | `{ anchor, offset, padding = [v, h], radius }`: "unattested" |
| `content` | `{ anchor, offset, max_width, align }`: the column holding title, text and the screen's list, field or actions; `align` is `left`, `center` or `right` |
| `hints` | `{ anchor, offset, gap }`: the key hints |
| `decorations` | images drawn only where they overlap nothing: `[{ image, anchor, offset }]` |
| `spacing` | `{ title, paragraph, block }`: gaps after a title, between paragraphs, around blocks |
| `row` | `{ height, padding, gap, radius, marker }`: list rows (`marker`: selection bar/outline width) |
| `field` | `{ height, padding, radius, border, cursor, group_gap }`: text fields and the recovery-key groups |
| `keycap` | `{ padding, radius, border, gap }` |
| `toast` | `{ padding = [v, h], radius, gap }`: "That did not unlock…" |

Anchors: `top-left`, `top-center`, `top-right`, `center-left`, `center`,
`center-right`, `bottom-left`, `bottom-center`, `bottom-right`. The brand,
banner and hints must use a `top-*` or `bottom-*` anchor: the content column
owns the band between them. Offsets move an element from its anchor; nothing
is ever placed outside the frame.

What the renderer guarantees whatever the theme says: text is cut with the
ellipsis rather than spilled (the browser's path is cut at the front, so the
current folder stays visible), paragraphs and lists give up lines when the
screen is short (lists scroll to the selection; the browser shows at most ten
rows and its position), text never overlaps other text or images, and nothing
is drawn outside the frame. The layout-invariant
tests (`crates/paguro-ui/tests/layout_prop.rs`) check this for random sizes
and labels.

## Variants

`variants/<file>.toml` overlays `theme.toml` key by key (tables merge,
anything else replaces) and must set `[theme] name`. The default theme's
`high-contrast` variant changes the colours, the selection style and sets
`scale_bias = 1`: everything one step larger with no extra font data.

## `strings/<lang>.toml`

Every key the loader uses is required and unknown keys are refused (the
catalogue is `crates/paguro-theme/src/spec.rs`). `{name}` is a placeholder
filled at run time; only the placeholders a key declares are accepted. A
newline starts a new paragraph; lines are wrapped to the layout.

## Checking a theme

- `cargo test -p paguro-ui` renders every screen in representative states at
  800×600, 1366×768, 1920×1080 and 3840×2160 for every variant and compares
  against `crates/paguro-ui/tests/golden/` (`PAGURO_BLESS=1` regenerates after
  a deliberate change);
- `cargo run -p paguro-ui-preview -- --all` writes the same gallery as PNGs.

## The default theme

Inter 4.1 (SIL Open Font License 1.1, `fonts/OFL.txt`), subset to Latin-1
and the punctuation the strings use by `tools/subset-fonts.sh`. The logo is
drawn by `tools/draw-logo.py` (standard library only; regenerate with
`python3 themes/tools/draw-logo.py`).
