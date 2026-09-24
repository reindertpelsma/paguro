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
cargo run -p paguro-ui-preview -- --screen unlock --res 1920x1080 --theme light --lang de --out x.png
cargo run -p paguro-ui-preview -- --screen unlock --text          # the text UI
cargo run -p paguro-ui-preview -- --screen unlock --cursor 400,300 --out x.png
```

`PAGURO_THEME` is a directory name under `themes/` or a path (default
`default`). Every language in the theme's `strings/` is compiled in (F5
chooses one on screen); `PAGURO_LANG` (default `en`) is the one the loader
starts in. A theme that fails validation fails the build with a message
naming the file and key.
Changing the theme changes the binary, so PCR 4 moves and machines re-seal —
deliberately (DESIGN.md §4.2).

## Layout of a theme

```text
themes/<name>/
  theme.toml            everything below
  variants/*.toml       compiled-in alternates, each overlaying theme.toml;
                        F2 cycles them at run time
  images/*.png          any PNG; scaled at build time to each scale step
  fonts/*.ttf           TrueType/OpenType, rasterised at build time
  strings/<lang>.toml   every user-visible string, one file per language
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
| `name` | `[A-Za-z0-9_-]+`; a variant must set its own. Every theme provides `dark`, `light`, `dark-contrast` and `light-contrast` (the names `paguro.ini [UI] theme` uses) |
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
| `pointer` | the `[images]` entry drawn as the pointer's cursor; its top-left pixel is the pointer's position (give light and dark variants their own) |

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
anything else replaces) and must set `[theme] name`. Every build carries
`dark` (the default), `light`, and a high-contrast version of each
(INTERFACES.md §13.2a): the build fails when one of the four is missing.
They are compiled in F2 order — dark, light, dark-contrast,
light-contrast — then any other variants a theme adds.

The default theme: `theme.toml` is `dark`; `light` is a proper light theme,
not an inversion — warm off-white paper, near-black text (15:1), secondary
text at 6:1, and the same warm accent taken darker so it still works as
text and as a focus ring (4.8:1), with a slightly deeper logo; the two
contrast variants are pure black/white with a strong accent (yellow on
black, deep orange on white at 7:1), outlined selection and `scale_bias =
1`: everything one step larger with no extra font data. The cursors are a
light arrow with a dark outline on the dark variants and the reverse on the
light ones (`tools/draw-cursor.py`).

## `strings/<lang>.toml` — languages

One file per language, shared with the Windows app (INTERFACES.md §13.5):
the loader reads the `[loader]` table (`loader.*` keys); `[win]` is the
app's and is not read here; anything else at the top level is an error.
Every `loader` key is required and unknown keys are refused (the catalogue
is `crates/paguro-theme/src/spec.rs`). `{name}` is a placeholder filled at
run time — numbers and names always go through placeholders, never
concatenation, so "{n} TPM attempts left" can be "noch {n} TPM-Versuche";
only the placeholders a key declares are accepted. A newline starts a new
paragraph; lines are wrapped to the layout, and nothing assumes a string's
width: text that does not fit is cut with an ellipsis (the layout property
tests run every language). `key_w` and `key_r` name the keys the loader
binds and stay `W` and `R`.

**Adding a Latin-script language is adding one file**: the build rasterises
whatever characters the strings use (per text style, from the theme's
fonts), so `strings/it.toml` needs no code change; `PAGURO_LANG=it` makes it
the starting language. Compiled in today: `en` (source), `nl`, `de`, `fr`,
`es` — all but `en` are machine translations pending native review (see
each file's header). `language_name` is the language's own name, as the F5
list shows it; the F5 hint names "language" in English too, so English is
always one obvious step away.

Not supported yet, and why:

- **CJK**: the fonts would need thousands of glyphs per style and scale step
  (megabytes in the signed binary), and line breaking has no spaces to
  break at; both want a different text pipeline (glyph subsetting from the
  strings is already there, wrapping is not).
- **Right-to-left scripts** (Arabic, Hebrew): the renderer lays out left to
  right only; RTL needs bidi reordering, mirrored layouts and, for Arabic,
  contextual shaping, which pre-rasterised glyphs do not provide.
- Other scripts with complex shaping (Indic, Thai) have the same problem.

## Keyboard layouts

Firmware keyboards report keys as a US layout would. `paguro.ini [UI]
keyboard` (`us`, `uk`, `de`, `fr`, `es`, `be`, `ch-de`, `nl-intl`) and F4 on
any screen choose a compiled-in table that turns that back into what the
layout gives for the same physical key (`crates/paguro-boot/src/keymap.rs`;
tables generated from xkeyboard-config by
`crates/paguro-boot/tools/xkb-keymaps.py`, checked key by key against the
extracted `tests/keymaps/*.tsv`). Screens that take typed text name the
layout ("Keyboard: German"). Dead keys give nothing; menus and the recovery
key read the number row as digits on every layout (AZERTY included).
Serial terminals send their own layout's characters and are not remapped.

## Text mode, serial consoles, several displays

INTERFACES.md §13.2a. The same screens, strings and state as the graphics,
on an 80×24 grid (`crates/paguro-ui/src/textui.rs`); typographic characters
(dashes, arrows, ellipsis) are written as ASCII so every terminal and the
firmware console font can show them. What shows where:

| `[UI] mode`  | GOP display covered by ConOut | GOP display ConOut does not cover | ConOut (firmware text console) | serial console in ConOut |
|--------------|-------------------------------|-----------------------------------|--------------------------------|--------------------------|
| `auto`       | graphics                      | graphics                          | untouched                      | text UI, VT100, owned by the loader (keys read from it) |
| `auto` + F3  | text UI (through ConOut)      | text UI painted by the loader     | text UI                        | text UI, as above        |
| `graphics`   | graphics                      | graphics                          | untouched                      | the firmware's; log only (keys through ConIn) |
| `graphics` + F3 | text UI (through ConOut)   | text UI painted by the loader     | text UI                        | text UI through ConOut   |
| `text`       | text UI (through ConOut)      | text UI painted by the loader     | text UI                        | text UI through ConOut   |
| `text` + F3  | graphics                      | graphics                          | untouched                      | the firmware's           |
| no GOP       | —                             | —                                 | text UI                        | text UI through ConOut   |

No display is ever left blank or stale: where the firmware's text console
does not reach a GOP display, the loader paints the text UI there itself
(the field font in fixed cells, the variant's colours). Every GOP device is
drawn, each at its own preferred mode from its EDID, never in a mode larger
than one display (a 3840×1080 surface over two 1920×1080 panels is refused
for a single panel's mode); one frame is rendered per distinct resolution.
Recovery never reads the configuration: dark, auto, US keyboard.

## Pointer

INTERFACES.md §13.2b. Mice and touch/tablets through the firmware's pointer
protocols; missing or failing ones are ignored. The cursor (the theme's
`pointer` image) appears on the first movement and hides on the next key;
it lives on the first display and moving it redraws only its old and new
rectangles. A click on a list row selects and opens it, a click in a field
moves the text cursor there, a click on an action or key hint acts as the
key, a click on a list's "↑ n more" / "↓ n more" pages; the wheel moves the
selection.

Later: an on-screen keyboard for pointer/touch-only machines (not built).

## Checking a theme

- `cargo test -p paguro-ui` renders every screen in representative states at
  800×600, 1366×768, 1920×1080 and 3840×2160 for every variant, a set of
  screens in every language, with the cursor, and as the text UI, and
  compares against `crates/paguro-ui/tests/golden/` (`PAGURO_BLESS=1`
  regenerates after a deliberate change);
- `cargo run -p paguro-ui-preview -- --all` writes the same gallery as PNGs
  (`--lang de --lang fr` for translations: check that long strings fit).

## The default theme

Inter 4.1 (SIL Open Font License 1.1, `fonts/OFL.txt`), subset to Latin-1
and the punctuation the strings use by `tools/subset-fonts.sh`. The logo is
drawn by `tools/draw-logo.py` (standard library only; regenerate with
`python3 themes/tools/draw-logo.py`, and `--palette light
themes/default/images/logo-light.png`), the cursors by
`tools/draw-cursor.py`.
