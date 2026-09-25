//! `paguro-theme` — the build-time half of the loader's theme (INTERFACES.md
//! §13.1, DESIGN.md §4.2 "Theme — compiled in").
//!
//! A theme is a directory (`themes/<name>/`: `theme.toml`, `images/*.png`,
//! `fonts/*.ttf`, `strings/<lang>.toml`, optional `variants/*.toml`). This
//! crate validates it and writes Rust source for `paguro-ui` to `include!`:
//! pre-rasterised glyph alpha maps per text style and scale step,
//! pre-decoded premultiplied BGRA images per scale step, a resolved layout
//! table per screen kind, and the string table split into literal and
//! placeholder parts. **Everything that parses PNG, TOML or TTF runs here, on
//! the build host; the loader only reads the statics.**
//!
//! Every error is a sentence naming the file and key, and fails the build.

// Host build tool: a panic here fails the build, which is already where
// every invalid input ends up; the loader never contains this code.
#![allow(clippy::indexing_slicing)]

pub mod spec;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use toml::{Table, Value};

// Limits a theme is validated against (INTERFACES.md §13.1).
/// The smallest reference size a layout may be designed for.
const MIN_REFERENCE: [u32; 2] = [320, 240];
const MAX_SCALES: usize = 8;
const SCALE_MIN: f64 = 0.25;
const SCALE_MAX: f64 = 4.0;
const FONT_SIZE_MIN: f64 = 6.0;
const FONT_SIZE_MAX: f64 = 200.0;
/// A style's line height, as a multiple of its size.
const LINE_MIN: f64 = 0.9;
const LINE_MAX: f64 = 3.0;
/// An image's declared size, per side.
const IMAGE_SIDE_MAX: u32 = 1024;
/// Images are indexed by a `u8`.
const MAX_IMAGES: usize = 255;
/// Every layout length.
const LENGTH_MAX: i32 = 2000;
const CONTENT_WIDTH_MIN: i32 = 240;
const ROW_HEIGHT_MIN: i32 = 16;
const ROW_HEIGHT_MAX: i32 = 400;
const CURSOR_WIDTH_MIN: i32 = 1;
const CURSOR_WIDTH_MAX: i32 = 40;
/// A source PNG, per side.
const PNG_SIDE_MAX: u32 = 4096;

/// RGBA / BGRA pixels: four bytes, alpha last.
const RGBA: usize = 4;
const RGB: usize = 3;
const ALPHA: usize = 3;
const OPAQUE: u8 = 255;

/// Glyph advances are 26.6 fixed point (`paguro_ui::theme::SUBPX`).
const SUBPX: f32 = 64.0;
/// Scales are emitted ×1000 (`paguro_ui::theme::MILLI`), pixel sizes ×10.
const MILLI: f64 = 1000.0;
const PX_X10: f32 = 10.0;
/// The emitted `paguro_ui::theme::Glyph`: u16, u16, i16, i16, u16, u16, u32.
const GLYPH_BYTES: usize = 16;

/// Printable ASCII, and Latin-1's printable upper half.
const ASCII_PRINTABLE: std::ops::Range<u8> = 0x20..0x7f;
const LATIN1_UPPER: std::ops::Range<u32> = 0xa0..0x100;

pub type Error = String;

/// What to compile.
pub struct Options {
    /// `themes/` (for a theme given by name).
    pub themes_dir: PathBuf,
    /// A theme name under `themes_dir`, or a path to a theme directory.
    pub theme: String,
    pub lang: String,
    /// Where `theme.rs`, `strings.rs` and the binary blobs go.
    pub out_dir: PathBuf,
}

/// What was compiled: files to watch, and a size report.
pub struct Output {
    pub inputs: Vec<PathBuf>,
    pub summary: String,
}

// ---------------------------------------------------------------------------
// theme.toml, as written

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Meta {
    name: String,
    #[serde(default)]
    description: String,
    reference: [u32; 2],
    scales: Vec<f64>,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[serde(rename_all = "lowercase")]
enum Charset {
    #[default]
    Strings,
    Ascii,
    Latin1,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct TextSpec {
    font: String,
    size: f64,
    line: f64,
    #[serde(default)]
    charset: Charset,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImageSpec {
    file: String,
    size: [u32; 2],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OptionsSpec {
    bullet: String,
    ellipsis: String,
    selection: String,
    #[serde(default)]
    scale_bias: u8,
    /// The pointer's cursor: an `[images]` name, drawn with its top-left
    /// pixel at the pointer's position.
    pointer: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrandSpec {
    anchor: String,
    offset: [i32; 2],
    #[serde(default)]
    logo: Option<String>,
    gap: i32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BannerSpec {
    anchor: String,
    offset: [i32; 2],
    padding: [i32; 2],
    radius: i32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContentSpec {
    anchor: String,
    offset: [i32; 2],
    max_width: i32,
    align: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HintsSpec {
    anchor: String,
    offset: [i32; 2],
    gap: i32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecorationSpec {
    image: String,
    anchor: String,
    offset: [i32; 2],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SpacingSpec {
    title: i32,
    paragraph: i32,
    block: i32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RowSpec {
    height: i32,
    padding: i32,
    gap: i32,
    radius: i32,
    marker: i32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FieldSpec {
    height: i32,
    padding: i32,
    radius: i32,
    border: i32,
    cursor: i32,
    group_gap: i32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeycapSpec {
    padding: i32,
    radius: i32,
    border: i32,
    gap: i32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ToastSpec {
    padding: [i32; 2],
    radius: i32,
    gap: i32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LayoutSpec {
    margin: [i32; 2],
    show_logo: bool,
    show_name: bool,
    show_hints: bool,
    brand: BrandSpec,
    banner: BannerSpec,
    content: ContentSpec,
    hints: HintsSpec,
    decorations: Vec<DecorationSpec>,
    spacing: SpacingSpec,
    row: RowSpec,
    field: FieldSpec,
    keycap: KeycapSpec,
    toast: ToastSpec,
}

/// One compiled-in theme (the base or a variant), validated.
struct Theme {
    meta: Meta,
    fonts: BTreeMap<String, PathBuf>,
    text: Vec<TextSpec>,
    colors: Vec<[u8; 3]>,
    images: BTreeMap<String, ImageSpec>,
    options: OptionsSpec,
    layouts: Vec<LayoutSpec>,
}

// ---------------------------------------------------------------------------
// Loading and validation

fn read(path: &Path, inputs: &mut Vec<PathBuf>) -> Result<Vec<u8>, Error> {
    inputs.push(path.to_path_buf());
    std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn parse_toml(path: &Path, inputs: &mut Vec<PathBuf>) -> Result<Table, Error> {
    let bytes = read(path, inputs)?;
    let text = String::from_utf8(bytes).map_err(|_| format!("{}: not UTF-8", path.display()))?;
    text.parse::<Table>()
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// Overlay `over` on `base`: tables merge key by key, anything else replaces.
fn merge(base: &mut Table, over: &Table) {
    for (k, v) in over {
        match (base.get_mut(k), v) {
            (Some(Value::Table(b)), Value::Table(o)) => merge(b, o),
            _ => {
                base.insert(k.clone(), v.clone());
            }
        }
    }
}

fn section<T: for<'de> Deserialize<'de>>(t: &Table, key: &str, file: &str) -> Result<T, Error> {
    let v = t
        .get(key)
        .ok_or_else(|| format!("{file}: missing [{key}]"))?
        .clone();
    v.try_into()
        .map_err(|e: toml::de::Error| format!("{file}: [{key}]: {}", e.message()))
}

fn table<'a>(t: &'a Table, key: &str, file: &str) -> Result<&'a Table, Error> {
    match t.get(key) {
        Some(Value::Table(x)) => Ok(x),
        Some(_) => Err(format!("{file}: [{key}] must be a table")),
        None => Err(format!("{file}: missing [{key}]")),
    }
}

fn color(s: &str) -> Option<[u8; 3]> {
    let h = s.strip_prefix('#')?;
    if h.len() != 6 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let v = u32::from_str_radix(h, 16).ok()?;
    Some([(v >> 16) as u8, (v >> 8) as u8, v as u8])
}

fn one_char(s: &str, what: &str, file: &str) -> Result<char, Error> {
    let mut it = s.chars();
    match (it.next(), it.next()) {
        (Some(c), None) => Ok(c),
        _ => Err(format!(
            "{file}: [options] {what} must be exactly one character"
        )),
    }
}

fn anchor(a: &str, ctx: &str) -> Result<&'static str, Error> {
    spec::ANCHORS
        .iter()
        .find(|(n, _)| *n == a)
        .map(|(_, v)| *v)
        .ok_or_else(|| {
            let names: Vec<_> = spec::ANCHORS.iter().map(|(n, _)| *n).collect();
            format!("{ctx}: unknown anchor {a:?} (one of {})", names.join(", "))
        })
}

fn edge_anchor(a: &str, ctx: &str) -> Result<&'static str, Error> {
    let v = anchor(a, ctx)?;
    if a.starts_with("top") || a.starts_with("bottom") {
        Ok(v)
    } else {
        Err(format!(
            "{ctx}: anchor {a:?} must be a top-* or bottom-* anchor (the content column owns the middle band)"
        ))
    }
}

fn load_theme(dir: &Path, t: &Table, file: &str) -> Result<Theme, Error> {
    let known: BTreeSet<&str> = [
        "theme",
        "fonts",
        "text",
        "colors",
        "images",
        "options",
        "layout",
        "primitive",
        "screen",
    ]
    .into_iter()
    .collect();
    for k in t.keys() {
        if !known.contains(k.as_str()) {
            return Err(format!("{file}: unknown section [{k}]"));
        }
    }
    let meta: Meta = section(t, "theme", file)?;
    if meta.name.is_empty()
        || !meta
            .name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(format!(
            "{file}: [theme] name {:?} must be [A-Za-z0-9_-]+",
            meta.name
        ));
    }
    if meta.reference[0] < MIN_REFERENCE[0] || meta.reference[1] < MIN_REFERENCE[1] {
        return Err(format!("{file}: [theme] reference is too small"));
    }
    if meta.scales.is_empty() || meta.scales.len() > MAX_SCALES {
        return Err(format!("{file}: [theme] scales: 1 to {MAX_SCALES} entries"));
    }
    for w in meta.scales.windows(2) {
        if w[0] >= w[1] {
            return Err(format!(
                "{file}: [theme] scales must be strictly increasing"
            ));
        }
    }
    if meta
        .scales
        .iter()
        .any(|&s| !(SCALE_MIN..=SCALE_MAX).contains(&s))
    {
        return Err(format!(
            "{file}: [theme] scales must be within {SCALE_MIN}..={SCALE_MAX}"
        ));
    }

    let mut fonts = BTreeMap::new();
    for (k, v) in table(t, "fonts", file)? {
        let p = v
            .as_str()
            .ok_or_else(|| format!("{file}: [fonts] {k} must be a path"))?;
        fonts.insert(k.clone(), dir.join(p));
    }

    let text_t = table(t, "text", file)?;
    let mut text = Vec::new();
    for (name, needs) in spec::STYLES {
        let v = text_t
            .get(*name)
            .ok_or_else(|| format!("{file}: [text] missing style {name:?}"))?;
        let s: TextSpec = v
            .clone()
            .try_into()
            .map_err(|e: toml::de::Error| format!("{file}: [text] {name}: {}", e.message()))?;
        if !fonts.contains_key(&s.font) {
            return Err(format!(
                "{file}: [text] {name}: font {:?} is not in [fonts]",
                s.font
            ));
        }
        if !(FONT_SIZE_MIN..=FONT_SIZE_MAX).contains(&s.size)
            || s.line < s.size * LINE_MIN
            || s.line > s.size * LINE_MAX
        {
            return Err(format!(
                "{file}: [text] {name}: size must be {FONT_SIZE_MIN}..{FONT_SIZE_MAX} and line between {LINE_MIN} and {LINE_MAX} times the size"
            ));
        }
        let need = match needs {
            spec::Needs::Strings => Charset::Strings,
            spec::Needs::Ascii => Charset::Ascii,
            spec::Needs::Latin1 => Charset::Latin1,
        };
        if s.charset < need {
            return Err(format!(
                "{file}: [text] {name}: this style shows {}, so it needs charset = \"{}\" (or wider)",
                if need == Charset::Latin1 {
                    "typed text and file names"
                } else {
                    "paths the loader composes"
                },
                if need == Charset::Latin1 {
                    "latin1"
                } else {
                    "ascii"
                }
            ));
        }
        text.push(s);
    }
    for k in text_t.keys() {
        if !spec::STYLES.iter().any(|(n, _)| n == k) {
            return Err(format!("{file}: [text] unknown style {k:?}"));
        }
    }

    let colors_t = table(t, "colors", file)?;
    let mut colors = Vec::new();
    for role in spec::COLORS {
        let v = colors_t
            .get(*role)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{file}: [colors] missing {role:?}"))?;
        colors.push(
            color(v).ok_or_else(|| format!("{file}: [colors] {role}: {v:?} is not #rrggbb"))?,
        );
    }
    for k in colors_t.keys() {
        if !spec::COLORS.contains(&k.as_str()) {
            return Err(format!("{file}: [colors] unknown role {k:?}"));
        }
    }

    let mut images = BTreeMap::new();
    if let Some(v) = t.get("images") {
        let it = v
            .as_table()
            .ok_or_else(|| format!("{file}: [images] must be a table"))?;
        for (k, v) in it {
            let s: ImageSpec = v
                .clone()
                .try_into()
                .map_err(|e: toml::de::Error| format!("{file}: [images] {k}: {}", e.message()))?;
            if s.size[0] == 0
                || s.size[1] == 0
                || s.size[0] > IMAGE_SIDE_MAX
                || s.size[1] > IMAGE_SIDE_MAX
            {
                return Err(format!(
                    "{file}: [images] {k}: size must be 1..={IMAGE_SIDE_MAX}"
                ));
            }
            images.insert(k.clone(), s);
        }
    }
    if images.len() > MAX_IMAGES {
        return Err(format!("{file}: at most {MAX_IMAGES} images"));
    }

    let options: OptionsSpec = section(t, "options", file)?;
    one_char(&options.bullet, "bullet", file)?;
    one_char(&options.ellipsis, "ellipsis", file)?;
    if usize::from(options.scale_bias) >= meta.scales.len() {
        return Err(format!(
            "{file}: [options] scale_bias must be below the number of scales"
        ));
    }
    if !images.contains_key(&options.pointer) {
        return Err(format!(
            "{file}: [options] pointer {:?} is not in [images]",
            options.pointer
        ));
    }
    if !["bar", "fill", "outline"].contains(&options.selection.as_str()) {
        return Err(format!(
            "{file}: [options] selection must be \"bar\", \"fill\" or \"outline\""
        ));
    }

    let layout_t = table(t, "layout", file)?;
    let empty = Table::new();
    let prim_t = match t.get("primitive") {
        Some(Value::Table(x)) => x,
        Some(_) => return Err(format!("{file}: [primitive] must be a table")),
        None => &empty,
    };
    let screen_t = match t.get("screen") {
        Some(Value::Table(x)) => x,
        Some(_) => return Err(format!("{file}: [screen] must be a table")),
        None => &empty,
    };
    for k in prim_t.keys() {
        if !spec::PRIMITIVES.contains(&k.as_str()) {
            return Err(format!(
                "{file}: unknown primitive [primitive.{k}] (one of {})",
                spec::PRIMITIVES.join(", ")
            ));
        }
    }
    for k in screen_t.keys() {
        if !spec::SCREENS.iter().any(|(s, _)| s == k) {
            let names: Vec<_> = spec::SCREENS.iter().map(|(s, _)| *s).collect();
            return Err(format!(
                "{file}: unknown screen [screen.{k}] (one of {})",
                names.join(", ")
            ));
        }
    }
    let defaults = layout_t.clone();
    let mut layouts = Vec::new();
    for (screen, prim) in spec::SCREENS {
        let mut l = defaults.clone();
        for (what, t, key) in [("primitive", prim_t, *prim), ("screen", screen_t, *screen)] {
            match t.get(key) {
                Some(Value::Table(o)) => merge(&mut l, o),
                Some(_) => return Err(format!("{file}: [{what}.{key}] must be a table")),
                None => {}
            }
        }
        let ctx = format!("{file}: [layout] for the {screen:?} screen");
        let ls: LayoutSpec = Value::Table(l)
            .try_into()
            .map_err(|e: toml::de::Error| format!("{ctx}: {}", e.message()))?;
        edge_anchor(&ls.brand.anchor, &format!("{ctx}, brand"))?;
        edge_anchor(&ls.banner.anchor, &format!("{ctx}, banner"))?;
        edge_anchor(&ls.hints.anchor, &format!("{ctx}, hints"))?;
        anchor(&ls.content.anchor, &format!("{ctx}, content"))?;
        if let Some(logo) = &ls.brand.logo {
            if !images.contains_key(logo) {
                return Err(format!("{ctx}: brand logo {logo:?} is not in [images]"));
            }
        }
        for d in &ls.decorations {
            anchor(&d.anchor, &format!("{ctx}, decoration"))?;
            if !images.contains_key(&d.image) {
                return Err(format!(
                    "{ctx}: decoration {:?} is not in [images]",
                    d.image
                ));
            }
        }
        if !["left", "center", "right"].contains(&ls.content.align.as_str()) {
            return Err(format!(
                "{ctx}: content align must be left, center or right"
            ));
        }
        let nonneg = [
            ("margin", ls.margin[0].min(ls.margin[1])),
            ("brand gap", ls.brand.gap),
            (
                "banner padding",
                ls.banner.padding[0].min(ls.banner.padding[1]),
            ),
            ("banner radius", ls.banner.radius),
            ("hints gap", ls.hints.gap),
            (
                "spacing",
                ls.spacing
                    .title
                    .min(ls.spacing.paragraph)
                    .min(ls.spacing.block),
            ),
            ("row padding", ls.row.padding),
            ("row gap", ls.row.gap),
            ("row radius", ls.row.radius),
            ("row marker", ls.row.marker),
            ("field padding", ls.field.padding),
            ("field radius", ls.field.radius),
            ("field border", ls.field.border),
            ("field group_gap", ls.field.group_gap),
            (
                "keycap",
                ls.keycap
                    .padding
                    .min(ls.keycap.radius)
                    .min(ls.keycap.border)
                    .min(ls.keycap.gap),
            ),
            (
                "toast",
                ls.toast.padding[0]
                    .min(ls.toast.padding[1])
                    .min(ls.toast.radius)
                    .min(ls.toast.gap),
            ),
        ];
        for (what, v) in nonneg {
            if !(0..=LENGTH_MAX).contains(&v) {
                return Err(format!("{ctx}: {what} must be within 0..={LENGTH_MAX}"));
            }
        }
        if ls.content.max_width < CONTENT_WIDTH_MIN {
            return Err(format!(
                "{ctx}: content max_width must be at least {CONTENT_WIDTH_MIN}"
            ));
        }
        let heights = ROW_HEIGHT_MIN..=ROW_HEIGHT_MAX;
        if !heights.contains(&ls.row.height) || !heights.contains(&ls.field.height) {
            return Err(format!(
                "{ctx}: row and field heights must be {ROW_HEIGHT_MIN}..={ROW_HEIGHT_MAX}"
            ));
        }
        if !(CURSOR_WIDTH_MIN..=CURSOR_WIDTH_MAX).contains(&ls.field.cursor) {
            return Err(format!(
                "{ctx}: field cursor must be {CURSOR_WIDTH_MIN}..={CURSOR_WIDTH_MAX}"
            ));
        }
        layouts.push(ls);
    }
    Ok(Theme {
        meta,
        fonts,
        text,
        colors,
        images,
        options,
        layouts,
    })
}

// ---------------------------------------------------------------------------
// Strings

enum Part {
    Lit(String),
    Arg(u8),
    Break,
}

/// The loader's strings of one language: the `[loader]` table of
/// `strings/<lang>.toml` (`loader.*` keys). The file is shared with the
/// Windows app, whose strings live under `[win]` (`win.*`) and are not
/// read here; any other top-level key is an error.
fn load_strings(path: &Path, inputs: &mut Vec<PathBuf>) -> Result<Vec<Vec<Part>>, Error> {
    let file = path.display().to_string();
    let top = parse_toml(path, inputs)?;
    for k in top.keys() {
        match (k.as_str(), top.get(k)) {
            ("loader" | "win", Some(Value::Table(_))) => {}
            ("loader" | "win", _) => return Err(format!("{file}: [{k}] must be a table")),
            _ => {
                return Err(format!(
                    "{file}: unknown key {k:?}: strings live in [loader] (and [win] for the Windows app)"
                ));
            }
        }
    }
    let t = match top.get("loader") {
        Some(Value::Table(t)) => t.clone(),
        _ => return Err(format!("{file}: no [loader] table")),
    };
    for k in t.keys() {
        if !spec::STRINGS.iter().any(|s| s.key == k) {
            return Err(format!("{file}: unknown string loader.{k}"));
        }
    }
    let mut out = Vec::new();
    for s in spec::STRINGS {
        let v = t
            .get(s.key)
            .ok_or_else(|| format!("{file}: missing string loader.{}", s.key))?
            .as_str()
            .ok_or_else(|| format!("{file}: {} must be a string", s.key))?;
        if v.trim().is_empty() {
            return Err(format!("{file}: {} is empty", s.key));
        }
        if v.chars().any(|c| c.is_control() && c != '\n') {
            return Err(format!("{file}: {} contains a control character", s.key));
        }
        let mut parts = Vec::new();
        let mut lit = String::new();
        let mut rest = v;
        while let Some(c) = rest.chars().next() {
            match c {
                '{' => {
                    let end = rest
                        .find('}')
                        .ok_or_else(|| format!("{file}: {}: unclosed {{", s.key))?;
                    let name = &rest[1..end];
                    let i = s.args.iter().position(|a| *a == name).ok_or_else(|| {
                        format!(
                            "{file}: {}: unknown placeholder {{{name}}} (allowed: {})",
                            s.key,
                            if s.args.is_empty() {
                                "none".to_string()
                            } else {
                                s.args.join(", ")
                            }
                        )
                    })?;
                    if !lit.is_empty() {
                        parts.push(Part::Lit(std::mem::take(&mut lit)));
                    }
                    parts.push(Part::Arg(i as u8));
                    rest = &rest[end + 1..];
                }
                '}' => return Err(format!("{file}: {}: stray }}", s.key)),
                '\n' => {
                    if !lit.is_empty() {
                        parts.push(Part::Lit(std::mem::take(&mut lit)));
                    }
                    parts.push(Part::Break);
                    rest = &rest[1..];
                }
                c => {
                    lit.push(c);
                    rest = &rest[c.len_utf8()..];
                }
            }
        }
        if !lit.is_empty() {
            parts.push(Part::Lit(lit));
        }
        out.push(parts);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Rasterisation

struct Glyph {
    ch: u32,
    adv: u32,
    x: i32,
    y: i32,
    w: u32,
    h: u32,
    off: u32,
}

struct Raster {
    px: f32,
    ascent: i32,
    descent: i32,
    line: i32,
    glyphs: Vec<Glyph>,
    alpha: Vec<u8>,
}

/// Run-length coding of one glyph's 4-bit coverage, row-major, decoded
/// sequentially by `paguro_ui::theme::Font::pixels`:
///
/// | byte | meaning |
/// |---|---|
/// | `00nnnnnn` | `n + 1` transparent pixels |
/// | `01nnnnnn` | `n + 1` fully covered pixels |
/// | `10nnnnnn` + ⌈(n+1)/2⌉ bytes | `n + 1` literal 4-bit values, low nibble first |
pub fn rle_encode(nibbles: &[u8], out: &mut Vec<u8>) {
    // A run of 0 or 15 shorter than this is cheaper inside a literal.
    const MIN_RUN: usize = RLE_MIN_RUN;
    let run_at = |i: usize| -> usize {
        let Some(&v) = nibbles.get(i) else {
            return 0;
        };
        if v != 0 && v != NIBBLE_MAX {
            return 0;
        }
        nibbles[i..]
            .iter()
            .take(RLE_MAX_RUN)
            .take_while(|&&x| x == v)
            .count()
    };
    let mut i = 0usize;
    while i < nibbles.len() {
        let run = run_at(i);
        if run >= MIN_RUN || (run > 0 && i + run == nibbles.len()) {
            let tag = if nibbles[i] == 0 {
                RLE_TRANSPARENT
            } else {
                RLE_COVERED
            };
            out.push(tag | (run - 1) as u8);
            i += run;
            continue;
        }
        // A literal until the next worthwhile run (at most 64 values).
        let start = i;
        let mut end = i + 1;
        while end < nibbles.len() && end - start < RLE_MAX_RUN && run_at(end) < MIN_RUN {
            end += 1;
        }
        let lit = &nibbles[start..end];
        out.push(RLE_LITERAL | (lit.len() - 1) as u8);
        for pair in lit.chunks(2) {
            out.push(pair[0] | pair.get(1).map_or(0, |b| b << NIBBLE_BITS));
        }
        i = end;
    }
}

const RLE_MIN_RUN: usize = 4;
/// The tags in a run's top two bits, and the longest run (six bits of
/// length − 1).
const RLE_TRANSPARENT: u8 = 0x00;
const RLE_COVERED: u8 = 0x40;
const RLE_LITERAL: u8 = 0x80;
const RLE_MAX_RUN: usize = 64;
/// 4-bit coverage: 0..=15, ×17 back to 0..=255.
const NIBBLE_BITS: u32 = 4;
const NIBBLE_MAX: u8 = 15;
const NIBBLE_TO_ALPHA: u32 = 17;

fn rasterise(font: &fontdue::Font, px: f32, line: i32, chars: &BTreeSet<char>) -> Raster {
    let lm = font.horizontal_line_metrics(px);
    let (ascent, descent) = lm.map_or((px.round() as i32, 0), |m| {
        (m.ascent.round() as i32, m.descent.round() as i32)
    });
    let mut glyphs = Vec::new();
    let mut alpha: Vec<u8> = Vec::new();
    for &c in chars {
        if font.lookup_glyph_index(c) == 0 && c != ' ' {
            continue;
        }
        let (m, cov) = font.rasterize(c, px);
        // The emitted Glyph's fields are u16.
        let max = usize::from(u16::MAX);
        if c as u32 > u32::from(u16::MAX) || m.width > max || m.height > max {
            continue;
        }
        let off = alpha.len() as u32;
        let nibbles: Vec<u8> = cov
            .iter()
            .map(|a| ((u32::from(*a) + NIBBLE_TO_ALPHA / 2) / NIBBLE_TO_ALPHA) as u8)
            .collect();
        rle_encode(&nibbles, &mut alpha);
        glyphs.push(Glyph {
            ch: c as u32,
            adv: ((m.advance_width * SUBPX).round().max(0.0) as u32).min(u32::from(u16::MAX)),
            x: m.xmin,
            // Top of the bitmap relative to the baseline, y down.
            y: -(m.ymin + m.height as i32),
            w: m.width as u32,
            h: m.height as u32,
            off,
        });
    }
    Raster {
        px,
        ascent,
        descent,
        line,
        glyphs,
        alpha,
    }
}

/// Decode any PNG to straight RGBA8.
fn decode_png(bytes: &[u8], file: &str) -> Result<(u32, u32, Vec<u8>), Error> {
    let mut dec = png::Decoder::new(std::io::Cursor::new(bytes));
    dec.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut r = dec.read_info().map_err(|e| format!("{file}: {e}"))?;
    let (w, h) = (r.info().width, r.info().height);
    if w == 0 || h == 0 || w > PNG_SIDE_MAX || h > PNG_SIDE_MAX {
        return Err(format!(
            "{file}: images must be 1..={PNG_SIDE_MAX} pixels a side"
        ));
    }
    let mut buf = vec![
        0u8;
        r.output_buffer_size()
            .ok_or_else(|| format!("{file}: too large"))?
    ];
    let info = r.next_frame(&mut buf).map_err(|e| format!("{file}: {e}"))?;
    let data = &buf[..info.buffer_size()];
    let n = (w * h) as usize;
    let mut out = Vec::with_capacity(n * RGBA);
    match info.color_type {
        png::ColorType::Rgba => out.extend_from_slice(&data[..n * RGBA]),
        png::ColorType::Rgb => {
            for p in data.chunks_exact(RGB).take(n) {
                out.extend_from_slice(&[p[0], p[1], p[2], OPAQUE]);
            }
        }
        png::ColorType::GrayscaleAlpha => {
            for p in data.chunks_exact(2).take(n) {
                out.extend_from_slice(&[p[0], p[0], p[0], p[1]]);
            }
        }
        png::ColorType::Grayscale => {
            for p in data.iter().take(n) {
                out.extend_from_slice(&[*p, *p, *p, OPAQUE]);
            }
        }
        png::ColorType::Indexed => return Err(format!("{file}: palette PNG was not expanded")),
    }
    Ok((w, h, out))
}

/// Premultiplied area-average resample to `tw`×`th`, emitted as BGRA.
fn resample(w: u32, h: u32, rgba: &[u8], tw: u32, th: u32) -> Vec<u8> {
    let pm: Vec<[f64; RGBA]> = rgba
        .chunks_exact(RGBA)
        .map(|p| {
            let a = f64::from(p[ALPHA]) / f64::from(OPAQUE);
            [
                f64::from(p[0]) * a,
                f64::from(p[1]) * a,
                f64::from(p[2]) * a,
                f64::from(p[ALPHA]),
            ]
        })
        .collect();
    let (sx, sy) = (f64::from(w) / f64::from(tw), f64::from(h) / f64::from(th));
    let mut out = Vec::with_capacity((tw * th) as usize * RGBA);
    for ty in 0..th {
        let (y0, y1) = (f64::from(ty) * sy, f64::from(ty + 1) * sy);
        for tx in 0..tw {
            let (x0, x1) = (f64::from(tx) * sx, f64::from(tx + 1) * sx);
            let mut acc = [0.0f64; RGBA];
            let mut area = 0.0;
            let mut y = y0.floor() as u32;
            while f64::from(y) < y1 && y < h {
                let wy = (f64::from(y + 1).min(y1) - f64::from(y).max(y0)).max(0.0);
                let mut x = x0.floor() as u32;
                while f64::from(x) < x1 && x < w {
                    let wx = (f64::from(x + 1).min(x1) - f64::from(x).max(x0)).max(0.0);
                    let k = wx * wy;
                    let p = pm[(y * w + x) as usize];
                    for c in 0..RGBA {
                        acc[c] += p[c] * k;
                    }
                    area += k;
                    x += 1;
                }
                y += 1;
            }
            let v = |c: usize| (acc[c] / area).round().clamp(0.0, f64::from(OPAQUE)) as u8;
            // BGRA, premultiplied.
            out.extend_from_slice(&[v(2), v(1), v(0), v(3)]);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Emission

/// FNV-1a (64-bit): a stable name for identical blobs, so variants share them.
fn fnv(parts: &[&[u8]]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0100_0000_01b3;
    /// Mixed in after each part, so part boundaries count.
    const SEPARATOR: u64 = 0xff;
    let mut h = OFFSET_BASIS;
    for p in parts {
        for b in *p {
            h ^= u64::from(*b);
            h = h.wrapping_mul(PRIME);
        }
        h ^= SEPARATOR;
        h = h.wrapping_mul(PRIME);
    }
    h
}

fn rust_str(s: &str) -> String {
    format!("{s:?}")
}

struct Emitter {
    out_dir: PathBuf,
    code: String,
    emitted: HashMap<String, ()>,
    font_bytes: usize,
    glyph_count: usize,
    image_bytes: usize,
}

impl Emitter {
    fn blob(&mut self, name: &str, data: &[u8]) -> Result<String, Error> {
        let file = format!("{name}.bin");
        if !self.emitted.contains_key(&file) {
            std::fs::write(self.out_dir.join(&file), data)
                .map_err(|e| format!("writing {file}: {e}"))?;
            self.emitted.insert(file.clone(), ());
        }
        Ok(format!(
            "include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{file}\"))"
        ))
    }

    fn font(&mut self, r: &Raster) -> Result<String, Error> {
        let mut meta = Vec::new();
        for g in &r.glyphs {
            for v in [g.ch, g.adv, g.x as u32, g.y as u32, g.w, g.h, g.off] {
                meta.extend_from_slice(&v.to_le_bytes());
            }
        }
        let h = fnv(&[
            &meta,
            &r.alpha,
            &r.ascent.to_le_bytes(),
            &r.descent.to_le_bytes(),
            &r.line.to_le_bytes(),
        ]);
        let name = format!("F_{h:016X}");
        if self.emitted.contains_key(&name) {
            return Ok(name);
        }
        let data = self.blob(&format!("a_{h:016X}"), &r.alpha)?;
        self.font_bytes += r.alpha.len() + r.glyphs.len() * GLYPH_BYTES;
        self.glyph_count += r.glyphs.len();
        let mut g = String::new();
        for x in &r.glyphs {
            let _ = write!(
                g,
                "Glyph{{ch:{},adv:{},x:{},y:{},w:{},h:{},off:{}}},",
                x.ch, x.adv, x.x, x.y, x.w, x.h, x.off
            );
        }
        let _ = writeln!(
            self.code,
            "static G_{h:016X}: [Glyph; {}] = [{g}];\n\
             static {name}: Font = Font {{ px_x10: {}, ascent: {}, descent: {}, line: {}, glyphs: &G_{h:016X}, alpha: {data} }};",
            r.glyphs.len(),
            (r.px * PX_X10).round() as u32,
            r.ascent,
            r.descent,
            r.line,
        );
        self.emitted.insert(name.clone(), ());
        Ok(name)
    }

    fn image(&mut self, w: u32, h: u32, bgra: &[u8]) -> Result<String, Error> {
        let hsh = fnv(&[&w.to_le_bytes(), &h.to_le_bytes(), bgra]);
        let name = format!("I_{hsh:016X}");
        if self.emitted.contains_key(&name) {
            return Ok(name);
        }
        let data = self.blob(&format!("i_{hsh:016X}"), bgra)?;
        self.image_bytes += bgra.len();
        let _ = writeln!(
            self.code,
            "static {name}: Image = Image {{ w: {w}, h: {h}, px: {data} }};"
        );
        self.emitted.insert(name.clone(), ());
        Ok(name)
    }
}

fn placement(anchor_name: &str, offset: [i32; 2]) -> String {
    let a = anchor(anchor_name, "").unwrap_or("Center");
    format!(
        "Placement {{ anchor: Anchor::{a}, offset: ({}, {}) }}",
        offset[0], offset[1]
    )
}

fn layout_code(l: &LayoutSpec, images: &BTreeMap<String, ImageSpec>) -> String {
    let img = |n: &str| images.keys().position(|k| k == n).unwrap_or(0);
    let logo = match &l.brand.logo {
        Some(n) => format!("Some({})", img(n)),
        None => "None".into(),
    };
    let decos: Vec<String> = l
        .decorations
        .iter()
        .map(|d| {
            format!(
                "Decoration {{ image: {}, place: {} }}",
                img(&d.image),
                placement(&d.anchor, d.offset)
            )
        })
        .collect();
    let align = match l.content.align.as_str() {
        "center" => "Center",
        "right" => "Right",
        _ => "Left",
    };
    format!(
        "Layout {{ margin: ({}, {}), show_logo: {}, show_name: {}, show_hints: {}, \
         brand: Brand {{ place: {}, logo: {logo}, gap: {} }}, \
         banner: Banner {{ place: {}, padding: ({}, {}), radius: {} }}, \
         content: Content {{ place: {}, max_width: {}, align: Align::{align} }}, \
         hints: Hints {{ place: {}, gap: {} }}, \
         decorations: &[{}], \
         spacing: Spacing {{ title: {}, paragraph: {}, block: {} }}, \
         row: RowStyle {{ height: {}, padding: {}, gap: {}, radius: {}, marker: {} }}, \
         field: FieldStyle {{ height: {}, padding: {}, radius: {}, border: {}, cursor: {}, group_gap: {} }}, \
         keycap: KeycapStyle {{ padding: {}, radius: {}, border: {}, gap: {} }}, \
         toast: ToastStyle {{ padding: ({}, {}), radius: {}, gap: {} }} }}",
        l.margin[0],
        l.margin[1],
        l.show_logo,
        l.show_name,
        l.show_hints,
        placement(&l.brand.anchor, l.brand.offset),
        l.brand.gap,
        placement(&l.banner.anchor, l.banner.offset),
        l.banner.padding[0],
        l.banner.padding[1],
        l.banner.radius,
        placement(&l.content.anchor, l.content.offset),
        l.content.max_width,
        placement(&l.hints.anchor, l.hints.offset),
        l.hints.gap,
        decos.join(", "),
        l.spacing.title,
        l.spacing.paragraph,
        l.spacing.block,
        l.row.height,
        l.row.padding,
        l.row.gap,
        l.row.radius,
        l.row.marker,
        l.field.height,
        l.field.padding,
        l.field.radius,
        l.field.border,
        l.field.cursor,
        l.field.group_gap,
        l.keycap.padding,
        l.keycap.radius,
        l.keycap.border,
        l.keycap.gap,
        l.toast.padding[0],
        l.toast.padding[1],
        l.toast.radius,
        l.toast.gap,
    )
}

/// The `Str` enum: independent of any theme.
pub fn strings_enum() -> String {
    let mut s = String::from(
        "// @generated by paguro-theme from its string catalogue. Do not edit.\n\
         /// Every user-visible string of the graphical loader.\n\
         #[derive(Clone, Copy, Debug, PartialEq, Eq)]\n#[repr(u8)]\npub enum Str {\n",
    );
    for sp in spec::STRINGS {
        let _ = writeln!(s, "    {},", spec::camel(sp.key));
    }
    let _ = writeln!(
        s,
        "}}\n\n/// Number of [`Str`] values.\npub const STR_COUNT: usize = {};\n\n\
         /// Every [`Str`], in order (for tests and tools).\npub const ALL_STR: [Str; STR_COUNT] = [{}];",
        spec::STRINGS.len(),
        spec::STRINGS
            .iter()
            .map(|sp| format!("Str::{}", spec::camel(sp.key)))
            .collect::<Vec<_>>()
            .join(", ")
    );
    s
}

/// Compile a theme and its variants for one language.
pub fn compile(o: &Options) -> Result<Output, Error> {
    let dir = if o.theme.contains('/') || o.theme.contains('\\') {
        PathBuf::from(&o.theme)
    } else {
        o.themes_dir.join(&o.theme)
    };
    if !dir.is_dir() {
        return Err(format!(
            "theme {:?}: {} is not a directory (PAGURO_THEME names a directory under themes/ or a path)",
            o.theme,
            dir.display()
        ));
    }
    if o.lang.is_empty()
        || !o
            .lang
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(format!(
            "language {:?}: expected a name like \"en\"",
            o.lang
        ));
    }
    let mut inputs = vec![dir.clone()];
    let base_file = dir.join("theme.toml");
    let base = parse_toml(&base_file, &mut inputs)?;
    let mut sources = vec![(base_file.display().to_string(), base.clone())];
    let vdir = dir.join("variants");
    if vdir.is_dir() {
        inputs.push(vdir.clone());
        let mut names: Vec<PathBuf> = std::fs::read_dir(&vdir)
            .map_err(|e| format!("{}: {e}", vdir.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .collect();
        names.sort();
        for p in names {
            let over = parse_toml(&p, &mut inputs)?;
            let mut merged = base.clone();
            merge(&mut merged, &over);
            sources.push((p.display().to_string(), merged));
        }
    }
    let mut themes = Vec::new();
    for (file, t) in &sources {
        themes.push(load_theme(&dir, t, file)?);
    }
    let mut seen = BTreeSet::new();
    for t in &themes {
        if !seen.insert(t.meta.name.clone()) {
            return Err(format!(
                "{}: theme name {:?} is used twice (a variant must set its own [theme] name)",
                dir.display(),
                t.meta.name
            ));
        }
    }
    // Every build carries the variants paguro.ini can name, in F2 order
    // (INTERFACES.md §13.2a); any others follow.
    for want in spec::VARIANTS {
        if !seen.contains(*want) {
            return Err(format!(
                "{}: no variant named {want:?}: every theme provides {} (theme.toml or variants/*.toml)",
                dir.display(),
                spec::VARIANTS.join(", ")
            ));
        }
    }
    let rank = |n: &str| {
        spec::VARIANTS
            .iter()
            .position(|v| *v == n)
            .unwrap_or(spec::VARIANTS.len())
    };
    themes.sort_by(|a, b| {
        rank(&a.meta.name)
            .cmp(&rank(&b.meta.name))
            .then_with(|| a.meta.name.cmp(&b.meta.name))
    });
    // Every language in strings/ is compiled in (on-screen choice, F5);
    // PAGURO_LANG is the one the loader starts in, then English.
    let sdir = dir.join("strings");
    let strings_file = sdir.join(format!("{}.toml", o.lang));
    if !strings_file.is_file() {
        return Err(format!(
            "theme {:?} has no strings for language {:?} ({} is missing)",
            o.theme,
            o.lang,
            strings_file.display()
        ));
    }
    inputs.push(sdir.clone());
    let mut codes: Vec<String> = std::fs::read_dir(&sdir)
        .map_err(|e| format!("{}: {e}", sdir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .filter_map(|p| p.file_stem().map(|s| s.to_string_lossy().to_string()))
        .collect();
    codes.sort_by_key(|c| (c != &o.lang, c != "en", c.clone()));
    for c in &codes {
        if c.is_empty()
            || !c
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(format!("{}: {c:?} is not a language code", sdir.display()));
        }
    }
    let mut langs = Vec::new();
    for c in &codes {
        langs.push(load_strings(&sdir.join(format!("{c}.toml")), &mut inputs)?);
    }

    // Characters each style needs: the strings drawn in it (in every
    // language), digits and the fallback, and the options' bullet and
    // ellipsis.
    let mut needed: Vec<BTreeSet<char>> = spec::STYLES
        .iter()
        .map(|_| spec::ALWAYS.chars().collect())
        .collect();
    for strings in &langs {
        for (sp, parts) in spec::STRINGS.iter().zip(strings) {
            let i = spec::STYLES
                .iter()
                .position(|(n, _)| *n == sp.style)
                .ok_or_else(|| format!("string {:?}: unknown style {:?}", sp.key, sp.style))?;
            for p in parts {
                if let Part::Lit(s) = p {
                    needed[i].extend(s.chars());
                }
            }
        }
    }
    let latin1: BTreeSet<char> = (u32::from(ASCII_PRINTABLE.start)..u32::from(ASCII_PRINTABLE.end))
        .chain(LATIN1_UPPER)
        .filter_map(char::from_u32)
        .collect();

    let mut em = Emitter {
        out_dir: o.out_dir.clone(),
        code: String::new(),
        emitted: HashMap::new(),
        font_bytes: 0,
        glyph_count: 0,
        image_bytes: 0,
    };
    let mut font_cache: HashMap<PathBuf, fontdue::Font> = HashMap::new();
    let mut theme_code = Vec::new();
    let mut shared = String::new();
    for (ti, t) in themes.iter().enumerate() {
        let file = &t.meta.name;
        let bullet = one_char(&t.options.bullet, "bullet", file)?;
        let ellipsis = one_char(&t.options.ellipsis, "ellipsis", file)?;
        // Decode images once per theme.
        let mut decoded = Vec::new();
        for (name, spec_) in &t.images {
            let p = dir.join(&spec_.file);
            let bytes = read(&p, &mut inputs)?;
            let d = decode_png(&bytes, &p.display().to_string())
                .map_err(|e| format!("theme {file:?}, image {name:?}: {e}"))?;
            decoded.push((spec_, d));
        }
        let mut steps = Vec::new();
        for &scale in &t.meta.scales {
            let mut fonts = Vec::new();
            for (((style, _), ts), need) in spec::STYLES.iter().zip(&t.text).zip(&needed) {
                let path = &t.fonts[&ts.font];
                if !font_cache.contains_key(path) {
                    let bytes = read(path, &mut inputs)?;
                    let f = fontdue::Font::from_bytes(bytes, fontdue::FontSettings::default())
                        .map_err(|e| format!("{}: {e}", path.display()))?;
                    font_cache.insert(path.clone(), f);
                }
                let font = &font_cache[path];
                let mut chars = need.clone();
                chars.insert(bullet);
                chars.insert(ellipsis);
                for c in &chars {
                    if *c != ' ' && font.lookup_glyph_index(*c) == 0 {
                        return Err(format!(
                            "theme {file:?}: font {} (style {style}) has no glyph for {c:?}, which the strings or options use",
                            path.display()
                        ));
                    }
                }
                match ts.charset {
                    Charset::Latin1 => chars.extend(latin1.iter().copied()),
                    Charset::Ascii => chars.extend(ASCII_PRINTABLE.map(char::from)),
                    Charset::Strings => {}
                }
                let px = (ts.size * scale) as f32;
                let line = (ts.line * scale).round().max(1.0) as i32;
                let r = rasterise(font, px, line, &chars);
                fonts.push(em.font(&r)?);
            }
            let mut imgs = Vec::new();
            for (spec_, (w, h, rgba)) in &decoded {
                let tw = ((f64::from(spec_.size[0]) * scale).round() as u32).max(1);
                let th = ((f64::from(spec_.size[1]) * scale).round() as u32).max(1);
                let bgra = resample(*w, *h, rgba, tw, th);
                imgs.push(em.image(tw, th, &bgra)?);
            }
            steps.push(format!(
                "Step {{ milli: {}, fonts: [{}], images: &[{}] }}",
                (scale * MILLI).round() as u32,
                fonts
                    .iter()
                    .map(|f| format!("&{f}"))
                    .collect::<Vec<_>>()
                    .join(", "),
                imgs.iter()
                    .map(|i| format!("&{i}"))
                    .collect::<Vec<_>>()
                    .join(", "),
            ));
        }
        let palette: Vec<String> = spec::COLORS
            .iter()
            .zip(&t.colors)
            .map(|(role, c)| {
                format!(
                    "{role}: Color::rgb(0x{:02x}, 0x{:02x}, 0x{:02x})",
                    c[0], c[1], c[2]
                )
            })
            .collect();
        let selection = match t.options.selection.as_str() {
            "fill" => "Fill",
            "outline" => "Outline",
            _ => "Bar",
        };
        let layouts: Vec<String> = t
            .layouts
            .iter()
            .map(|l| layout_code(l, &t.images))
            .collect();
        let pointer = t
            .images
            .keys()
            .position(|k| *k == t.options.pointer)
            .unwrap_or(0);
        let _ = writeln!(
            shared,
            "static STEPS_{ti}: [Step; {}] = [{}];\nstatic LAYOUTS_{ti}: [Layout; SCREEN_KINDS] = [{}];",
            steps.len(),
            steps.join(", "),
            layouts.join(", "),
        );
        theme_code.push(format!(
            "Theme {{ name: {}, description: {}, reference: ({}, {}), \
             palette: Palette {{ {} }}, \
             options: Options {{ bullet: {bullet:?}, ellipsis: {ellipsis:?}, selection: Selection::{selection}, scale_bias: {}, pointer: {pointer} }}, \
             steps: &STEPS_{ti}, layouts: &LAYOUTS_{ti}, strings: &STRINGS_@L }}",
            rust_str(&t.meta.name),
            rust_str(&t.meta.description),
            t.meta.reference[0],
            t.meta.reference[1],
            palette.join(", "),
            t.options.scale_bias,
        ));
    }

    let mut code = format!(
        "// @generated by paguro-theme from {} (languages {:?}). Do not edit.\n\
         /// The theme directory this build compiled.\npub const THEME_SOURCE: &str = {};\n\
         /// The language the loader starts in (PAGURO_LANG): [`LANGS`]`[0]`.\npub const LANG: &str = {};\n\n",
        dir.display(),
        codes,
        rust_str(&o.theme),
        rust_str(&o.lang)
    );
    code.push_str(&em.code);
    code.push_str(&shared);
    for (li, strings) in langs.iter().enumerate() {
        let _ = writeln!(code, "\n/// Strings of language `{}`.", codes[li]);
        let _ = write!(code, "static STRINGS_{li}: [Tpl; STR_COUNT] = [");
        for parts in strings {
            let ps: Vec<String> = parts
                .iter()
                .map(|p| match p {
                    Part::Lit(s) => format!("Part::Lit({})", rust_str(s)),
                    Part::Arg(i) => format!("Part::Arg({i})"),
                    Part::Break => "Part::Break".to_string(),
                })
                .collect();
            let _ = write!(code, "Tpl(&[{}]), ", ps.join(", "));
        }
        let _ = writeln!(code, "];");
    }
    let _ = writeln!(
        code,
        "\n/// The compiled-in languages' codes, the starting one first, then English.\npub static LANGS: [&str; {}] = [{}];",
        codes.len(),
        codes
            .iter()
            .map(|c| rust_str(c))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let by_lang: Vec<String> = (0..langs.len())
        .map(|li| {
            format!(
                "[{}]",
                theme_code
                    .iter()
                    .map(|t| t.replace("STRINGS_@L", &format!("STRINGS_{li}")))
                    .collect::<Vec<_>>()
                    .join(",\n")
            )
        })
        .collect();
    let _ = writeln!(
        code,
        "\n/// Every variant in every language: `BY_LANG[language][variant]`.\n\
         /// Variants: dark, light, dark-contrast, light-contrast (F2 order, and the order\n\
         /// of `paguro_core::config::UiTheme::ALL`), then any others.\n\
         pub static BY_LANG: [[Theme; {v}]; {l}] = [{}];\n\
         /// The variants in the starting language.\npub static THEMES: &[Theme; {v}] = &BY_LANG[0];",
        by_lang.join(",\n"),
        v = theme_code.len(),
        l = langs.len(),
    );
    std::fs::write(o.out_dir.join("theme.rs"), code)
        .map_err(|e| format!("writing theme.rs: {e}"))?;
    std::fs::write(o.out_dir.join("strings.rs"), strings_enum())
        .map_err(|e| format!("writing strings.rs: {e}"))?;

    let summary = format!(
        "theme {:?} ({} variant(s)), languages {:?}: {} glyphs, {} KiB glyph data, {} KiB images",
        o.theme,
        themes.len(),
        codes,
        em.glyph_count,
        em.font_bytes / 1024,
        em.image_bytes / 1024
    );
    std::fs::write(o.out_dir.join("theme-summary.txt"), &summary)
        .map_err(|e| format!("writing summary: {e}"))?;
    inputs.sort();
    inputs.dedup();
    Ok(Output { inputs, summary })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("paguro-theme-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn themes_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../themes")
    }

    /// Copy the default theme, apply `edit` to theme.toml's text, compile.
    fn compile_edited(name: &str, edit: impl Fn(String) -> String) -> Result<Output, Error> {
        let src = themes_dir().join("default");
        let dst = tmpdir(name).join("t");
        copy_dir(&src, &dst);
        let t = std::fs::read_to_string(dst.join("theme.toml")).unwrap();
        std::fs::write(dst.join("theme.toml"), edit(t)).unwrap();
        let out = tmpdir(&format!("{name}-out"));
        compile(&Options {
            themes_dir: themes_dir(),
            theme: dst.display().to_string(),
            lang: "en".into(),
            out_dir: out,
        })
    }

    fn copy_dir(src: &Path, dst: &Path) {
        std::fs::create_dir_all(dst).unwrap();
        for e in std::fs::read_dir(src).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            if p.is_dir() {
                copy_dir(&p, &dst.join(e.file_name()));
            } else {
                std::fs::copy(&p, dst.join(e.file_name())).unwrap();
            }
        }
    }

    #[test]
    fn the_default_theme_compiles() {
        let out = compile_edited("ok", |t| t).unwrap();
        assert!(out.summary.contains("4 variant(s)"), "{}", out.summary);
    }

    #[test]
    fn invalid_themes_fail_with_a_clear_message() {
        type Edit<'a> = &'a dyn Fn(String) -> String;
        let cases: &[(&str, Edit<'_>, &str)] = &[
            (
                "color",
                &|t| t.replace("cursor = \"#e8875b\"", "cursor = \"orange\""),
                "[colors] cursor: \"orange\" is not #rrggbb",
            ),
            (
                "missing-color",
                &|t| t.replace("cursor = \"#e8875b\"\n", ""),
                "[colors] missing \"cursor\"",
            ),
            (
                "unknown-role",
                &|t| t.replace("[colors]\n", "[colors]\nsparkle = \"#ffffff\"\n"),
                "[colors] unknown role \"sparkle\"",
            ),
            (
                "anchor",
                &|t| t.replace("anchor = \"top-left\"", "anchor = \"middle\""),
                "unknown anchor \"middle\"",
            ),
            (
                "edge",
                &|t| {
                    t.replace(
                        "hints = { anchor = \"bottom-center\"",
                        "hints = { anchor = \"center\"",
                    )
                },
                "must be a top-* or bottom-* anchor",
            ),
            (
                "latin1",
                &|t| {
                    t.replace("field = { font = \"regular\", size = 20, line = 28, charset = \"latin1\" }", "field = { font = \"regular\", size = 20, line = 28 }")
                },
                "needs charset = \"latin1\"",
            ),
            (
                "font",
                &|t| t.replace("title = { font = \"semibold\"", "title = { font = \"bold\""),
                "font \"bold\" is not in [fonts]",
            ),
            (
                "image",
                &|t| t.replace("logo = \"logo\"", "logo = \"crab\""),
                "brand logo \"crab\" is not in [images]",
            ),
            (
                "section",
                &|t| t + "\n[extras]\nx = 1\n",
                "unknown section [extras]",
            ),
            (
                "layout-key",
                &|t| t + "\n[screen.unlock]\nwobble = 3\n",
                "unknown field `wobble`",
            ),
            (
                "screen-name",
                &|t| t + "\n[screen.unlcok]\nshow_logo = false\n",
                "unknown screen [screen.unlcok]",
            ),
            (
                "scales",
                &|t| t.replace("scales = [0.7, 0.85, 1.0, 1.4, 2.0]", "scales = [1.0, 0.5]"),
                "strictly increasing",
            ),
            (
                "bullet",
                &|t| t.replace("bullet = \"•\"", "bullet = \"**\""),
                "bullet must be exactly one character",
            ),
            (
                "pointer",
                &|t| t.replace("pointer = \"cursor\"", "pointer = \"arrow\""),
                "[options] pointer \"arrow\" is not in [images]",
            ),
            (
                "variant-name",
                &|t| t.replace("name = \"dark\"", "name = \"midnight\""),
                "no variant named \"dark\"",
            ),
            (
                "glyph",
                &|t| t.replace("bullet = \"•\"", "bullet = \"☃\""),
                "has no glyph for '☃'",
            ),
        ];
        for (name, edit, needle) in cases {
            let err = match compile_edited(name, edit) {
                Ok(_) => panic!("{name}: compiled"),
                Err(e) => e,
            };
            assert!(err.contains(needle), "{name}: {err}");
        }
    }

    #[test]
    fn strings_are_checked() {
        let src = themes_dir().join("default");
        for (name, edit, needle) in [
            (
                "unknown-ph",
                "attempts = \"{count} left\"",
                "unknown placeholder {count}",
            ),
            ("stray", "brand = \"pag}uro\"", "stray }"),
        ] {
            let dst = tmpdir(name).join("t");
            copy_dir(&src, &dst);
            let f = dst.join("strings/en.toml");
            let key = edit.split(' ').next().unwrap();
            let t: String = std::fs::read_to_string(&f)
                .unwrap()
                .lines()
                .map(|l| {
                    if l.starts_with(&format!("{key} =")) {
                        edit.to_string()
                    } else {
                        l.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            std::fs::write(&f, t).unwrap();
            let err = compile(&Options {
                themes_dir: themes_dir(),
                theme: dst.display().to_string(),
                lang: "en".into(),
                out_dir: tmpdir(&format!("{name}-out")),
            })
            .err()
            .unwrap();
            assert!(err.contains(needle), "{err}");
        }
        let err = compile(&Options {
            themes_dir: themes_dir(),
            theme: "default".into(),
            lang: "xx".into(),
            out_dir: tmpdir("lang-out"),
        })
        .err()
        .unwrap();
        assert!(err.contains("no strings for language \"xx\""), "{err}");
        let err = compile(&Options {
            themes_dir: themes_dir(),
            theme: "nope".into(),
            lang: "en".into(),
            out_dir: tmpdir("nope-out"),
        })
        .err()
        .unwrap();
        assert!(err.contains("is not a directory"), "{err}");
    }

    #[test]
    fn resampling_premultiplies_and_averages() {
        // 2×1: opaque red and transparent → one pixel, half-covered red.
        let px = resample(2, 1, &[255, 0, 0, 255, 0, 255, 0, 0], 1, 1);
        assert_eq!(px, vec![0, 0, 128, 128], "BGRA, premultiplied");
    }
}
