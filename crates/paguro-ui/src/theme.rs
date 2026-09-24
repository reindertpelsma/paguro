//! The compiled-in theme, as data. `paguro-theme` (build time) validates a
//! theme directory and emits statics of these types; nothing here parses.
//! Lengths are reference pixels, scaled by the chosen [`Step`].

use crate::strings::{STR_COUNT, Str};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Color {
    pub const fn rgb(r: u8, g: u8, b: u8) -> Color {
        Color { r, g, b }
    }
}

/// One pre-rasterised glyph. The bitmap is `w`×`h` 4-bit coverage values,
/// run-length coded (`paguro_theme::rle_encode`) from byte `off` of the
/// font's `alpha`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Glyph {
    /// A BMP code point (others use the fallback).
    pub ch: u16,
    /// Advance in 1/64 px.
    pub adv: u16,
    /// Bitmap left edge relative to the pen.
    pub x: i16,
    /// Bitmap top relative to the baseline (y down).
    pub y: i16,
    pub w: u16,
    pub h: u16,
    pub off: u32,
}

/// A text style rasterised at one size.
#[derive(Debug)]
pub struct Font {
    /// Pixel size ×10 (informational).
    pub px_x10: u32,
    pub ascent: i32,
    /// Negative: below the baseline.
    pub descent: i32,
    pub line: i32,
    /// Sorted by `ch`.
    pub glyphs: &'static [Glyph],
    pub alpha: &'static [u8],
}

impl Font {
    pub fn glyph(&self, c: char) -> Option<&'static Glyph> {
        let c = u16::try_from(c as u32).ok()?;
        let glyphs: &'static [Glyph] = self.glyphs;
        glyphs
            .binary_search_by_key(&c, |g| g.ch)
            .ok()
            .and_then(|i| glyphs.get(i))
    }

    /// The glyph for `c`, or the fallback `?` (every theme has it).
    pub fn glyph_or_fallback(&self, c: char) -> Option<&'static Glyph> {
        self.glyph(c).or_else(|| self.glyph('?'))
    }

    /// Visit `g`'s pixels in row-major order with their coverage (0..=255),
    /// skipping transparent ones. Malformed data ends the walk early; it
    /// never reads outside `alpha` or reports a pixel outside `w`×`h`.
    pub fn pixels(&self, g: &Glyph, mut f: impl FnMut(u32, u32, u8)) {
        let (w, total) = (u32::from(g.w), u32::from(g.w) * u32::from(g.h));
        if w == 0 {
            return;
        }
        let data = self.alpha.get(g.off as usize..).unwrap_or(&[]);
        let mut i = 0usize;
        let mut k = 0u32;
        while k < total {
            let Some(&b) = data.get(i) else {
                return;
            };
            i += 1;
            let n = u32::from(b & 0x3f) + 1;
            match b >> 6 {
                0 => k += n,
                1 => {
                    for _ in 0..n.min(total - k) {
                        f(k % w, k / w, 255);
                        k += 1;
                    }
                }
                _ => {
                    for j in 0..n {
                        let Some(&byte) = data.get(i + (j / 2) as usize) else {
                            return;
                        };
                        let v = if j % 2 == 0 { byte & 0xf } else { byte >> 4 };
                        if k < total && v != 0 {
                            f(k % w, k / w, v * 17);
                        }
                        k += 1;
                    }
                    i += n.div_ceil(2) as usize;
                }
            }
        }
    }
}

/// Premultiplied BGRA, `w`×`h`, rows packed.
#[derive(Debug)]
pub struct Image {
    pub w: u32,
    pub h: u32,
    pub px: &'static [u8],
}

/// Text styles, in the order of `paguro_theme::spec::STYLES`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Style {
    Brand,
    Title,
    Body,
    Label,
    Detail,
    Field,
    Hint,
    Key,
    Banner,
}

pub const STYLE_COUNT: usize = 9;

/// Fonts and images for one scale factor.
#[derive(Debug)]
pub struct Step {
    /// The scale ×1000.
    pub milli: u32,
    pub fonts: [&'static Font; STYLE_COUNT],
    /// Indexed like the theme's `[images]` table (sorted by name).
    pub images: &'static [&'static Image],
}

impl Step {
    pub fn font(&self, s: Style) -> &'static Font {
        // Style has exactly STYLE_COUNT variants.
        let fonts: &[&'static Font; STYLE_COUNT] = &self.fonts;
        match fonts.get(s as usize) {
            Some(f) => f,
            None => fonts[0],
        }
    }
    /// A reference length at this scale (rounded, never negative for a
    /// non-negative input).
    pub fn px(&self, v: i32) -> i32 {
        let v = i64::from(v) * i64::from(self.milli);
        let r = if v >= 0 {
            (v + 500) / 1000
        } else {
            (v - 500) / 1000
        };
        i32::try_from(r).unwrap_or(0)
    }
    pub fn image(&self, i: u8) -> Option<&'static Image> {
        let images: &'static [&'static Image] = self.images;
        images.get(usize::from(i)).copied()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Palette {
    pub background: Color,
    pub text: Color,
    pub muted: Color,
    pub faint: Color,
    pub accent: Color,
    pub surface: Color,
    pub surface_selected: Color,
    pub border: Color,
    pub border_focus: Color,
    pub cursor: Color,
    pub key_border: Color,
    pub key_text: Color,
    pub banner_background: Color,
    pub banner_text: Color,
    pub toast_background: Color,
    pub toast_text: Color,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selection {
    Bar,
    Fill,
    Outline,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    pub bullet: char,
    pub ellipsis: char,
    pub selection: Selection,
    /// Steps larger than the resolution calls for (a large-text variant).
    pub scale_bias: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Anchor {
    TopLeft,
    TopCenter,
    TopRight,
    CenterLeft,
    Center,
    CenterRight,
    BottomLeft,
    BottomCenter,
    BottomRight,
}

impl Anchor {
    /// Horizontal: 0 left, 1 centre, 2 right. Vertical likewise.
    pub const fn h(self) -> u8 {
        match self {
            Anchor::TopLeft | Anchor::CenterLeft | Anchor::BottomLeft => 0,
            Anchor::TopCenter | Anchor::Center | Anchor::BottomCenter => 1,
            _ => 2,
        }
    }
    pub const fn v(self) -> u8 {
        match self {
            Anchor::TopLeft | Anchor::TopCenter | Anchor::TopRight => 0,
            Anchor::CenterLeft | Anchor::Center | Anchor::CenterRight => 1,
            _ => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Align {
    Left,
    Center,
    Right,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placement {
    pub anchor: Anchor,
    pub offset: (i32, i32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Brand {
    pub place: Placement,
    pub logo: Option<u8>,
    pub gap: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Banner {
    pub place: Placement,
    pub padding: (i32, i32),
    pub radius: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Content {
    pub place: Placement,
    pub max_width: i32,
    pub align: Align,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hints {
    pub place: Placement,
    pub gap: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decoration {
    pub image: u8,
    pub place: Placement,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Spacing {
    pub title: i32,
    pub paragraph: i32,
    pub block: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RowStyle {
    pub height: i32,
    pub padding: i32,
    pub gap: i32,
    pub radius: i32,
    pub marker: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldStyle {
    pub height: i32,
    pub padding: i32,
    pub radius: i32,
    pub border: i32,
    pub cursor: i32,
    pub group_gap: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeycapStyle {
    pub padding: i32,
    pub radius: i32,
    pub border: i32,
    pub gap: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ToastStyle {
    pub padding: (i32, i32),
    pub radius: i32,
    pub gap: i32,
}

/// One screen kind's layout, fully resolved at build time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    /// Vertical, horizontal.
    pub margin: (i32, i32),
    pub show_logo: bool,
    pub show_name: bool,
    pub show_hints: bool,
    pub brand: Brand,
    pub banner: Banner,
    pub content: Content,
    pub hints: Hints,
    pub decorations: &'static [Decoration],
    pub spacing: Spacing,
    pub row: RowStyle,
    pub field: FieldStyle,
    pub keycap: KeycapStyle,
    pub toast: ToastStyle,
}

/// Screen kinds with their own layout, in the order of
/// `paguro_theme::spec::SCREENS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScreenKind {
    Unlock,
    Secret,
    RecoveryKey,
    Path,
    Message,
    Volumes,
    Targets,
    Roots,
}

pub const SCREEN_KINDS: usize = 8;

/// One piece of a string: literal text, a run-time argument (by position),
/// or a paragraph break.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Part {
    Lit(&'static str),
    Arg(u8),
    Break,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tpl(pub &'static [Part]);

#[derive(Debug)]
pub struct Theme {
    pub name: &'static str,
    pub description: &'static str,
    /// The size the layout is designed for.
    pub reference: (u32, u32),
    pub palette: Palette,
    pub options: Options,
    /// Ascending scale.
    pub steps: &'static [Step],
    pub layouts: [Layout; SCREEN_KINDS],
    pub strings: &'static [Tpl; STR_COUNT],
}

impl Theme {
    /// The largest step not above `min(w / ref_w, h / ref_h)` (the smallest
    /// when even that is too large).
    pub fn step_for(&self, w: u32, h: u32) -> &'static Step {
        let steps: &'static [Step] = self.steps;
        let (rw, rh) = (
            u64::from(self.reference.0.max(1)),
            u64::from(self.reference.1.max(1)),
        );
        let s = (u64::from(w) * 1000 / rw).min(u64::from(h) * 1000 / rh);
        let mut pick = 0usize;
        for (i, st) in steps.iter().enumerate() {
            if u64::from(st.milli) <= s {
                pick = i;
            }
        }
        let pick = pick
            .saturating_add(usize::from(self.options.scale_bias))
            .min(steps.len().saturating_sub(1));
        match steps.get(pick) {
            Some(p) => p,
            None => &EMPTY_STEP,
        }
    }

    pub fn layout(&self, k: ScreenKind) -> &Layout {
        let layouts: &[Layout; SCREEN_KINDS] = &self.layouts;
        match layouts.get(k as usize) {
            Some(l) => l,
            None => &layouts[0],
        }
    }

    pub fn tpl(&self, s: Str) -> Tpl {
        let strings: &[Tpl; STR_COUNT] = self.strings;
        strings.get(s as usize).copied().unwrap_or(Tpl(&[]))
    }
}

static EMPTY_FONT: Font = Font {
    px_x10: 0,
    ascent: 0,
    descent: 0,
    line: 1,
    glyphs: &[],
    alpha: &[],
};

/// Never used by a generated theme (they have at least one step); keeps
/// [`Theme::step_for`] total.
static EMPTY_STEP: Step = Step {
    milli: 1000,
    fonts: [&EMPTY_FONT; STYLE_COUNT],
    images: &[],
};
