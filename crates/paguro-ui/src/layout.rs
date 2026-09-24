//! `(Screen, View, Theme, resolution) → DrawList` (INTERFACES.md §13.2).
//!
//! The frame is the same on every screen (DESIGN.md §4.1): the name (and
//! logo) in the brand slot, the unattested banner when the prompt is
//! unverified, the key hints, and a content column holding one primitive —
//! a list, a text field, or a message with actions. Everything is measured
//! with the compiled-in fonts and fitted: text that does not fit is cut
//! with an ellipsis, paragraphs and lists give up lines when the screen is
//! short, and nothing is placed outside the frame. The layout invariants
//! tests check exactly that for random sizes and labels.

use core::fmt::Write;

use paguro_boot::platform::{Grey, Notice, Row, Screen, TargetKind, UnlockMenu, VolumeFormat};
use paguro_boot::ui::{self, Field, FieldKind, Item, RECOVERY_DIGITS, RECOVERY_GROUP, Size, Unit};

use crate::canvas::Rect;
use crate::draw::{Cmd, DrawList, TextRun, TextSrc};
use crate::strings::Str;
use crate::text;
use crate::theme::{
    Align, Color, Font, Layout, Palette, Part, Placement, ScreenKind, Selection, Step, Style, Theme,
};

/// Below this the loader uses the text console instead.
pub const MIN_WIDTH: u32 = 640;
pub const MIN_HEIGHT: u32 = 480;

pub const fn supported(w: u32, h: u32) -> bool {
    w >= MIN_WIDTH && h >= MIN_HEIGHT && w <= 16384 && h <= 16384
}

/// A short message carried over from a screen that needs no key
/// ([`Screen::Incorrect`], [`Screen::PathRefused`]) to the next one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Toast {
    Incorrect,
    PathRefused,
}

/// The interaction state the picture depends on.
#[derive(Clone, Copy, Debug)]
pub struct View<'a> {
    /// The highlighted list row.
    pub selected: usize,
    /// The text field and the buffer it edits.
    pub field: Option<Field>,
    pub buf: &'a [u8],
    pub toast: Option<Toast>,
}

impl View<'static> {
    pub const IDLE: View<'static> = View {
        selected: 0,
        field: None,
        buf: &[],
        toast: None,
    };
}

pub fn kind(screen: &Screen) -> ScreenKind {
    match screen {
        Screen::Unlock(_) => ScreenKind::Unlock,
        Screen::EnterSecret {
            row: Row::RecoveryKey,
            ..
        } => ScreenKind::RecoveryKey,
        Screen::EnterSecret { .. } => ScreenKind::Secret,
        Screen::EnterPath => ScreenKind::Path,
        Screen::SelectVolume(_) => ScreenKind::Volumes,
        Screen::SelectTarget(_) => ScreenKind::Targets,
        Screen::SelectRoot { .. } => ScreenKind::Roots,
        _ => ScreenKind::Message,
    }
}

/// A template argument.
#[derive(Clone, Copy, Debug)]
pub enum Arg<'a> {
    Num(u64),
    Text(&'a str),
    Size(u64),
}

const MAX_BLOCKS: usize = 10;
const MAX_ACTIONS: usize = 3;
const MAX_HINTS: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BlockKind {
    Toast,
    Title,
    Para,
    Label,
    List,
    Field,
    Actions,
}

#[derive(Clone, Copy, Debug)]
struct Block<'a> {
    kind: BlockKind,
    src: TextSrc<'a>,
    color: Color,
    bar: bool,
    /// Lines (text) or rows (list) the block may use.
    max: usize,
    min: usize,
}

struct Ctx<'t> {
    theme: &'t Theme,
    step: &'static Step,
    lay: &'t Layout,
    pal: Palette,
}

impl Ctx<'_> {
    fn px(&self, v: i32) -> i32 {
        self.step.px(v)
    }
    fn font(&self, s: Style) -> &'static Font {
        self.step.font(s)
    }
}

fn line_h(f: &Font) -> i32 {
    f.line.max(f.ascent.saturating_sub(f.descent)).max(1)
}

/// Compose `s` with `args` into the arena; paragraph `para` only (0-based)
/// when the template has breaks. A single literal is borrowed, not copied.
pub fn compose<'a>(
    list: &mut DrawList<'a>,
    theme: &Theme,
    s: Str,
    args: &[Arg<'a>],
    para: usize,
) -> TextSrc<'a> {
    let tpl = theme.tpl(s);
    if let [Part::Lit(l)] = tpl.0 {
        if para == 0 {
            return TextSrc::Str(l);
        }
    }
    let units = [
        theme.tpl(Str::UnitB),
        theme.tpl(Str::UnitKb),
        theme.tpl(Str::UnitMb),
        theme.tpl(Str::UnitGb),
        theme.tpl(Str::UnitTb),
    ];
    let decimal = theme.tpl(Str::Decimal);
    let mut c = list.compose();
    let mut p = 0usize;
    for part in tpl.0 {
        match *part {
            Part::Break => p += 1,
            _ if p != para => {}
            Part::Lit(l) => {
                let _ = c.write_str(l);
            }
            Part::Arg(i) => match args.get(usize::from(i)) {
                Some(Arg::Num(n)) => {
                    let _ = write!(c, "{n}");
                }
                Some(Arg::Text(t)) => {
                    let _ = c.write_str(t);
                }
                Some(Arg::Size(b)) => {
                    let sz = Size::of(*b);
                    let _ = write!(c, "{}", sz.whole);
                    if let Some(t) = sz.tenth {
                        write_lits(&mut c, decimal.0);
                        let _ = write!(c, "{t}");
                    }
                    let _ = c.write_str(" ");
                    let u = match sz.unit {
                        Unit::B => 0,
                        Unit::KB => 1,
                        Unit::MB => 2,
                        Unit::GB => 3,
                        Unit::TB => 4,
                    };
                    write_lits(&mut c, units.get(u).map_or(&[][..], |t| t.0));
                }
                None => {}
            },
        }
    }
    c.finish()
}

fn write_lits(w: &mut impl Write, parts: &[Part]) {
    for p in parts {
        if let Part::Lit(l) = p {
            let _ = w.write_str(l);
        }
    }
}

fn paragraphs(theme: &Theme, s: Str) -> usize {
    1 + theme
        .tpl(s)
        .0
        .iter()
        .filter(|p| matches!(p, Part::Break))
        .count()
}

/// "a · b" into the arena.
fn joined<'a>(list: &mut DrawList<'a>, a: TextSrc<'a>, b: TextSrc<'a>) -> TextSrc<'a> {
    let mut buf = [0u8; 256];
    let mut n = 0usize;
    let mut put = |s: &str, n: &mut usize| {
        for ch in s.chars() {
            let mut e = [0u8; 4];
            let e = ch.encode_utf8(&mut e).as_bytes();
            if let Some(d) = buf.get_mut(*n..*n + e.len()) {
                d.copy_from_slice(e);
                *n += e.len();
            }
        }
    };
    if let Some(s) = list.as_str(&a) {
        put(s, &mut n);
    }
    put(" · ", &mut n);
    if let Some(s) = list.as_str(&b) {
        put(s, &mut n);
    }
    let text = core::str::from_utf8(buf.get(..n).unwrap_or(&[])).unwrap_or("");
    let mut c = list.compose();
    let _ = c.write_str(text);
    c.finish()
}

/// Place a `w`×`h` box by anchor and offset in `area`, kept inside it.
fn place(p: &Placement, w: i32, h: i32, off: (i32, i32), area: Rect) -> Rect {
    let x = area.x
        + match p.anchor.h() {
            0 => 0,
            1 => (area.w - w) / 2,
            _ => area.w - w,
        }
        + off.0;
    let y = area.y
        + match p.anchor.v() {
            0 => 0,
            1 => (area.h - h) / 2,
            _ => area.h - h,
        }
        + off.1;
    let x = x.min(area.right() - w).max(area.x);
    let y = y.min(area.bottom() - h).max(area.y);
    Rect::new(x, y, w.min(area.w), h.min(area.h))
}

/// One line of text fitted into `bounds` (cut with an ellipsis if needed),
/// aligned horizontally and centred vertically on the line box.
fn line<'a>(
    list: &mut DrawList<'a>,
    ctx: &Ctx<'_>,
    font: &'static Font,
    src: TextSrc<'a>,
    color: Color,
    bounds: Rect,
    align: Align,
) -> Rect {
    if bounds.is_empty() {
        return Rect::default();
    }
    let ell = ctx.theme.options.ellipsis;
    let (src, ellipsis) = match src {
        TextSrc::Repeat(c, n) => {
            let (k, cut) = text::fit_repeat(font, c, n, bounds.w, ell);
            (TextSrc::Repeat(c, k), cut.then_some(ell))
        }
        _ => {
            let s = list.as_str(&src).unwrap_or("");
            let (k, cut) = text::fit(font, s, bounds.w, ell);
            (list.prefix(&src, k), cut.then_some(ell))
        }
    };
    let (l, r) = text::extent(font, list.chars(&src).chain(ellipsis));
    let w = r - l;
    let x = match align {
        Align::Left => bounds.x,
        Align::Center => bounds.x + (bounds.w - w) / 2,
        Align::Right => bounds.right() - w,
    } - l;
    let asc_desc = font.ascent - font.descent;
    let baseline = bounds.y + (bounds.h - asc_desc) / 2 + font.ascent;
    let run = TextRun {
        x,
        baseline,
        font,
        color,
        src,
        ellipsis,
        bounds,
    };
    list.push(Cmd::Text(run));
    Rect::new(x + l, bounds.y, w, bounds.h)
}

// ---------------------------------------------------------------------------
// What each screen shows

struct Spec<'a> {
    blocks: [Option<Block<'a>>; MAX_BLOCKS],
    actions: [Option<(Str, Str)>; MAX_ACTIONS],
    hints: [Option<(Str, Str)>; MAX_HINTS],
    unattested: bool,
}

impl<'a> Spec<'a> {
    fn new() -> Self {
        Spec {
            blocks: [None; MAX_BLOCKS],
            actions: [None; MAX_ACTIONS],
            hints: [None; MAX_HINTS],
            unattested: false,
        }
    }
    fn block(&mut self, b: Block<'a>) {
        if let Some(slot) = self.blocks.iter_mut().find(|s| s.is_none()) {
            *slot = Some(b);
        }
    }
    fn action(&mut self, key: Str, label: Str) {
        if let Some(slot) = self.actions.iter_mut().find(|s| s.is_none()) {
            *slot = Some((key, label));
        }
    }
    fn hint(&mut self, key: Str, label: Str) {
        if let Some(slot) = self.hints.iter_mut().find(|s| s.is_none()) {
            *slot = Some((key, label));
        }
    }
}

fn text_block<'a>(kind: BlockKind, src: TextSrc<'a>, color: Color, max: usize) -> Block<'a> {
    Block {
        kind,
        src,
        color,
        bar: false,
        max,
        min: 1,
    }
}

fn paras<'a>(
    spec: &mut Spec<'a>,
    list: &mut DrawList<'a>,
    theme: &Theme,
    s: Str,
    args: &[Arg<'a>],
    color: Color,
) {
    for i in 0..paragraphs(theme, s) {
        let src = compose(list, theme, s, args, i);
        spec.block(text_block(BlockKind::Para, src, color, 12));
    }
}

fn describe<'a>(
    screen: &'a Screen,
    view: &View<'a>,
    theme: &Theme,
    list: &mut DrawList<'a>,
) -> Spec<'a> {
    let pal = &theme.palette;
    let mut sp = Spec::new();
    if let Some(t) = view.toast {
        let s = match t {
            Toast::Incorrect => Str::Incorrect,
            Toast::PathRefused => Str::PathRefused,
        };
        sp.block(text_block(
            BlockKind::Toast,
            compose(list, theme, s, &[], 0),
            pal.toast_text,
            1,
        ));
    }
    let title = |sp: &mut Spec<'a>, list: &mut DrawList<'a>, s: Str| {
        sp.block(text_block(
            BlockKind::Title,
            compose(list, theme, s, &[], 0),
            pal.text,
            3,
        ));
    };
    let list_block = Block {
        kind: BlockKind::List,
        src: TextSrc::Str(""),
        color: pal.text,
        bar: false,
        max: ui::MAX_ITEMS,
        min: 1,
    };
    let field_block = Block {
        kind: BlockKind::Field,
        src: TextSrc::Str(""),
        color: pal.text,
        bar: false,
        max: 1,
        min: 1,
    };
    let nav = |sp: &mut Spec<'a>| {
        sp.hint(Str::KeyArrows, Str::HintSelect);
        sp.hint(Str::KeyEnter, Str::HintContinue);
    };
    match screen {
        Screen::Unlock(m) => {
            sp.unattested = m.unattested;
            title(&mut sp, list, Str::UnlockTitle);
            if m.first_boot {
                let mut b = text_block(
                    BlockKind::Para,
                    compose(list, theme, Str::FirstBoot, &[], 0),
                    pal.text,
                    6,
                );
                b.bar = true;
                sp.block(b);
            }
            sp.block(list_block);
            nav(&mut sp);
            sp.hint(Str::KeyW, Str::HintWindows);
            sp.hint(Str::KeyEsc, Str::HintOther);
        }
        Screen::EnterSecret { row, unattested } => {
            sp.unattested = *unattested;
            let t = match row {
                Row::PasswordOrPin => Str::SecretPassword,
                Row::RecoveryPassphrase => Str::SecretPassphrase,
                Row::RecoveryKey => Str::SecretRecoveryKey,
            };
            title(&mut sp, list, t);
            sp.block(field_block);
            if *row == Row::RecoveryKey {
                paras(&mut sp, list, theme, Str::RecoveryKeyHelp, &[], pal.muted);
            }
            sp.hint(Str::KeyEnter, Str::HintContinue);
            let shown = view.field.is_some_and(|f| f.revealed());
            sp.hint(
                Str::KeyInsert,
                if shown { Str::HintHide } else { Str::HintShow },
            );
            sp.hint(Str::KeyEsc, Str::HintBack);
        }
        Screen::EnterPath => {
            sp.unattested = true;
            title(&mut sp, list, Str::PathTitle);
            sp.block(text_block(
                BlockKind::Label,
                compose(list, theme, Str::PathLabel, &[], 0),
                pal.muted,
                1,
            ));
            sp.block(field_block);
            paras(&mut sp, list, theme, Str::PathHelp, &[], pal.muted);
            sp.hint(Str::KeyEnter, Str::HintContinue);
            sp.hint(Str::KeyEsc, Str::HintBack);
        }
        Screen::SelectVolume(_) => {
            sp.unattested = true;
            title(&mut sp, list, Str::VolumesTitle);
            sp.block(list_block);
            nav(&mut sp);
            sp.hint(Str::KeyW, Str::HintWindows);
        }
        Screen::SelectTarget(t) => {
            sp.unattested = true;
            title(&mut sp, list, Str::TargetsTitle);
            let body = if t.count == 0 {
                Str::TargetsEmpty
            } else {
                Str::TargetsBody
            };
            paras(&mut sp, list, theme, body, &[], pal.muted);
            sp.block(list_block);
            nav(&mut sp);
            sp.hint(Str::KeyW, Str::HintWindows);
        }
        Screen::SelectRoot { efi, .. } => {
            sp.unattested = true;
            title(&mut sp, list, Str::RootsTitle);
            paras(
                &mut sp,
                list,
                theme,
                Str::RootsBody,
                &[Arg::Text(efi.as_str())],
                pal.muted,
            );
            sp.block(list_block);
            nav(&mut sp);
            sp.hint(Str::KeyEsc, Str::HintBack);
        }
        _ => {
            type Message = (Str, Option<Str>, [Option<(Str, Str)>; 2]);
            let (t, body, acts): Message = match screen {
                Screen::CannotUnlock => (
                    Str::CannotTitle,
                    Some(Str::CannotBody),
                    [
                        Some((Str::KeyEnter, Str::ActStartWindows)),
                        Some((Str::KeyR, Str::ActNeedLinux)),
                    ],
                ),
                Screen::ConfigInvalid => (
                    Str::ConfigTitle,
                    Some(Str::ConfigBody),
                    [
                        Some((Str::KeyEnter, Str::ActStartWindows)),
                        Some((Str::KeyR, Str::ActRecover)),
                    ],
                ),
                Screen::TpmLocked => (
                    Str::LockedTitle,
                    Some(Str::LockedBody),
                    [Some((Str::KeyEnter, Str::ActTryAnother)), None],
                ),
                Screen::NoInstallation => (
                    Str::NoinstTitle,
                    Some(Str::NoinstBody),
                    [Some((Str::KeyEnter, Str::ActStartWindows)), None],
                ),
                Screen::Notice(n) => match n {
                    Notice::Hibernated => (
                        Str::HibernatedTitle,
                        Some(Str::HibernatedBody),
                        [
                            Some((Str::KeyEnter, Str::ActContinueRo)),
                            Some((Str::KeyW, Str::ActRestartWindows)),
                        ],
                    ),
                    Notice::Dirty => (
                        Str::DirtyTitle,
                        Some(Str::DirtyBody),
                        [
                            Some((Str::KeyEnter, Str::ActContinueRo)),
                            Some((Str::KeyW, Str::ActRestartWindows)),
                        ],
                    ),
                    Notice::Pcr12NotZero => (
                        Str::Pcr12Title,
                        Some(Str::Pcr12Body),
                        [
                            Some((Str::KeyEnter, Str::ActStartWindows)),
                            Some((Str::KeyR, Str::ActRecoverShort)),
                        ],
                    ),
                    Notice::VolumeMissing => (
                        Str::MissingTitle,
                        Some(Str::MissingBody),
                        [
                            Some((Str::KeyEnter, Str::ActStartWindows)),
                            Some((Str::KeyR, Str::ActRecoverShort)),
                        ],
                    ),
                    Notice::SealOverPlaintext => (
                        Str::PlaintextTitle,
                        Some(Str::PlaintextBody),
                        [Some((Str::KeyEnter, Str::ActContinue)), None],
                    ),
                    Notice::NotImplemented => (
                        Str::NotimplTitle,
                        Some(Str::NotimplBody),
                        [Some((Str::KeyEnter, Str::ActContinue)), None],
                    ),
                },
                Screen::PathRefused => (
                    Str::PathRefused,
                    None,
                    [Some((Str::KeyEnter, Str::ActContinue)), None],
                ),
                _ => (
                    Str::Incorrect,
                    None,
                    [Some((Str::KeyEnter, Str::ActContinue)), None],
                ),
            };
            title(&mut sp, list, t);
            if let Some(b) = body {
                paras(&mut sp, list, theme, b, &[], pal.muted);
            }
            if matches!(screen, Screen::NoInstallation) {
                let mut b = text_block(
                    BlockKind::Para,
                    compose(list, theme, Str::NoinstFix, &[], 0),
                    pal.text,
                    4,
                );
                b.bar = true;
                sp.block(b);
            }
            for (k, l) in acts.into_iter().flatten() {
                sp.action(k, l);
            }
            sp.block(Block {
                kind: BlockKind::Actions,
                src: TextSrc::Str(""),
                color: pal.text,
                bar: false,
                max: MAX_ACTIONS,
                min: 1,
            });
        }
    }
    sp.hint(Str::KeyTheme, Str::HintContrast);
    sp
}

// ---------------------------------------------------------------------------
// Rows

fn row_texts<'a>(
    screen: &'a Screen,
    item: Item,
    theme: &Theme,
    list: &mut DrawList<'a>,
) -> (TextSrc<'a>, TextSrc<'a>) {
    let none = TextSrc::Str("");
    match (item, screen) {
        (Item::Unlock { row, enabled }, Screen::Unlock(m)) => {
            let label = compose(
                list,
                theme,
                match row {
                    Row::PasswordOrPin => Str::RowPassword,
                    Row::RecoveryPassphrase => Str::RowPassphrase,
                    Row::RecoveryKey => Str::RowRecoveryKey,
                },
                &[],
                0,
            );
            let detail = match row {
                Row::PasswordOrPin => password_detail(m, enabled, theme, list),
                Row::RecoveryPassphrase => compose(list, theme, Str::NoLimit, &[], 0),
                Row::RecoveryKey => compose(list, theme, Str::Digits, &[], 0),
            };
            (label, detail)
        }
        (Item::Volume(i), Screen::SelectVolume(v)) => {
            let Some(c) = v.as_slice().get(usize::from(i)) else {
                return (none, none);
            };
            let row = compose(
                list,
                theme,
                Str::VolumeRow,
                &[
                    Arg::Num(u64::from(c.disk)),
                    Arg::Num(u64::from(c.partition)),
                ],
                0,
            );
            let label = if c.name.is_empty() {
                row
            } else {
                joined(list, TextSrc::Str(c.name.as_str()), row)
            };
            let size = size_text(list, theme, c.bytes);
            let fmt = compose(
                list,
                theme,
                match c.format {
                    VolumeFormat::BitLocker => Str::FormatBitlocker,
                    VolumeFormat::Ntfs => Str::FormatNtfs,
                },
                &[],
                0,
            );
            (label, joined(list, size, fmt))
        }
        (Item::Target(i), Screen::SelectTarget(t)) => {
            let Some(e) = t.get(usize::from(i)) else {
                return (none, none);
            };
            let size = size_text(list, theme, e.bytes);
            let k = compose(
                list,
                theme,
                match e.kind {
                    TargetKind::Disk => Str::TargetDisk,
                    TargetKind::EfiFile => Str::TargetEfi,
                },
                &[],
                0,
            );
            (TextSrc::Str(e.name.as_str()), joined(list, size, k))
        }
        (Item::TypePath, _) => (
            compose(list, theme, Str::TypePath, &[], 0),
            compose(list, theme, Str::TypePathWhy, &[], 0),
        ),
        (Item::Root(i), Screen::SelectRoot { roots, .. }) => {
            let Some(e) = roots.get(usize::from(i)) else {
                return (none, none);
            };
            (
                TextSrc::Str(e.name.as_str()),
                size_text(list, theme, e.bytes),
            )
        }
        (Item::NoRoot, _) => (
            compose(list, theme, Str::NoRoot, &[], 0),
            compose(list, theme, Str::NoRootWhy, &[], 0),
        ),
        _ => (none, none),
    }
}

fn size_text<'a>(list: &mut DrawList<'a>, theme: &Theme, bytes: u64) -> TextSrc<'a> {
    // Any template with one argument would do; compose the size directly.
    let mut c = list.compose();
    let sz = Size::of(bytes);
    let _ = write!(c, "{}", sz.whole);
    if let Some(t) = sz.tenth {
        write_lits(&mut c, theme.tpl(Str::Decimal).0);
        let _ = write!(c, "{t}");
    }
    let _ = c.write_str(" ");
    let u = match sz.unit {
        Unit::B => Str::UnitB,
        Unit::KB => Str::UnitKb,
        Unit::MB => Str::UnitMb,
        Unit::GB => Str::UnitGb,
        Unit::TB => Str::UnitTb,
    };
    write_lits(&mut c, theme.tpl(u).0);
    c.finish()
}

fn password_detail<'a>(
    m: &UnlockMenu,
    enabled: bool,
    theme: &Theme,
    list: &mut DrawList<'a>,
) -> TextSrc<'a> {
    match (m.tpm, enabled) {
        (Err(Grey::RecoveryMode), false) => {
            let a = compose(list, theme, Str::GreyRestart, &[], 0);
            let b = compose(list, theme, Str::GreyRestartWhy, &[], 0);
            joined(list, a, b)
        }
        (Err(Grey::Locked), false) => {
            let a = compose(list, theme, Str::GreyLocked, &[], 0);
            let b = compose(list, theme, Str::GreyLockedWhy, &[], 0);
            joined(list, a, b)
        }
        (Err(Grey::RecoveryMode), true) => compose(list, theme, Str::GreyRestart, &[], 0),
        (Err(Grey::Locked), true) => compose(list, theme, Str::GreyLocked, &[], 0),
        (Ok(Some(1)), _) => compose(list, theme, Str::AttemptLast, &[], 0),
        (Ok(Some(n)), _) => compose(list, theme, Str::Attempts, &[Arg::Num(u64::from(n))], 0),
        _ => TextSrc::Str(""),
    }
}

// ---------------------------------------------------------------------------
// Measuring the column

struct Dims {
    title: &'static Font,
    body: &'static Font,
    label: &'static Font,
    detail: &'static Font,
    field: &'static Font,
    key: &'static Font,
    banner: &'static Font,
    row_h: i32,
    row_gap: i32,
    field_h: i32,
}

fn dims(ctx: &Ctx<'_>) -> Dims {
    let l = ctx.lay;
    let label = ctx.font(Style::Label);
    let field = ctx.font(Style::Field);
    Dims {
        title: ctx.font(Style::Title),
        body: ctx.font(Style::Body),
        label,
        detail: ctx.font(Style::Detail),
        field,
        key: ctx.font(Style::Key),
        banner: ctx.font(Style::Banner),
        row_h: ctx.px(l.row.height).max(line_h(label) + 2),
        row_gap: ctx.px(l.row.gap),
        field_h: ctx
            .px(l.field.height)
            .max(line_h(field) + 2 * ctx.px(l.field.border) + 2),
    }
}

/// Recovery-key grid geometry: groups per row, group width, slot width.
fn key_grid(ctx: &Ctx<'_>, d: &Dims, cw: i32) -> (i32, i32, i32) {
    let mut slot = text::char_width(d.field, ctx.theme.options.bullet);
    for c in '0'..='9' {
        slot = slot.max(text::char_width(d.field, c));
    }
    slot = slot.max(text::char_width(d.field, '·'));
    slot += (slot / 8).max(1);
    let pad = ctx.px(ctx.lay.field.padding) / 2 + ctx.px(ctx.lay.field.border);
    let gw = slot * RECOVERY_GROUP as i32 + 2 * pad;
    let gap = ctx.px(ctx.lay.field.group_gap);
    let mut per = 8i32;
    while per > 1 && per * gw + (per - 1) * gap > cw {
        per /= 2;
    }
    (per, gw, slot)
}

fn keycap_size(ctx: &Ctx<'_>, d: &Dims, list: &DrawList<'_>, key: TextSrc<'_>) -> (i32, i32) {
    let pad = ctx.px(ctx.lay.keycap.padding);
    let tw = list.as_str(&key).map_or(0, |s| text::width(d.key, s));
    let h = line_h(d.key) + pad;
    ((tw + 2 * pad).max(h), h)
}

#[allow(clippy::too_many_arguments)]
fn block_height(
    ctx: &Ctx<'_>,
    d: &Dims,
    list: &DrawList<'_>,
    b: &Block<'_>,
    cw: i32,
    n_items: usize,
    n_actions: usize,
    fkind: Option<FieldKind>,
) -> i32 {
    match b.kind {
        BlockKind::Toast => line_h(d.banner) + 2 * ctx.px(ctx.lay.toast.padding.0),
        BlockKind::Title => {
            let n = list
                .as_str(&b.src)
                .map_or(1, |s| text::count_lines(d.title, s, cw));
            line_h(d.title) * n.clamp(b.min, b.max) as i32
        }
        BlockKind::Para => {
            let inset = if b.bar { bar_inset(ctx) } else { 0 };
            let n = list
                .as_str(&b.src)
                .map_or(1, |s| text::count_lines(d.body, s, cw - inset));
            line_h(d.body) * n.clamp(b.min, b.max) as i32
        }
        BlockKind::Label => line_h(d.detail),
        BlockKind::List => {
            let n = n_items.clamp(b.min, b.max) as i32;
            n * d.row_h + (n - 1).max(0) * d.row_gap
        }
        BlockKind::Field => match fkind {
            Some(FieldKind::RecoveryKey) => {
                let (per, _, _) = key_grid(ctx, d, cw);
                let rows = (8 + per - 1) / per;
                rows * d.field_h + (rows - 1) * ctx.px(ctx.lay.field.group_gap)
            }
            _ => d.field_h,
        },
        BlockKind::Actions => {
            let one = line_h(d.label).max(line_h(d.key) + ctx.px(ctx.lay.keycap.padding));
            let n = n_actions.clamp(b.min, b.max) as i32;
            n * one + (n - 1).max(0) * d.row_gap
        }
    }
}

fn bar_inset(ctx: &Ctx<'_>) -> i32 {
    ctx.px(ctx.lay.row.marker).max(2) + ctx.px(ctx.lay.row.padding)
}

fn gap_between(ctx: &Ctx<'_>, a: BlockKind, b: BlockKind) -> i32 {
    let s = &ctx.lay.spacing;
    ctx.px(match (a, b) {
        (BlockKind::Title, BlockKind::Para) => s.title,
        (BlockKind::Para, BlockKind::Para) => s.paragraph,
        (BlockKind::Label, BlockKind::Field) => s.paragraph / 2,
        (BlockKind::Field, BlockKind::Para) => s.paragraph + s.paragraph / 2,
        _ => s.block,
    })
}

// ---------------------------------------------------------------------------
// The layout

/// Build the draw list for `screen` at `w`×`h`. The list borrows labels
/// from `screen` and the typed text from `view.buf`.
pub fn layout<'a>(
    screen: &'a Screen,
    view: &View<'a>,
    theme: &Theme,
    w: u32,
    h: u32,
    list: &mut DrawList<'a>,
) {
    list.clear(w, h);
    let step = theme.step_for(w, h);
    let kind = kind(screen);
    let ctx = Ctx {
        theme,
        step,
        lay: theme.layout(kind),
        pal: theme.palette,
    };
    let (wi, hi) = (i32::try_from(w).unwrap_or(0), i32::try_from(h).unwrap_or(0));
    let full = Rect::new(0, 0, wi, hi);
    list.push(Cmd::Fill {
        r: full,
        radius: 0,
        color: ctx.pal.background,
    });
    let d = dims(&ctx);
    let spec = describe(screen, view, theme, list);
    let lay = ctx.lay;

    let my = ctx.px(lay.margin.0).min(hi / 8);
    let mx = ctx.px(lay.margin.1).min(wi / 8);
    let safe = Rect::new(mx, my, wi - 2 * mx, hi - 2 * my);
    // Everything placed so far, for the non-overlap rule.
    let mut taken: [Rect; 4] = [Rect::default(); 4];
    let mut n_taken = 0usize;
    let mut take = |r: Rect, taken: &mut [Rect; 4]| {
        if let Some(s) = taken.get_mut(n_taken) {
            *s = r;
            n_taken += 1;
        }
    };

    // Brand: logo and name.
    let brand_font = ctx.font(Style::Brand);
    let logo = lay
        .brand
        .logo
        .filter(|_| lay.show_logo)
        .and_then(|i| step.image(i));
    let name_src = compose(list, theme, Str::Brand, &[], 0);
    let name_w = if lay.show_name {
        list.as_str(&name_src)
            .map_or(0, |s| text::width(brand_font, s))
    } else {
        0
    };
    let gap = ctx.px(lay.brand.gap);
    let logo_w = logo.map_or(0, |i| i.w as i32);
    let logo_h = logo.map_or(0, |i| i.h as i32);
    let bw = logo_w
        + if logo.is_some() && lay.show_name {
            gap
        } else {
            0
        }
        + name_w;
    let bh = logo_h.max(if lay.show_name { line_h(brand_font) } else { 0 });
    let mut brand = Rect::default();
    if bw > 0 && bw <= safe.w {
        brand = place(
            &lay.brand.place,
            bw,
            bh,
            (
                ctx.px(lay.brand.place.offset.0),
                ctx.px(lay.brand.place.offset.1),
            ),
            safe,
        );
        if let Some(img) = logo {
            list.push(Cmd::Image {
                img,
                x: brand.x,
                y: brand.y + (bh - logo_h) / 2,
            });
        }
        if lay.show_name {
            let x = brand.x + logo_w + if logo.is_some() { gap } else { 0 };
            let lh = line_h(brand_font);
            line(
                list,
                &ctx,
                brand_font,
                name_src,
                ctx.pal.text,
                Rect::new(x, brand.y + (bh - lh) / 2, name_w, lh),
                Align::Left,
            );
        }
        take(brand, &mut taken);
    }

    // Unattested banner.
    let mut banner = Rect::default();
    if spec.unattested {
        let (py, px) = (ctx.px(lay.banner.padding.0), ctx.px(lay.banner.padding.1));
        let src = compose(list, theme, Str::Unattested, &[], 0);
        let tw = list.as_str(&src).map_or(0, |s| text::width(d.banner, s));
        let bw = (tw + 2 * px).min(safe.w);
        let bh = line_h(d.banner) + 2 * py;
        let off = (
            ctx.px(lay.banner.place.offset.0),
            ctx.px(lay.banner.place.offset.1),
        );
        let mut r = place(&lay.banner.place, bw, bh, off, safe);
        // Never over the brand: move away from it vertically.
        if r.intersects(&brand) {
            if lay.banner.place.anchor.v() == 0 {
                r.y = brand.bottom() + ctx.px(lay.spacing.paragraph);
            } else {
                r.y = brand.y - ctx.px(lay.spacing.paragraph) - bh;
            }
        }
        if safe.contains(&r) && !r.intersects(&brand) {
            list.push(Cmd::Fill {
                r,
                radius: ctx.px(lay.banner.radius),
                color: ctx.pal.banner_background,
            });
            line(
                list,
                &ctx,
                d.banner,
                src,
                ctx.pal.banner_text,
                Rect::new(r.x + px, r.y + py, r.w - 2 * px, bh - 2 * py),
                Align::Center,
            );
            banner = r;
            take(r, &mut taken);
        }
    }

    // Hints: keycap + label pairs, dropped from the end until they fit.
    if lay.show_hints {
        let hint_font = ctx.font(Style::Hint);
        let kpad = ctx.px(lay.keycap.padding);
        let kgap = ctx.px(lay.keycap.gap);
        let hgap = ctx.px(lay.hints.gap);
        let mut items: [(TextSrc<'a>, TextSrc<'a>, i32, i32); MAX_HINTS] =
            [(TextSrc::Str(""), TextSrc::Str(""), 0, 0); MAX_HINTS];
        let mut n = 0usize;
        for (k, l) in spec.hints.iter().flatten() {
            let ks = compose(list, theme, *k, &[], 0);
            let ls = compose(list, theme, *l, &[], 0);
            let (kw, _) = keycap_size(&ctx, &d, list, ks);
            let lw = list.as_str(&ls).map_or(0, |s| text::width(hint_font, s));
            if let Some(slot) = items.get_mut(n) {
                *slot = (ks, ls, kw, lw);
                n += 1;
            }
        }
        let total = |n: usize| -> i32 {
            items
                .iter()
                .take(n)
                .map(|(_, _, kw, lw)| kw + kgap + lw)
                .sum::<i32>()
                + hgap * (n as i32 - 1).max(0)
        };
        while n > 0 && total(n) > safe.w {
            n -= 1;
        }
        let kh = line_h(d.key) + kpad;
        let hh = kh.max(line_h(hint_font));
        if n > 0 {
            let off = (
                ctx.px(lay.hints.place.offset.0),
                ctx.px(lay.hints.place.offset.1),
            );
            let r = place(&lay.hints.place, total(n), hh, off, safe);
            if !r.intersects(&brand) && !r.intersects(&banner) {
                let mut x = r.x;
                for (ks, ls, kw, lw) in items.iter().take(n) {
                    let cap = Rect::new(x, r.y + (hh - kh) / 2, *kw, kh);
                    list.push(Cmd::Stroke {
                        r: cap,
                        radius: ctx.px(lay.keycap.radius),
                        width: ctx.px(lay.keycap.border).max(1),
                        color: ctx.pal.key_border,
                    });
                    line(
                        list,
                        &ctx,
                        d.key,
                        *ks,
                        ctx.pal.key_text,
                        Rect::new(cap.x + kpad, cap.y, (*kw - 2 * kpad).max(0), kh),
                        Align::Center,
                    );
                    x += kw + kgap;
                    let lh = line_h(hint_font);
                    line(
                        list,
                        &ctx,
                        hint_font,
                        *ls,
                        ctx.pal.muted,
                        Rect::new(x, r.y + (hh - lh) / 2, *lw, lh),
                        Align::Left,
                    );
                    x += lw + hgap;
                }
                take(r, &mut taken);
            }
        }
    }

    // The band left for content: below everything at the top, above
    // everything at the bottom.
    let block_gap = ctx.px(lay.spacing.block);
    let mut top = safe.y;
    let mut bottom = safe.bottom();
    for r in taken.iter().take(n_taken) {
        if r.y + r.h / 2 < hi / 2 {
            top = top.max(r.bottom() + block_gap);
        } else {
            bottom = bottom.min(r.y - block_gap);
        }
    }
    let cw = ctx.px(lay.content.max_width).min(safe.w);
    let band = Rect::new(safe.x, top, safe.w, (bottom - top).max(0));

    let items = ui::items(screen);
    let n_actions = spec.actions.iter().flatten().count();
    let fkind = view
        .field
        .map(|f| f.kind())
        .or_else(|| ui::field_kind(screen));
    let mut blocks = spec.blocks;
    let heights = |blocks: &[Option<Block<'a>>; MAX_BLOCKS], list: &DrawList<'a>| -> i32 {
        let mut total = 0;
        let mut prev: Option<BlockKind> = None;
        for b in blocks.iter().flatten() {
            if let Some(p) = prev {
                total += gap_between(&ctx, p, b.kind);
            }
            total += block_height(&ctx, &d, list, b, cw, items.len(), n_actions, fkind);
            prev = Some(b.kind);
        }
        total
    };
    // Shrink until it fits: paragraphs from the last, then the list, then
    // the title.
    let mut guard = 0;
    while heights(&blocks, list) > band.h && guard < 64 {
        guard += 1;
        let mut shrunk = false;
        for b in blocks.iter_mut().rev().flatten() {
            if b.kind == BlockKind::Para {
                let lines = list.as_str(&b.src).map_or(1, |s| {
                    text::count_lines(d.body, s, cw - if b.bar { bar_inset(&ctx) } else { 0 })
                });
                let cur = lines.min(b.max);
                if cur > 1 {
                    b.max = cur - 1;
                    shrunk = true;
                    break;
                }
            }
        }
        if shrunk {
            continue;
        }
        for b in blocks.iter_mut().flatten() {
            if b.kind == BlockKind::List {
                let cur = items.len().min(b.max);
                if cur > 1 {
                    b.max = cur - 1;
                    shrunk = true;
                    break;
                }
            }
        }
        if shrunk {
            continue;
        }
        for b in blocks.iter_mut().flatten() {
            if b.kind == BlockKind::Title && b.max > 1 {
                b.max = 1;
                shrunk = true;
                break;
            }
        }
        if !shrunk {
            // Drop the last paragraph altogether.
            if let Some(slot) = blocks
                .iter_mut()
                .rev()
                .find(|s| s.is_some_and(|b| b.kind == BlockKind::Para))
            {
                *slot = None;
                continue;
            }
            break;
        }
    }
    let total = heights(&blocks, list).min(band.h);
    let off = (
        ctx.px(lay.content.place.offset.0),
        ctx.px(lay.content.place.offset.1),
    );
    let col = place(&lay.content.place, cw, total, off, band);

    // Draw the blocks top to bottom; whatever would cross the band's
    // bottom is left out.
    let mut y = col.y;
    let mut prev: Option<BlockKind> = None;
    for b in blocks.iter().flatten() {
        if let Some(p) = prev {
            y += gap_between(&ctx, p, b.kind);
        }
        let bh = block_height(&ctx, &d, list, b, cw, items.len(), n_actions, fkind);
        if y + bh > band.bottom() {
            break;
        }
        let r = Rect::new(col.x, y, cw, bh);
        match b.kind {
            BlockKind::Toast => draw_toast(list, &ctx, &d, b, r),
            BlockKind::Title => draw_para(list, &ctx, d.title, b, r, lay.content.align),
            BlockKind::Para => draw_para(list, &ctx, d.body, b, r, lay.content.align),
            BlockKind::Label => {
                line(list, &ctx, d.detail, b.src, b.color, r, lay.content.align);
            }
            BlockKind::List => draw_list(list, &ctx, &d, screen, view, &items, b.max, r),
            BlockKind::Field => {
                if let Some(f) = view.field {
                    draw_field(list, &ctx, &d, &f, view.buf, r, cw);
                } else if let Some(k) = fkind {
                    let f = Field::begin(k, &mut []);
                    draw_field(list, &ctx, &d, &f, &[], r, cw);
                }
            }
            BlockKind::Actions => draw_actions(list, &ctx, &d, &spec.actions, b.max, r),
        }
        y += bh;
        prev = Some(b.kind);
    }

    // Decorations: only where they overlap nothing.
    let content_r = Rect::new(col.x, col.y, cw, (y - col.y).max(0));
    for deco in lay.decorations {
        let Some(img) = step.image(deco.image) else {
            continue;
        };
        let off = (ctx.px(deco.place.offset.0), ctx.px(deco.place.offset.1));
        let r = place(&deco.place, img.w as i32, img.h as i32, off, safe);
        let clear =
            !r.intersects(&content_r) && taken.iter().take(n_taken).all(|t| !t.intersects(&r));
        if clear && full.contains(&r) && r.w == img.w as i32 && r.h == img.h as i32 {
            list.push(Cmd::Image {
                img,
                x: r.x,
                y: r.y,
            });
        }
    }
}

fn draw_toast<'a>(list: &mut DrawList<'a>, ctx: &Ctx<'_>, d: &Dims, b: &Block<'a>, r: Rect) {
    let (py, px) = (
        ctx.px(ctx.lay.toast.padding.0),
        ctx.px(ctx.lay.toast.padding.1),
    );
    list.push(Cmd::Fill {
        r,
        radius: ctx.px(ctx.lay.toast.radius),
        color: ctx.pal.toast_background,
    });
    line(
        list,
        ctx,
        d.banner,
        b.src,
        b.color,
        Rect::new(r.x + px, r.y + py, r.w - 2 * px, r.h - 2 * py),
        Align::Left,
    );
}

fn draw_para<'a>(
    list: &mut DrawList<'a>,
    ctx: &Ctx<'_>,
    font: &'static Font,
    b: &Block<'a>,
    r: Rect,
    align: Align,
) {
    let lh = line_h(font);
    let mut x = r.x;
    let mut w = r.w;
    if b.bar {
        let bar = ctx.px(ctx.lay.row.marker).max(2);
        list.push(Cmd::Fill {
            r: Rect::new(r.x, r.y, bar, r.h),
            radius: bar / 2,
            color: ctx.pal.accent,
        });
        x += bar_inset(ctx);
        w -= bar_inset(ctx);
    }
    let Some(s) = list.as_str(&b.src) else {
        return;
    };
    let max_lines = (r.h / lh).max(0) as usize;
    let full_len = s.len();
    let mut rest_off = 0usize;
    for i in 0..max_lines {
        // (start of the line, its length, what is left after it)
        let (start, len, after_len) = {
            let Some(s) = list.as_str(&b.src) else {
                return;
            };
            let rest = s.get(rest_off..).unwrap_or("");
            let (ln, after) = text::next_line(font, rest, w);
            if ln.is_empty() {
                break;
            }
            let start = full_len - rest.trim_start_matches(' ').len();
            (start, ln.len(), after.trim_start_matches(' ').len())
        };
        let last = i + 1 == max_lines;
        // The last allowed line takes everything left, cut with an ellipsis.
        let take = if last { full_len - start } else { len };
        let src = list.prefix(&list.suffix(&b.src, start), take);
        line(
            list,
            ctx,
            font,
            src,
            b.color,
            Rect::new(x, r.y + i as i32 * lh, w, lh),
            align,
        );
        if after_len == 0 {
            break;
        }
        rest_off = full_len - after_len;
    }
}

#[allow(clippy::too_many_arguments)]
fn draw_list<'a>(
    list: &mut DrawList<'a>,
    ctx: &Ctx<'_>,
    d: &Dims,
    screen: &'a Screen,
    view: &View<'a>,
    items: &ui::Items,
    visible: usize,
    r: Rect,
) {
    let n = items.len();
    let visible = visible.min(n).max(1);
    let sel = view.selected.min(n.saturating_sub(1));
    let first = sel
        .saturating_sub(visible - 1)
        .min(n.saturating_sub(visible));
    let lay = ctx.lay;
    let pad = ctx.px(lay.row.padding);
    let marker = ctx.px(lay.row.marker);
    for (k, idx) in (first..(first + visible).min(n)).enumerate() {
        let Some(item) = items.get(idx) else {
            break;
        };
        let rr = Rect::new(r.x, r.y + k as i32 * (d.row_h + d.row_gap), r.w, d.row_h);
        let selected = idx == sel && item.enabled();
        let radius = ctx.px(lay.row.radius);
        list.push(Cmd::Fill {
            r: rr,
            radius,
            color: if selected {
                ctx.pal.surface_selected
            } else {
                ctx.pal.surface
            },
        });
        let mut inner_x = rr.x + pad;
        if selected {
            match ctx.theme.options.selection {
                Selection::Bar => {
                    let m = marker.max(2);
                    let inset = (d.row_h / 4).max(1);
                    list.push(Cmd::Fill {
                        r: Rect::new(rr.x + m, rr.y + inset, m, rr.h - 2 * inset),
                        radius: m / 2,
                        color: ctx.pal.accent,
                    });
                    inner_x = inner_x.max(rr.x + 2 * m + pad / 2);
                }
                Selection::Outline => list.push(Cmd::Stroke {
                    r: rr,
                    radius,
                    width: marker.max(1),
                    color: ctx.pal.accent,
                }),
                Selection::Fill => {}
            }
        }
        let inner_w = rr.right() - pad - inner_x;
        let (label, detail) = row_texts(screen, item, ctx.theme, list);
        let enabled = item.enabled();
        let (lc, dc) = if enabled {
            (ctx.pal.text, ctx.pal.muted)
        } else {
            (ctx.pal.faint, ctx.pal.faint)
        };
        // Both at their natural width when they fit; otherwise a short
        // label keeps its width and the detail is cut, or the detail keeps
        // up to 45% and the label is cut.
        let dw_nat = list.as_str(&detail).map_or(0, |s| text::width(d.detail, s));
        let lw_nat = list.as_str(&label).map_or(0, |s| text::width(d.label, s));
        let lgap = if dw_nat > 0 { pad } else { 0 };
        let dw = if lw_nat + lgap + dw_nat <= inner_w {
            dw_nat
        } else if lw_nat <= inner_w * 55 / 100 {
            (inner_w - lw_nat - lgap).max(0)
        } else {
            dw_nat.min(inner_w * 45 / 100)
        };
        let lw = (inner_w - dw - lgap).max(0);
        let lh = line_h(d.label);
        line(
            list,
            ctx,
            d.label,
            label,
            lc,
            Rect::new(inner_x, rr.y + (rr.h - lh) / 2, lw, lh),
            Align::Left,
        );
        if dw > 0 {
            let dh = line_h(d.detail);
            line(
                list,
                ctx,
                d.detail,
                detail,
                dc,
                Rect::new(inner_x + lw + lgap, rr.y + (rr.h - dh) / 2, dw, dh),
                Align::Right,
            );
        }
    }
}

fn draw_actions<'a>(
    list: &mut DrawList<'a>,
    ctx: &Ctx<'_>,
    d: &Dims,
    actions: &[Option<(Str, Str)>; MAX_ACTIONS],
    max: usize,
    r: Rect,
) {
    let kpad = ctx.px(ctx.lay.keycap.padding);
    let one = line_h(d.label).max(line_h(d.key) + kpad);
    // Keycaps share one width so the labels line up.
    let mut kw = 0;
    let mut srcs = [(TextSrc::Str(""), TextSrc::Str("")); MAX_ACTIONS];
    let mut n = 0usize;
    for (k, l) in actions.iter().flatten().take(max) {
        let ks = compose(list, ctx.theme, *k, &[], 0);
        let ls = compose(list, ctx.theme, *l, &[], 0);
        kw = kw.max(keycap_size(ctx, d, list, ks).0);
        if let Some(s) = srcs.get_mut(n) {
            *s = (ks, ls);
            n += 1;
        }
    }
    let kh = line_h(d.key) + kpad;
    let gap = ctx.px(ctx.lay.keycap.gap) * 2;
    kw = kw.min(r.w / 3);
    for (i, (ks, ls)) in srcs.iter().take(n).enumerate() {
        let y = r.y + i as i32 * (one + d.row_gap);
        let cap = Rect::new(r.x, y + (one - kh) / 2, kw, kh);
        list.push(Cmd::Stroke {
            r: cap,
            radius: ctx.px(ctx.lay.keycap.radius),
            width: ctx.px(ctx.lay.keycap.border).max(1),
            color: ctx.pal.key_border,
        });
        line(
            list,
            ctx,
            d.key,
            *ks,
            ctx.pal.key_text,
            Rect::new(cap.x + kpad, cap.y, (kw - 2 * kpad).max(0), kh),
            Align::Center,
        );
        let lh = line_h(d.label);
        line(
            list,
            ctx,
            d.label,
            *ls,
            ctx.pal.text,
            Rect::new(
                r.x + kw + gap,
                y + (one - lh) / 2,
                (r.w - kw - gap).max(0),
                lh,
            ),
            Align::Left,
        );
    }
}

fn draw_field<'a>(
    list: &mut DrawList<'a>,
    ctx: &Ctx<'_>,
    d: &Dims,
    f: &Field,
    buf: &'a [u8],
    r: Rect,
    cw: i32,
) {
    let lay = &ctx.lay.field;
    let border = ctx.px(lay.border).max(1);
    let radius = ctx.px(lay.radius);
    let cursor_w = ctx.px(lay.cursor).max(1);
    let font = d.field;
    let lh = line_h(font);
    let text = f.text(buf);
    let (before, total) = f.char_counts(buf);
    let bullet = ctx.theme.options.bullet;
    if f.kind() == FieldKind::RecoveryKey {
        let (per, gw, slot) = key_grid(ctx, d, cw);
        let gap = ctx.px(lay.group_gap);
        let pad = (gw - slot * RECOVERY_GROUP as i32) / 2;
        let active = (before / RECOVERY_GROUP).min(RECOVERY_DIGITS / RECOVERY_GROUP - 1);
        let mut digits = text.char_indices();
        for g in 0..(RECOVERY_DIGITS / RECOVERY_GROUP) {
            let (row, colm) = ((g as i32) / per, (g as i32) % per);
            let gr = Rect::new(
                r.x + colm * (gw + gap),
                r.y + row * (d.field_h + gap),
                gw,
                d.field_h,
            );
            list.push(Cmd::Fill {
                r: gr,
                radius,
                color: ctx.pal.surface,
            });
            list.push(Cmd::Stroke {
                r: gr,
                radius,
                width: border,
                color: if g == active {
                    ctx.pal.border_focus
                } else {
                    ctx.pal.border
                },
            });
            for j in 0..RECOVERY_GROUP {
                let k = g * RECOVERY_GROUP + j;
                let sr = Rect::new(
                    gr.x + pad + j as i32 * slot,
                    gr.y + (gr.h - lh) / 2,
                    slot,
                    lh,
                );
                if k < total {
                    let src = match digits.next() {
                        Some((i, c)) if f.revealed() => {
                            TextSrc::Str(text.get(i..i + c.len_utf8()).unwrap_or(""))
                        }
                        _ => TextSrc::Repeat(bullet, 1),
                    };
                    line(list, ctx, font, src, ctx.pal.text, sr, Align::Center);
                } else {
                    line(
                        list,
                        ctx,
                        font,
                        TextSrc::Str("·"),
                        ctx.pal.faint,
                        sr,
                        Align::Center,
                    );
                }
                if k == before && k < RECOVERY_DIGITS {
                    list.push(Cmd::Fill {
                        r: Rect::new(sr.x - cursor_w / 2, sr.y, cursor_w, lh),
                        radius: 0,
                        color: ctx.pal.cursor,
                    });
                }
            }
            if before == RECOVERY_DIGITS && g + 1 == RECOVERY_DIGITS / RECOVERY_GROUP {
                list.push(Cmd::Fill {
                    r: Rect::new(gr.right() - pad, gr.y + (gr.h - lh) / 2, cursor_w, lh),
                    radius: 0,
                    color: ctx.pal.cursor,
                });
            }
        }
        return;
    }
    list.push(Cmd::Fill {
        r,
        radius,
        color: ctx.pal.surface,
    });
    list.push(Cmd::Stroke {
        r,
        radius,
        width: border,
        color: ctx.pal.border_focus,
    });
    let pad = ctx.px(lay.padding);
    let area = Rect::new(
        r.x + pad,
        r.y + (r.h - lh) / 2,
        r.w - 2 * pad - cursor_w,
        lh,
    );
    if area.is_empty() {
        return;
    }
    // A window of the text that keeps the cursor visible.
    let (src, cur_x) = if f.revealed() {
        let cur_byte = f.cursor();
        let mut start = 0usize;
        while text::width(font, text.get(start..cur_byte).unwrap_or("")) > area.w {
            match text.get(start..).and_then(|s| s.chars().next()) {
                Some(c) => start += c.len_utf8(),
                None => break,
            }
        }
        let shown = text.get(start..).unwrap_or("");
        let mut m = text::Measure::new(font);
        let mut end = 0usize;
        for (i, c) in shown.char_indices() {
            m.push(c);
            if m.width() > area.w {
                break;
            }
            end = i + c.len_utf8();
        }
        let src = TextSrc::Str(shown.get(..end).unwrap_or(""));
        let cx = text::width(font, text.get(start..cur_byte).unwrap_or(""));
        (src, cx)
    } else {
        let bw = text::char_width(font, bullet).max(1);
        let fit = (area.w / bw).max(0) as usize;
        let start = before.saturating_sub(fit);
        let shown = (total - start).min(fit);
        let (l, rr) = text::extent(font, core::iter::repeat_n(bullet, before - start));
        (TextSrc::Repeat(bullet, shown), rr - l)
    };
    let (l, _) = text::extent(font, list.chars(&src));
    list.push(Cmd::Text(TextRun {
        x: area.x - l,
        baseline: area.y + (lh - (font.ascent - font.descent)) / 2 + font.ascent,
        font,
        color: ctx.pal.text,
        src,
        ellipsis: None,
        bounds: area,
    }));
    list.push(Cmd::Fill {
        r: Rect::new(area.x + cur_x.min(area.w), area.y, cursor_w, lh),
        radius: 0,
        color: ctx.pal.cursor,
    });
}
