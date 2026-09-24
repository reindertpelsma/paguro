//! The prompt loop the firmware adapter runs (INTERFACES.md §13.2, §13.2a,
//! §13.2b, §13.5): show a screen on every output, take input from every
//! console, feed it to [`paguro_boot::ui::Prompt`] / [`Browser`], redraw,
//! return the [`Input`]. Everything here is exercised on the host through
//! the [`Frontend`] trait (a memory "GOP", ConOut and serial port in the
//! tests; the firmware in `paguro-efi`).
//!
//! What is drawn where:
//!
//! | local display  | graphics frames (GOP)                 | ConOut        | serial mirror |
//! |----------------|---------------------------------------|---------------|---------------|
//! | graphics       | the graphical UI, cursor on frame 0   | untouched     | text UI       |
//! | text (F3/text) | text UI painted where ConOut is absent| text UI       | text UI       |
//! | no GOP         | —                                     | text UI       | —             |
//!
//! The serial mirror exists only when the adapter offers it (`auto` mode
//! with graphics: the loader owns the ports). Input from every console is
//! accepted at once; firmware keyboard input goes through the chosen
//! keyboard layout ([`paguro_boot::keymap`]), serial input does not.

use paguro_boot::keymap::{self, Keyboard, Purpose, Typed};
use paguro_boot::platform::{DirView, Input, Screen};
use paguro_boot::ui::{self, Browser, FieldKind, Key, Prompt, Reaction};
use paguro_core::config::{Ui, UiMode, UiTheme};

use crate::builtin::BY_LANG;
use crate::canvas::{Canvas, Rect};
use crate::draw::{DrawList, Hits, Target, paint};
use crate::layout::{Toast, View, layout};
use crate::pointer::{Cursor, Pointer, Report};
use crate::strings::Str;
use crate::textui::{self, Grid};
use crate::theme::Theme;

/// One input event, from any console.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// A decoded key: firmware special keys, or anything from a serial
    /// terminal (already in the terminal's layout).
    Key(Key),
    /// A printable key from the firmware keyboard, US-mapped: goes through
    /// the chosen layout.
    Typed(Typed),
    /// A pointer report.
    Pointer(Report),
}

/// Somewhere the text UI is shown.
pub trait TextSink {
    /// Show `grid`. `full`: a new screen (redraw everything); otherwise the
    /// sink may redraw only what changed since its last `show`.
    fn show(&mut self, grid: &Grid, full: bool);
}

/// The outputs and inputs the loop drives.
pub trait Frontend {
    /// Graphics frames: one per distinct display resolution; 0 without GOP.
    fn frames(&self) -> usize;
    /// Frame `i`'s size in pixels.
    fn frame_size(&self, i: usize) -> (u32, u32);
    /// Frame `i`: `width × height` BGRA pixels, rows packed.
    fn frame(&mut self, i: usize) -> &mut [u8];
    /// Show rectangle `r` of frame `i` on the displays that show it — in
    /// text mode only those the firmware text console does not cover —
    /// with `cursor` over it on the pointer's display (frame 0's first).
    fn present(&mut self, i: usize, r: Rect, cursor: Option<&Cursor>);
    /// Every display of frame `i` is covered by the firmware text console
    /// (ConOut): in text mode the loader draws nothing there itself.
    fn covered(&self, i: usize) -> bool;
    /// The firmware text console: the text UI in text mode, and everything
    /// without GOP.
    fn console(&mut self) -> Option<&mut dyn TextSink>;
    /// Serial consoles mirrored beside graphics (`auto`).
    fn serial(&mut self) -> Option<&mut dyn TextSink>;
    /// The local display switches between graphics (`false`) and text.
    fn set_text(&mut self, text: bool) {
        let _ = text;
    }
    /// The next input event (blocks).
    fn next_event(&mut self) -> Event;
    /// A screen is about to be shown (the adapter logs its name).
    fn shown(&mut self, screen: &Screen) {
        let _ = screen;
    }
}

/// What persists across prompts for the whole boot: the variant, language
/// and layout (F2, F5, F4, or the configuration's `[UI]`), graphics or
/// text, a message carried to the next screen, the pointer.
#[derive(Clone, Debug)]
pub struct Session {
    /// Index into the variants (`UiTheme::ALL` order).
    pub theme: usize,
    /// Index into [`crate::builtin::LANGS`].
    pub lang: usize,
    pub keyboard: Keyboard,
    /// The configured mode.
    pub mode: UiMode,
    /// The local display shows the text UI.
    pub text: bool,
    pub toast: Option<Toast>,
    /// A character typed in the browser that opened the path field.
    pub carry: Option<char>,
    pub pointer: Pointer,
    grid: Grid,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    pub const fn new() -> Self {
        Session {
            theme: 0,
            lang: 0,
            keyboard: Keyboard::Us,
            mode: UiMode::Auto,
            text: false,
            toast: None,
            carry: None,
            pointer: Pointer::new(),
            grid: Grid::new(),
        }
    }

    /// Apply the configuration's `[UI]` (or the defaults, for recovery).
    pub fn apply(&mut self, ui: Ui) {
        self.theme = UiTheme::ALL
            .iter()
            .position(|t| *t == ui.theme)
            .unwrap_or(0);
        self.mode = ui.mode;
        self.text = ui.mode == UiMode::Text;
        self.keyboard = ui.keyboard;
    }

    /// The theme in use.
    pub fn look(&self) -> &'static Theme {
        let lang = BY_LANG.get(self.lang).or_else(|| BY_LANG.first());
        match lang.and_then(|l| l.get(self.theme).or_else(|| l.first())) {
            Some(t) => t,
            None => &crate::builtin::THEMES[0],
        }
    }
}

fn toast_for(screen: &Screen) -> Option<Toast> {
    match screen {
        Screen::Incorrect => Some(Toast::Incorrect),
        Screen::PathRefused => Some(Toast::PathRefused),
        Screen::NoEfiPartition => Some(Toast::NoEfiPartition),
        _ => None,
    }
}

/// The graphics are what the local display shows.
fn graphics<F: Frontend>(fe: &F, s: &Session) -> bool {
    fe.frames() > 0 && !s.text
}

fn full(w: u32, h: u32) -> Rect {
    Rect::new(
        0,
        0,
        i32::try_from(w).unwrap_or(0),
        i32::try_from(h).unwrap_or(0),
    )
}

fn cursor(s: &Session, theme: &Theme, w: u32, h: u32) -> Option<Cursor> {
    let img = theme.step_for(w, h).image(theme.options.pointer)?;
    let (x, y) = s.pointer.position();
    s.pointer.visible().then_some(Cursor { img, x, y })
}

/// Draw `view` of `screen` everywhere. Returns the rows the list shows
/// at once and what a click on frame 0 hits.
fn draw_all<F: Frontend>(
    fe: &mut F,
    s: &mut Session,
    screen: &Screen,
    view: &View<'_>,
    fresh: bool,
) -> (usize, Hits) {
    let theme = s.look();
    let mut list = DrawList::new();
    let mut page = 1;
    let mut hits = Hits::new();
    if graphics(fe, s) {
        // Frame 0 last: its list holds the hits.
        for i in (0..fe.frames()).rev() {
            let (w, h) = fe.frame_size(i);
            layout(screen, view, theme, w, h, &mut list);
            if let Some(mut c) = Canvas::new(fe.frame(i), w, h, w) {
                paint(&list, &mut c);
            }
            if i == 0 {
                s.pointer.set_bounds(w, h);
                if let Some(img) = theme.step_for(w, h).image(theme.options.pointer) {
                    s.pointer.set_image(img);
                }
                page = list.page;
                hits = list.hits;
            }
            let c = if i == 0 { cursor(s, theme, w, h) } else { None };
            fe.present(i, full(w, h), c.as_ref());
        }
    } else {
        let opts = textui::Opts {
            mode_hint: (fe.frames() > 0).then_some(Str::HintGraphics),
        };
        page = textui::render(screen, view, theme, &opts, &mut list, &mut s.grid);
        if let Some(c) = fe.console() {
            c.show(&s.grid, fresh);
        }
        for i in 0..fe.frames() {
            if fe.covered(i) {
                continue;
            }
            let (w, h) = fe.frame_size(i);
            if let Some(mut c) = Canvas::new(fe.frame(i), w, h, w) {
                textui::paint_grid(&s.grid, theme, &mut c);
            }
            fe.present(i, full(w, h), None);
        }
    }
    if fe.serial().is_some() {
        let opts = textui::Opts { mode_hint: None };
        let p = textui::render(screen, view, theme, &opts, &mut list, &mut s.grid);
        if let Some(sr) = fe.serial() {
            sr.show(&s.grid, fresh);
        }
        if fe.frames() == 0 {
            page = p;
        }
    }
    (page, hits)
}

/// The interaction state of one prompt.
enum Ctl<'d> {
    Prompt(Prompt),
    Browse(Browser, &'d DirView<'d>),
}

impl Ctl<'_> {
    fn selected(&self) -> usize {
        match self {
            Ctl::Prompt(p) => p.selected(),
            Ctl::Browse(b, _) => b.selected(),
        }
    }
    fn set_page(&mut self, n: usize) {
        match self {
            Ctl::Prompt(p) => p.set_page(n),
            Ctl::Browse(b, _) => b.set_page(n),
        }
    }
    fn field_kind(&self) -> Option<FieldKind> {
        match self {
            Ctl::Prompt(p) => p.field().map(|f| f.kind()),
            Ctl::Browse(..) => None,
        }
    }
    fn feed(&mut self, screen: &Screen, key: Key, buf: &mut [u8]) -> Reaction {
        match self {
            Ctl::Prompt(p) => p.feed(screen, key, buf),
            Ctl::Browse(b, d) => b.feed(d, key),
        }
    }
    fn activate(&mut self, screen: &Screen, i: usize) -> Reaction {
        match self {
            Ctl::Prompt(p) => p.activate(screen, i),
            Ctl::Browse(b, d) => b.activate(d, i),
        }
    }
    fn click_field(&mut self, chars: usize, buf: &[u8]) -> Reaction {
        match self {
            Ctl::Prompt(p) => p.click_field(chars, buf),
            Ctl::Browse(..) => Reaction::Ignore,
        }
    }
}

/// Show `screen` and wait for an action (the graphical
/// [`Platform::prompt`](paguro_boot::Platform::prompt)).
pub fn prompt<F: Frontend>(
    fe: &mut F,
    s: &mut Session,
    screen: &Screen,
    secret: &mut [u8],
) -> Input {
    fe.shown(screen);
    if !ui::needs_key(screen) {
        // Shown on the next screen instead, without costing a keystroke.
        s.toast = toast_for(screen);
        return Input::Continue;
    }
    let mut p = Prompt::new(screen, secret);
    if let Some(c) = s.carry.take() {
        if p.field().is_some_and(|f| f.kind() == FieldKind::Path) {
            let _ = p.feed(screen, Key::Char(c), secret);
        }
    }
    run(fe, s, screen, Ctl::Prompt(p), secret, None, false)
}

/// The recovery browser (the graphical
/// [`Platform::prompt_browse`](paguro_boot::Platform::prompt_browse)).
pub fn prompt_browse<F: Frontend>(
    fe: &mut F,
    s: &mut Session,
    screen: &Screen,
    dir: &DirView<'_>,
) -> Input {
    fe.shown(screen);
    let b = Browser::new(dir);
    run(
        fe,
        s,
        screen,
        Ctl::Browse(b, dir),
        &mut [],
        Some(dir),
        false,
    )
}

/// The layout (F4) or language (F5) list over the current prompt; the new
/// choice, or `None` after Esc.
fn choose<F: Frontend>(fe: &mut F, s: &mut Session, keyboard: bool) -> Option<usize> {
    let screen = if keyboard {
        Screen::ChooseKeyboard {
            current: s.keyboard,
        }
    } else {
        Screen::ChooseLanguage {
            current: u8::try_from(s.lang).unwrap_or(0),
            count: u8::try_from(BY_LANG.len()).unwrap_or(u8::MAX),
        }
    };
    fe.shown(&screen);
    let p = Prompt::new(&screen, &mut []);
    match run(fe, s, &screen, Ctl::Prompt(p), &mut [], None, true) {
        Input::Choose(i) => Some(usize::from(i)),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn run<F: Frontend>(
    fe: &mut F,
    s: &mut Session,
    screen: &Screen,
    mut ctl: Ctl<'_>,
    secret: &mut [u8],
    dir: Option<&DirView<'_>>,
    nested: bool,
) -> Input {
    let mut toast = if nested { None } else { s.toast.take() };
    let mut fresh = true;
    loop {
        let (page, hits) = {
            let view = View {
                selected: ctl.selected(),
                field: match &ctl {
                    Ctl::Prompt(p) => p.field().copied(),
                    Ctl::Browse(..) => None,
                },
                buf: secret,
                toast,
                dir: dir.copied(),
                keyboard: s.keyboard,
            };
            draw_all(fe, s, screen, &view, fresh)
        };
        fresh = false;
        ctl.set_page(page);
        loop {
            let (r, key) = match fe.next_event() {
                Event::Key(k) => {
                    hide_pointer(fe, s);
                    (ctl.feed(screen, k, secret), Some(k))
                }
                Event::Typed(t) => {
                    hide_pointer(fe, s);
                    let purpose = match ctl.field_kind() {
                        Some(FieldKind::Secret | FieldKind::Path) => Purpose::Text,
                        _ => Purpose::Digits,
                    };
                    match keymap::remap(s.keyboard, t, purpose) {
                        Some(c) => (ctl.feed(screen, Key::Char(c), secret), Some(Key::Char(c))),
                        None => (Reaction::Ignore, None),
                    }
                }
                Event::Pointer(rep) => (pointer(fe, s, screen, &mut ctl, &hits, rep, secret), None),
            };
            let had_toast = toast.take().is_some();
            match r {
                Reaction::Redraw => break,
                Reaction::Ignore if had_toast => break,
                Reaction::Ignore => {}
                Reaction::NextTheme => {
                    s.theme = (s.theme + 1) % UiTheme::ALL.len();
                    break;
                }
                Reaction::ToggleMode => {
                    if fe.frames() > 0 {
                        s.text = !s.text;
                        s.pointer.hide();
                        fe.set_text(s.text);
                        fresh = true;
                    }
                    break;
                }
                Reaction::ChooseKeyboard | Reaction::ChooseLanguage if !nested => {
                    let kb = r == Reaction::ChooseKeyboard;
                    if let Some(i) = choose(fe, s, kb) {
                        if kb {
                            s.keyboard = Keyboard::ALL.get(i).copied().unwrap_or(s.keyboard);
                        } else if i < BY_LANG.len() {
                            s.lang = i;
                        }
                    }
                    fresh = true;
                    break;
                }
                Reaction::ChooseKeyboard | Reaction::ChooseLanguage => {}
                Reaction::Done(input) => {
                    if input == Input::TypePath && matches!(key, Some(Key::Char('/' | '\\'))) {
                        // The path field starts with what was typed.
                        s.carry = Some('\\');
                    }
                    if ctl.field_kind().is_some() {
                        // Leave no typed text on the screen behind us.
                        let view = View {
                            selected: 0,
                            field: None,
                            buf: &[],
                            toast: None,
                            dir: None,
                            keyboard: s.keyboard,
                        };
                        draw_all(fe, s, screen, &view, false);
                    }
                    return input;
                }
            }
        }
    }
}

/// A key was pressed: the cursor goes (its rectangle is redrawn).
fn hide_pointer<F: Frontend>(fe: &mut F, s: &mut Session) {
    if let Some(r) = s.pointer.hide() {
        if graphics(fe, s) {
            fe.present(0, r, None);
        }
    }
}

/// One pointer report: move the cursor (redrawing only its old and new
/// rectangles), scroll with the wheel, act on a click.
#[allow(clippy::too_many_arguments)]
fn pointer<F: Frontend>(
    fe: &mut F,
    s: &mut Session,
    screen: &Screen,
    ctl: &mut Ctl<'_>,
    hits: &Hits,
    rep: Report,
    secret: &mut [u8],
) -> Reaction {
    if !graphics(fe, s) {
        // Text mode: no cursor, no targets.
        return Reaction::Ignore;
    }
    let u = s.pointer.report(rep);
    let theme = s.look();
    let (w, h) = fe.frame_size(0);
    let c = cursor(s, theme, w, h);
    for r in u.dirty.into_iter().flatten() {
        fe.present(0, r, c.as_ref());
    }
    if u.wheel != 0 {
        let key = if u.wheel > 0 { Key::Down } else { Key::Up };
        let mut out = Reaction::Ignore;
        for _ in 0..u.wheel.unsigned_abs() {
            match ctl.feed(screen, key, secret) {
                Reaction::Redraw => out = Reaction::Redraw,
                Reaction::Ignore => {}
                other => return other,
            }
        }
        return out;
    }
    let Some((x, y)) = u.click else {
        return Reaction::Ignore;
    };
    match hits.at(x, y) {
        Some(Target::Row(i)) => ctl.activate(screen, i),
        Some(Target::Field) => match hits.char_at(x, y) {
            Some(n) => ctl.click_field(n, secret),
            None => Reaction::Ignore,
        },
        Some(Target::Key(k)) => ctl.feed(screen, k, secret),
        None => Reaction::Ignore,
    }
}
