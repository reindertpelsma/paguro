//! The prompt loops the firmware adapter runs: show a screen, feed keys to
//! [`paguro_boot::ui::Prompt`], redraw, return the [`Input`]. The graphical
//! loop draws through a [`Display`]; the text loop writes to a [`Console`]
//! (no GOP, or a mode below 640×480). Both are exercised on the host.

use core::fmt::Write;

use paguro_boot::platform::{Input, Screen};
use paguro_boot::ui::{self, Key, Prompt, Reaction};

use crate::builtin::THEMES;
use crate::canvas::Canvas;
use crate::draw::{DrawList, paint};
use crate::layout::{Toast, View, layout};

/// A frame buffer the loop draws into and a keyboard.
pub trait Display {
    /// Frame size in pixels.
    fn size(&self) -> (u32, u32);
    /// The frame to draw into: `width × height` BGRA pixels, rows packed.
    fn frame(&mut self) -> &mut [u8];
    /// Show the frame (GOP: blit it).
    fn present(&mut self);
    fn read_key(&mut self) -> Key;
    /// A text copy of each new screen (the serial log in QEMU). Never gets
    /// the field's contents.
    fn mirror(&mut self, screen: &Screen) {
        let _ = screen;
    }
}

/// What persists across prompts: the chosen theme variant and a message
/// carried to the next screen.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Session {
    pub theme: usize,
    pub toast: Option<Toast>,
}

impl Session {
    pub const fn new() -> Self {
        Session {
            theme: 0,
            toast: None,
        }
    }
}

fn toast_for(screen: &Screen) -> Option<Toast> {
    match screen {
        Screen::Incorrect => Some(Toast::Incorrect),
        Screen::PathRefused => Some(Toast::PathRefused),
        _ => None,
    }
}

fn draw<D: Display>(d: &mut D, s: &Session, screen: &Screen, view: &View<'_>) {
    let (w, h) = d.size();
    let theme = THEMES.get(s.theme).unwrap_or(&THEMES[0]);
    let mut list = DrawList::new();
    layout(screen, view, theme, w, h, &mut list);
    if let Some(mut c) = Canvas::new(d.frame(), w, h, w) {
        paint(&list, &mut c);
    }
    d.present();
}

/// Show `screen` and wait for an action (the graphical
/// [`Platform::prompt`](paguro_boot::Platform::prompt)).
pub fn prompt<D: Display>(d: &mut D, s: &mut Session, screen: &Screen, secret: &mut [u8]) -> Input {
    if !ui::needs_key(screen) {
        // Shown on the next screen instead, without costing a keystroke.
        s.toast = toast_for(screen);
        return Input::Continue;
    }
    d.mirror(screen);
    let mut p = Prompt::new(screen, secret);
    let mut toast = s.toast.take();
    loop {
        let view = View {
            selected: p.selected(),
            field: p.field().copied(),
            buf: secret,
            toast,
        };
        draw(d, s, screen, &view);
        loop {
            let key = d.read_key();
            let r = p.feed(screen, key, secret);
            let had_toast = toast.take().is_some();
            match r {
                Reaction::Redraw => break,
                Reaction::Ignore if had_toast => break,
                Reaction::Ignore => {}
                Reaction::NextTheme => {
                    s.theme = (s.theme + 1) % THEMES.len().max(1);
                    break;
                }
                Reaction::Done(input) => {
                    if p.field().is_some() {
                        // Leave no typed text on the screen behind us.
                        let view = View {
                            selected: 0,
                            field: None,
                            buf: &[],
                            toast: None,
                        };
                        draw(d, s, screen, &view);
                    }
                    return input;
                }
            }
        }
    }
}

/// A text console and a keyboard.
pub trait Console {
    fn write_str(&mut self, s: &str);
    fn read_key(&mut self) -> Key;
}

struct W<'c, C: Console>(&'c mut C);

impl<C: Console> Write for W<'_, C> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.0.write_str(s);
        Ok(())
    }
}

/// The text-console prompt (no graphics output).
pub fn prompt_text<C: Console>(c: &mut C, screen: &Screen, secret: &mut [u8]) -> Input {
    let _ = ui::render(screen, &mut W(c));
    if !ui::needs_key(screen) {
        return Input::Continue;
    }
    let mut p = Prompt::new(screen, secret);
    loop {
        let key = c.read_key();
        match p.feed(screen, key, secret) {
            Reaction::Redraw => {
                if let Some(f) = p.field() {
                    let _ = ui::render_field_line(f, secret, &mut W(c));
                }
            }
            Reaction::Ignore | Reaction::NextTheme => {}
            Reaction::Done(i) => {
                c.write_str("\r\n");
                return i;
            }
        }
    }
}
