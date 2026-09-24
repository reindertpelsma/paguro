//! [`Frontend`] over the firmware: the displays ([`Displays`]), ConOut,
//! the serial consoles ([`Serials`]) and every input ([`Inputs`]). Which
//! of them show what follows the configured mode (INTERFACES.md §13.2a):
//!
//! | mode       | GOP displays                         | ConOut         | serial consoles in ConOut |
//! |------------|--------------------------------------|----------------|---------------------------|
//! | `auto`     | graphics (F3: text, painted where ConOut is absent) | F3: text UI | text UI, owned (VT100 in and out) |
//! | `graphics` | graphics (F3 as above)               | F3: text UI    | the firmware's (log only)  |
//! | `text`     | text UI painted where ConOut is absent (F3: graphics) | text UI | through ConOut            |
//! | no GOP     | —                                    | text UI        | through ConOut            |

use log::info;
use paguro_boot::platform::Screen;
use paguro_core::config::UiMode;
use paguro_ui::canvas::Rect;
use paguro_ui::driver::{Event, Frontend, TextSink};
use paguro_ui::pointer::Cursor;

use crate::console::{self, ConOut, Serials};
use crate::gop::Displays;
use crate::input::Inputs;

pub struct Front {
    pub gop: Option<Displays>,
    conout: ConOut,
    serials: Serials,
    inputs: Inputs,
    /// The serial consoles show the text UI (`auto` with graphics).
    mirror: bool,
    text: bool,
}

impl Front {
    pub fn new() -> Front {
        let gop = Displays::new();
        let serials = Serials::find();
        let inputs = Inputs::new();
        let (simple, absolute, splitter) = inputs.describe();
        info!(
            "paguro: {} display frame(s), {} serial console(s), pointers: {simple} relative, {absolute} absolute{}",
            gop.as_ref().map_or(0, Displays::frames),
            serials.count(),
            if splitter { " (console splitter)" } else { "" }
        );
        let mut f = Front {
            gop,
            conout: ConOut::new(),
            serials,
            inputs,
            mirror: false,
            text: false,
        };
        f.configure(UiMode::Auto, false);
        f
    }

    /// Apply a mode: who shows what, where the log goes.
    pub fn configure(&mut self, mode: UiMode, text: bool) {
        let graphics = self.gop.is_some();
        let text = text || !graphics;
        self.mirror = graphics && mode == UiMode::Auto && self.serials.count() > 0;
        let was = self.serials.owned();
        if self.mirror {
            self.serials.own();
        } else {
            self.serials.release();
        }
        self.set_text(text);
        let now = self.serials.owned();
        if self.mirror && now != was {
            info!(
                "paguro: text UI on {} serial console(s), {now} owned (VT100 keys read directly)",
                self.serials.count()
            );
        }
    }

    pub fn text(&self) -> bool {
        self.text
    }

    /// Give the serial consoles back before anything else runs.
    pub fn release(&mut self) {
        self.serials.release();
        self.mirror = false;
        console::set_graphical(false);
    }
}

impl Frontend for Front {
    fn frames(&self) -> usize {
        self.gop.as_ref().map_or(0, Displays::frames)
    }
    fn frame_size(&self, i: usize) -> (u32, u32) {
        self.gop.as_ref().map_or((0, 0), |g| g.size(i))
    }
    fn frame(&mut self, i: usize) -> &mut [u8] {
        match self.gop.as_mut() {
            Some(g) => g.frame(i),
            None => &mut [],
        }
    }
    fn present(&mut self, i: usize, r: Rect, cursor: Option<&Cursor>) {
        if let Some(g) = self.gop.as_mut() {
            g.present(i, r, cursor);
        }
    }
    fn covered(&self, i: usize) -> bool {
        self.gop.as_ref().is_none_or(|g| g.covered(i))
    }
    fn console(&mut self) -> Option<&mut dyn TextSink> {
        Some(&mut self.conout)
    }
    fn serial(&mut self) -> Option<&mut dyn TextSink> {
        if self.mirror {
            Some(&mut self.serials)
        } else {
            None
        }
    }
    fn set_text(&mut self, text: bool) {
        self.text = text;
        if let Some(g) = self.gop.as_mut() {
            g.set_text(text);
        }
        self.conout.reset();
        // Graphics own the display: the log must not reach ConOut. In text
        // mode ConOut shows the UI, so the log goes to the serial port as
        // well when there is one.
        console::set_graphical(!text || self.serials.count() > 0);
    }
    fn next_event(&mut self) -> Event {
        self.inputs.next(&mut self.serials)
    }
    fn shown(&mut self, screen: &Screen) {
        info!("paguro: screen {}", screen_name(screen));
    }
}

/// A screen's name for the log (never its contents).
pub fn screen_name(s: &Screen) -> &'static str {
    match s {
        Screen::Unlock(_) => "unlock",
        Screen::EnterSecret { .. } => "secret",
        Screen::Incorrect => "incorrect",
        Screen::PathRefused => "path-refused",
        Screen::CannotUnlock => "cannot-unlock",
        Screen::ConfigInvalid => "config-invalid",
        Screen::TpmLocked => "tpm-locked",
        Screen::Notice(_) => "notice",
        Screen::NoInstallation => "no-installation",
        Screen::SelectVolume(_) => "volumes",
        Screen::Browse(_) => "browse",
        Screen::EnterPath(_) => "path",
        Screen::DiskStart { .. } => "disk",
        Screen::NoEfiPartition => "no-esp",
        Screen::ChooseKeyboard { .. } => "keyboards",
        Screen::ChooseLanguage { .. } => "languages",
    }
}
