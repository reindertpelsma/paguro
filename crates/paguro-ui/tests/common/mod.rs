//! A whole front end in memory for the host tests: GOP frames (any number
//! of displays at any resolutions, each covered by the firmware text
//! console or not), ConOut and a serial port as text sinks, and a scripted
//! input queue — driven by the real prompt loop over the mock platform of
//! `paguro-boot`'s tests.
#![allow(dead_code, clippy::indexing_slicing)]

use std::collections::VecDeque;
use std::fmt;

use paguro_boot::keymap::Typed;
use paguro_boot::platform::{DirView, DiskInfo, Input, Platform, PlatformError, Screen};
use paguro_boot::ui::Key;
use paguro_boot::{Buffers, Outcome};
use paguro_core::config::Ui;
use paguro_core::guid::Guid;
use paguro_ui::canvas::Rect;
use paguro_ui::driver::{self, Event, Frontend, Session, TextSink};
use paguro_ui::pointer::{Cursor, Report, composite};
use paguro_ui::textui::{self, Grid, ROWS};
use paguro_ui::theme::Color;

use crate::mock::{Mock, PARAMS, World};

/// A text console in memory: every grid shown, and (for a serial port) the
/// VT100 byte stream.
#[derive(Default)]
pub struct Sink {
    pub vt100: bool,
    pub grids: Vec<(Grid, bool)>,
    pub bytes: String,
    prev: Option<Grid>,
}

impl Sink {
    pub fn serial() -> Sink {
        Sink {
            vt100: true,
            ..Sink::default()
        }
    }
    /// The last grid shown, as text lines.
    pub fn text(&self) -> String {
        self.grids
            .last()
            .map(|(g, _)| grid_text(g))
            .unwrap_or_default()
    }
    /// Every grid ever shown, as text.
    pub fn all_text(&self) -> String {
        self.grids
            .iter()
            .map(|(g, _)| grid_text(g))
            .collect::<Vec<_>>()
            .join("\n----\n")
    }
}

pub fn grid_text(g: &Grid) -> String {
    let mut out = String::new();
    for r in 0..ROWS {
        g.line(r, &mut out).unwrap();
        out.push('\n');
    }
    out
}

impl TextSink for Sink {
    fn show(&mut self, grid: &Grid, full: bool) {
        if self.vt100 {
            let prev = if full { None } else { self.prev.as_ref() };
            textui::write_vt100(prev, grid, &mut self.bytes).unwrap();
        }
        self.grids.push((grid.clone(), full));
        self.prev = Some(grid.clone());
    }
}

/// One display.
pub struct Display {
    pub w: u32,
    pub h: u32,
    /// What it shows now.
    pub px: Vec<u8>,
    /// Covered by ConOut (the firmware draws the text console there).
    pub covered: bool,
    /// Which frame it shows.
    pub frame: usize,
}

/// A frame shown, for the assertions: which screen and its pixels.
pub struct Shown {
    pub screen: Option<Screen>,
    pub frame: usize,
    pub px: Vec<u8>,
}

pub struct Mem {
    pub sizes: Vec<(u32, u32)>,
    pub frames: Vec<Vec<u8>>,
    pub displays: Vec<Display>,
    pub console: Option<Sink>,
    pub serial: Option<Sink>,
    pub events: VecDeque<Event>,
    pub text: bool,
    pub shown_screens: Vec<Screen>,
    pub current: Option<Screen>,
    /// Every full present of frame 0.
    pub shown: Vec<Shown>,
    /// Every present: frame, rectangle, cursor drawn.
    pub presents: Vec<(usize, Rect, bool)>,
}

impl Mem {
    /// Displays at these resolutions (displays of equal size share a
    /// frame), ConOut, and a serial mirror when `serial`.
    pub fn new(displays: &[(u32, u32, bool)], serial: bool) -> Mem {
        let mut sizes: Vec<(u32, u32)> = Vec::new();
        let mut ds = Vec::new();
        for &(w, h, covered) in displays {
            let frame = match sizes.iter().position(|s| *s == (w, h)) {
                Some(i) => i,
                None => {
                    sizes.push((w, h));
                    sizes.len() - 1
                }
            };
            ds.push(Display {
                w,
                h,
                px: vec![0; (w * h * 4) as usize],
                covered,
                frame,
            });
        }
        Mem {
            frames: sizes
                .iter()
                .map(|(w, h)| vec![0; (w * h * 4) as usize])
                .collect(),
            sizes,
            displays: ds,
            console: Some(Sink::default()),
            serial: serial.then(Sink::serial),
            events: VecDeque::new(),
            text: false,
            shown_screens: Vec::new(),
            current: None,
            shown: Vec::new(),
            presents: Vec::new(),
        }
    }

    pub fn keys(mut self, keys: &[Key]) -> Mem {
        self.events.extend(keys.iter().map(|k| Event::Key(*k)));
        self
    }

    pub fn px(&self, display: usize, x: u32, y: u32) -> Color {
        let d = &self.displays[display];
        let i = ((y * d.w + x) * 4) as usize;
        Color::rgb(d.px[i + 2], d.px[i + 1], d.px[i])
    }
}

impl Frontend for Mem {
    fn frames(&self) -> usize {
        self.sizes.len()
    }
    fn frame_size(&self, i: usize) -> (u32, u32) {
        self.sizes[i]
    }
    fn frame(&mut self, i: usize) -> &mut [u8] {
        &mut self.frames[i]
    }
    fn present(&mut self, i: usize, r: Rect, cursor: Option<&Cursor>) {
        let (fw, fh) = self.sizes[i];
        let mut first = true;
        for d in self.displays.iter_mut().filter(|d| d.frame == i) {
            if self.text && d.covered {
                continue;
            }
            // The cursor lives on frame 0's first display only.
            let c = if i == 0 && first { cursor } else { None };
            first = false;
            let mut out = vec![0u8; (r.w.max(0) * r.h.max(0) * 4) as usize];
            let got = composite(&self.frames[i], fw, fh, r, c, &mut out);
            for row in 0..got.h {
                let src = (row * got.w * 4) as usize;
                let dst = (((got.y + row) as u32 * d.w + got.x as u32) * 4) as usize;
                let n = (got.w * 4) as usize;
                d.px[dst..dst + n].copy_from_slice(&out[src..src + n]);
            }
        }
        self.presents.push((i, r, cursor.is_some()));
        if i == 0 && (r.w as u32, r.h as u32) == (fw, fh) {
            self.shown.push(Shown {
                screen: self.current,
                frame: i,
                px: self
                    .displays
                    .iter()
                    .find(|d| d.frame == 0)
                    .map_or_else(Vec::new, |d| d.px.clone()),
            });
        }
    }
    fn covered(&self, i: usize) -> bool {
        self.displays
            .iter()
            .filter(|d| d.frame == i)
            .all(|d| d.covered)
    }
    fn console(&mut self) -> Option<&mut dyn TextSink> {
        self.console.as_mut().map(|s| s as &mut dyn TextSink)
    }
    fn serial(&mut self) -> Option<&mut dyn TextSink> {
        self.serial.as_mut().map(|s| s as &mut dyn TextSink)
    }
    fn set_text(&mut self, text: bool) {
        self.text = text;
    }
    fn next_event(&mut self) -> Event {
        // An exhausted script leaves every screen the way Esc does.
        self.events.pop_front().unwrap_or(Event::Key(Key::Escape))
    }
    fn shown(&mut self, screen: &Screen) {
        self.shown_screens.push(*screen);
    }
}

/// The mock platform with the real front end.
pub struct Gop {
    pub m: Mock,
    pub d: Mem,
    pub s: Session,
}

impl Platform for Gop {
    fn read_esp_file(
        &mut self,
        name: &str,
        buf: &mut [u8],
    ) -> Result<Option<usize>, PlatformError> {
        self.m.read_esp_file(name, buf)
    }
    fn get_var(
        &mut self,
        name: &str,
        vendor: &Guid,
        buf: &mut [u8],
    ) -> Result<Option<usize>, PlatformError> {
        self.m.get_var(name, vendor, buf)
    }
    fn set_var(
        &mut self,
        name: &str,
        vendor: &Guid,
        attrs: u32,
        data: &[u8],
    ) -> Result<(), PlatformError> {
        self.m.set_var(name, vendor, attrs, data)
    }
    fn delete_var(&mut self, name: &str, vendor: &Guid) -> Result<(), PlatformError> {
        self.m.delete_var(name, vendor)
    }
    fn secure_boot(&mut self) -> bool {
        self.m.secure_boot()
    }
    fn tpm_present(&mut self) -> bool {
        self.m.tpm_present()
    }
    fn hash_log_extend(
        &mut self,
        pcr: u32,
        data: &[u8],
        event: &[u8],
    ) -> Result<(), PlatformError> {
        self.m.hash_log_extend(pcr, data, event)
    }
    fn tpm_submit(&mut self, cmd: &[u8], resp: &mut [u8]) -> Result<usize, PlatformError> {
        self.m.tpm_submit(cmd, resp)
    }
    fn disk_count(&mut self) -> usize {
        self.m.disk_count()
    }
    fn disk_info(&mut self, disk: usize) -> Option<DiskInfo> {
        self.m.disk_info(disk)
    }
    fn read_blocks(&mut self, disk: usize, lba: u64, buf: &mut [u8]) -> Result<(), PlatformError> {
        self.m.read_blocks(disk, lba, buf)
    }
    fn random(&mut self, buf: &mut [u8]) -> Result<(), PlatformError> {
        self.m.random(buf)
    }
    fn prompt(&mut self, screen: &Screen, secret: &mut [u8]) -> Input {
        self.m.screens.push(*screen);
        self.d.current = Some(*screen);
        driver::prompt(&mut self.d, &mut self.s, screen, secret)
    }
    fn prompt_browse(&mut self, screen: &Screen, dir: &DirView<'_>) -> Input {
        self.m.screens.push(*screen);
        self.d.current = Some(*screen);
        driver::prompt_browse(&mut self.d, &mut self.s, screen, dir)
    }
    fn ui_prefs(&mut self, ui: Ui) {
        self.m.ui_prefs(ui);
        self.s.apply(ui);
        let text = self.s.text || self.d.frames() == 0;
        self.s.text = text;
        self.d.set_text(text);
    }
    fn log(&mut self, args: fmt::Arguments<'_>) {
        self.m.log(args)
    }
    fn publish_handoff(&mut self, blob: &[u8]) -> Result<(), PlatformError> {
        self.m.publish_handoff(blob)
    }
    fn load_start_image(&mut self, dp: &[u8]) -> Result<(), PlatformError> {
        self.m.load_start_image(dp)
    }
    fn load_start_image_buffer(&mut self, image: &[u8]) -> Result<(), PlatformError> {
        self.m.load_start_image_buffer(image)
    }
    fn reset(&mut self) {
        self.m.reset()
    }
}

pub fn keys(s: &str) -> Vec<Key> {
    s.chars().map(Key::Char).collect()
}

/// Firmware keyboard input: US-mapped characters, Shift from their case.
pub fn typed(s: &str) -> Vec<Event> {
    s.chars().map(|c| Event::Typed(Typed::plain(c))).collect()
}

/// Run `w`'s boot through `d`, starting in `ui` (dark / auto by default).
pub fn boot_with(w: &mut World, d: Mem, ui: Option<Ui>) -> (Outcome, Gop) {
    let m = std::mem::replace(&mut w.m, Mock::new());
    let mut s = Session::new();
    if let Some(ui) = ui {
        s.apply(ui);
    }
    if d.frames() == 0 {
        s.text = true;
    }
    let mut g = Gop { m, d, s };
    let text = g.s.text;
    g.d.set_text(text);
    let mut bufs = Box::new(Buffers::new());
    let out = paguro_boot::run(&mut g, &mut w.v, &mut bufs, &PARAMS);
    assert!(bufs.secret.iter().all(|&b| b == 0), "secret buffer wiped");
    assert!(bufs.path.iter().all(|&b| b == 0), "path buffer wiped");
    (out, g)
}

/// One 800×600 display covered by ConOut, no serial mirror, `script`.
pub fn boot(w: &mut World, script: &[Key]) -> (Outcome, Gop) {
    boot_with(w, Mem::new(&[(800, 600, true)], false).keys(script), None)
}

pub fn has_color(f: &[u8], c: Color) -> bool {
    f.chunks_exact(4)
        .any(|p| (p[2], p[1], p[0]) == (c.r, c.g, c.b))
}

/// The most common colour of a frame.
pub fn dominant(f: &[u8]) -> Color {
    let mut counts = std::collections::HashMap::new();
    for p in f.chunks_exact(4) {
        *counts.entry((p[2], p[1], p[0])).or_insert(0usize) += 1;
    }
    let ((r, g, b), _) = counts.into_iter().max_by_key(|(_, n)| *n).unwrap();
    Color::rgb(r, g, b)
}

pub fn pointer_move(x: u64, y: u64, touch: bool) -> Event {
    Event::Pointer(Report::Absolute {
        x,
        y,
        min: (0, 0),
        max: (0xffff, 0xffff),
        touch,
    })
}
