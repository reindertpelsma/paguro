//! Whole boots through the graphical front end: the stage machine over the
//! mock platform (paguro-boot's `tests/mock`), with `Platform::prompt`
//! answered by the real prompt loop drawing into a memory "GOP" frame and
//! reading scripted keystrokes — the path `paguro-efi` takes, minus the
//! firmware.
#![allow(clippy::indexing_slicing, dead_code)]

#[path = "../../paguro-boot/tests/mock/mod.rs"]
mod mock;

use std::collections::VecDeque;
use std::fmt;

use mock::*;
use paguro_boot::platform::{DiskInfo, Input, Platform, PlatformError, Screen, TargetKind};
use paguro_boot::ui::Key;
use paguro_boot::{Buffers, Outcome};
use paguro_core::guid::Guid;
use paguro_core::handoff::Rung;
use paguro_ui::builtin::THEMES;
use paguro_ui::driver::{self, Display, Session};
use paguro_ui::theme::Color;
use paguro_ui::{Canvas, View, render};

const W: u32 = 800;
const H: u32 = 600;

struct Frame {
    screen: Screen,
    px: Vec<u8>,
}

/// A frame buffer and a keyboard in memory.
struct MemGop {
    frame: Vec<u8>,
    keys: VecDeque<Key>,
    shown: Vec<Frame>,
    current: Option<Screen>,
    mirrored: Vec<Screen>,
}

impl Display for MemGop {
    fn size(&self) -> (u32, u32) {
        (W, H)
    }
    fn frame(&mut self) -> &mut [u8] {
        &mut self.frame
    }
    fn present(&mut self) {
        let screen = self.current.unwrap_or(Screen::Incorrect);
        self.shown.push(Frame {
            screen,
            px: self.frame.clone(),
        });
    }
    fn read_key(&mut self) -> Key {
        // An exhausted script leaves every screen the way Esc does.
        self.keys.pop_front().unwrap_or(Key::Escape)
    }
    fn mirror(&mut self, screen: &Screen) {
        self.mirrored.push(*screen);
    }
}

/// The mock platform with a graphical `prompt`.
struct Gop {
    m: Mock,
    d: MemGop,
    s: Session,
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

fn keys(s: &str) -> Vec<Key> {
    s.chars().map(Key::Char).collect()
}

/// Run `w`'s boot with `script` typed on the keyboard.
fn boot(w: &mut World, script: &[Key]) -> (Outcome, Gop) {
    let m = std::mem::replace(&mut w.m, Mock::new());
    let mut g = Gop {
        m,
        d: MemGop {
            frame: vec![0; (W * H * 4) as usize],
            keys: script.iter().copied().collect(),
            shown: Vec::new(),
            current: None,
            mirrored: Vec::new(),
        },
        s: Session::new(),
    };
    let mut bufs = Box::new(Buffers::new());
    let out = paguro_boot::run(&mut g, &mut w.v, &mut bufs, &PARAMS);
    assert!(bufs.secret.iter().all(|&b| b == 0), "secret buffer wiped");
    assert!(bufs.path.iter().all(|&b| b == 0), "path buffer wiped");
    (out, g)
}

fn px(f: &[u8], x: u32, y: u32) -> Color {
    let i = ((y * W + x) * 4) as usize;
    Color::rgb(f[i + 2], f[i + 1], f[i])
}

fn has_color(f: &[u8], c: Color) -> bool {
    f.chunks_exact(4)
        .any(|p| (p[2], p[1], p[0]) == (c.r, c.g, c.b))
}

fn render_plain(screen: &Screen, theme: usize) -> Vec<u8> {
    let mut buf = vec![0u8; (W * H * 4) as usize];
    let mut c = Canvas::new(&mut buf, W, H, W).unwrap();
    render(screen, &View::IDLE, &THEMES[theme], &mut c);
    buf
}

#[test]
fn tpm_unlock_by_keyboard() {
    let mut w = World::new();
    w.with_tpm_seal(PIN);
    // Enter on the highlighted first row, then the PIN, then Enter.
    let mut script = vec![Key::Enter];
    script.extend(keys(PIN));
    script.push(Key::Enter);
    let (out, g) = boot(&mut w, &script);
    assert_eq!(out, Outcome::Started(Rung::Tpm));
    let theme = &THEMES[0];
    let first = &g.d.shown[0];
    assert!(matches!(first.screen, Screen::Unlock(_)));
    assert_eq!(
        px(&first.px, 2, 2),
        theme.palette.background,
        "the theme's background"
    );
    assert!(
        has_color(&first.px, theme.palette.accent),
        "the selection bar"
    );
    // One frame per keystroke on the secret screen, and a clean one last.
    let secret: Vec<_> =
        g.d.shown
            .iter()
            .filter(|f| matches!(f.screen, Screen::EnterSecret { .. }))
            .collect();
    assert_eq!(secret.len(), 1 + PIN.len() + 1);
    let last = secret.last().unwrap();
    assert_eq!(
        last.px,
        render_plain(&last.screen, 0),
        "no typed text left on screen"
    );
    assert_eq!(g.d.mirrored.len(), 2, "each screen mirrored once, as text");
}

#[test]
fn a_wrong_pin_shows_a_toast_on_the_next_screen() {
    let mut w = World::new();
    w.with_tpm_seal(PIN);
    let mut script = vec![Key::Char('1')];
    script.extend(keys("wrong"));
    script.push(Key::Enter);
    script.push(Key::Char('1'));
    script.extend(keys(PIN));
    script.push(Key::Enter);
    let (out, g) = boot(&mut w, &script);
    assert_eq!(out, Outcome::Started(Rung::Tpm));
    assert!(g.m.screens.contains(&Screen::Incorrect));
    let toast = THEMES[0].palette.toast_background;
    let unlocks: Vec<_> =
        g.d.shown
            .iter()
            .filter(|f| matches!(f.screen, Screen::Unlock(_)))
            .collect();
    assert!(!has_color(&unlocks[0].px, toast));
    assert!(has_color(&unlocks[1].px, toast), "the retry says why");
    assert!(
        !g.d.shown.iter().any(|f| f.screen == Screen::Incorrect),
        "no extra key"
    );
}

#[test]
fn recovery_key_typed_with_edits_and_reveal() {
    let mut w = World::new();
    w.v.recovery = Some((mock_recovery_key(), VMK));
    // Down to the recovery-key row; type with separators (ignored), a
    // mistake fixed with Left/Delete, reveal and hide.
    let mut script = vec![Key::Down, Key::Enter];
    script.extend(keys(
        "000011-000022-000033-000044-000055-000066-000077-72088",
    ));
    script.extend([
        Key::Char('9'),
        Key::Left,
        Key::Delete,
        Key::End,
        Key::Char('5'),
    ]);
    script.extend([Key::Insert, Key::Insert, Key::Enter]);
    let (out, g) = boot(&mut w, &script);
    assert_eq!(out, Outcome::Started(Rung::RecoveryKey), "{:?}", g.m.log);
}

fn mock_recovery_key() -> [u8; 16] {
    [1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 0xff, 0xff]
}

#[test]
fn f2_switches_to_high_contrast_for_the_rest_of_the_boot() {
    let mut w = World::new();
    w.with_tpm_seal(PIN);
    let mut script = vec![Key::Function(2), Key::Enter];
    script.extend(keys(PIN));
    script.push(Key::Enter);
    let (out, g) = boot(&mut w, &script);
    assert_eq!(out, Outcome::Started(Rung::Tpm));
    let hc = &THEMES[1];
    assert_eq!(px(&g.d.shown[0].px, 2, 2), THEMES[0].palette.background);
    assert_eq!(px(&g.d.shown[1].px, 2, 2), hc.palette.background);
    assert_eq!(
        px(&g.d.shown.last().unwrap().px, 2, 2),
        hc.palette.background
    );
}

#[test]
fn escape_everywhere_still_ends() {
    let mut w = World::new();
    w.with_tpm_seal(PIN);
    let (out, _) = boot(&mut w, &[]);
    assert_eq!(out, Outcome::Halted(paguro_boot::BootError::UserAbort));
}

#[test]
fn recovery_flow_by_keyboard() {
    // No configuration; a clear key; \paguro\ holds a UKI and two disks.
    let mut w = World::new();
    w.m.files.remove("paguro.ini");
    w.v.clear_key = Some(VMK);
    w.v.targets = Some(vec![
        ("rescue.efi".into(), 112 << 20, TargetKind::EfiFile),
        ("debian.vhd".into(), 214 << 30, TargetKind::Disk),
        ("arch.vhdx".into(), 64 << 30, TargetKind::Disk),
    ]);
    // Target list: Enter on the UKI; root list: End (None), Up, Enter → arch.
    let script = [Key::Enter, Key::End, Key::Up, Key::Enter];
    let (out, g) = boot(&mut w, &script);
    assert_eq!(out, Outcome::Started(Rung::ClearKey));
    let saw = w.v.saw_entry.clone().unwrap();
    assert_eq!(saw.root.as_deref(), Some("\\paguro\\arch.vhdx"));
    let banner = THEMES[0].palette.banner_background;
    for f in g.d.shown.iter() {
        assert!(
            has_color(&f.px, banner),
            "recovery screens say they are unattested"
        );
    }
}

#[test]
fn recovery_typed_path_by_keyboard() {
    let mut w = World::new();
    w.m.files.remove("paguro.ini");
    w.v.clear_key = Some(VMK);
    w.v.targets = Some(vec![]);
    // The only row is "Type a path"; type it with a correction.
    let mut script = vec![Key::Enter];
    script.extend(keys("\\paguro\\debainx"));
    script.extend([Key::Left, Key::Delete, Key::Left, Key::Left, Key::Backspace]);
    script.extend([Key::Right, Key::Char('a'), Key::End]);
    script.extend(keys(".vhd"));
    script.push(Key::Enter);
    let (out, g) = boot(&mut w, &script);
    assert_eq!(out, Outcome::Started(Rung::ClearKey), "{:?}", g.m.log);
    assert_eq!(
        w.v.saw_entry.clone().unwrap().root.as_deref(),
        Some("\\paguro\\debian.vhd")
    );
}
