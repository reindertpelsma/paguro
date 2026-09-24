//! Whole boots through the graphical front end: the stage machine over the
//! mock platform (paguro-boot's `tests/mock`), with `Platform::prompt`
//! answered by the real prompt loop drawing into a memory "GOP" frame and
//! reading scripted keystrokes — the path `paguro-efi` takes, minus the
//! firmware.
#![allow(clippy::indexing_slicing, dead_code)]

mod common;
#[path = "../../paguro-boot/tests/mock/mod.rs"]
mod mock;

use common::*;
use mock::*;
use paguro_boot::Outcome;
use paguro_boot::platform::{Level, Screen};
use paguro_boot::ui::Key;
use paguro_core::handoff::Rung;
use paguro_ui::builtin::THEMES;
use paguro_ui::theme::Color;
use paguro_ui::{Canvas, View, render};

const W: u32 = 800;
const H: u32 = 600;

fn px(f: &[u8], x: u32, y: u32) -> Color {
    let i = ((y * W + x) * 4) as usize;
    Color::rgb(f[i + 2], f[i + 1], f[i])
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
    assert!(matches!(first.screen, Some(Screen::Unlock(_))));
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
            .filter(|f| matches!(f.screen, Some(Screen::EnterSecret { .. })))
            .collect();
    assert_eq!(secret.len(), 1 + PIN.len() + 1);
    let last = secret.last().unwrap();
    assert_eq!(
        last.px,
        render_plain(&last.screen.unwrap(), 0),
        "no typed text left on screen"
    );
    assert_eq!(g.d.shown_screens.len(), 2, "each screen announced once");
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
            .filter(|f| matches!(f.screen, Some(Screen::Unlock(_))))
            .collect();
    assert!(!has_color(&unlocks[0].px, toast));
    assert!(has_color(&unlocks[1].px, toast), "the retry says why");
    assert!(
        !g.d.shown
            .iter()
            .any(|f| f.screen == Some(Screen::Incorrect)),
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
fn f2_switches_to_the_light_variant_for_the_rest_of_the_boot() {
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

fn recovery_world() -> World {
    let mut w = World::new();
    w.m.files.remove("paguro.ini");
    w.v.clear_key = Some(VMK);
    w
}

#[test]
fn browse_to_a_uki_then_choose_its_root_by_keyboard() {
    let mut w = recovery_world();
    w.v.dir("\\paguro", &["tools/", "debian.vhd", "arch.vhdx"])
        .dir("\\paguro\\tools", &["old/", "rescue.efi"]);
    // \paguro: Enter on "tools"; in tools: type "r" to jump to rescue.efi,
    // Enter; the root browser (tools, arch.vhdx, debian.vhd, Type a path,
    // None): "d" jumps to debian.vhd, Enter.
    let script = [
        Key::Enter,
        Key::Char('r'),
        Key::Enter,
        Key::Char('d'),
        Key::Enter,
    ];
    let (out, g) = boot(&mut w, &script);
    assert_eq!(out, Outcome::Started(Rung::ClearKey), "{:?}", g.m.log);
    let saw = w.v.saw_entry.clone().unwrap();
    assert_eq!(
        saw.efi,
        format!(
            "{:?}",
            paguro_core::config::Efi::File("\\paguro\\tools\\rescue.efi")
        )
    );
    assert_eq!(saw.root.as_deref(), Some("\\paguro\\debian.vhd"));
    let banner = THEMES[0].palette.banner_background;
    for f in g.d.shown.iter() {
        assert!(
            has_color(&f.px, banner),
            "recovery screens say they are unattested"
        );
    }
    assert!(g.d.shown_screens.contains(&Screen::Browse(Level::Volume)));
    assert!(g.d.shown_screens.contains(&Screen::Browse(Level::Root)));
}

#[test]
fn browse_a_disk_efi_partition_by_keyboard() {
    let mut w = recovery_world();
    w.v.dir("\\paguro", &["arch.vhdx", "debian.vhd"])
        .esp_dir("\\paguro\\debian.vhd", "\\", &["EFI/"])
        .esp_dir("\\paguro\\debian.vhd", "\\EFI", &["BOOT/", "systemd/"])
        .esp_dir(
            "\\paguro\\debian.vhd",
            "\\EFI\\systemd",
            &["systemd-bootx64.efi"],
        );
    // debian.vhd; "Choose another on its EFI partition"; open EFI (->),
    // systemd (Down, Enter), then the image; Backspace and Right on the way
    // exercise the parent and open keys.
    let script = [
        Key::Down,
        Key::Enter,
        Key::Down,
        Key::Enter,
        Key::Right,
        Key::Backspace,
        Key::Enter,
        Key::Down,
        Key::Enter,
        Key::Enter,
    ];
    let (out, g) = boot(&mut w, &script);
    assert_eq!(out, Outcome::Started(Rung::ClearKey), "{:?}", g.m.log);
    let saw = w.v.saw_entry.clone().unwrap();
    assert_eq!(
        saw.efi,
        format!(
            "{:?}",
            paguro_core::config::Efi::Disk {
                disk: "\\paguro\\debian.vhd",
                path: "\\EFI\\systemd\\systemd-bootx64.efi"
            }
        )
    );
    assert_eq!(saw.root.as_deref(), Some("\\paguro\\debian.vhd"));
    assert!(
        g.d.shown_screens
            .contains(&Screen::Browse(Level::EfiPartition))
    );
    assert_eq!(
        g.m.events.last(),
        Some(&Event::Start(
            b"chain-device-path:\\EFI\\systemd\\systemd-bootx64.efi".to_vec()
        ))
    );
}

#[test]
fn recovery_typed_path_by_keyboard() {
    let mut w = recovery_world();
    w.v.dir("\\paguro", &[]);
    // The only row is "Type a path"; type it with a correction, then start
    // the disk's default image.
    let mut script = vec![Key::Enter];
    script.extend(keys("\\paguro\\debainx"));
    script.extend([Key::Left, Key::Delete, Key::Left, Key::Left, Key::Backspace]);
    script.extend([Key::Right, Key::Char('a'), Key::End]);
    script.extend(keys(".vhd"));
    script.push(Key::Enter);
    script.push(Key::Enter);
    let (out, g) = boot(&mut w, &script);
    assert_eq!(out, Outcome::Started(Rung::ClearKey), "{:?}", g.m.log);
    assert_eq!(
        w.v.saw_entry.clone().unwrap().root.as_deref(),
        Some("\\paguro\\debian.vhd")
    );
}
