//! Every screen of the loader through the real front end, in every variant
//! and in every mode (graphics, text, auto with a serial mirror): whole
//! boots over the mock platform, driven by keys only, each ending the way
//! the stage machine says it should. The union of the screens shown is
//! checked against the full list, so a screen nobody reaches here fails
//! the test.
#![allow(clippy::indexing_slicing, dead_code)]

mod common;
#[path = "../../paguro-boot/tests/mock/mod.rs"]
mod mock;

use std::collections::BTreeSet;

use common::*;
use mock::*;
use paguro_boot::platform::Screen;
use paguro_boot::ui::Key;
use paguro_boot::{BootError, Outcome};
use paguro_core::config::{Keyboard, Ui, UiMode, UiTheme};
use paguro_core::guid::Guid;
use paguro_core::handoff::{Rung, state};

const RECOVERY_PW: &str = "000011-000022-000033-000044-000055-000066-000077-720885";
const RECOVERY_KEY: [u8; 16] = [1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 0xff, 0xff];

fn recovery_world() -> World {
    let mut w = World::new();
    w.m.files.remove("paguro.ini");
    w.v.clear_key = Some(VMK);
    w
}

fn script(parts: &[&[Key]]) -> Vec<Key> {
    parts.concat()
}

fn t(s: &str) -> Vec<Key> {
    keys(s)
}

type Case = (&'static str, fn() -> World, Vec<Key>, Outcome);

fn cases() -> Vec<Case> {
    let e = Key::Enter;
    vec![
        (
            "tpm-unlock",
            || {
                let mut w = World::new();
                w.with_tpm_seal(PIN);
                w
            },
            script(&[&[e], &t(PIN), &[e]]),
            Outcome::Started(Rung::Tpm),
        ),
        (
            "wrong-pin-then-right",
            || {
                let mut w = World::new();
                w.with_tpm_seal(PIN);
                w
            },
            script(&[&t("1wrong"), &[e], &t("1"), &t(PIN), &[e]]),
            Outcome::Started(Rung::Tpm),
        ),
        (
            "cannot-unlock",
            || {
                let mut w = World::new();
                w.with_tpm_seal(PIN);
                w
            },
            vec![Key::Escape, e],
            Outcome::StartWindows,
        ),
        (
            "tpm-locked",
            || {
                let mut w = World::new();
                w.with_tpm_seal(PIN);
                w.m.tpm().max_tries = 1;
                w
            },
            script(&[&t("1wrong"), &[e], &t("1"), &t(PIN), &[e, e], &t("w")]),
            Outcome::StartWindows,
        ),
        (
            "config-invalid-then-recovery-key",
            || {
                let mut w = World::new();
                let mut bad = w.ini.clone();
                bad.extend_from_slice(b"\n");
                w.set_ini(bad, false);
                w.v.recovery = Some((RECOVERY_KEY, VMK));
                w
            },
            script(&[&t("r3"), &t(RECOVERY_PW), &[e]]),
            Outcome::Started(Rung::RecoveryKey),
        ),
        (
            "hibernated-and-dirty",
            || {
                let mut w = World::new();
                w.v.clear_key = Some(VMK);
                w.v.flags = state::HIBERNATED | state::DIRTY;
                w
            },
            vec![e, e],
            Outcome::Started(Rung::ClearKey),
        ),
        (
            "pcr12",
            || {
                let mut w = World::new();
                w.with_tpm_seal(PIN);
                w.m.tpm().pcrs[12] = [1; 32];
                w
            },
            vec![e],
            Outcome::StartWindows,
        ),
        (
            "volume-missing",
            || {
                let mut w = World::new();
                w.m.disks = vec![disk(&[(Guid([0x77; 16]), BITLOCKER)])];
                w.v.clear_key = Some(VMK);
                w
            },
            t("r"),
            Outcome::Started(Rung::ClearKey),
        ),
        (
            "seal-over-plaintext",
            || {
                let mut w = World::new();
                w.with_tpm_seal(PIN);
                w.m.disks = vec![disk(&[(VOLUME, NTFS)])];
                w
            },
            vec![e],
            Outcome::Halted(BootError::SealOverPlaintext),
        ),
        (
            "no-installation",
            || {
                let mut w = World::new();
                w.m.files.remove("paguro.ini");
                w.m.disks = vec![disk(&[(Guid([1; 16]), b"FAT32   ")])];
                w
            },
            vec![Key::Escape],
            Outcome::Halted(BootError::NoVolume),
        ),
        (
            "select-volume",
            || {
                let mut w = World::new();
                w.m.files.remove("paguro.ini");
                w.m.disks = vec![
                    disk(&[(Guid([0xa1; 16]), BITLOCKER)]),
                    disk(&[(Guid([0xcc; 16]), b"FAT32   "), (Guid([0xb2; 16]), NTFS)]),
                ];
                w
            },
            vec![Key::Down, e],
            Outcome::Started(Rung::Unencrypted),
        ),
        (
            "browse-to-a-uki-and-its-root",
            || {
                let mut w = recovery_world();
                w.v.dir("\\paguro", &["tools/", "debian.vhd", "arch.vhdx"])
                    .dir("\\paguro\\tools", &["old/", "rescue.efi"]);
                w
            },
            vec![e, Key::Char('r'), e, Key::Char('d'), e],
            Outcome::Started(Rung::ClearKey),
        ),
        (
            "browse-a-disk-esp",
            || {
                let mut w = recovery_world();
                w.v.dir("\\paguro", &["arch.vhdx", "debian.vhd"])
                    .esp_dir("\\paguro\\debian.vhd", "\\", &["EFI/"])
                    .esp_dir("\\paguro\\debian.vhd", "\\EFI", &["BOOT/", "systemd/"])
                    .esp_dir(
                        "\\paguro\\debian.vhd",
                        "\\EFI\\systemd",
                        &["systemd-bootx64.efi"],
                    );
                w
            },
            vec![
                Key::Down,
                e,
                Key::Down,
                e,
                Key::Right,
                Key::Backspace,
                e,
                Key::Down,
                e,
                e,
            ],
            Outcome::Started(Rung::ClearKey),
        ),
        (
            "disk-without-esp",
            || {
                let mut w = recovery_world();
                w.v.dir("\\paguro", &["plain.img", "other.img"]);
                w
            },
            // other.img, plain.img: plain.img; browse its EFI partition (none:
            // the toast, back on the disk screen); its default image.
            vec![Key::Down, e, Key::Down, e, Key::Char('1')],
            Outcome::Started(Rung::ClearKey),
        ),
        (
            "typed-path",
            || {
                let mut w = recovery_world();
                w.v.dir("\\paguro", &[]);
                w
            },
            script(&[&[e], &t("paguro/debian.vhd"), &[e, e]]),
            Outcome::Started(Rung::ClearKey),
        ),
        (
            "refused-path-then-good",
            || {
                let mut w = recovery_world();
                w.v.dir("\\paguro", &[]);
                w
            },
            script(&[
                &[e],
                &t("\\a*b"),
                &[e, e],
                &t("\\paguro\\debian.vhd"),
                &[e, e],
            ]),
            Outcome::Started(Rung::ClearKey),
        ),
        (
            "choosers-from-the-unlock-screen",
            || {
                let mut w = World::new();
                w.with_tpm_seal(PIN);
                w
            },
            script(&[
                &[Key::Function(4), Key::Down, Key::Escape],
                &[Key::Function(5), Key::End, Key::Escape],
                &[e],
                &t(PIN),
                &[e],
            ]),
            Outcome::Started(Rung::Tpm),
        ),
    ]
}

fn kind(s: &Screen) -> &'static str {
    match s {
        Screen::Unlock(_) => "unlock",
        Screen::EnterSecret { .. } => "secret",
        Screen::Incorrect => "incorrect",
        Screen::PathRefused => "path-refused",
        Screen::CannotUnlock => "cannot-unlock",
        Screen::ConfigInvalid => "config-invalid",
        Screen::TpmLocked => "tpm-locked",
        Screen::Notice(n) => match n {
            paguro_boot::platform::Notice::Hibernated => "hibernated",
            paguro_boot::platform::Notice::Dirty => "dirty",
            paguro_boot::platform::Notice::Pcr12NotZero => "pcr12",
            paguro_boot::platform::Notice::SealOverPlaintext => "plaintext",
            paguro_boot::platform::Notice::VolumeMissing => "volume-missing",
            paguro_boot::platform::Notice::NotImplemented => "not-implemented",
            paguro_boot::platform::Notice::StartFailed => "start-failed",
        },
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

#[test]
fn every_screen_in_every_variant_and_mode() {
    let mut seen = BTreeSet::new();
    let mut boots = 0;
    for (name, world, keys, want) in cases() {
        for theme in UiTheme::ALL {
            for mode in UiMode::ALL {
                let mut w = world();
                let serial = mode == UiMode::Auto;
                let d = Mem::new(&[(800, 600, true)], serial).keys(&keys);
                let ui = Ui {
                    theme,
                    mode,
                    keyboard: Keyboard::Us,
                };
                let (out, g) = boot_with(&mut w, d, Some(ui));
                let ctx = format!("{name} in {} {}", theme.name(), mode.name());
                assert_eq!(out, want, "{ctx}: {:?}", g.m.log);
                for s in &g.d.shown_screens {
                    seen.insert(kind(s));
                }
                // What each mode must have shown.
                let console = g.d.console.as_ref().unwrap();
                match mode {
                    UiMode::Text => {
                        assert!(g.d.shown.is_empty(), "{ctx}");
                        assert!(!console.grids.is_empty(), "{ctx}");
                        for (grid, _) in &console.grids {
                            assert!(grid_text(grid).starts_with(" paguro\n"), "{ctx}");
                        }
                    }
                    _ => {
                        assert!(!g.d.shown.is_empty(), "{ctx}");
                        assert!(console.grids.is_empty(), "{ctx}");
                    }
                }
                if serial {
                    let s = g.d.serial.as_ref().unwrap();
                    assert!(!s.grids.is_empty() && s.bytes.contains("\x1b["), "{ctx}");
                }
                boots += 1;
            }
        }
    }
    let all: BTreeSet<&str> = [
        "unlock",
        "secret",
        "incorrect",
        "path-refused",
        "cannot-unlock",
        "config-invalid",
        "tpm-locked",
        "hibernated",
        "dirty",
        "pcr12",
        "plaintext",
        "volume-missing",
        "no-installation",
        "volumes",
        "browse",
        "path",
        "disk",
        "no-esp",
        "keyboards",
        "languages",
    ]
    .into_iter()
    .collect();
    let missing: Vec<_> = all.difference(&seen).collect();
    assert!(missing.is_empty(), "never shown: {missing:?}");
    // NotImplemented is the stub volume's (QEMU scenarios reach it).
    assert_eq!(boots, cases().len() * 12);
}
