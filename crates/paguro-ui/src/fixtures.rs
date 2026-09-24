//! Named screens in representative states, for the preview tool
//! (`paguro-ui-preview`) and the golden tests. Host tooling only: nothing in
//! the loader calls this (the linker drops it).

use paguro_boot::platform::{
    Grey, Label, Notice, Row, Screen, Target, TargetKind, TargetList, UnlockMenu, VolumeChoice,
    VolumeFormat, VolumeList,
};
use paguro_boot::ui::{Field, Key, Prompt};

use crate::layout::{Toast, View};

/// A screen plus the interaction state it is shown in.
pub struct Fixture {
    pub name: &'static str,
    pub screen: Screen,
    pub selected: usize,
    pub field: Option<Field>,
    pub buf: [u8; 256],
    pub toast: Option<Toast>,
}

impl Fixture {
    pub fn view(&self) -> View<'_> {
        View {
            selected: self.selected,
            field: self.field,
            buf: &self.buf,
            toast: self.toast,
        }
    }
}

const MENU: UnlockMenu = UnlockMenu {
    password_or_pin: true,
    recovery_passphrase: false,
    recovery_key: true,
    tpm: Ok(Some(3)),
    unattested: false,
    first_boot: false,
};

fn label(s: &str) -> Label {
    Label::truncated(s)
}

fn volumes(n: u8, long: bool) -> VolumeList {
    let names = [
        "Basic data partition",
        "",
        "Data",
        "Windows",
        "Games",
        "",
        "Backup",
        "Scratch",
    ];
    let mut v = VolumeList::new();
    for i in 0..n {
        let name = if long && i == 1 {
            "A partition whose name is far longer than any row could show"
        } else {
            names.get(usize::from(i)).copied().unwrap_or("")
        };
        v.push(VolumeChoice {
            disk: i / 2,
            partition: 3 + u32::from(i % 2),
            bytes: (931u64 << 30) / u64::from(i + 1) + (u64::from(i) << 28),
            format: if i % 3 == 2 {
                VolumeFormat::Ntfs
            } else {
                VolumeFormat::BitLocker
            },
            name: label(name),
        });
    }
    v
}

fn targets(entries: &[(&str, u64, TargetKind)]) -> TargetList {
    let mut t = TargetList::new();
    for (n, b, k) in entries {
        t.push(Target {
            name: label(n),
            bytes: *b,
            kind: *k,
        });
    }
    t
}

/// Type `keys` into a fresh prompt for `screen`.
fn typed(name: &'static str, screen: Screen, keys: &[Key]) -> Fixture {
    let mut f = Fixture {
        name,
        screen,
        selected: 0,
        field: None,
        buf: [0; 256],
        toast: None,
    };
    let mut p = Prompt::new(&f.screen, &mut f.buf);
    for k in keys {
        p.feed(&f.screen, *k, &mut f.buf);
    }
    f.selected = p.selected();
    f.field = p.field().copied();
    f
}

fn chars(s: &str, out: &mut [Key; 128]) -> usize {
    let mut n = 0;
    for (slot, c) in out.iter_mut().zip(s.chars()) {
        *slot = Key::Char(c);
        n += 1;
    }
    n
}

fn text_then(s: &str, extra: &[Key]) -> ([Key; 128], usize) {
    let mut k = [Key::Enter; 128];
    let mut n = chars(s, &mut k);
    for (slot, e) in k.iter_mut().skip(n).zip(extra) {
        *slot = *e;
        n += 1;
    }
    (k, n)
}

const SECRET: Screen = Screen::EnterSecret {
    row: Row::PasswordOrPin,
    unattested: false,
};
const RECOVERY_KEY: Screen = Screen::EnterSecret {
    row: Row::RecoveryKey,
    unattested: false,
};

/// Every fixture, in gallery order.
pub fn all() -> [Fixture; FIXTURES] {
    let plain = |name, screen| typed(name, screen, &[]);
    let with = |name, screen, keys: ([Key; 128], usize)| {
        typed(name, screen, keys.0.get(..keys.1).unwrap_or(&[]))
    };
    let mut incorrect = plain("unlock-incorrect", Screen::Unlock(MENU));
    incorrect.toast = Some(Toast::Incorrect);
    let mut refused = plain(
        "targets-path-refused",
        Screen::SelectTarget(targets(&[("debian.vhd", 214 << 30, TargetKind::Disk)])),
    );
    refused.toast = Some(Toast::PathRefused);
    [
        plain("unlock", Screen::Unlock(MENU)),
        with(
            "unlock-all-rows",
            Screen::Unlock(UnlockMenu {
                recovery_passphrase: true,
                tpm: Ok(Some(1)),
                ..MENU
            }),
            text_then("", &[Key::Down]),
        ),
        plain(
            "unlock-first-boot",
            Screen::Unlock(UnlockMenu {
                first_boot: true,
                unattested: true,
                tpm: Ok(None),
                ..MENU
            }),
        ),
        plain(
            "unlock-recovery",
            Screen::Unlock(UnlockMenu {
                password_or_pin: false,
                recovery_passphrase: true,
                tpm: Err(Grey::RecoveryMode),
                unattested: true,
                ..MENU
            }),
        ),
        plain(
            "unlock-locked",
            Screen::Unlock(UnlockMenu {
                password_or_pin: false,
                tpm: Err(Grey::Locked),
                ..MENU
            }),
        ),
        incorrect,
        plain("password-empty", SECRET),
        with("password-hidden", SECRET, text_then("correct horse", &[])),
        with(
            "password-revealed",
            SECRET,
            text_then("correct horse", &[Key::Insert]),
        ),
        with(
            "password-cursor-mid",
            SECRET,
            text_then(
                "correct horse",
                &[
                    Key::Insert,
                    Key::Left,
                    Key::Left,
                    Key::Left,
                    Key::Left,
                    Key::Left,
                ],
            ),
        ),
        with(
            "password-long",
            SECRET,
            text_then(
                "this passphrase is much longer than the field can show at once, so it scrolls",
                &[Key::Insert],
            ),
        ),
        plain(
            "passphrase-unattested",
            Screen::EnterSecret {
                row: Row::RecoveryPassphrase,
                unattested: true,
            },
        ),
        plain("recovery-key-empty", RECOVERY_KEY),
        with(
            "recovery-key-half",
            RECOVERY_KEY,
            text_then("000011000022000033000044", &[]),
        ),
        with(
            "recovery-key-revealed",
            RECOVERY_KEY,
            text_then("000011000022000033000044000055", &[Key::Insert]),
        ),
        plain("cannot-unlock", Screen::CannotUnlock),
        plain("config-invalid", Screen::ConfigInvalid),
        plain("tpm-locked", Screen::TpmLocked),
        plain("hibernated", Screen::Notice(Notice::Hibernated)),
        plain("dirty", Screen::Notice(Notice::Dirty)),
        plain("pcr12", Screen::Notice(Notice::Pcr12NotZero)),
        plain("plaintext", Screen::Notice(Notice::SealOverPlaintext)),
        plain("volume-missing", Screen::Notice(Notice::VolumeMissing)),
        plain("not-implemented", Screen::Notice(Notice::NotImplemented)),
        plain("no-installation", Screen::NoInstallation),
        plain("volumes-1", Screen::SelectVolume(volumes(1, false))),
        with(
            "volumes-8",
            Screen::SelectVolume(volumes(8, true)),
            text_then("", &[Key::Down, Key::Down]),
        ),
        with(
            "targets",
            Screen::SelectTarget(targets(&[
                ("debian.vhd", 214 << 30, TargetKind::Disk),
                ("rescue.efi", 112 << 20, TargetKind::EfiFile),
                ("arch.vhdx", 64 << 30, TargetKind::Disk),
            ])),
            text_then("", &[Key::Down]),
        ),
        plain("targets-empty", Screen::SelectTarget(TargetList::new())),
        plain(
            "targets-long",
            Screen::SelectTarget(targets(&[
                (
                    "ubuntu-24.04-desktop-with-a-very-long-descriptive-file-name-amd64.vhdx",
                    1_900_000_000_000,
                    TargetKind::Disk,
                ),
                ("Ünïcødé ñame – ☃.efi", 5 << 20, TargetKind::EfiFile),
            ])),
        ),
        refused,
        with(
            "path-typing",
            Screen::EnterPath,
            text_then("\\paguro\\rescue.efi", &[]),
        ),
        with(
            "roots",
            Screen::SelectRoot {
                efi: label("rescue.efi"),
                roots: targets(&[
                    ("debian.vhd", 214 << 30, TargetKind::Disk),
                    ("arch.vhdx", 64 << 30, TargetKind::Disk),
                ]),
            },
            text_then("", &[Key::End]),
        ),
    ]
}

pub const FIXTURES: usize = 33;

/// The resolutions the golden tests and `--all` render.
pub const RESOLUTIONS: [(u32, u32); 4] = [(800, 600), (1366, 768), (1920, 1080), (3840, 2160)];
