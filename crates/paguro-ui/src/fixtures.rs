//! Named screens in representative states, for the preview tool
//! (`paguro-ui-preview`) and the golden tests. Host tooling only: nothing in
//! the loader calls this (the linker drops it).

use paguro_boot::platform::{
    DirItem, DirView, EntryKind, Grey, Label, Level, Listing, Notice, Row, Screen, UnlockMenu,
    VolumeChoice, VolumeFormat, VolumeList,
};
use paguro_boot::ui::{Field, Key, Prompt};
use paguro_core::config::Keyboard;

use crate::layout::{Toast, View};

/// A screen plus the interaction state it is shown in.
pub struct Fixture {
    pub name: &'static str,
    pub screen: Screen,
    pub selected: usize,
    pub field: Option<Field>,
    pub buf: [u8; 256],
    pub toast: Option<Toast>,
    /// The browsed directory: its path and entries.
    pub dir: Option<(&'static str, &'static StaticListing)>,
    /// The keyboard layout named on typed-text screens.
    pub keyboard: Keyboard,
}

impl Fixture {
    pub fn view(&self) -> View<'_> {
        View {
            selected: self.selected,
            field: self.field,
            buf: &self.buf,
            toast: self.toast,
            dir: self.dir.map(|(path, listing)| DirView {
                path,
                listing,
                selected: self.selected,
                level: match self.screen {
                    Screen::Browse(l) => l,
                    _ => Level::Volume,
                },
            }),
            keyboard: self.keyboard,
        }
    }
}

/// A directory listing in static memory.
pub struct StaticListing {
    pub items: &'static [(&'static str, EntryKind, u64)],
    pub more: bool,
}

impl Listing for StaticListing {
    fn len(&self) -> usize {
        self.items.len()
    }
    fn item(&self, i: usize) -> Option<DirItem<'_>> {
        self.items
            .get(i)
            .map(|&(name, kind, bytes)| DirItem { name, kind, bytes })
    }
    fn more(&self) -> bool {
        self.more
    }
}

use EntryKind::{Dir as D, Disk as K, Efi as E};

static PAGURO: StaticListing = StaticListing {
    items: &[
        ("Old", D, 0),
        ("tools", D, 0),
        ("arch.vhdx", K, 64 << 30),
        ("debian.vhd", K, 214 << 30),
        ("rescue.efi", E, 112 << 20),
    ],
    more: false,
};
static ROOTS: StaticListing = StaticListing {
    items: &[
        ("vms", D, 0),
        ("arch.vhdx", K, 64 << 30),
        ("debian.vhd", K, 214 << 30),
    ],
    more: false,
};
static EMPTY: StaticListing = StaticListing {
    items: &[],
    more: false,
};
static DEEP: StaticListing = StaticListing {
    items: &[
        ("snapshot-before-upgrade-2024-06-01.vhdx", K, 88 << 30),
        ("ubuntu-24.04.vhdx", K, 120 << 30),
    ],
    more: false,
};
static ESP: StaticListing = StaticListing {
    items: &[
        ("BOOT", D, 0),
        ("Linux", D, 0),
        ("systemd", D, 0),
        ("ubuntu", D, 0),
        ("grubx64.efi", E, 2 << 20),
    ],
    more: false,
};
static MORE: StaticListing = StaticListing {
    items: &[
        ("a", D, 0),
        ("b", D, 0),
        ("c.vhd", K, 1 << 30),
        ("d.efi", E, 1 << 20),
    ],
    more: true,
};
static LONG: StaticListing = StaticListing {
    items: &LONG_ITEMS,
    more: false,
};
static LONG_ITEMS: [(&str, EntryKind, u64); 40] = [
    ("backup-00", D, 0),
    ("backup-01", D, 0),
    ("backup-02", D, 0),
    ("backup-03", D, 0),
    ("backup-04", D, 0),
    ("backup-05", D, 0),
    ("backup-06", D, 0),
    ("backup-07", D, 0),
    ("kernel-6.0.0-generic.efi", E, 20 << 20),
    ("kernel-6.1.3-generic.efi", E, 21 << 20),
    ("kernel-6.2.6-generic.efi", E, 22 << 20),
    ("kernel-6.3.9-generic.efi", E, 23 << 20),
    ("kernel-6.4.1-generic.efi", E, 24 << 20),
    ("kernel-6.5.4-generic.efi", E, 25 << 20),
    ("kernel-6.6.7-generic.efi", E, 26 << 20),
    ("kernel-6.7.10-generic.efi", E, 27 << 20),
    ("kernel-6.8.2-generic.efi", E, 28 << 20),
    ("kernel-6.9.5-generic.efi", E, 29 << 20),
    ("kernel-6.10.8-generic.efi", E, 30 << 20),
    ("kernel-6.11.0-generic.efi", E, 31 << 20),
    ("kernel-6.12.3-generic.efi", E, 32 << 20),
    ("kernel-6.13.6-generic.efi", E, 33 << 20),
    ("kernel-6.14.9-generic.efi", E, 34 << 20),
    ("kernel-6.15.1-generic.efi", E, 35 << 20),
    ("vm-a-test.vhdx", K, 8 << 30),
    ("vm-b.vhdx", K, 16 << 30),
    ("vm-c.vhdx", K, 24 << 30),
    ("vm-d-test.vhdx", K, 32 << 30),
    ("vm-e.vhdx", K, 40 << 30),
    ("vm-f.vhdx", K, 48 << 30),
    ("vm-g-test.vhdx", K, 56 << 30),
    ("vm-h.vhdx", K, 64 << 30),
    ("vm-i.vhdx", K, 72 << 30),
    ("vm-j-test.vhdx", K, 80 << 30),
    ("vm-k.vhdx", K, 88 << 30),
    ("vm-l.vhdx", K, 96 << 30),
    ("vm-m-test.vhdx", K, 104 << 30),
    ("vm-n.vhdx", K, 112 << 30),
    ("vm-o.vhdx", K, 120 << 30),
    ("vm-p-test.vhdx", K, 128 << 30),
];
const DEEP_PATH: &str =
    "\\Users\\alice\\Documents\\Virtual Machines\\Linux\\Ubuntu 24.04 LTS (desktop)\\disks\\2024";

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

/// Type `keys` into a fresh prompt for `screen`.
fn typed(name: &'static str, screen: Screen, keys: &[Key]) -> Fixture {
    let mut f = Fixture {
        name,
        screen,
        selected: 0,
        field: None,
        buf: [0; 256],
        toast: None,
        dir: None,
        keyboard: Keyboard::Us,
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
    let browse = |name, level, path, listing: &'static StaticListing, selected| Fixture {
        name,
        screen: Screen::Browse(level),
        selected,
        field: None,
        buf: [0; 256],
        toast: None,
        dir: Some((path, listing)),
        keyboard: Keyboard::Us,
    };
    let mut refused = browse("browse-path-refused", Level::Volume, "\\paguro", &PAGURO, 5);
    refused.toast = Some(Toast::PathRefused);
    let disk = Screen::DiskStart {
        disk: label("debian.vhd"),
    };
    let mut no_esp = plain("disk-start-no-esp", disk);
    no_esp.toast = Some(Toast::NoEfiPartition);
    no_esp.selected = 1;
    let mut german = with(
        "password-keyboard-de",
        Screen::EnterSecret {
            row: Row::RecoveryPassphrase,
            unattested: false,
        },
        text_then("Grüße", &[]),
    );
    german.keyboard = Keyboard::De;
    let langs = u8::try_from(crate::builtin::BY_LANG.len()).unwrap_or(1);
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
            "volumes-8-bottom",
            Screen::SelectVolume(volumes(8, false)),
            text_then("", &[Key::End]),
        ),
        browse("browse-paguro", Level::Volume, "\\paguro", &PAGURO, 0),
        browse(
            "browse-disk-selected",
            Level::Volume,
            "\\paguro",
            &PAGURO,
            3,
        ),
        browse("browse-efi-selected", Level::Volume, "\\paguro", &PAGURO, 4),
        browse("browse-empty", Level::Volume, "\\paguro\\Old", &EMPTY, 0),
        browse(
            "browse-long-top",
            Level::Volume,
            "\\paguro\\tools",
            &LONG,
            0,
        ),
        browse(
            "browse-long-scrolled",
            Level::Volume,
            "\\paguro\\tools",
            &LONG,
            30,
        ),
        browse(
            "browse-long-bottom",
            Level::Volume,
            "\\paguro\\tools",
            &LONG,
            40,
        ),
        browse("browse-deep", Level::Volume, DEEP_PATH, &DEEP, 1),
        browse("browse-esp", Level::EfiPartition, "\\EFI", &ESP, 2),
        browse("browse-more", Level::Volume, "\\", &MORE, 0),
        refused,
        plain("disk-start", disk),
        no_esp,
        with(
            "path-typing",
            Screen::EnterPath(Level::Volume),
            text_then("\\paguro\\rescue.efi", &[]),
        ),
        with(
            "path-typing-esp",
            Screen::EnterPath(Level::EfiPartition),
            text_then("\\EFI\\systemd\\systemd-bootx64.efi", &[]),
        ),
        browse("browse-root", Level::Root, "\\paguro", &ROOTS, 2),
        browse("browse-root-none", Level::Root, "\\paguro", &ROOTS, 4),
        german,
        plain(
            "keyboards",
            Screen::ChooseKeyboard {
                current: Keyboard::De,
            },
        ),
        with(
            "keyboards-bottom",
            Screen::ChooseKeyboard {
                current: Keyboard::Us,
            },
            text_then("", &[Key::End]),
        ),
        plain(
            "languages",
            Screen::ChooseLanguage {
                current: 0,
                count: langs,
            },
        ),
    ]
}

pub const FIXTURES: usize = 49;

/// The resolutions the golden tests and `--all` render.
pub const RESOLUTIONS: [(u32, u32); 4] = [(800, 600), (1366, 768), (1920, 1080), (3840, 2160)];
