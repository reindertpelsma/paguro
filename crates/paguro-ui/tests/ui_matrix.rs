//! Whole boots through the real front end on the host (INTERFACES.md
//! §13.2a, §13.2b, §13.5): every variant in every mode (graphics, text,
//! auto with a serial mirror), several displays, text mode on displays the
//! firmware console does not cover, F2/F3/F4/F5 mid-boot, keyboard layouts,
//! the pointer (rows, fields, hints, actions, list arrows, the wheel), and
//! the browser's typed paths.
#![allow(clippy::indexing_slicing, dead_code)]

mod common;
#[path = "../../paguro-boot/tests/mock/mod.rs"]
mod mock;

use common::*;
use mock::*;
use paguro_boot::Outcome;
use paguro_boot::keymap::{self, Keyboard, Typed};
use paguro_boot::platform::{Level, Row, Screen, UnlockMenu};
use paguro_boot::ui::Key;
use paguro_core::config::{UiMode, UiTheme};
use paguro_core::handoff::Rung;
use paguro_ui::builtin::{BY_LANG, THEMES};
use paguro_ui::draw::{DrawList, Target};
use paguro_ui::driver::Event;
use paguro_ui::pointer::Report;
use paguro_ui::{View, layout};

fn with_ui(w: &mut World, ui: &str) {
    let mut ini = w.ini.clone();
    ini.extend_from_slice(format!("\n[UI]\n{ui}\n").as_bytes());
    w.set_ini(ini, true);
}

fn pin_script() -> Vec<Key> {
    let mut s = vec![Key::Enter];
    s.extend(keys(PIN));
    s.push(Key::Enter);
    s
}

// ---------------------------------------------------------------------------
// Variants × modes

#[test]
fn every_variant_in_every_mode() {
    for (vi, theme) in UiTheme::ALL.into_iter().enumerate() {
        for mode in UiMode::ALL {
            let mut w = World::new();
            with_ui(
                &mut w,
                &format!("theme = {}\nmode = {}", theme.name(), mode.name()),
            );
            w.with_tpm_seal(PIN);
            let serial = mode == UiMode::Auto;
            let d = Mem::new(&[(800, 600, true)], serial).keys(&pin_script());
            let (out, g) = boot_with(&mut w, d, None);
            let ctx = format!("{} {}", theme.name(), mode.name());
            assert_eq!(out, Outcome::Started(Rung::Tpm), "{ctx}: {:?}", g.m.log);
            let bg = THEMES[vi].palette.background;
            let console = g.d.console.as_ref().unwrap();
            match mode {
                UiMode::Graphics | UiMode::Auto => {
                    let unlock =
                        g.d.shown
                            .iter()
                            .find(|f| matches!(f.screen, Some(Screen::Unlock(_))))
                            .unwrap_or_else(|| panic!("{ctx}: no unlock frame"));
                    assert_eq!(dominant(&unlock.px), bg, "{ctx}");
                    assert!(console.grids.is_empty(), "{ctx}: ConOut untouched");
                }
                UiMode::Text => {
                    assert!(g.d.shown.is_empty(), "{ctx}: no graphics");
                    assert!(
                        g.d.displays[0].px.iter().all(|&b| b == 0),
                        "{ctx}: the display is ConOut's"
                    );
                    let all = console.all_text();
                    assert!(all.contains("Unlock Linux"), "{ctx}");
                    assert!(all.contains("Enter your password or PIN"), "{ctx}");
                    assert!(all.contains(&"*".repeat(PIN.len())), "{ctx}: bullets");
                    assert!(!all.contains(PIN), "{ctx}: the secret is never shown");
                    assert!(all.contains("[F3] graphics"), "{ctx}: F3 offered");
                }
            }
            match (&g.d.serial, serial) {
                (Some(s), true) => {
                    assert!(s.bytes.contains("\x1b[2J"), "{ctx}: VT100");
                    let all = s.all_text();
                    assert!(all.contains("Unlock Linux"), "{ctx}");
                    assert!(all.contains("Enter your password or PIN"), "{ctx}");
                    assert!(!all.contains(PIN), "{ctx}");
                    assert!(!all.contains("[F3]"), "{ctx}: F3 acts on the local display");
                }
                (None, false) => {}
                _ => panic!("{ctx}: serial mirror"),
            }
        }
    }
}

#[test]
fn without_gop_the_text_ui_is_on_conout() {
    let mut w = World::new();
    w.with_tpm_seal(PIN);
    let d = Mem::new(&[], false).keys(&pin_script());
    let (out, g) = boot_with(&mut w, d, None);
    assert_eq!(out, Outcome::Started(Rung::Tpm));
    let all = g.d.console.as_ref().unwrap().all_text();
    assert!(all.contains("Unlock Linux") && all.contains("3 TPM attempts left"));
    assert!(!all.contains("[F3]"), "nothing to switch to");
}

#[test]
fn text_mode_paints_displays_conout_does_not_cover() {
    let mut w = World::new();
    with_ui(&mut w, "mode = text\ntheme = light");
    w.with_tpm_seal(PIN);
    let d = Mem::new(&[(800, 600, true), (1024, 768, false)], false).keys(&pin_script());
    let (out, g) = boot_with(&mut w, d, None);
    assert_eq!(out, Outcome::Started(Rung::Tpm));
    assert!(
        g.d.displays[0].px.iter().all(|&b| b == 0),
        "ConOut's display"
    );
    let other = &g.d.displays[1].px;
    assert_eq!(
        dominant(other),
        THEMES[1].palette.background,
        "painted text UI"
    );
    assert!(has_color(other, THEMES[1].palette.text));
    assert!(
        g.d.console
            .as_ref()
            .unwrap()
            .all_text()
            .contains("Unlock Linux")
    );
}

#[test]
fn f2_and_f3_mid_boot() {
    let mut w = World::new();
    w.with_tpm_seal(PIN);
    // F2 (light), F3 (text), F3 (graphics again), then the PIN.
    let mut script = vec![Key::Function(2), Key::Function(3), Key::Function(3)];
    script.extend(pin_script());
    let d = Mem::new(&[(800, 600, true)], true).keys(&script);
    let (out, g) = boot_with(&mut w, d, None);
    assert_eq!(out, Outcome::Started(Rung::Tpm));
    let bgs: Vec<_> = g.d.shown.iter().map(|f| dominant(&f.px)).collect();
    assert_eq!(bgs[0], THEMES[0].palette.background, "dark first");
    assert_eq!(bgs[1], THEMES[1].palette.background, "F2: light");
    assert_eq!(
        *bgs.last().unwrap(),
        THEMES[1].palette.background,
        "stays light"
    );
    let console = g.d.console.as_ref().unwrap();
    assert_eq!(console.grids.len(), 1, "one text frame while F3 was on");
    assert!(console.grids[0].1, "a full redraw on switching");
    assert!(console.text().contains("[F3] graphics"));
    assert!(!g.d.text, "back to graphics");
    // The serial mirror kept going the whole time.
    assert!(g.d.serial.as_ref().unwrap().grids.len() >= 4);
}

#[test]
fn several_displays_one_render_per_resolution() {
    let mut w = World::new();
    w.with_tpm_seal(PIN);
    let d = Mem::new(
        &[(1920, 1080, true), (1920, 1080, true), (1280, 1024, true)],
        false,
    )
    .keys(&pin_script());
    assert_eq!(d.sizes.len(), 2);
    let (out, g) = boot_with(&mut w, d, None);
    assert_eq!(out, Outcome::Started(Rung::Tpm));
    assert_eq!(g.d.displays[0].px, g.d.displays[1].px, "mirrored");
    let bg = THEMES[0].palette.background;
    for d in &g.d.displays {
        assert_eq!(dominant(&d.px), bg);
    }
    // Every full present went to one of the two frames.
    assert!(g.d.presents.iter().all(|(i, _, _)| *i < 2));
    let f0 = g.d.presents.iter().filter(|(i, _, _)| *i == 0).count();
    let f1 = g.d.presents.iter().filter(|(i, _, _)| *i == 1).count();
    assert_eq!(f0, f1, "each frame drawn once per change");
}

// ---------------------------------------------------------------------------
// Languages and keyboard layouts

/// What US firmware reports for `s` typed on `layout` (the inverse table).
fn typed_on(layout: Keyboard, s: &str) -> Vec<Event> {
    let t = keymap::table(layout);
    let us = keymap::table(Keyboard::Us);
    s.chars()
        .map(|c| {
            if c == ' ' {
                return Event::Typed(Typed::plain(' '));
            }
            for (k, lv) in t.iter().enumerate() {
                for (level, &ch) in lv.iter().enumerate() {
                    if ch == c {
                        return Event::Typed(Typed {
                            ch: us[k][level & 1],
                            shift: Some(level & 1 == 1),
                            altgr: level >= 2,
                            caps: Some(false),
                        });
                    }
                }
            }
            panic!("{c:?} is not on {layout:?}")
        })
        .collect()
}

fn passphrase_boot(ui: &str, pass: &str, events: Vec<Event>) -> (Outcome, Gop) {
    let mut w = World::new();
    if !ui.is_empty() {
        with_ui(&mut w, ui);
    }
    w.with_passphrase_seal(pass);
    let mut d = Mem::new(&[(800, 600, true)], true);
    d.events.push_back(Event::Key(Key::Char('2')));
    d.events.extend(events);
    d.events.push_back(Event::Key(Key::Enter));
    boot_with(&mut w, d, None)
}

#[test]
fn german_and_french_passphrases_through_their_layouts() {
    for (layout, ui, pass) in [
        (Keyboard::De, "keyboard = de", "Zürich-Straße #1 {ÄÖÜ} @€"),
        (
            Keyboard::Fr,
            "keyboard = fr",
            "Déjà vu: azerty & qwerty 1234 @",
        ),
        (Keyboard::ChDe, "keyboard = ch-de", "Grüezi zäme 99!"),
        (Keyboard::Es, "keyboard = es", "Año ñu ¿Q? ºª ç"),
        (Keyboard::Uk, "keyboard = uk", "£5 \"quoted\" @home #tag"),
        (Keyboard::Be, "keyboard = be", "Mémé à Bruxelles 2024"),
        (Keyboard::NlIntl, "keyboard = nl-intl", "Een test 123"),
    ] {
        let (out, g) = passphrase_boot(ui, pass, typed_on(layout, pass));
        assert_eq!(
            out,
            Outcome::Started(Rung::Passphrase),
            "{layout:?}: {:?}",
            g.m.log
        );
        // The screen names the layout.
        let serial = g.d.serial.as_ref().unwrap().all_text();
        assert!(serial.contains("Keyboard: "), "{layout:?}");
    }
    // The same key presses without the layout do not unlock.
    let pass = "Zürich-Straße";
    let (out, _) = passphrase_boot("", pass, typed_on(Keyboard::De, pass));
    assert_ne!(out, Outcome::Started(Rung::Passphrase));
}

#[test]
fn f4_picks_a_layout_on_screen_and_esc_keeps_it() {
    let pass = "yzYZ";
    let mut w = World::new();
    w.with_passphrase_seal(pass);
    let mut d = Mem::new(&[(800, 600, true)], true);
    // On the passphrase screen: F4, Down twice to German, Enter; then F4
    // and Esc (no change); then type on a German keyboard.
    d.events.push_back(Event::Key(Key::Char('2')));
    d.events.extend(
        [
            Key::Function(4),
            Key::Down,
            Key::Down,
            Key::Enter,
            Key::Function(4),
            Key::Escape,
        ]
        .map(Event::Key),
    );
    d.events.extend(typed_on(Keyboard::De, pass));
    d.events.push_back(Event::Key(Key::Enter));
    let (out, g) = boot_with(&mut w, d, None);
    assert_eq!(out, Outcome::Started(Rung::Passphrase), "{:?}", g.m.log);
    assert_eq!(g.s.keyboard, Keyboard::De);
    assert!(
        g.d.shown_screens
            .iter()
            .any(|s| matches!(s, Screen::ChooseKeyboard { .. }))
    );
    let serial = g.d.serial.as_ref().unwrap().all_text();
    assert!(serial.contains("Keyboard layout"));
    assert!(serial.contains("Keyboard: German"));
}

#[test]
fn recovery_starts_in_us_and_dark() {
    let mut w = World::new();
    with_ui(&mut w, "theme = light\nkeyboard = fr");
    w.with_tpm_seal(PIN).with_passphrase_seal("pw");
    // R: voluntary recovery; the passphrase then is typed as US.
    let mut d = Mem::new(&[(800, 600, true)], false);
    d.events.push_back(Event::Key(Key::Char('r')));
    d.events.push_back(Event::Key(Key::Char('2')));
    d.events.extend(typed("pw"));
    d.events.push_back(Event::Key(Key::Enter));
    let (out, g) = boot_with(&mut w, d, None);
    assert_eq!(out, Outcome::Started(Rung::Passphrase), "{:?}", g.m.log);
    assert_eq!(g.s.keyboard, Keyboard::Us);
    assert_eq!(
        dominant(&g.d.shown.last().unwrap().px),
        THEMES[0].palette.background
    );
    assert_eq!(
        dominant(&g.d.shown[0].px),
        THEMES[1].palette.background,
        "light before"
    );
}

#[test]
fn f5_switches_the_language_for_the_rest_of_the_boot() {
    let mut w = World::new();
    w.with_tpm_seal(PIN);
    let nl = paguro_ui::builtin::LANGS
        .iter()
        .position(|l| *l == "nl")
        .unwrap();
    let mut script = vec![Key::Function(5)];
    script.extend(std::iter::repeat_n(Key::Down, nl));
    script.push(Key::Enter);
    script.extend(pin_script());
    let d = Mem::new(&[(800, 600, true)], true).keys(&script);
    let (out, g) = boot_with(&mut w, d, None);
    assert_eq!(out, Outcome::Started(Rung::Tpm));
    assert_eq!(g.s.lang, nl);
    let serial = g.d.serial.as_ref().unwrap().all_text();
    assert!(serial.contains("Linux ontgrendelen"));
    assert!(serial.contains("Voer je wachtwoord of pincode in"));
    // English is always there to go back to.
    assert!(serial.contains("English"));
    assert_eq!(BY_LANG[g.s.lang][0].palette, THEMES[0].palette);
}

// ---------------------------------------------------------------------------
// The pointer

/// The centre of the first element with `target` on `screen` at 800×600,
/// as an absolute pointer position.
fn at(screen: &Screen, view: &View<'_>, target: Target) -> (u64, u64) {
    let mut list = DrawList::new();
    layout(screen, view, &THEMES[0], 800, 600, &mut list);
    let h = list
        .hits
        .as_slice()
        .iter()
        .find(|h| h.target == target)
        .unwrap_or_else(|| panic!("no {target:?} on {screen:?}"));
    let (x, y) = (h.rect.x + h.rect.w / 2, h.rect.y + h.rect.h / 2);
    (
        (x as u64 * 0xffff).div_ceil(799),
        (y as u64 * 0xffff).div_ceil(599),
    )
}

fn click(pos: (u64, u64)) -> [Event; 3] {
    [
        pointer_move(pos.0, pos.1, false),
        pointer_move(pos.0, pos.1, true),
        pointer_move(pos.0, pos.1, false),
    ]
}

const MENU: UnlockMenu = UnlockMenu {
    password_or_pin: true,
    recovery_passphrase: true,
    recovery_key: true,
    tpm: Ok(Some(3)),
    unattested: false,
    first_boot: false,
};

#[test]
fn clicking_a_row_then_typing() {
    let mut w = World::new();
    w.with_tpm_seal(PIN).with_passphrase_seal("pw");
    let unlock = Screen::Unlock(MENU);
    let mut d = Mem::new(&[(800, 600, true)], false);
    d.events
        .extend(click(at(&unlock, &View::IDLE, Target::Row(1))));
    d.events.extend(typed("pw"));
    d.events.push_back(Event::Key(Key::Enter));
    let (out, g) = boot_with(&mut w, d, None);
    assert_eq!(out, Outcome::Started(Rung::Passphrase), "{:?}", g.m.log);
    // The cursor was drawn with only its rectangles, then hidden by typing.
    let cursor_presents: Vec<_> = g.d.presents.iter().filter(|p| p.2).collect();
    assert!(
        cursor_presents.iter().any(|(_, r, _)| r.w < 40 && r.h < 40),
        "a move redraws the cursor's rectangle only: {cursor_presents:?}"
    );
}

#[test]
fn clicking_hints_and_actions_acts_as_their_keys() {
    // The Esc hint on the unlock screen leads to "Cannot unlock"; its
    // "Start Windows" action ends the boot.
    let mut w = World::new();
    w.with_tpm_seal(PIN);
    let unlock = Screen::Unlock(UnlockMenu {
        recovery_passphrase: false,
        ..MENU
    });
    let mut d = Mem::new(&[(800, 600, true)], false);
    d.events
        .extend(click(at(&unlock, &View::IDLE, Target::Key(Key::Escape))));
    d.events.extend(click(at(
        &Screen::CannotUnlock,
        &View::IDLE,
        Target::Key(Key::Enter),
    )));
    let (out, g) = boot_with(&mut w, d, None);
    assert!(
        g.m.screens.contains(&Screen::CannotUnlock),
        "{:?}",
        g.m.screens
    );
    assert_eq!(out, Outcome::StartWindows);
}

#[test]
fn the_f2_hint_by_pointer_and_the_cursor_on_the_new_variant() {
    let mut w = World::new();
    w.with_tpm_seal(PIN);
    let unlock = Screen::Unlock(UnlockMenu {
        recovery_passphrase: false,
        ..MENU
    });
    let mut d = Mem::new(&[(800, 600, true)], false);
    d.events.extend(click(at(
        &unlock,
        &View::IDLE,
        Target::Key(Key::Function(2)),
    )));
    d.events.extend(pin_script().into_iter().map(Event::Key));
    let (out, g) = boot_with(&mut w, d, None);
    assert_eq!(out, Outcome::Started(Rung::Tpm));
    assert_eq!(g.s.theme, 1);
}

#[test]
fn a_click_in_the_field_moves_the_text_cursor() {
    // Recovery: type a path without its leading backslash, click before
    // its first character, add it.
    let mut w = World::new();
    w.m.files.remove("paguro.ini");
    w.v.clear_key = Some(VMK);
    w.v.dir("\\paguro", &[]);
    let path = Screen::EnterPath(Level::Volume);
    let mut d = Mem::new(&[(800, 600, true)], false);
    d.events.push_back(Event::Key(Key::Enter)); // "Type a path"
    d.events
        .extend(keys("paguroXdebian.vhd").into_iter().map(Event::Key));
    // Click at the left end of the field (the first stop).
    let mut list = DrawList::new();
    let mut buf = [0u8; 64];
    let mut p = paguro_boot::ui::Prompt::new(&path, &mut buf);
    for k in keys("paguroXdebian.vhd") {
        p.feed(&path, k, &mut buf);
    }
    let view = View {
        field: p.field().copied(),
        buf: &buf,
        ..View::IDLE
    };
    layout(&path, &view, &THEMES[0], 800, 600, &mut list);
    let field = list
        .hits
        .as_slice()
        .iter()
        .find(|h| h.target == Target::Field)
        .unwrap()
        .rect;
    let (fx, fy) = (field.x + 3, field.y + field.h / 2);
    assert_eq!(list.hits.char_at(fx, fy), Some(0), "the first stop");
    assert_eq!(
        list.hits.char_at(field.right() - 3, fy),
        Some(17),
        "the last"
    );
    let pos = (
        (fx as u64 * 0xffff).div_ceil(799),
        (fy as u64 * 0xffff).div_ceil(599),
    );
    d.events.extend(click(pos));
    d.events.push_back(Event::Key(Key::Char('\\')));
    // Fix the X: End, Left × 10, Backspace, '\\'.
    d.events.push_back(Event::Key(Key::End));
    d.events
        .extend(std::iter::repeat_n(Event::Key(Key::Left), 10));
    d.events.push_back(Event::Key(Key::Backspace));
    d.events.push_back(Event::Key(Key::Char('\\')));
    d.events.push_back(Event::Key(Key::Enter));
    d.events.push_back(Event::Key(Key::Enter)); // the disk's default image
    let (out, g) = boot_with(&mut w, d, None);
    assert_eq!(out, Outcome::Started(Rung::ClearKey), "{:?}", g.m.log);
    assert_eq!(
        w.v.saw_entry.clone().unwrap().root.as_deref(),
        Some("\\paguro\\debian.vhd")
    );
}

#[test]
fn the_wheel_and_the_list_arrows_scroll() {
    let names: Vec<String> = (0..30).map(|i| format!("disk{i}.vhd")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let mut w = World::new();
    w.m.files.remove("paguro.ini");
    w.v.clear_key = Some(VMK);
    w.v.dir("\\paguro", &refs);
    let mut d = Mem::new(&[(800, 600, true)], false);
    // Wheel down 3, then Enter: the fourth entry (natural order: disk3).
    d.events.push_back(Event::Pointer(Report::Relative {
        dx: 0,
        dy: 0,
        dz: 3,
        resolution: 0,
        left: false,
    }));
    d.events.push_back(Event::Key(Key::Enter));
    d.events.push_back(Event::Key(Key::Enter));
    let (out, g) = boot_with(&mut w, d, None);
    assert_eq!(out, Outcome::Started(Rung::ClearKey), "{:?}", g.m.log);
    assert_eq!(
        w.v.saw_entry.clone().unwrap().root.as_deref(),
        Some("\\paguro\\disk3.vhd")
    );
    // disk3, not disk11: the listing is in natural order.
}

#[test]
fn the_more_below_arrow_pages_down() {
    let names: Vec<String> = (0..30).map(|i| format!("disk{i:02}.vhd")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let mut w = World::new();
    w.m.files.remove("paguro.ini");
    w.v.clear_key = Some(VMK);
    w.v.dir("\\paguro", &refs);
    // Where "↓ n more" is on the browser's first view.
    let listing = paguro_ui::fixtures::StaticListing {
        items: Box::leak(
            names
                .iter()
                .map(|n| {
                    (
                        &*Box::leak(n.clone().into_boxed_str()),
                        paguro_boot::platform::EntryKind::Disk,
                        1u64 << 30,
                    )
                })
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        ),
        more: false,
    };
    let dir = paguro_boot::platform::DirView {
        path: "\\paguro",
        listing: &listing,
        selected: 0,
        level: Level::Volume,
    };
    let browse = Screen::Browse(Level::Volume);
    let view = View {
        dir: Some(dir),
        ..View::IDLE
    };
    let mut list = DrawList::new();
    layout(&browse, &view, &THEMES[0], 800, 600, &mut list);
    let page = list.page;
    let mut d = Mem::new(&[(800, 600, true)], false);
    d.events
        .extend(click(at(&browse, &view, Target::Key(Key::PageDown))));
    d.events.push_back(Event::Key(Key::Enter));
    d.events.push_back(Event::Key(Key::Enter));
    let (out, g) = boot_with(&mut w, d, None);
    assert_eq!(out, Outcome::Started(Rung::ClearKey), "{:?}", g.m.log);
    assert_eq!(
        w.v.saw_entry.clone().unwrap().root.as_deref(),
        Some(format!("\\paguro\\disk{page:02}.vhd").as_str())
    );
}

#[test]
fn pointer_reports_that_make_no_sense_are_ignored() {
    let mut w = World::new();
    w.with_tpm_seal(PIN);
    let mut d = Mem::new(&[(800, 600, true)], false);
    d.events.push_back(Event::Pointer(Report::Absolute {
        x: 5,
        y: 5,
        min: (10, 10),
        max: (10, 10),
        touch: true,
    }));
    d.events.extend(pin_script().into_iter().map(Event::Key));
    let (out, g) = boot_with(&mut w, d, None);
    assert_eq!(out, Outcome::Started(Rung::Tpm));
    assert!(g.d.presents.iter().all(|p| !p.2), "no cursor ever drawn");
}

#[test]
fn the_cursor_lives_on_one_display() {
    let mut w = World::new();
    w.with_tpm_seal(PIN);
    let mut d = Mem::new(&[(800, 600, true), (800, 600, true)], false);
    d.events.push_back(pointer_move(0x8000, 0x8000, false));
    // Record the displays with the cursor showing: Esc on the unlock
    // screen is "Cannot unlock", where the boot ends on the next Esc.
    d.events.push_back(pointer_move(0x8000, 0x8000, false));
    let (_, g) = boot_with(&mut w, d, None);
    let (a, b) = (&g.d.displays[0].px, &g.d.displays[1].px);
    // After the moves and the Esc keys the cursor is hidden again: both
    // show the same frame.
    assert_eq!(a, b);
    let with_cursor: Vec<_> = g.d.presents.iter().filter(|p| p.2).collect();
    assert!(!with_cursor.is_empty());
}

#[test]
fn text_mode_ignores_the_pointer() {
    let mut w = World::new();
    with_ui(&mut w, "mode = text");
    w.with_tpm_seal(PIN);
    let mut d = Mem::new(&[(800, 600, true)], false);
    d.events.extend(click((0x8000, 0x8000)));
    d.events.extend(pin_script().into_iter().map(Event::Key));
    let (out, g) = boot_with(&mut w, d, None);
    assert_eq!(out, Outcome::Started(Rung::Tpm));
    assert!(g.d.presents.is_empty());
}

// ---------------------------------------------------------------------------
// The browser

#[test]
fn slash_in_the_browser_starts_a_typed_path() {
    let mut w = World::new();
    w.m.files.remove("paguro.ini");
    w.v.clear_key = Some(VMK);
    w.v.dir("\\paguro", &["a.vhd", "b.vhd"]);
    let mut d = Mem::new(&[(800, 600, true)], true);
    d.events.push_back(Event::Key(Key::Char('/')));
    d.events
        .extend(keys("C:/paguro/b.vhd").into_iter().map(Event::Key));
    d.events.push_back(Event::Key(Key::Enter));
    d.events.push_back(Event::Key(Key::Enter));
    let (out, g) = boot_with(&mut w, d, None);
    assert_eq!(out, Outcome::Started(Rung::ClearKey), "{:?}", g.m.log);
    assert_eq!(
        w.v.saw_entry.clone().unwrap().root.as_deref(),
        Some("\\paguro\\b.vhd")
    );
    assert!(g.m.logged("drive letter ignored"));
    let serial = g.d.serial.as_ref().unwrap().all_text();
    assert!(serial.contains("A drive letter such as C: is ignored"));
}

#[test]
fn every_screen_says_paguro_in_text_and_every_language() {
    use paguro_ui::textui::{self, Grid, Opts};
    let fx = paguro_ui::fixtures::all();
    let mut list = DrawList::new();
    let mut grid = Grid::new();
    for lang in BY_LANG.iter() {
        for theme in lang.iter() {
            for f in &fx {
                textui::render(
                    &f.screen,
                    &f.view(),
                    theme,
                    &Opts::default(),
                    &mut list,
                    &mut grid,
                );
                let text = grid_text(&grid);
                assert!(text.starts_with(" paguro\n"), "{}: {}", f.name, text);
                assert!(!text.chars().any(|c| c.is_control() && c != '\n'));
            }
        }
    }
}

#[test]
fn the_serial_console_drives_the_unlock_with_escape_sequences() {
    // Arrows as VT100 sequences (decoded by paguro_boot::vt100 in the
    // adapter): here as the keys they decode to, after the decoder.
    let mut dec = paguro_boot::vt100::Decoder::new();
    let bytes = b"\x1b[B\x1b[A\r";
    let mut script: Vec<Key> = bytes.iter().filter_map(|&b| dec.feed(b)).collect();
    script.extend(keys(PIN));
    script.push(Key::Enter);
    let mut w = World::new();
    w.with_tpm_seal(PIN);
    let d = Mem::new(&[(800, 600, true)], true).keys(&script);
    let (out, g) = boot_with(&mut w, d, None);
    assert_eq!(out, Outcome::Started(Rung::Tpm), "{:?}", g.m.log);
    let _ = Row::PasswordOrPin;
}
