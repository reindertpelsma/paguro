//! Layout invariants for random resolutions (≥ 640×480), random labels and
//! typed text, every screen kind and every theme variant:
//!
//! - nothing is drawn outside the frame, and the draw list never overflows;
//! - every text run's ink stays inside its box (long text is cut with an
//!   ellipsis, never spilled);
//! - text boxes never overlap each other or an image;
//! - painting any of it never panics and never writes past the frame.
#![allow(clippy::indexing_slicing)]

use paguro_boot::platform::{
    Grey, Label, Notice, Row, Screen, Target, TargetKind, TargetList, UnlockMenu, VolumeChoice,
    VolumeFormat, VolumeList,
};
use paguro_boot::ui::{Key, Prompt};
use paguro_ui::builtin::THEMES;
use paguro_ui::draw::Cmd;
use paguro_ui::{Canvas, DrawList, Rect, Toast, View, layout, paint};
use proptest::prelude::*;

fn label_text() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-zA-Z0-9 ._-]{0,40}",
        "[a-zA-Z0-9]{60,110}",
        prop::collection::vec(any::<char>(), 0..30).prop_map(|v| v.into_iter().collect()),
        "[ÀÉÎÕÜàéîõüßñç☃€–—•…]{1,30}",
    ]
}

fn targets() -> impl Strategy<Value = TargetList> {
    prop::collection::vec((label_text(), any::<u64>(), any::<bool>()), 0..=8).prop_map(|v| {
        let mut t = TargetList::new();
        for (n, b, efi) in v {
            t.push(Target {
                name: Label::truncated(&n),
                bytes: b,
                kind: if efi {
                    TargetKind::EfiFile
                } else {
                    TargetKind::Disk
                },
            });
        }
        t
    })
}

fn screen() -> impl Strategy<Value = Screen> {
    let menu = (
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        0u8..5,
        any::<bool>(),
        any::<bool>(),
        0u32..40,
    )
        .prop_map(|(pw, pp, rk, tpm, unatt, first, n)| {
            Screen::Unlock(UnlockMenu {
                password_or_pin: pw,
                recovery_passphrase: pp,
                recovery_key: rk,
                tpm: match tpm {
                    0 => Ok(Some(n)),
                    1 => Ok(None),
                    2 => Err(Grey::RecoveryMode),
                    3 => Err(Grey::Locked),
                    _ => Err(Grey::Unavailable),
                },
                unattested: unatt,
                first_boot: first,
            })
        });
    let volumes = prop::collection::vec(
        (
            label_text(),
            any::<u8>(),
            any::<u32>(),
            any::<u64>(),
            any::<bool>(),
        ),
        1..=8,
    )
    .prop_map(|v| {
        let mut l = VolumeList::new();
        for (n, d, p, b, bl) in v {
            l.push(VolumeChoice {
                disk: d,
                partition: p,
                bytes: b,
                format: if bl {
                    VolumeFormat::BitLocker
                } else {
                    VolumeFormat::Ntfs
                },
                name: Label::truncated(&n),
            });
        }
        Screen::SelectVolume(l)
    });
    let fixed = prop::sample::select(vec![
        Screen::CannotUnlock,
        Screen::ConfigInvalid,
        Screen::TpmLocked,
        Screen::NoInstallation,
        Screen::Incorrect,
        Screen::PathRefused,
        Screen::EnterPath,
        Screen::Notice(Notice::Hibernated),
        Screen::Notice(Notice::Dirty),
        Screen::Notice(Notice::Pcr12NotZero),
        Screen::Notice(Notice::SealOverPlaintext),
        Screen::Notice(Notice::VolumeMissing),
        Screen::Notice(Notice::NotImplemented),
    ]);
    let secret = (
        prop::sample::select(vec![
            Row::PasswordOrPin,
            Row::RecoveryPassphrase,
            Row::RecoveryKey,
        ]),
        any::<bool>(),
    )
        .prop_map(|(row, unattested)| Screen::EnterSecret { row, unattested });
    prop_oneof![
        menu,
        volumes,
        fixed,
        secret,
        targets().prop_map(Screen::SelectTarget),
        (label_text(), targets()).prop_map(|(e, roots)| Screen::SelectRoot {
            efi: Label::truncated(&e),
            roots
        }),
    ]
}

fn keys() -> impl Strategy<Value = Vec<Key>> {
    prop::collection::vec(
        prop_oneof![
            6 => any::<char>().prop_map(Key::Char),
            4 => prop::sample::select(vec!['a', 'W', '5', '0', 'é', '€', ' ']).prop_map(Key::Char),
            1 => Just(Key::Left),
            1 => Just(Key::Insert),
            1 => Just(Key::Down),
            1 => Just(Key::Up),
            1 => Just(Key::Home),
        ],
        0..120,
    )
}

fn check(list: &DrawList<'_>, w: u32, h: u32) -> Result<(), TestCaseError> {
    let frame = Rect::new(0, 0, w as i32, h as i32);
    prop_assert_eq!(list.dropped, 0, "draw list overflowed");
    let mut texts: Vec<Rect> = Vec::new();
    let mut images: Vec<Rect> = Vec::new();
    for c in list.cmds() {
        match *c {
            Cmd::Nop => {}
            Cmd::Fill { r, .. } | Cmd::Stroke { r, .. } => {
                prop_assert!(frame.contains(&r), "shape {r:?} outside {w}x{h}");
            }
            Cmd::Image { img, x, y } => {
                let r = Rect::new(x, y, img.w as i32, img.h as i32);
                prop_assert!(frame.contains(&r), "image {r:?} outside {w}x{h}");
                images.push(r);
            }
            Cmd::Text(t) => {
                prop_assert!(
                    frame.contains(&t.bounds),
                    "text box {:?} outside {w}x{h}",
                    t.bounds
                );
                let ink = list.ink(&t);
                prop_assert!(
                    ink.w == 0 || (ink.x >= t.bounds.x && ink.right() <= t.bounds.right()),
                    "text ink {ink:?} leaves its box {:?}: {:?}",
                    t.bounds,
                    list.chars(&t.src).collect::<String>()
                );
                if !t.bounds.is_empty() && ink.w > 0 {
                    texts.push(t.bounds);
                }
            }
        }
    }
    for (i, a) in texts.iter().enumerate() {
        for b in texts.iter().skip(i + 1) {
            prop_assert!(!a.intersects(b), "text boxes overlap: {a:?} {b:?}");
        }
        for im in &images {
            prop_assert!(!a.intersects(im), "text {a:?} over image {im:?}");
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    #[test]
    fn layout_stays_in_bounds(
        w in 640u32..4200,
        h in 480u32..2400,
        screen in screen(),
        keys in keys(),
        theme in 0usize..8,
        toast in prop::option::of(prop::bool::ANY),
    ) {
        let theme = &THEMES[theme % THEMES.len()];
        let mut buf = [0u8; 256];
        let mut p = Prompt::new(&screen, &mut buf);
        for k in &keys {
            p.feed(&screen, *k, &mut buf);
        }
        let view = View {
            selected: p.selected(),
            field: p.field().copied(),
            buf: &buf,
            toast: toast.map(|b| if b { Toast::Incorrect } else { Toast::PathRefused }),
        };
        let mut list = DrawList::new();
        layout(&screen, &view, theme, w, h, &mut list);
        check(&list, w, h)?;
    }

    #[test]
    fn painting_never_escapes_the_frame(
        w in 640u32..1100,
        h in 480u32..800,
        stride_extra in 0u32..9,
        screen in screen(),
        keys in keys(),
        theme in 0usize..8,
    ) {
        let theme = &THEMES[theme % THEMES.len()];
        let mut buf = [0u8; 256];
        let mut p = Prompt::new(&screen, &mut buf);
        for k in &keys {
            p.feed(&screen, *k, &mut buf);
        }
        let view = View { selected: p.selected(), field: p.field().copied(), buf: &buf, toast: None };
        let mut list = DrawList::new();
        layout(&screen, &view, theme, w, h, &mut list);
        let stride = w + stride_extra;
        let mut frame = vec![0u8; (stride * h * 4) as usize + 64];
        let guard = frame.len() - 64;
        frame[guard..].fill(0xa5);
        {
            let mut c = Canvas::new(&mut frame, w, h, stride).unwrap();
            paint(&list, &mut c);
        }
        prop_assert!(frame[guard..].iter().all(|&b| b == 0xa5), "wrote past the frame");
        // The padding columns of a wider stride are never touched either.
        if stride_extra > 0 {
            for y in 0..h as usize {
                let row = &frame[(y * stride as usize + w as usize) * 4..(y + 1) * stride as usize * 4];
                prop_assert!(row.iter().all(|&b| b == 0), "wrote into the stride padding");
            }
        }
    }
}

/// The fixtures at a few awkward sizes, deterministically (no shrinking
/// needed to read a failure).
#[test]
fn fixtures_at_awkward_sizes() {
    for (w, h) in [
        (640, 480),
        (641, 481),
        (1024, 600),
        (1280, 720),
        (4096, 2160),
        (1080, 1920),
        (2560, 1080),
    ] {
        for theme in THEMES.iter() {
            for f in paguro_ui::fixtures::all().iter() {
                let mut list = DrawList::new();
                layout(&f.screen, &f.view(), theme, w, h, &mut list);
                if let Err(e) = check(&list, w, h) {
                    panic!("{} {} {w}x{h}: {e}", theme.name, f.name);
                }
                let texts = list
                    .cmds()
                    .iter()
                    .filter(|c| matches!(c, Cmd::Text(_)))
                    .count();
                assert!(texts >= 5, "{} {w}x{h}: only {texts} text runs", f.name);
            }
        }
    }
}
