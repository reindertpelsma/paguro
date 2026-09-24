//! Choosing each display's graphics mode (INTERFACES.md §13.2a), as a pure
//! function the firmware adapter calls once per GOP device with what GOP
//! and EDID report (host-tested; the adapter only queries and sets).
//!
//! The rule: a display shows the UI at its own preferred resolution (the
//! EDID's first detailed timing, `paguro_core::edid`), and **never in a
//! mode larger than one display in either direction** — firmware that
//! drives two panels as one 3840×1080 surface while each reports 1920×1080
//! would otherwise get a UI split across two screens. Without EDID the
//! firmware's choice stands.

use crate::layout::supported;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModeChoice {
    /// The current mode is right: do not touch the display.
    Keep,
    /// Switch to mode number `n`.
    Set(u32),
    /// Nothing usable on this display: leave it dark (or, without any
    /// usable display, the text console).
    Text,
}

/// `(w, h)` fits on one display of `edid` size.
const fn fits(m: (u32, u32), edid: (u32, u32)) -> bool {
    m.0 <= edid.0 && m.1 <= edid.1
}

/// Pick the mode for one display. `modes` yields `(mode number, width,
/// height)`; `edid` is the display's preferred resolution when its EDID
/// could be read.
pub fn choose_mode(
    current: (u32, u32),
    modes: impl Iterator<Item = (u32, u32, u32)> + Clone,
    edid: Option<(u32, u32)>,
) -> ModeChoice {
    let area = |w: u32, h: u32| u64::from(w) * u64::from(h);
    if let Some(p) = edid.filter(|&(w, h)| supported(w, h)) {
        if current == p {
            return ModeChoice::Keep;
        }
        if let Some((n, _, _)) = modes.clone().find(|&(_, w, h)| (w, h) == p) {
            return ModeChoice::Set(n);
        }
        // The native mode is not offered: the largest usable mode that fits
        // on this one display. A current mode larger than the display in
        // either direction spans several and is never kept.
        let best = modes
            .clone()
            .filter(|&(_, w, h)| supported(w, h) && fits((w, h), p))
            .max_by_key(|&(_, w, h)| area(w, h));
        let keep = supported(current.0, current.1) && fits(current, p);
        return match best {
            Some((_, w, h)) if keep && area(current.0, current.1) >= area(w, h) => ModeChoice::Keep,
            Some((n, _, _)) => ModeChoice::Set(n),
            None if keep => ModeChoice::Keep,
            None => ModeChoice::Text,
        };
    }
    if supported(current.0, current.1) {
        return ModeChoice::Keep;
    }
    modes
        .filter(|&(_, w, h)| supported(w, h))
        .max_by_key(|&(_, w, h)| area(w, h))
        .map_or(ModeChoice::Text, |(n, _, _)| ModeChoice::Set(n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use paguro_core::edid;

    const MODES: [(u32, u32, u32); 6] = [
        (0, 640, 480),
        (1, 800, 600),
        (2, 1920, 1080),
        (3, 1024, 768),
        (4, 3840, 1080),
        (5, 1600, 900),
    ];

    fn it() -> impl Iterator<Item = (u32, u32, u32)> + Clone {
        MODES.iter().copied()
    }

    #[test]
    fn without_edid_the_firmware_choice_stands() {
        assert_eq!(choose_mode((800, 600), it(), None), ModeChoice::Keep);
        assert_eq!(choose_mode((3840, 1080), it(), None), ModeChoice::Keep);
        // An unusable current mode: the largest usable one.
        assert_eq!(choose_mode((320, 200), it(), None), ModeChoice::Set(4));
        assert_eq!(
            choose_mode((320, 200), [(0, 320, 200)].into_iter(), None),
            ModeChoice::Text
        );
    }

    #[test]
    fn the_display_native_mode() {
        let p = Some((1920, 1080));
        assert_eq!(choose_mode((1920, 1080), it(), p), ModeChoice::Keep);
        assert_eq!(choose_mode((800, 600), it(), p), ModeChoice::Set(2));
        // A preferred resolution below the supported minimum is no guide.
        assert_eq!(
            choose_mode((800, 600), it(), Some((320, 240))),
            ModeChoice::Keep
        );
    }

    #[test]
    fn never_one_canvas_across_two_displays() {
        // Two 1920×1080 panels driven as one 3840×1080 surface.
        let p = Some((1920, 1080));
        assert_eq!(choose_mode((3840, 1080), it(), p), ModeChoice::Set(2));
        // The native mode not offered: the largest that fits one panel,
        // never the spanning one.
        let no_native = || MODES.iter().copied().filter(|m| m.0 != 2);
        assert_eq!(
            choose_mode((3840, 1080), no_native(), p),
            ModeChoice::Set(5)
        );
        assert_eq!(choose_mode((800, 600), no_native(), p), ModeChoice::Set(5));
        // Stacked vertically.
        assert_eq!(
            choose_mode(
                (1920, 2160),
                [(7, 1920, 2160), (8, 1280, 720)].into_iter(),
                p
            ),
            ModeChoice::Set(8)
        );
        // A current mode that fits and is as large as anything offered.
        assert_eq!(choose_mode((1600, 900), no_native(), p), ModeChoice::Keep);
        // Nothing fits one display: leave it dark.
        assert_eq!(
            choose_mode((3840, 1080), [(4, 3840, 1080)].into_iter(), p),
            ModeChoice::Text
        );
        // A real 32:9 monitor reports 3840×1080 itself: that is one display.
        assert_eq!(
            choose_mode((1920, 1080), it(), Some((3840, 1080))),
            ModeChoice::Set(4)
        );
    }

    #[test]
    fn with_a_parsed_edid() {
        let e = edid::build::block(1920, 1080, false);
        let p = edid::preferred(&e).ok();
        assert_eq!(choose_mode((3840, 1080), it(), p), ModeChoice::Set(2));
        let mut bad = e;
        bad[100] ^= 0xff;
        let p = edid::preferred(&bad).ok();
        assert_eq!(p, None);
        assert_eq!(choose_mode((3840, 1080), it(), p), ModeChoice::Keep);
    }
}
