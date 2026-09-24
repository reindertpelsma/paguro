//! Choosing the graphics mode, as a pure function the firmware adapter
//! calls with what GOP and EDID report (host-tested; the adapter only
//! queries and sets).

use crate::layout::supported;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModeChoice {
    /// The current mode is right: do not touch the display.
    Keep,
    /// Switch to mode number `n`.
    Set(u32),
    /// Nothing usable: the text console.
    Text,
}

/// The display's preferred resolution: the first detailed timing
/// descriptor of an EDID 1.x block (bytes 54..72). `None` for anything
/// that is not a well-formed base block.
pub fn edid_preferred(edid: &[u8]) -> Option<(u32, u32)> {
    const HEADER: [u8; 8] = [0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00];
    let base = edid.get(..128)?;
    if base.get(..8)? != HEADER {
        return None;
    }
    if base.iter().fold(0u8, |a, b| a.wrapping_add(*b)) != 0 {
        return None;
    }
    let d = base.get(54..72)?;
    // A pixel clock of zero marks a display descriptor, not a timing.
    if d.first().copied()? == 0 && d.get(1).copied()? == 0 {
        return None;
    }
    let lo = |i: usize| u32::from(d.get(i).copied().unwrap_or(0));
    let w = lo(2) | (lo(4) >> 4) << 8;
    let h = lo(5) | (lo(7) >> 4) << 8;
    (w > 0 && h > 0).then_some((w, h))
}

/// Keep the mode the firmware chose unless it is unusable or the display
/// says it prefers another one that the adapter offers. `modes` yields
/// `(mode number, width, height)`.
pub fn choose_mode(
    current: (u32, u32),
    modes: impl Iterator<Item = (u32, u32, u32)> + Clone,
    preferred: Option<(u32, u32)>,
) -> ModeChoice {
    if let Some(p) = preferred.filter(|&(w, h)| supported(w, h)) {
        if current == p {
            return ModeChoice::Keep;
        }
        if let Some((n, _, _)) = modes.clone().find(|&(_, w, h)| (w, h) == p) {
            return ModeChoice::Set(n);
        }
    }
    if supported(current.0, current.1) {
        return ModeChoice::Keep;
    }
    modes
        .filter(|&(_, w, h)| supported(w, h))
        .max_by_key(|&(_, w, h)| u64::from(w) * u64::from(h))
        .map_or(ModeChoice::Text, |(n, _, _)| ModeChoice::Set(n))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edid(w: u32, h: u32) -> [u8; 128] {
        let mut e = [0u8; 128];
        e[..8].copy_from_slice(&[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0]);
        e[54] = 0x01;
        e[55] = 0x1d;
        e[56] = w as u8;
        e[58] = ((w >> 8) as u8) << 4;
        e[59] = h as u8;
        e[61] = ((h >> 8) as u8) << 4;
        let sum = e.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        e[127] = 0u8.wrapping_sub(sum);
        e
    }

    #[test]
    fn edid_preferred_timing() {
        assert_eq!(edid_preferred(&edid(1920, 1080)), Some((1920, 1080)));
        assert_eq!(edid_preferred(&edid(3840, 2160)), Some((3840, 2160)));
        let mut bad = edid(1920, 1080);
        bad[20] ^= 1;
        assert_eq!(edid_preferred(&bad), None, "checksum");
        assert_eq!(edid_preferred(&bad[..100]), None);
        assert_eq!(edid_preferred(&[0; 128]), None);
    }

    #[test]
    fn mode_policy() {
        let modes = [
            (0, 640, 480),
            (1, 800, 600),
            (2, 1920, 1080),
            (3, 1024, 768),
        ];
        let it = || modes.iter().copied();
        // The firmware's choice stands without a better-informed preference.
        assert_eq!(choose_mode((800, 600), it(), None), ModeChoice::Keep);
        assert_eq!(
            choose_mode((1920, 1080), it(), Some((1920, 1080))),
            ModeChoice::Keep
        );
        // The display's native mode, when offered.
        assert_eq!(
            choose_mode((800, 600), it(), Some((1920, 1080))),
            ModeChoice::Set(2)
        );
        // A preference the adapter lacks changes nothing.
        assert_eq!(
            choose_mode((800, 600), it(), Some((2560, 1440))),
            ModeChoice::Keep
        );
        // An unusable current mode: the largest usable one.
        assert_eq!(choose_mode((320, 200), it(), None), ModeChoice::Set(2));
        assert_eq!(
            choose_mode((320, 200), [(0, 320, 200)].into_iter(), None),
            ModeChoice::Text
        );
    }
}
