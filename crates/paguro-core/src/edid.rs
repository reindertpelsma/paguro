//! The one thing the loader reads from a display's EDID: its preferred
//! resolution (INTERFACES.md §13.2a, "Several displays").
//!
//! EDID comes from the display over DDC, through the firmware's
//! `EFI_EDID_ACTIVE_PROTOCOL` / `EFI_EDID_DISCOVERED_PROTOCOL`: external data
//! a malicious display (or dongle) controls. The parser reads the fixed
//! 128-byte base block only — no extension blocks, no descriptors beyond the
//! first — checks the header and checksum, and returns two 12-bit numbers.
//! Bounded by construction; fuzzed by `fuzz/fuzz_targets/edid.rs`.

/// The base block's size.
pub const BLOCK: usize = 128;
const HEADER: [u8; 8] = [0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00];
/// The first detailed timing descriptor: the preferred timing (EDID 1.3+).
const DTD: core::ops::Range<usize> = 54..72;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdidError {
    /// Fewer than 128 bytes.
    Short,
    BadHeader,
    BadChecksum,
    /// The first descriptor is a display descriptor (pixel clock 0), not a
    /// timing: there is no preferred timing to read.
    NoTiming,
    /// A zero width or height.
    Empty,
}

/// The display's preferred resolution in pixels: the active area of the
/// first detailed timing descriptor, a whole frame for an interlaced
/// timing. Anything after the base block is ignored.
pub fn preferred(edid: &[u8]) -> Result<(u32, u32), EdidError> {
    let base = edid.get(..BLOCK).ok_or(EdidError::Short)?;
    if base.get(..HEADER.len()) != Some(&HEADER[..]) {
        return Err(EdidError::BadHeader);
    }
    if base.iter().fold(0u8, |a, b| a.wrapping_add(*b)) != 0 {
        return Err(EdidError::BadChecksum);
    }
    let d: &[u8; 18] = base
        .get(DTD)
        .and_then(|s| s.try_into().ok())
        .ok_or(EdidError::Short)?;
    if d[0] == 0 && d[1] == 0 {
        return Err(EdidError::NoTiming);
    }
    let w = u32::from(d[2]) | (u32::from(d[4] >> 4) << 8);
    let mut h = u32::from(d[5]) | (u32::from(d[7] >> 4) << 8);
    if d[17] & 0x80 != 0 {
        // Interlaced: the descriptor gives one field.
        h *= 2;
    }
    if w == 0 || h == 0 {
        return Err(EdidError::Empty);
    }
    Ok((w, h))
}

/// Build a base block with one detailed timing (tests, fuzz seeds, the
/// mode-selection tests in `paguro-ui`).
pub mod build {
    use super::*;

    pub fn block(w: u32, h: u32, interlaced: bool) -> [u8; BLOCK] {
        let mut e = [0u8; BLOCK];
        if let Some(hd) = e.get_mut(..8) {
            hd.copy_from_slice(&HEADER);
        }
        let set = |e: &mut [u8; BLOCK], i: usize, v: u8| {
            if let Some(b) = e.get_mut(i) {
                *b = v;
            }
        };
        // EDID 1.4, a 148.5 MHz pixel clock.
        set(&mut e, 18, 1);
        set(&mut e, 19, 4);
        set(&mut e, 54, 0x02);
        set(&mut e, 55, 0x3a);
        set(&mut e, 56, w as u8);
        set(&mut e, 58, ((w >> 8) as u8 & 0xf) << 4);
        let fh = if interlaced { h / 2 } else { h };
        set(&mut e, 59, fh as u8);
        set(&mut e, 61, ((fh >> 8) as u8 & 0xf) << 4);
        set(&mut e, 71, if interlaced { 0x80 } else { 0x18 });
        let sum = e.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        set(&mut e, 127, 0u8.wrapping_sub(sum));
        e
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preferred_timing() {
        assert_eq!(
            preferred(&build::block(1920, 1080, false)),
            Ok((1920, 1080))
        );
        assert_eq!(
            preferred(&build::block(3840, 2160, false)),
            Ok((3840, 2160))
        );
        assert_eq!(
            preferred(&build::block(4095, 4095, false)),
            Ok((4095, 4095))
        );
        assert_eq!(preferred(&build::block(1920, 1080, true)), Ok((1920, 1080)));
        // Extension blocks are ignored.
        let mut long = build::block(2560, 1440, false).to_vec();
        long.extend_from_slice(&[0xab; 128]);
        assert_eq!(preferred(&long), Ok((2560, 1440)));
    }

    #[test]
    fn every_error_variant() {
        let good = build::block(1920, 1080, false);
        assert_eq!(preferred(&good[..127]), Err(EdidError::Short));
        assert_eq!(preferred(&[]), Err(EdidError::Short));
        let mut b = good;
        b[0] = 1;
        b[127] = b[127].wrapping_sub(1);
        assert_eq!(preferred(&b), Err(EdidError::BadHeader));
        let mut b = good;
        b[20] ^= 1;
        assert_eq!(preferred(&b), Err(EdidError::BadChecksum));
        let mut b = good;
        let (c0, c1) = (b[54], b[55]);
        b[54] = 0;
        b[55] = 0;
        b[127] = b[127].wrapping_add(c0).wrapping_add(c1);
        assert_eq!(preferred(&b), Err(EdidError::NoTiming));
        assert_eq!(
            preferred(&build::block(0, 1080, false)),
            Err(EdidError::Empty)
        );
        assert_eq!(
            preferred(&build::block(1920, 0, false)),
            Err(EdidError::Empty)
        );
        assert_eq!(preferred(&[0u8; 128]), Err(EdidError::BadHeader));
    }
}
