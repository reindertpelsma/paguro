//! The one thing the loader reads from a display's EDID: its preferred
//! resolution (INTERFACES.md §13.2a, "Several displays").
//!
//! EDID comes from the display over DDC, through the firmware's
//! `EFI_EDID_ACTIVE_PROTOCOL` / `EFI_EDID_DISCOVERED_PROTOCOL`: external data
//! a malicious display (or dongle) controls. The parser reads the fixed
//! 128-byte base block only — no extension blocks, no descriptors beyond the
//! first — checks the header and checksum, and returns two 12-bit numbers.
//! Bounded by construction; fuzzed by `fuzz/fuzz_targets/edid.rs`.

use core::mem::{offset_of, size_of};

use crate::layout::field_size;

/// EDID base block (VESA E-EDID Release A.2, §3, Table 3.1). Layout only.
#[allow(dead_code)]
#[repr(C, packed)]
struct BaseBlock {
    header: [u8; 8],
    manufacturer_id: [u8; 2],
    product_code: u16,
    serial_number: u32,
    week: u8,
    year: u8,
    version: u8,
    revision: u8,
    video_input: u8,
    h_size_cm: u8,
    v_size_cm: u8,
    gamma: u8,
    features: u8,
    chromaticity: [u8; 10],
    established_timings: [u8; 3],
    standard_timings: [u8; 16],
    descriptors: [[u8; 18]; 4],
    extension_count: u8,
    checksum: u8,
}
const _: () = assert!(offset_of!(BaseBlock, version) == 18);
const _: () = assert!(offset_of!(BaseBlock, descriptors) == 54);
const _: () = assert!(offset_of!(BaseBlock, checksum) == 127);
const _: () = assert!(size_of::<BaseBlock>() == 128);

/// Detailed timing descriptor (E-EDID A.2 §3.10.2, Table 3.21). Layout only.
#[allow(dead_code)]
#[repr(C, packed)]
struct DetailedTiming {
    pixel_clock: u16,
    h_active_lo: u8,
    h_blank_lo: u8,
    h_active_blank_hi: u8,
    v_active_lo: u8,
    v_blank_lo: u8,
    v_active_blank_hi: u8,
    h_sync_offset_lo: u8,
    h_sync_width_lo: u8,
    v_sync_lo: u8,
    sync_hi: u8,
    h_image_mm_lo: u8,
    v_image_mm_lo: u8,
    image_mm_hi: u8,
    h_border: u8,
    v_border: u8,
    flags: u8,
}
const _: () = assert!(size_of::<DetailedTiming>() == 18);

/// The base block's size.
pub const BLOCK: usize = size_of::<BaseBlock>();
const HEADER: [u8; 8] = [0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00];
const DTD_LEN: usize = size_of::<DetailedTiming>();
/// The first detailed timing descriptor: the preferred timing (EDID 1.3+).
const DTD: core::ops::Range<usize> =
    offset_of!(BaseBlock, descriptors)..offset_of!(BaseBlock, descriptors) + DTD_LEN;
const _: () = assert!(field_size(|b: BaseBlock| b.descriptors) == 4 * DTD_LEN);

// Detailed timing descriptor fields used.
const DTD_PIXEL_CLOCK: usize = offset_of!(DetailedTiming, pixel_clock);
const DTD_H_ACTIVE_LO: usize = offset_of!(DetailedTiming, h_active_lo);
const DTD_H_ACTIVE_BLANK_HI: usize = offset_of!(DetailedTiming, h_active_blank_hi);
const DTD_V_ACTIVE_LO: usize = offset_of!(DetailedTiming, v_active_lo);
const DTD_V_ACTIVE_BLANK_HI: usize = offset_of!(DetailedTiming, v_active_blank_hi);
const DTD_FLAGS: usize = offset_of!(DetailedTiming, flags);
/// The active-size high nibble sits in the upper half of the `*_hi` byte.
const ACTIVE_HI_SHIFT: u32 = 4;
/// `flags` bit 7: interlaced.
const DTD_FLAG_INTERLACED: u8 = 0x80;

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
    let d: &[u8; DTD_LEN] = base
        .get(DTD)
        .and_then(|s| s.try_into().ok())
        .ok_or(EdidError::Short)?;
    if d[DTD_PIXEL_CLOCK] == 0 && d[DTD_PIXEL_CLOCK + 1] == 0 {
        return Err(EdidError::NoTiming);
    }
    let w = u32::from(d[DTD_H_ACTIVE_LO])
        | (u32::from(d[DTD_H_ACTIVE_BLANK_HI] >> ACTIVE_HI_SHIFT) << 8);
    let mut h = u32::from(d[DTD_V_ACTIVE_LO])
        | (u32::from(d[DTD_V_ACTIVE_BLANK_HI] >> ACTIVE_HI_SHIFT) << 8);
    if d[DTD_FLAGS] & DTD_FLAG_INTERLACED != 0 {
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

    /// EDID structure version 1.4.
    const VERSION: u8 = 1;
    const REVISION: u8 = 4;
    /// 148.5 MHz in the descriptor's 10 kHz units, little-endian (0x3A02).
    const PIXEL_CLOCK_148_5_MHZ: [u8; 2] = [0x02, 0x3a];
    /// `flags` for a progressive timing: digital separate sync.
    const FLAGS_DIGITAL_SEPARATE_SYNC: u8 = 0x18;
    const NIBBLE: u32 = 0xf;

    pub fn block(w: u32, h: u32, interlaced: bool) -> [u8; BLOCK] {
        let mut e = [0u8; BLOCK];
        let dtd = offset_of!(BaseBlock, descriptors);
        if let Some(hd) = e.get_mut(..HEADER.len()) {
            hd.copy_from_slice(&HEADER);
        }
        let set = |e: &mut [u8; BLOCK], i: usize, v: u8| {
            if let Some(b) = e.get_mut(i) {
                *b = v;
            }
        };
        // EDID 1.4, a 148.5 MHz pixel clock.
        set(&mut e, offset_of!(BaseBlock, version), VERSION);
        set(&mut e, offset_of!(BaseBlock, revision), REVISION);
        set(&mut e, dtd + DTD_PIXEL_CLOCK, PIXEL_CLOCK_148_5_MHZ[0]);
        set(&mut e, dtd + DTD_PIXEL_CLOCK + 1, PIXEL_CLOCK_148_5_MHZ[1]);
        set(&mut e, dtd + DTD_H_ACTIVE_LO, w as u8);
        set(
            &mut e,
            dtd + DTD_H_ACTIVE_BLANK_HI,
            (((w >> 8) & NIBBLE) as u8) << ACTIVE_HI_SHIFT,
        );
        let fh = if interlaced { h / 2 } else { h };
        set(&mut e, dtd + DTD_V_ACTIVE_LO, fh as u8);
        set(
            &mut e,
            dtd + DTD_V_ACTIVE_BLANK_HI,
            (((fh >> 8) & NIBBLE) as u8) << ACTIVE_HI_SHIFT,
        );
        let flags = if interlaced {
            DTD_FLAG_INTERLACED
        } else {
            FLAGS_DIGITAL_SEPARATE_SYNC
        };
        set(&mut e, dtd + DTD_FLAGS, flags);
        let sum = e.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        set(
            &mut e,
            offset_of!(BaseBlock, checksum),
            0u8.wrapping_sub(sum),
        );
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
