//! BitLocker metadata, the loader's first-line adversarial parser (DESIGN.md
//! §6): volume header, block + validation, the three-copy cross-check, the
//! entry schema, protectors, layout and the sector map.
//!
//! Input: sector 0 (512 bytes), then one metadata region. Copies 1 and 2 are
//! the region itself (the accept path) and the region with its last byte
//! flipped (the disagreement path). When sector 0 does not parse, the
//! block's own offsets stand in so the block parser is always reached.
#![no_main]

use libfuzzer_sys::fuzz_target;
use paguro_core::bde::*;

fn fix_crc(region: &[u8]) -> Vec<u8> {
    let mut r = region.to_vec();
    let size = r
        .get(8..10)
        .map_or(0, |b| usize::from(u16::from_le_bytes([b[0], b[1]])) * 16);
    if size + 8 <= r.len() {
        let c = crc32(&r[..size]);
        r[size + 4..size + 8].copy_from_slice(&c.to_le_bytes());
    }
    r
}

fuzz_target!(|data: &[u8]| {
    let Some((s0, region)) = data.split_at_checked(512) else {
        return;
    };
    let hdr = parse_volume_header(s0).unwrap_or_else(|_| {
        let o = |i: usize| {
            region
                .get(32 + 8 * i..40 + 8 * i)
                .and_then(|b| b.try_into().ok())
                .map(u64::from_le_bytes)
                .unwrap_or(0)
        };
        VolumeHeader {
            kind: HeaderKind::Standard,
            eow: false,
            bytes_per_sector: 512,
            metadata_offsets: [o(0), o(1), o(2)],
        }
    });
    let mut flipped = region.to_vec();
    if let Some(b) = flipped.last_mut() {
        *b ^= 1;
    }
    // The same region with its CRC-32 made to match, so mutations reach the
    // metadata header, the entries and the layout.
    let fixed = fix_crc(region);
    for copies in [
        [region, region, region],
        [region, region, &flipped[..]],
        [&fixed[..], &fixed[..], &fixed[..]],
    ] {
        let Ok(b) = cross_check(copies, &hdr) else {
            continue;
        };
        assert!(b.agreed.len() <= region.len() && b.raw.len() <= b.agreed.len());
        let Ok(m) = Metadata::parse(b) else { continue };
        for p in m.protectors() {
            if let Some(c) = p.wrapped_vmk {
                assert!(c.ciphertext.len() <= MAX_WRAPPED);
            }
        }
        assert!(m.protectors().count() <= MAX_PROTECTORS);
        for size in [104_857_600u64, u64::MAX, m.block.encrypted_size] {
            let Ok(l) = Layout::new(&hdr, &m, size) else {
                continue;
            };
            let units = l.units();
            let _ = l.reserved_ranges();
            let _ = l.fve_layout();
            for u in [0, 1, units / 2, units.saturating_sub(1), units, u64::MAX] {
                if let Some((_, run)) = l.map(u) {
                    assert!(run >= 1 && u + run <= units);
                } else {
                    assert!(u >= units);
                }
            }
            for o in hdr.metadata_offsets {
                let _ = l.map(o / u64::from(l.bytes_per_sector));
            }
        }
    }
    let _ = parse_key(region);
    let _ = parse_startup_key(region);
});
