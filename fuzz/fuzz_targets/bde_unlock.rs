//! The whole unlock path with attacker-authored metadata (DESIGN.md §6):
//! parse, cross-check, clear-key protector → VMK, FVEK unwrap under that VMK
//! and under the template's real VMK, the metadata's VMK-wrapped SHA-256,
//! then reads through the decrypted view.
//!
//! Template: Windows' clear-key volume (cryptsetup's
//! bitlk-aes-xts-128-clearkey-only, test/fixtures/bde/windows). The input
//! replaces its metadata region in all three copies. Password and recovery
//! protectors are not driven here: each attempt is 2^20 SHA-256 rounds.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use paguro_boot::bde::{DecryptingReader, ReadError, SectorRead, unlock_fvek, vmk_from_clear_key};
use paguro_core::bde::*;

struct Sparse<'a> {
    records: &'a [(u64, Vec<u8>)],
    bps: u64,
}

impl SectorRead for Sparse<'_> {
    fn read_units(&mut self, unit: u64, buf: &mut [u8]) -> std::result::Result<(), ReadError> {
        buf.fill(0);
        let at = unit.checked_mul(self.bps).ok_or(ReadError::Range)?;
        for (o, d) in self.records {
            if *o == at {
                let n = d.len().min(buf.len());
                buf[..n].copy_from_slice(&d[..n]);
            }
        }
        Ok(())
    }
}

struct Template {
    size: u64,
    records: Vec<(u64, Vec<u8>)>,
    vmk: [u8; 32],
}

fn template() -> &'static Template {
    static T: OnceLock<Template> = OnceLock::new();
    T.get_or_init(|| {
        let s = include_bytes!(
            "../../test/fixtures/bde/windows/bitlk-aes-xts-128-clearkey-only.sparse"
        );
        let size = u64::from_le_bytes(s[8..16].try_into().unwrap());
        let mut records = Vec::new();
        let mut at = 16;
        while at < s.len() {
            let o = u64::from_le_bytes(s[at..at + 8].try_into().unwrap());
            let n = u32::from_le_bytes(s[at + 8..at + 12].try_into().unwrap()) as usize;
            records.push((o, s[at + 12..at + 12 + n].to_vec()));
            at += 12 + n;
        }
        let hdr = parse_volume_header(&records[0].1).unwrap();
        let r = &records[1].1;
        let m = Metadata::parse(cross_check([r, r, r], &hdr).unwrap()).unwrap();
        let vmk = vmk_from_clear_key(&m).unwrap().unwrap();
        Template { size, records, vmk }
    })
}

fuzz_target!(|data: &[u8]| {
    let t = template();
    let Ok(hdr) = parse_volume_header(&t.records[0].1) else {
        return;
    };
    // Past the CRC-32 (the fuzzer cannot compute it): what is tested here
    // is everything after it.
    let mut fixed = data.to_vec();
    let size = fixed
        .get(8..10)
        .map_or(0, |b| usize::from(u16::from_le_bytes([b[0], b[1]])) * 16);
    if size + 8 <= fixed.len() {
        let c = crc32(&fixed[..size]);
        fixed[size + 4..size + 8].copy_from_slice(&c.to_le_bytes());
    }
    let data = &fixed[..];
    let Ok(block) = cross_check([data, data, data], &hdr) else {
        return;
    };
    let Ok(m) = Metadata::parse(block) else {
        return;
    };
    let layout = Layout::new(&hdr, &m, t.size);
    let mut vmks = vec![t.vmk];
    if let Ok(Some(v)) = vmk_from_clear_key(&m) {
        vmks.push(v);
    }
    for vmk in vmks {
        let Ok(Some(fvek)) = unlock_fvek(&m, &vmk) else {
            continue;
        };
        let (Ok(l), Some(xts)) = (layout, fvek.xts()) else {
            continue;
        };
        let bps = u64::from(l.bytes_per_sector);
        let mut records = t.records.clone();
        for o in hdr.metadata_offsets {
            records.push((o, data.to_vec()));
        }
        let mut r = DecryptingReader::new(
            Sparse {
                records: &records,
                bps,
            },
            l,
            &xts,
        );
        let mut buf = vec![0u8; 4 * bps as usize];
        let units = r.units();
        for u in [
            0,
            l.reloc_offset / bps,
            hdr.metadata_offsets[0] / bps,
            units.saturating_sub(4),
        ] {
            let _ = r.read(u, &mut buf);
        }
        let mut s = [0u8; 512];
        let _ = paguro_core::ntfs::Disk::read(&mut r, 0, &mut s);
    }
});
