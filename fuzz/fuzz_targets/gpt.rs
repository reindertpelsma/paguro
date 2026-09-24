//! GPT header + entry array (UEFI 2.10 §5.3). Input: 8-byte disk size, one
//! 512-byte header block, then the entry array bytes. The CRC gate is
//! bypassed half the time (by recomputing CRCs) so the fuzzer reaches the
//! range checks behind it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use paguro_core::gpt::{self, Header};

fuzz_target!(|data: &[u8]| {
    if data.len() < 9 + 512 {
        return;
    }
    let fix = data[0] & 1 == 1;
    let blocks = u64::from_le_bytes(data[1..9].try_into().unwrap());
    let mut hdr = [0u8; 512];
    hdr.copy_from_slice(&data[9..9 + 512]);
    let mut array = data[9 + 512..].to_vec();
    if fix {
        let hs = (u32::from_le_bytes(hdr[12..16].try_into().unwrap()) as usize).clamp(92, 512);
        let esz = u32::from_le_bytes(hdr[84..88].try_into().unwrap()) as usize;
        let cnt = u32::from_le_bytes(hdr[80..84].try_into().unwrap()) as usize;
        if let Some(len) = esz.checked_mul(cnt).filter(|l| *l <= gpt::MAX_ENTRY_ARRAY) {
            array.resize(len, 0);
            hdr[88..92].copy_from_slice(&gpt::crc32(&array).to_le_bytes());
        }
        hdr[16..20].fill(0);
        let crc = gpt::crc32(&hdr[..hs]);
        hdr[16..20].copy_from_slice(&crc.to_le_bytes());
    }
    let Ok(h) = Header::parse(&hdr, blocks) else { return };
    assert!(h.entries_len() <= gpt::MAX_ENTRY_ARRAY);
    assert!(h.first_usable <= h.last_usable && h.last_usable < blocks);
    let Ok(es) = h.entries(&array) else { return };
    for i in 0..es.count() {
        if let Ok(e) = es.get(i) {
            if !e.is_unused() {
                assert!(e.first_lba >= h.first_usable && e.last_lba <= h.last_usable);
                assert!(e.sectors() >= 1);
            }
        }
    }
    let _ = es.find(&paguro_core::guid::Guid([0x11; 16]));
});
