//! Disk format detection and finding the FAT32 (INTERFACES.md §3.2). Input:
//! a flag byte, the 8-byte file length, the file's last 512 bytes, then the
//! payload's first bytes. With the flag's low bit set the GPT header and
//! entry-array CRCs are recomputed, so the fuzzer reaches the ESP count and
//! range checks behind them.
#![no_main]

use libfuzzer_sys::fuzz_target;
use paguro_core::disk::{self, EfiFs, Format};
use paguro_core::gpt;

fuzz_target!(|data: &[u8]| {
    if data.len() < 1 + 8 + 512 {
        return;
    }
    let fix = data[0] & 1 == 1;
    let file_len = u64::from_le_bytes(data[1..9].try_into().unwrap());
    let tail: [u8; 512] = data[9..9 + 512].try_into().unwrap();
    let mut head = data[9 + 512..].to_vec();
    head.truncate(disk::HEAD_LEN);

    let p = disk::detect(file_len, &tail);
    match p.format {
        Format::Vhd => assert_eq!(p.len + 512, file_len),
        Format::Raw => assert_eq!(p.len, file_len),
    }

    if fix && head.len() >= 1024 && head[512..520] == gpt::SIGNATURE[..] {
        let hs = (u32::from_le_bytes(head[524..528].try_into().unwrap()) as usize).clamp(92, 512);
        let lba = u64::from_le_bytes(head[512 + 72..512 + 80].try_into().unwrap());
        let cnt = u32::from_le_bytes(head[512 + 80..512 + 84].try_into().unwrap()) as usize;
        let esz = u32::from_le_bytes(head[512 + 84..512 + 88].try_into().unwrap()) as usize;
        if let (Some(len), Some(at)) = (
            esz.checked_mul(cnt).filter(|l| *l <= gpt::MAX_ENTRY_ARRAY),
            usize::try_from(lba).ok().and_then(|l| l.checked_mul(512)),
        ) {
            if let Some(arr) = at.checked_add(len).and_then(|end| head.get(at..end)) {
                let crc = gpt::crc32(arr);
                head[512 + 88..512 + 92].copy_from_slice(&crc.to_le_bytes());
            }
        }
        head[512 + 16..512 + 20].fill(0);
        let crc = gpt::crc32(&head[512..512 + hs]);
        head[512 + 16..512 + 20].copy_from_slice(&crc.to_le_bytes());
    }

    let _ = disk::parse_fat32(&head, p.len);
    if let Ok(fs) = disk::classify(p.len, &head) {
        let (at, n) = fs.range();
        assert!(n > 0 && at.checked_add(n).is_some_and(|end| end <= p.len));
        match fs {
            EfiFs::Esp { first_lba, .. } => assert!(first_lba >= 2),
            EfiFs::Superfloppy(f) => {
                assert_eq!(disk::parse_fat32(&head, p.len), Ok(f));
                assert!(f.root_cluster >= 2 && f.clusters >= 1);
            }
        }
    }
});
