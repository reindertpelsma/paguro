//! The loader → initrd handoff (INTERFACES.md §8). Whatever decodes must
//! re-encode canonically and decode to the same value.
#![no_main]

use libfuzzer_sys::fuzz_target;
use paguro_core::handoff;

fuzz_target!(|data: &[u8]| {
    let Ok(h) = handoff::decode(data) else { return };
    assert!(h.efi_disk.is_none() || (h.root.is_some() && h.efi_file.is_none()));
    if let (Some(r), Some(e)) = (h.root, h.efi_disk.or(h.efi_file)) {
        assert_eq!(e.name, r.name);
        assert_ne!(e.mft_record, r.mft_record);
    }
    let mut buf = vec![0u8; handoff::MAX_LEN];
    let n = handoff::encode(&h, &mut buf).expect("a decoded handoff re-encodes");
    assert_eq!(n, data.len(), "same records, same size");
    assert_eq!(handoff::decode(&buf[..n]), Ok(h));
});
