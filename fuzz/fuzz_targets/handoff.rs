//! The loader → initrd handoff (INTERFACES.md §8). Whatever decodes must
//! re-encode canonically and decode to the same value.
#![no_main]

use libfuzzer_sys::fuzz_target;
use paguro_core::handoff;

fuzz_target!(|data: &[u8]| {
    let Ok(h) = handoff::decode(data) else { return };
    let mut buf = vec![0u8; handoff::MAX_LEN];
    let n = handoff::encode(&h, &mut buf).expect("a decoded handoff re-encodes");
    assert_eq!(n, data.len(), "same records, same size");
    assert_eq!(handoff::decode(&buf[..n]), Ok(h));
});
