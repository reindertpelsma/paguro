//! The Rust mapping-pairs decoder: no panic, decoded runs well-formed.
#![no_main]

use libfuzzer_sys::fuzz_target;
use paguro_core::runlist::{Run, decode};

fuzz_target!(|data: &[u8]| {
    let mut out = [Run { lcn: 0, count: 0 }; 256];
    if let Ok(n) = decode(data, &mut out) {
        for r in &out[..n] {
            assert!(r.count > 0 && r.lcn.checked_add(r.count).is_some());
        }
    }
});
