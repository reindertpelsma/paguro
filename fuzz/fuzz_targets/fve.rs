//! The bounded FVE metadata walk (DESIGN.md §6: the adversarial pre-key parser).
#![no_main]

use libfuzzer_sys::fuzz_target;
use paguro_core::fve::{self, Entry};

fuzz_target!(|data: &[u8]| {
    let _ = fve::check_signature(data);
    let empty = Entry {
        entry_type: 0,
        value_type: 0,
        version: 0,
        data: &[],
    };
    let mut out = [empty; 16];
    if let Ok(n) = fve::walk(data, &mut out) {
        assert!(n <= out.len());
        for e in &out[..n] {
            assert!(e.data.len() <= data.len());
        }
    }
});
