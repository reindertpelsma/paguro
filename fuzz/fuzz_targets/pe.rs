//! Any file with an `MZ` that `binfmt_misc` hands paguro's `.exe` handler
//! (DESIGN.md §5d): the subsystem, and nothing that panics.
#![no_main]

use libfuzzer_sys::fuzz_target;
use paguro_core::pe;

fuzz_target!(|data: &[u8]| {
    if pe::parse(data).is_ok() {
        assert!(data.starts_with(b"MZ"));
    }
});
