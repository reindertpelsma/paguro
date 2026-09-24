//! Seal files (INTERFACES.md §4): every kind, and the body parser the handoff
//! reuses for `PROVISION`. Parsed seals round-trip exactly.
#![no_main]

use libfuzzer_sys::fuzz_target;
use paguro_core::seal::{self, Kind};

fuzz_target!(|data: &[u8]| {
    for kind in Kind::ALL {
        if let Ok(s) = seal::read(kind, data) {
            let mut buf = [0u8; seal::MAX_FILE];
            let n = seal::write(&s, &mut buf).expect("fits");
            assert_eq!(&buf[..n], data, "seal files are canonical");
        }
        let _ = seal::read_body(kind, data);
    }
});
