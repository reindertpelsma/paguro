//! A display's EDID (INTERFACES.md §13.2a): external data from the monitor
//! or dongle. The preferred resolution is two 12-bit numbers, a whole frame
//! for an interlaced timing.
#![no_main]

use libfuzzer_sys::fuzz_target;
use paguro_core::edid;

fuzz_target!(|data: &[u8]| {
    if let Ok((w, h)) = edid::preferred(data) {
        assert!(data.len() >= edid::BLOCK);
        assert!((1..=4095).contains(&w) && (1..=8190).contains(&h));
    }
});
