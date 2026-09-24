//! `Boot####` load options and the bootstrap OptionalData (INTERFACES.md §9).
#![no_main]

use libfuzzer_sys::fuzz_target;
use paguro_core::bootstrap;

fuzz_target!(|data: &[u8]| {
    let _ = bootstrap::walk_device_path(data, |_| {});
    let _ = bootstrap::parse_optional_data(data);
    if let Ok(lo) = bootstrap::parse_load_option(data) {
        assert!(lo.description.len() + lo.file_path.len() + lo.optional_data.len() + 8 <= data.len());
        let _ = lo.is_windows_boot_manager();
        if let Ok(b) = bootstrap::parse_optional_data(lo.optional_data) {
            let od = bootstrap::write_optional_data(b.salt, b.wrapped_vmk);
            assert_eq!(&od[..], lo.optional_data);
        }
    }
});
