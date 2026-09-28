//! A Windows shortcut (DESIGN.md §5d): any `.lnk` in a folder Linux can
//! see. Every string it returns lies inside the input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use paguro_core::shllink::{self, Str};

fuzz_target!(|data: &[u8]| {
    if let Ok(l) = shllink::parse(data) {
        let range = data.as_ptr_range();
        for s in [
            l.name,
            l.relative_path,
            l.working_dir,
            l.arguments,
            l.icon_location,
            l.local_base_path,
            l.common_path_suffix,
            l.env_target,
            l.env_icon,
        ]
        .into_iter()
        .flatten()
        {
            let (Str::Utf16(b) | Str::Ansi(b)) = s;
            assert!(b.is_empty() || (range.contains(&b.as_ptr()) && b.len() <= data.len()));
            let _ = s.chars().count();
        }
    }
});
