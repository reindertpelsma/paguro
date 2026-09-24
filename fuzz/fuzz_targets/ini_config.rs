//! `paguro.ini`: grammar + schema (INTERFACES.md §3). Anything that parses
//! must re-serialise to something that parses to the same configuration.
#![no_main]

use libfuzzer_sys::fuzz_target;
use paguro_core::{config, ini};

fuzz_target!(|data: &[u8]| {
    if let Ok(entries) = ini::parse(data) {
        for e in entries {
            if e.is_err() {
                break;
            }
        }
    }
    if let Ok(cfg) = config::parse(data) {
        assert!(cfg.entry_count >= 1 && cfg.default < cfg.entry_count);
        for e in cfg.entries() {
            assert!(e.is_valid());
            if let config::Efi::Disk { .. } = e.efi {
                assert!(e.root.is_some(), "a disk-hosted UEFI image implies a root");
            }
        }
        let mut buf = vec![0u8; 70 * 1024];
        let n = config::write(&cfg, &mut buf).expect("a parsed config re-serialises");
        assert_eq!(config::parse(&buf[..n]).expect("canonical form parses"), cfg);
    }
});
