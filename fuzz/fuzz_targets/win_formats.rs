//! The external formats the Windows tool reads (INTERFACES.md §11.5, §11.6,
//! DESIGN.md §4.6): signature databases, SMBIOS, the TCG log, PnP IDs, the
//! recorded-boot file and GPT Hard Drive load options. The first byte picks
//! the parser; round-trippable ones must round-trip exactly.
#![no_main]

use libfuzzer_sys::fuzz_target;
use paguro_core::{bootstrap, efisig, hwid, recorded, smbios, tcglog};

fuzz_target!(|input: &[u8]| {
    let Some((&sel, data)) = input.split_first() else {
        return;
    };
    match sel % 6 {
        0 => {
            let _ = efisig::for_each(data, |s| {
                let _ = (s.kind, s.owner, s.data.len());
            });
        }
        1 => {
            let _ = smbios::parse(data);
        }
        2 => {
            let _ = tcglog::walk(data, |_| {});
            let _ = tcglog::driver_config_digests(data, |_| {});
        }
        3 => {
            if let Ok(s) = core::str::from_utf8(data) {
                let mut o = [0u8; 8];
                let mut b = [0u8; 128];
                if let Some(p) = hwid::pci(s.split('\n')) {
                    hwid::pci_modalias(&p, &mut b).expect("fits");
                }
                if let Some(u) = hwid::usb(s.split('\n')) {
                    hwid::usb_modalias(&u, &mut b).expect("fits");
                }
                for id in s.split('\n') {
                    if let Some(a) = hwid::acpi(id, &mut o) {
                        assert!(a.len() <= 8);
                    }
                }
            }
        }
        4 => {
            if let Ok(r) = recorded::parse(data) {
                let mut b = [0u8; recorded::LEN];
                let n = recorded::write(&r, &mut b).expect("fits");
                assert_eq!(&b[..n], data, "recorded.bin is canonical");
            }
        }
        _ => {
            if let Ok(lo) = bootstrap::parse_load_option(data) {
                let _ = bootstrap::walk_device_path(lo.file_path, |n| {
                    let _ = bootstrap::parse_hard_drive(&n);
                });
            }
        }
    }
});
