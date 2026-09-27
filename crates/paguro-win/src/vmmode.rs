//! Is this the paguro VM? (DESIGN.md §4.4 "On a native boot the driver is
//! present and inert".) The SMBIOS type 11 marker
//! (`paguro_core::smbios::has_vm_marker`), read the same way the minifilter
//! itself does at `DriverEntry` (`ExGetSystemFirmwareTable('RSMB')`,
//! mirrored here as [`crate::api::WinApi::smbios`]) — an independent check,
//! so the paguro service can gate its own VM-only behaviour (the agent
//! handshake, the chkdsk guard) without depending on the filter having
//! loaded yet, and without a channel to it at all until it has
//! (INTERFACES.md §11.3).

use crate::api::WinApi;

/// Any failure reading SMBIOS (no table, an unsupported call, a malformed
/// blob) is "native": the same fail-closed rule the driver's own check
/// uses (DESIGN.md §4.4).
pub fn detect(api: &dyn WinApi) -> bool {
    api.smbios()
        .map(|b| paguro_core::smbios::has_vm_marker(&b))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockApi;

    #[test]
    fn absent_by_default() {
        let m = MockApi::standard();
        assert!(!detect(&m));
    }

    #[test]
    fn present_with_the_marker() {
        let m = MockApi::standard();
        // A minimal RawSMBIOSData with one type 11 structure carrying the
        // marker string (mirrors `paguro_core::smbios`'s own test fixture).
        let table: Vec<u8> = [
            11u8, 5, 0, 0, 1, // header (type 11, len 5) + Count
            b'p', b'a', b'g', b'u', b'r', b'o', b'-', b'v', b'm', b'/', b'1', 0, 0,
        ]
        .to_vec();
        let mut blob = vec![0u8, 3, 4, 0];
        blob.extend_from_slice(&(table.len() as u32).to_le_bytes());
        blob.extend_from_slice(&table);
        *m.smbios_blob.borrow_mut() = blob;
        assert!(detect(&m));
    }
}
