//! The Rust NTFS specification over arbitrary sparse volumes: no panic, and
//! any accepted map is internally consistent.
#![no_main]

#[path = "../../crates/paguro-harness/src/cntfs.rs"]
#[allow(dead_code)]
mod cntfs;

use libfuzzer_sys::fuzz_target;
use paguro_core::ntfs;

fuzz_target!(|data: &[u8]| {
    let Some((rec, seq, mut disk)) = cntfs::SparseDisk::parse(data) else {
        return;
    };
    let _ = cntfs::rust_flags(&mut disk);
    let lbs = if seq & 1 != 0 { 4096 } else { 512 };
    let _ = ntfs::check_payload(&mut ntfs_flat(data), data.len() as u64 / 512, lbs);
    if let Ok(d) = cntfs::rust_file(&mut disk, rec, seq) {
        let mut norm = vec![paguro_core::range::Extent { start: 0, end: 0 }; d.extents.len()];
        if let Ok(n) = ntfs::normalise(&d.extents, &mut norm) {
            assert!(!ntfs::intersects(&norm[..n], &[]));
        }
        assert!(ntfs::grows(&d.extents, &d.extents) || d.extents.is_empty());
        let total: u64 = d.extents.iter().map(|e| e.end - e.start).sum();
        assert!(d.size <= total * 512);
    }
});

struct Flat<'a>(&'a [u8]);
impl ntfs::Disk for Flat<'_> {
    fn read(&mut self, s: u64, buf: &mut [u8; 512]) -> Result<(), ntfs::IoError> {
        let at = usize::try_from(s)
            .map_err(|_| ntfs::IoError)?
            .checked_mul(512)
            .ok_or(ntfs::IoError)?;
        buf.copy_from_slice(self.0.get(at..at + 512).ok_or(ntfs::IoError)?);
        Ok(())
    }
}
fn ntfs_flat(d: &[u8]) -> Flat<'_> {
    Flat(d)
}
