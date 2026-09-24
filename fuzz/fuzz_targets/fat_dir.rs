//! The recovery browser's FAT32 directory reader (INTERFACES.md §13.4):
//! the input is a FAT32 image (sectors past its end read as zero, so seeds
//! can be truncated). The root and each directory in it are listed; names
//! stay within 255 UTF-16 units, listings end, and nothing panics; a few
//! paths are looked up with `Fs::find`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use paguro_core::fat::{self, FatError, Fs, Sectors};

struct Img<'a>(&'a [u8]);

impl Sectors for Img<'_> {
    fn read(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), FatError> {
        let at = usize::try_from(sector)
            .ok()
            .and_then(|s| s.checked_mul(512))
            .ok_or(FatError::Io)?;
        buf.fill(0);
        if let Some(src) = self.0.get(at..) {
            let n = src.len().min(buf.len());
            buf[..n].copy_from_slice(&src[..n]);
        }
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    let mut img = Img(data);
    let mut scratch = [0u8; fat::SCRATCH];
    let Ok(fs) = Fs::open(&mut img, 1 << 40, &mut scratch) else {
        return;
    };
    // The loader's check that `efi` exists (fat::Fs::find).
    for p in ["\\EFI\\BOOT\\BOOTX64.EFI", "\\a", "\\x\\y\\z.efi"] {
        if let Ok(f) = fs.find(&mut img, p, &mut scratch) {
            let _ = (f.is_dir, f.size, f.cluster);
        }
    }
    let mut dirs: Vec<Vec<u16>> = Vec::new();
    let mut n = 0u32;
    let _ = fs.list(&mut img, "\\", &mut scratch, |e| {
        assert!(!e.name.is_empty() && e.name.len() <= fat::MAX_NAME);
        n += 1;
        assert!(n <= fat::MAX_DIR_ENTRIES);
        if e.is_dir && dirs.len() < 8 && e.name != [u16::from(b'.')] && e.name != [u16::from(b'.'); 2] {
            dirs.push(e.name.to_vec());
        }
        true
    });
    for d in dirs {
        let Ok(name) = String::from_utf16(&d) else {
            continue;
        };
        let _ = fs.list(&mut img, &format!("\\{name}"), &mut scratch, |e| {
            assert!(e.name.len() <= fat::MAX_NAME);
            true
        });
    }
});
