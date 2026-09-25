//! The synthetic ESP (DESIGN.md §4.3, §12): Windows' boot files copied from
//! the real ESP into a fresh FAT32, with `testsigning` set in this BCD only.
//!
//! Copied: `EFI/Microsoft/Boot/**` (boot manager, BCD, fonts, locales) and
//! `bootmgfw.efi` again as the removable-media path `EFI/Boot/bootx64.efi`,
//! so a fresh variable store boots it. Left out: every other operating
//! system's directory, `EFI/Microsoft/Recovery` (WinRE stays absent, §4.3),
//! and the BCD's transaction logs — the BCD itself must be clean
//! ([`crate::regf::RegError::Dirty`] otherwise), so they hold nothing it
//! lacks.
//!
//! The guest's writes to this ESP land in the session's scratch file and
//! are gone with it; the real ESP is never shown to the guest.

use std::fs;
use std::path::{Path, PathBuf};

use crate::fat::{self, Tree};
use crate::regf::bcd;

/// Where the boot manager lives on every Windows ESP.
pub const BOOT_DIR: &str = "EFI/Microsoft/Boot";
pub const BOOTMGR: &str = "bootmgfw.efi";
pub const BCD: &str = "BCD";
/// The removable-media default path (x86_64).
pub const FALLBACK: &str = "EFI/Boot/bootx64.efi";
/// Smallest ESP made: what Windows setup creates on 512-byte disks.
pub const MIN_BYTES: u64 = 100 << 20;
/// Files larger than this are not ESP boot files: refuse rather than copy.
const MAX_FILE: u64 = 64 << 20;
const MAX_FILES: usize = 10_000;
const MAX_DEPTH: usize = 8;

pub struct Esp {
    pub image: Vec<u8>,
    pub files: usize,
    /// The BCD object `testsigning` was set on, when asked.
    pub testsigning: Option<String>,
}

fn find_ci(dir: &Path, name: &str) -> Option<PathBuf> {
    let direct = dir.join(name);
    if direct.exists() {
        return Some(direct);
    }
    fs::read_dir(dir).ok()?.flatten().find_map(|e| {
        e.file_name()
            .to_str()
            .is_some_and(|n| n.eq_ignore_ascii_case(name))
            .then(|| e.path())
    })
}

fn find_path_ci(root: &Path, rel: &str) -> Option<PathBuf> {
    rel.split('/')
        .try_fold(root.to_path_buf(), |d, c| find_ci(&d, c))
}

fn is_log(name: &str) -> bool {
    let u = name.to_ascii_uppercase();
    u.starts_with("BCD.") && u.contains("LOG")
}

fn copy_tree(
    src: &Path,
    dst: &str,
    tree: &mut Tree,
    count: &mut usize,
    depth: usize,
) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(format!("{}: too deep", src.display()));
    }
    tree.mkdir(dst).map_err(|e| e.to_string())?;
    let mut entries: Vec<_> = fs::read_dir(src)
        .map_err(|e| format!("{}: {e}", src.display()))?
        .flatten()
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let name = e.file_name().to_string_lossy().into_owned();
        let path = e.path();
        let md = fs::symlink_metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let to = format!("{dst}/{name}");
        if md.is_dir() {
            copy_tree(&path, &to, tree, count, depth + 1)?;
        } else if md.is_file() {
            if is_log(&name) {
                continue;
            }
            if md.len() > MAX_FILE {
                return Err(format!(
                    "{}: {} bytes, not an ESP boot file",
                    path.display(),
                    md.len()
                ));
            }
            *count += 1;
            if *count > MAX_FILES {
                return Err("too many files on the ESP".into());
            }
            let data = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            tree.add(&to, data).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Build the synthetic ESP from the real one mounted (read-only) at `src`.
pub fn build(src: &Path, testsigning: bool, min_bytes: u64) -> Result<Esp, String> {
    let boot = find_path_ci(src, BOOT_DIR)
        .ok_or_else(|| format!("{}: no {BOOT_DIR} (not a Windows ESP)", src.display()))?;
    let mut tree = Tree::new();
    let mut files = 0;
    copy_tree(&boot, BOOT_DIR, &mut tree, &mut files, 0)?;
    let mgr =
        find_ci(&boot, BOOTMGR).ok_or_else(|| format!("no {BOOTMGR} in {}", boot.display()))?;
    let bcd_path = find_ci(&boot, BCD).ok_or_else(|| format!("no {BCD} in {}", boot.display()))?;
    tree.add(
        FALLBACK,
        fs::read(&mgr).map_err(|e| format!("{}: {e}", mgr.display()))?,
    )
    .map_err(|e| e.to_string())?;
    let mut object = None;
    if testsigning {
        let raw = fs::read(&bcd_path).map_err(|e| format!("{}: {e}", bcd_path.display()))?;
        let (edited, obj) = bcd::enable_testsigning(raw).map_err(|e| format!("BCD: {e}"))?;
        tree.replace(&format!("{BOOT_DIR}/{BCD}"), edited)
            .map_err(|e| e.to_string())?;
        object = Some(obj);
    }
    let sectors = fat::sectors_for(tree.data_bytes(), min_bytes.max(MIN_BYTES));
    let image = fat::build(&tree, sectors, "SYSTEM", 0x5041_4755).map_err(|e| e.to_string())?;
    Ok(Esp {
        image,
        files: files + 1,
        testsigning: object,
    })
}

/// The removable device carrying the `.BEK`: a small FAT32 with the file
/// in its root, as `manage-bde` writes it to a USB stick.
pub fn bek_stick(name: &str, bek: &[u8]) -> Result<Vec<u8>, String> {
    let mut t = Tree::new();
    t.add(name, bek.to_vec()).map_err(|e| e.to_string())?;
    let sectors = fat::sectors_for(t.data_bytes(), 0);
    fat::build(&t, sectors, "PAGURO-KEY", 0x4245_4B31).map_err(|e| e.to_string())
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::regf::{Hive, bcd::get_bool, tests::bcd_hive};

    #[test]
    fn from_a_windows_like_esp() {
        let dir = std::env::temp_dir().join(format!("paguro-vm-esp-{}", std::process::id()));
        let b = dir.join("EFI/Microsoft/Boot");
        fs::create_dir_all(b.join("en-US")).unwrap();
        fs::create_dir_all(dir.join("EFI/Microsoft/Recovery")).unwrap();
        fs::create_dir_all(dir.join("EFI/ubuntu")).unwrap();
        fs::write(b.join("bootmgfw.efi"), b"MZ boot manager").unwrap();
        fs::write(b.join("BCD"), bcd_hive(Some(false), b"lh")).unwrap();
        fs::write(b.join("BCD.LOG"), b"log").unwrap();
        fs::write(b.join("BCD.LOG1"), b"log").unwrap();
        fs::write(b.join("en-US/bootmgfw.efi.mui"), b"mui").unwrap();
        fs::write(dir.join("EFI/Microsoft/Recovery/BCD"), b"x").unwrap();
        fs::write(dir.join("EFI/ubuntu/shimx64.efi"), b"x").unwrap();
        let esp = build(&dir, true, 0).unwrap();
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(esp.image.len() as u64, MIN_BYTES);
        assert_eq!(esp.files, 4); // bootmgfw, BCD, mui + the fallback copy
        assert_eq!(
            esp.testsigning.as_deref(),
            Some("{9d37057e-b92b-11f1-94f8-aa07fdcbec39}")
        );
        // read it back
        use paguro_core::fat::{Fs, SCRATCH, Sectors};
        struct Mem<'a>(&'a [u8]);
        impl Sectors for Mem<'_> {
            fn read(&mut self, s: u64, buf: &mut [u8]) -> Result<(), paguro_core::fat::FatError> {
                let at = s as usize * 512;
                buf.copy_from_slice(&self.0[at..at + buf.len()]);
                Ok(())
            }
        }
        let img = &esp.image;
        let mut scratch = [0u8; SCRATCH];
        let fs_ = Fs::open(&mut Mem(img), img.len() as u64, &mut scratch).unwrap();
        let get = |p: &str| {
            let mut scratch = [0u8; SCRATCH];
            fs_.find(&mut Mem(img), p, &mut scratch)
        };
        assert!(get("\\EFI\\Boot\\bootx64.efi").is_ok());
        assert!(get("\\EFI\\Microsoft\\Boot\\en-US\\bootmgfw.efi.mui").is_ok());
        assert!(get("\\EFI\\Microsoft\\Boot\\BCD.LOG").is_err());
        assert!(get("\\EFI\\Microsoft\\Recovery").is_err());
        assert!(get("\\EFI\\ubuntu").is_err());
        let f = get("\\EFI\\Microsoft\\Boot\\BCD").unwrap();
        let at = ((32
            + 2 * fs_.bpb.fat_sectors
            + (f.cluster - 2) * u32::from(fs_.bpb.sectors_per_cluster)) as usize)
            * 512;
        let h = Hive::parse(img[at..at + f.size as usize].to_vec()).unwrap();
        assert_eq!(
            get_bool(&h, "{9d37057e-b92b-11f1-94f8-aa07fdcbec39}", "16000049").unwrap(),
            Some(true)
        );
    }

    #[test]
    fn not_an_esp() {
        let dir = std::env::temp_dir().join(format!("paguro-vm-noesp-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        assert!(build(&dir, true, 0).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn bek_stick_holds_the_file() {
        let img = bek_stick("03EA97FB-B9C1-413D-9BA0-28EEE3D9DDE2.BEK", &[7u8; 180]).unwrap();
        assert!(img.windows(11).any(|w| w == b"PAGURO-KEY "));
    }
}
