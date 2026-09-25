//! The Rust reference (and the C core, compiled in) over a real device, for
//! the kernel VM tests: the coexistence test re-parses the images' runlists
//! after the stress, and the power-loss replay (INTERFACES §12.1) derives
//! the map at every replayed state.
//!
//! `ntfs-map <device> <rec> <seq>` prints the file's extents in file order,
//! one `<start> <len>` line each (512-byte sectors, the format `pgctl
//! crosscheck-list` reads), or `error <code> <Name>`; both implementations
//! must agree (else exit 3). `ntfs-between <pre> <map> <post>` exits 0 when
//! `map` is an append-only growth of `pre` and `post` an append-only growth
//! of `map` (a state inside a growth).

use std::fs::File;
use std::os::unix::fs::{FileExt, FileTypeExt, OpenOptionsExt};

use paguro_core::ntfs::{self, Disk, IoError};
use paguro_core::range::Extent;

use crate::ntfsdiff::both;

/// The sector every `Disk` read and extent line is counted in.
const SECTOR: u64 = 512;
/// O_DIRECT reads: buffer alignment and length (4Kn devices), inside a
/// buffer large enough to hold one aligned block wherever it lands.
const DIRECT_ALIGN: usize = 4096;
const DIRECT_BUF: usize = 2 * DIRECT_ALIGN;

/// 512-byte reads from a file or block device; a block device is read with
/// `O_DIRECT` so nothing stale comes from the page cache.
pub struct DevDisk {
    file: File,
    direct: bool,
    buf: Vec<u8>,
}

impl DevDisk {
    pub fn open(path: &str) -> std::io::Result<DevDisk> {
        let block = std::fs::metadata(path)?.file_type().is_block_device();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(if block { libc::O_DIRECT } else { 0 })
            .open(path)?;
        Ok(DevDisk {
            file,
            direct: block,
            buf: vec![0; DIRECT_BUF],
        })
    }
}

impl Disk for DevDisk {
    fn read(&mut self, sector: u64, out: &mut [u8; 512]) -> Result<(), IoError> {
        let at = sector.checked_mul(SECTOR).ok_or(IoError)?;
        if !self.direct {
            return self.file.read_exact_at(out, at).map_err(|_| IoError);
        }
        // O_DIRECT: an aligned 4 KiB read around the sector (4Kn devices).
        let base = self.buf.as_ptr() as usize;
        let off = (DIRECT_ALIGN - base % DIRECT_ALIGN) % DIRECT_ALIGN;
        let aligned = self.buf.get_mut(off..off + DIRECT_ALIGN).ok_or(IoError)?;
        let blk = at & !(DIRECT_ALIGN as u64 - 1);
        self.file.read_exact_at(aligned, blk).map_err(|_| IoError)?;
        let s = usize::try_from(at - blk).map_err(|_| IoError)?;
        out.copy_from_slice(aligned.get(s..s + SECTOR as usize).ok_or(IoError)?);
        Ok(())
    }
}

pub fn ntfs_map(path: &str, rec: u64, seq: u16) -> i32 {
    let r = both(
        || DevDisk::open(path).unwrap_or_else(|e| panic!("{path}: {e}")),
        rec,
        seq,
    );
    match r {
        Err(e) => {
            eprintln!("DIVERGED: {e}");
            3
        }
        Ok((Err(code), _)) => {
            println!("error {code} {}", crate::cntfs::error_name(code));
            0
        }
        Ok((Ok(d), _)) => {
            for e in &d.extents {
                println!("{} {}", e.start, e.end - e.start);
            }
            0
        }
    }
}

fn read_map(path: &str) -> Option<Vec<Extent>> {
    let text = std::fs::read_to_string(path).ok()?;
    text.lines()
        .map(|l| {
            let mut it = l.split_whitespace();
            let s: u64 = it.next()?.parse().ok()?;
            let n: u64 = it.next()?.parse().ok()?;
            Some(Extent {
                start: s,
                end: s.checked_add(n)?,
            })
        })
        .collect()
}

pub fn ntfs_between(pre: &str, map: &str, post: &str) -> i32 {
    match (read_map(pre), read_map(map), read_map(post)) {
        (Some(a), Some(m), Some(b)) => i32::from(!(ntfs::grows(&a, &m) && ntfs::grows(&m, &b))),
        _ => 2,
    }
}

/// `payload <image> <lbs> [vhd]`: the structural assertion over an image
/// file (a fixed VHD's footer excluded), both implementations.
pub fn payload(path: &str, lbs: u32, vhd: bool) -> i32 {
    let Ok(len) = std::fs::metadata(path).map(|m| m.len()) else {
        eprintln!("{path}: cannot stat");
        return 2;
    };
    // A fixed VHD's footer is one sector.
    let sectors = len / SECTOR - u64::from(vhd);
    let r = crate::payloaddiff::both(
        || DevDisk::open(path).unwrap_or_else(|e| panic!("{path}: {e}")),
        sectors,
        lbs,
    );
    match r {
        Err(e) => {
            eprintln!("DIVERGED: {e}");
            3
        }
        Ok((r, _)) => {
            println!("{}", crate::payloaddiff::show(r));
            i32::from(r.is_err())
        }
    }
}
