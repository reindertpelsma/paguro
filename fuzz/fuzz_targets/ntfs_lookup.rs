//! The loader's path lookup, directory listing and file reading
//! (`ntfs::dir`) over arbitrary sparse volumes (the ntfs_file input
//! format; sectors not in the input fail to read). `$UpCase` is replaced
//! by an ASCII table so small inputs reach the index code. No panic, and
//! every walk ends within its bounds.
#![no_main]

#[path = "../../crates/paguro-harness/src/cntfs.rs"]
#[allow(dead_code)]
mod cntfs;

use libfuzzer_sys::fuzz_target;
use paguro_core::ntfs::dir::{self, Data, FileRef, Scratch, UPCASE_LEN};
use paguro_core::ntfs::{self, MAX_ALIST};
use paguro_core::runlist::Run;
use std::sync::OnceLock;

fn upcase() -> &'static [u16; UPCASE_LEN] {
    static U: OnceLock<Box<[u16; UPCASE_LEN]>> = OnceLock::new();
    U.get_or_init(|| {
        let mut t = Box::new([0u16; UPCASE_LEN]);
        for (i, u) in t.iter_mut().enumerate() {
            let c = i as u16;
            *u = if (u16::from(b'a')..=u16::from(b'z')).contains(&c) { c - 32 } else { c };
        }
        t
    })
}

const PATHS: &[&str] = &["\\paguro", "\\paguro\\debian.vhd", "\\paguro\\rescue.efi", "\\hiberfil.sys", "\\a\\b\\c"];

fuzz_target!(|data: &[u8]| {
    let Some((_, _, mut disk)) = cntfs::SparseDisk::parse(data) else {
        return;
    };
    let mut alist = Box::new([0u8; MAX_ALIST]);
    let mut mft_runs = vec![Run { lcn: 0, count: 0 }; 1024];
    let Ok(m) = ntfs::open(&mut disk, &mut alist, &mut mft_runs) else {
        return;
    };
    let mut s: Box<Scratch> = Box::new(Scratch::new());
    let up = upcase();
    let mut runs = vec![Run { lcn: 0, count: 0 }; 4096];
    let mut res = vec![0u8; 4096];
    // Listing the root and \paguro.
    for d in [FileRef::ROOT] {
        if let Ok(idx) = dir::open_index(&mut disk, &m, d, &mut s) {
            let mut n = 0usize;
            let _ = dir::list(&mut disk, &m, &idx, &mut s, |e| {
                assert!(e.name.len() <= dir::MAX_NAME);
                n += 1;
                n < 100_000
            });
        }
    }
    for p in PATHS {
        if let Ok(f) = dir::resolve(&mut disk, &m, up, p, &mut s) {
            if f.is_dir {
                if let Ok(idx) = dir::open_index(&mut disk, &m, f.file, &mut s) {
                    let _ = dir::list(&mut disk, &m, &idx, &mut s, |_| true);
                }
            } else if let Ok(Data::Runs { runs: n, size }) =
                dir::data(&mut disk, &m, f.file, &mut s, &mut res, &mut runs)
            {
                let mut b = [0u8; 700];
                let len = size.min(700) as usize;
                let _ = dir::read_runs(&mut disk, &m.vol, &runs[..n], size, 0, &mut b[..len]);
            }
        }
    }
});
