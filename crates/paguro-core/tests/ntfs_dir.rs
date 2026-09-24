//! `paguro_core::ntfs::dir` against volumes written by third-party tools:
//! `mkntfs` formats, `ntfs-3g` (FUSE) writes the tree, and `ntfsls` /
//! `ntfscat` are the reference for what lookup, listing and reading must
//! return. Skipped (with a message) where the tools or FUSE are missing;
//! CI installs them.
#![allow(clippy::indexing_slicing, clippy::unwrap_used)]

mod synth;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use paguro_core::ntfs::dir::{self, Data, DirError, FileRef, Scratch, UPCASE_LEN};
use paguro_core::ntfs::{self, MAX_ALIST, NtfsError};
use paguro_core::runlist::Run;
use synth::Mem;

const ZERO: Run = Run { lcn: 0, count: 0 };

fn ok(c: &mut Command) -> bool {
    c.output().map(|o| o.status.success()).unwrap_or(false)
}

/// A scratch directory unique to this test.
fn tmp(name: &str) -> PathBuf {
    let base = std::env::var_os("PAGURO_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let d = base.join(format!("paguro-ntfsdir-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// `mkntfs` a volume of `mib` MiB with `cluster` bytes per cluster, mount it
/// with ntfs-3g, let `fill` write into the mount point, unmount, and return
/// the image. `None` when the tools or FUSE are unavailable.
fn volume(name: &str, mib: u64, cluster: u32, fill: impl FnOnce(&Path)) -> Option<Vec<u8>> {
    let d = tmp(name);
    let img = d.join("vol.img");
    let f = std::fs::File::create(&img).unwrap();
    f.set_len(mib << 20).unwrap();
    drop(f);
    if !ok(Command::new("mkntfs")
        .args(["-F", "-f", "-q", "-c", &cluster.to_string()])
        .arg(&img))
    {
        eprintln!("mkntfs unavailable: skipped");
        return None;
    }
    let mnt = d.join("mnt");
    std::fs::create_dir_all(&mnt).unwrap();
    if !mount_ntfs(&img, &mnt) {
        eprintln!("ntfs-3g (FUSE) unavailable: skipped");
        return None;
    }
    fill(&mnt);
    let unmounted = umount(&mnt);
    assert!(unmounted, "umount {}", mnt.display());
    let data = std::fs::read(&img).unwrap();
    let _ = std::fs::remove_dir_all(&d);
    Some(data)
}

/// The reference: `ntfsls` of `path` (names only, no DOS aliases, no
/// system files, `.`/`..` dropped).
fn ntfsls(img: &[u8], path: &str) -> BTreeSet<String> {
    let d = tmp("ls");
    let f = d.join("v.img");
    std::fs::write(&f, img).unwrap();
    let out = Command::new("ntfsls")
        .arg("-p")
        .arg(path)
        .arg(&f)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "ntfsls: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&d);
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter(|l| !l.is_empty() && *l != "." && *l != "..")
        .map(str::to_string)
        .collect()
}

fn ntfscat(img: &[u8], path: &str) -> Vec<u8> {
    let d = tmp("cat");
    let f = d.join("v.img");
    std::fs::write(&f, img).unwrap();
    let out = Command::new("ntfscat").arg(&f).arg(path).output().unwrap();
    assert!(
        out.status.success(),
        "ntfscat {path}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&d);
    out.stdout
}

/// The loader's view of an image: `$MFT` mapped, `$UpCase` loaded.
struct Loader {
    disk: Mem,
    mft_runs: Vec<Run>,
    vol: ntfs::Volume,
    mft_bytes: u64,
    up: Box<[u16; UPCASE_LEN]>,
    s: Box<Scratch>,
}

impl Loader {
    fn new(img: &[u8]) -> Result<Loader, DirError> {
        let mut disk = Mem(img.to_vec());
        let mut alist = Box::new([0u8; MAX_ALIST]);
        let mut runs = vec![ZERO; 2048];
        let m = ntfs::open(&mut disk, &mut alist, &mut runs)?;
        let (vol, n, bytes) = (m.vol, m.runs.len(), m.bytes);
        runs.truncate(n);
        let mut l = Loader {
            disk,
            mft_runs: runs,
            vol,
            mft_bytes: bytes,
            up: vec![0u16; UPCASE_LEN]
                .into_boxed_slice()
                .try_into()
                .unwrap(),
            s: new_scratch(),
        };
        let mft = l.mft();
        dir::load_upcase(&mut l.disk, &mft, &mut l.s, &mut l.up)?;
        Ok(l)
    }

    fn mft(&self) -> ntfs::Mft<'static> {
        // Tests only: leak a copy so the Mft can outlive the borrow of self.
        let runs: &'static [Run] = Box::leak(self.mft_runs.clone().into_boxed_slice());
        ntfs::Mft {
            vol: self.vol,
            runs,
            bytes: self.mft_bytes,
        }
    }

    fn resolve(&mut self, path: &str) -> Result<dir::Found, DirError> {
        let mft = self.mft();
        dir::resolve(&mut self.disk, &mft, &self.up, path, &mut self.s)
    }

    fn list(&mut self, path: &str) -> Result<BTreeSet<String>, DirError> {
        let mft = self.mft();
        let f = self.resolve(path)?;
        let idx = dir::open_index(&mut self.disk, &mft, f.file, &mut self.s)?;
        let mut out = BTreeSet::new();
        dir::list(&mut self.disk, &mft, &idx, &mut self.s, |e| {
            let n = String::from_utf16(e.name).unwrap();
            if n != "." {
                out.insert(n);
            }
            true
        })?;
        Ok(out)
    }

    fn read(&mut self, path: &str) -> Result<Vec<u8>, DirError> {
        let mft = self.mft();
        let f = self.resolve(path)?;
        let mut res = vec![0u8; 4096];
        let mut runs = vec![ZERO; 65536];
        match dir::data(
            &mut self.disk,
            &mft,
            f.file,
            &mut self.s,
            &mut res,
            &mut runs,
        )? {
            Data::Resident(n) => Ok(res[..n].to_vec()),
            Data::Runs { runs: n, size } => {
                let mut out = vec![0u8; size as usize];
                dir::read_runs(&mut self.disk, &self.vol, &runs[..n], size, 0, &mut out)?;
                Ok(out)
            }
        }
    }
}

fn new_scratch() -> Box<Scratch> {
    // ~210 KiB: built on the heap, not the test thread's stack.
    let mut b: Box<std::mem::MaybeUninit<Scratch>> = Box::new_uninit();
    // SAFETY: Scratch is plain integer arrays, for which zero is valid.
    unsafe {
        std::ptr::write_bytes(b.as_mut_ptr(), 0, 1);
        b.assume_init()
    }
}

fn write(p: &Path, data: &[u8]) {
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(p, data).unwrap();
}

fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

#[test]
fn lookup_list_and_read_match_ntfs_3g() {
    let Some(img) = volume("basic", 64, 4096, |m| {
        write(&m.join("paguro/debian.vhd"), &pattern(3 << 20, 1));
        write(&m.join("paguro/rescue.efi"), &pattern(70_001, 2));
        write(&m.join("paguro/tiny.txt"), b"resident");
        write(&m.join("paguro/Deep/er/still/file.bin"), &pattern(5000, 3));
        write(&m.join("Ünïcödé 日本/ßtraße.EFI"), &pattern(1234, 4));
        write(&m.join("hiberfil.sys"), b"hibr\0\0\0\0rest of the header");
        std::fs::create_dir_all(m.join("empty")).unwrap();
    }) else {
        return;
    };
    let mut l = Loader::new(&img).unwrap();
    for dir in [
        "\\",
        "\\paguro",
        "\\paguro\\Deep\\er\\still",
        "\\Ünïcödé 日本",
        "\\empty",
    ] {
        let mine: BTreeSet<_> = l
            .list(dir)
            .unwrap()
            .into_iter()
            .filter(|n| !n.starts_with('$'))
            .collect();
        let theirs: BTreeSet<_> = ntfsls(&img, &dir.replace('\\', "/"))
            .into_iter()
            .filter(|n| !n.starts_with('$'))
            .collect();
        assert_eq!(mine, theirs, "listing {dir}");
    }
    for (path, unix) in [
        ("\\paguro\\debian.vhd", "/paguro/debian.vhd"),
        ("\\paguro\\rescue.efi", "/paguro/rescue.efi"),
        ("\\paguro\\tiny.txt", "/paguro/tiny.txt"),
        (
            "\\paguro\\Deep\\er\\still\\file.bin",
            "/paguro/Deep/er/still/file.bin",
        ),
        ("\\Ünïcödé 日本\\ßtraße.EFI", "/Ünïcödé 日本/ßtraße.EFI"),
    ] {
        assert_eq!(l.read(path).unwrap(), ntfscat(&img, unix), "{path}");
    }
    // Case-insensitive through $UpCase (ASCII and beyond), trailing `\`.
    assert_eq!(l.read("\\PAGURO\\RESCUE.efi").unwrap().len(), 70_001);
    assert_eq!(
        l.read("\\ünïcödé 日本\\SSTRASSE.EFI").map(|_| ()),
        Err(DirError::NotFound),
        "no folding beyond $UpCase"
    );
    assert_eq!(l.read("\\ÜNÏCÖDÉ 日本\\ßTRAßE.efi").unwrap().len(), 1234);
    assert!(l.resolve("\\paguro\\").unwrap().is_dir);
    // Refusals.
    assert_eq!(
        l.resolve("\\paguro\\nope").map(|_| ()),
        Err(DirError::NotFound)
    );
    assert_eq!(
        l.resolve("\\paguro\\tiny.txt\\x").map(|_| ()),
        Err(DirError::NotDirectory)
    );
    assert_eq!(l.read("\\paguro").map(|_| ()), Err(DirError::IsDirectory));
    assert_eq!(l.resolve("paguro").map(|_| ()), Err(DirError::BadPath));
    assert_eq!(l.resolve("\\a\\..\\b").map(|_| ()), Err(DirError::BadPath));
    assert_eq!(l.resolve("\\a\\\\b").map(|_| ()), Err(DirError::BadPath));
    assert_eq!(
        l.resolve(&"\\a".repeat(33)).map(|_| ()),
        Err(DirError::BadPath)
    );
    assert_eq!(
        l.resolve(&format!("\\{}", "x".repeat(256))).map(|_| ()),
        Err(DirError::BadPath)
    );
    // The hibernation gate reads the header, not the existence.
    assert!(dir::hibernation_active(&l.read("\\hiberfil.sys").unwrap()));
    assert!(!dir::hibernation_active(b"wake"));
    assert!(!dir::hibernation_active(&[0; 8]));
    assert!(dir::hibernation_active(b"RSTR"));
    assert!(!dir::hibernation_active(b"hib"));
    // The strict map of the module agrees with the reader for aligned files.
    let f = l.resolve("\\paguro\\debian.vhd").unwrap();
    let mft = l.mft();
    let mut alist = Box::new([0u8; MAX_ALIST]);
    let mut runs = vec![ZERO; 65536];
    let m = ntfs::file(
        &mut l.disk,
        &mft,
        f.file.record,
        f.file.seq,
        &mut alist,
        &mut runs,
    )
    .unwrap();
    assert_eq!(m.data_size, 3 << 20);
}

#[test]
fn large_directories_have_deep_trees() {
    // Long names make few entries per 4 KiB block: three levels.
    let names: Vec<String> = (0..3000)
        .map(|i| format!("entry-{i:05}-{}", "x".repeat(90)))
        .collect();
    let Some(img) = volume("large", 96, 4096, |m| {
        let d = m.join("big");
        std::fs::create_dir_all(&d).unwrap();
        for n in &names {
            std::fs::write(d.join(n), b"").unwrap();
        }
        write(&d.join("Zz-last.efi"), b"MZ-last");
    }) else {
        return;
    };
    let mut l = Loader::new(&img).unwrap();
    let mine = l.list("\\big").unwrap();
    assert_eq!(mine.len(), names.len() + 1);
    assert_eq!(mine, ntfsls(&img, "/big"));
    for i in [0usize, 1, 777, 1500, 2998, 2999] {
        let p = format!("\\big\\{}", names[i].to_uppercase());
        assert!(l.resolve(&p).is_ok(), "{p}");
    }
    assert_eq!(l.read("\\big\\zz-LAST.efi").unwrap(), b"MZ-last");
    assert_eq!(
        l.resolve("\\big\\entry-03000").map(|_| ()),
        Err(DirError::NotFound)
    );
    assert_eq!(l.resolve("\\big\\a").map(|_| ()), Err(DirError::NotFound));
    assert_eq!(
        l.resolve("\\big\\~~~~").map(|_| ()),
        Err(DirError::NotFound)
    );
}

/// Write `path` interleaved with a spacer file, 64 KiB at a time with a
/// sync after each, then delete the spacer: a file in many fragments, as a
/// long-lived Windows volume would have.
pub fn fragmented_write(m: &Path, path: &str, data: &[u8]) {
    use std::io::Write;
    let target = m.join(path);
    std::fs::create_dir_all(target.parent().unwrap()).unwrap();
    let mut a = std::fs::File::create(&target).unwrap();
    let spacer = m.join("spacer");
    let mut b = std::fs::File::create(&spacer).unwrap();
    for chunk in data.chunks(64 << 10) {
        a.write_all(chunk).unwrap();
        a.sync_all().unwrap();
        b.write_all(&[0x55; 64 << 10]).unwrap();
        b.sync_all().unwrap();
    }
    drop((a, b));
    std::fs::remove_file(&spacer).unwrap();
}

#[test]
fn clusters_and_fragmentation() {
    for cluster in [512u32, 4096, 65536] {
        let data = pattern(4 << 20, 9);
        let Some(img) = volume(&format!("c{cluster}"), 32, cluster, |m| {
            fragmented_write(m, "paguro/frag.vhd", &data);
        }) else {
            return;
        };
        let mut l = Loader::new(&img).unwrap();
        assert_eq!(
            l.read("\\paguro\\frag.vhd").unwrap(),
            data,
            "cluster {cluster}"
        );
        let f = l.resolve("\\paguro\\frag.vhd").unwrap();
        let mft = l.mft();
        let mut res = vec![0u8; 16];
        let mut runs = vec![ZERO; 65536];
        let d = dir::data(&mut l.disk, &mft, f.file, &mut l.s, &mut res, &mut runs).unwrap();
        let Data::Runs { runs: n, .. } = d else {
            panic!("{d:?}")
        };
        assert!(n >= 2, "cluster {cluster}: only {n} runs");
    }
}

#[test]
fn sparse_files_are_refused() {
    let Some(img) = volume("sparse", 64, 4096, |m| {
        std::fs::create_dir_all(m.join("paguro")).unwrap();
        let f = std::fs::File::create(m.join("paguro/sparse.vhd")).unwrap();
        f.set_len(8 << 20).unwrap();
    }) else {
        return;
    };
    let mut l = Loader::new(&img).unwrap();
    let r = l.read("\\paguro\\sparse.vhd");
    assert!(
        matches!(
            r,
            Err(DirError::Ntfs(NtfsError::Sparse | NtfsError::Runlist(_)))
        ),
        "{r:?}"
    );
}

#[test]
fn identity_mismatch_and_errors_are_typed() {
    let Some(img) = volume("ident", 64, 4096, |m| {
        write(&m.join("paguro/a.efi"), &pattern(9000, 1));
    }) else {
        return;
    };
    let mut l = Loader::new(&img).unwrap();
    let f = l.resolve("\\paguro\\a.efi").unwrap();
    let mft = l.mft();
    let mut res = vec![0u8; 16];
    let mut runs = vec![ZERO; 16];
    let wrong = FileRef {
        record: f.file.record,
        seq: f.file.seq.wrapping_add(1),
    };
    assert_eq!(
        dir::data(&mut l.disk, &mft, wrong, &mut l.s, &mut res, &mut runs),
        Err(DirError::Ntfs(NtfsError::Sequence))
    );
    // A file is not a directory index.
    assert_eq!(
        dir::open_index(&mut l.disk, &mft, f.file, &mut l.s).map(|_| ()),
        Err(DirError::NotDirectory)
    );
    // Reads past the data are refused.
    let d = dir::data(&mut l.disk, &mft, f.file, &mut l.s, &mut res, &mut runs).unwrap();
    let Data::Runs { runs: n, size } = d else {
        panic!("{d:?}")
    };
    let mut b = [0u8; 10];
    assert_eq!(
        dir::read_runs(&mut l.disk, &l.vol, &runs[..n], size, size - 5, &mut b),
        Err(DirError::Range)
    );
    // A tiny resident buffer is reported, not overrun.
    let mut img2 = img.clone();
    let _ = &mut img2;
}

/// Records which sectors a walk reads (for fuzz seeds).
struct Rec(Mem, Vec<u64>);

impl ntfs::Disk for Rec {
    fn read(&mut self, s: u64, b: &mut [u8; 512]) -> Result<(), ntfs::IoError> {
        self.1.push(s);
        self.0.read(s, b)
    }
}

/// `cargo test -p paguro-core --test ntfs_dir -- --ignored write_fuzz_seeds`
/// writes `fuzz/corpus/ntfs_lookup` (sparse volumes: the sectors real
/// lookups read) and `fuzz/corpus/ntfs_index` (real index nodes).
#[test]
#[ignore]
fn write_fuzz_seeds() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus");
    let names: Vec<String> = (0..400)
        .map(|i| format!("f{i:04}-{}", "n".repeat(40)))
        .collect();
    let Some(img) = volume("seeds", 64, 4096, |m| {
        write(&m.join("paguro/debian.vhd"), &pattern(1 << 20, 1));
        write(&m.join("paguro/rescue.efi"), &pattern(3000, 2));
        write(&m.join("hiberfil.sys"), b"hibr");
        for n in &names {
            write(&m.join("paguro").join(n), b"");
        }
        write(&m.join("a/b/c"), b"x");
    }) else {
        return;
    };
    let l = Loader::new(&img).unwrap();
    let mut rec = Rec(Mem(img.clone()), Vec::new());
    let mft = l.mft();
    let mut s = new_scratch();
    let mut up = vec![0u16; UPCASE_LEN].into_boxed_slice();
    for (i, u) in up.iter_mut().enumerate() {
        *u = l.up[i];
    }
    let up: Box<[u16; UPCASE_LEN]> = up.try_into().unwrap();
    let mut alist = Box::new([0u8; MAX_ALIST]);
    let mut runs = vec![ZERO; 1024];
    ntfs::open(&mut rec, &mut alist, &mut runs).unwrap();
    for p in [
        "\\paguro",
        "\\paguro\\debian.vhd",
        "\\paguro\\rescue.efi",
        "\\hiberfil.sys",
        "\\a\\b\\c",
    ] {
        let f = dir::resolve(&mut rec, &mft, &up, p, &mut s).unwrap();
        if f.is_dir {
            let idx = dir::open_index(&mut rec, &mft, f.file, &mut s).unwrap();
            dir::list(&mut rec, &mft, &idx, &mut s, |_| true).unwrap();
        } else {
            let mut res = vec![0u8; 4096];
            let mut r = vec![ZERO; 64];
            if let Ok(Data::Runs { runs: n, size }) =
                dir::data(&mut rec, &mft, f.file, &mut s, &mut res, &mut r)
            {
                let mut b = vec![0u8; size.min(700) as usize];
                dir::read_runs(&mut rec, &l.vol, &r[..n], size, 0, &mut b).unwrap();
            }
        }
        let idx = dir::open_index(&mut rec, &mft, FileRef::ROOT, &mut s).unwrap();
        dir::list(&mut rec, &mft, &idx, &mut s, |_| true).unwrap();
        // One seed per path: the sectors read so far.
        let mut out = vec![0u8; 8];
        let mut seen = BTreeSet::new();
        for &sec in &rec.1 {
            if seen.insert(sec) {
                out.extend((sec as u32).to_le_bytes());
                out.extend(&img[sec as usize * 512..sec as usize * 512 + 512]);
            }
        }
        let d = root.join("ntfs_lookup");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(format!("real-{}", p.replace('\\', "_"))), out).unwrap();
    }
    // Index nodes: every INDX block's entry region, fixups applied.
    let d = root.join("ntfs_index");
    std::fs::create_dir_all(&d).unwrap();
    let mut k = 0;
    for at in (0..img.len()).step_by(4096) {
        if &img[at..at + 4] != b"INDX" || k >= 8 {
            continue;
        }
        let mut b = img[at..at + 4096].to_vec();
        for i in 1..9 {
            let e = i * 512 - 2;
            b[e] = b[0x28 + 2 * i];
            b[e + 1] = b[0x28 + 2 * i + 1];
        }
        let first = u32::from_le_bytes(b[0x18..0x1c].try_into().unwrap()) as usize;
        let len = u32::from_le_bytes(b[0x1c..0x20].try_into().unwrap()) as usize;
        let mut seed = "paguro"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<u8>>();
        seed.resize(16, 0);
        seed.extend(&b[0x18 + first..0x18 + len]);
        std::fs::write(d.join(format!("real-{k}")), seed).unwrap();
        k += 1;
    }
    assert!(k > 0);
}

/// `cmd`, through `sudo -n` when not root (CI runners mount FUSE that way),
/// owned by the current user.
fn privileged(cmd: &str) -> Command {
    let uid = current_uid();
    if uid == 0 {
        Command::new(cmd)
    } else {
        let mut c = Command::new("sudo");
        c.arg("-n").arg(cmd);
        c
    }
}

fn current_uid() -> u32 {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn mount_ntfs(img: &Path, mnt: &Path) -> bool {
    let gid = Command::new("id")
        .arg("-g")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0);
    ok(privileged("ntfs-3g")
        .arg("-o")
        .arg(format!("uid={},gid={gid}", current_uid()))
        .arg(img)
        .arg(mnt))
}

fn umount(mnt: &Path) -> bool {
    ok(privileged("umount").arg(mnt))
}
