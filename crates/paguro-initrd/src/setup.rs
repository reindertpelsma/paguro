//! The boot path (DESIGN.md §4.3, §6; INTERFACES.md §8, §10): handoff →
//! decrypted volume → `PG_VOLUME_ADD` → claims + ntfs3 cross-check →
//! view A (payload assertion in the module) → the root device.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use paguro_core::disk::{self, Format};
use paguro_core::gpt::{self, Entry, Header};
use paguro_core::guid::Guid;
use paguro_core::handoff::{self, FveLayout, Role, Rung, state};
use paguro_core::seal;
use zeroize::{Zeroize, Zeroizing};

use crate::dm::{self, Dm, Mapped};
use crate::pg::{self, Ctl};
use crate::plan::{self, RootChoice, Target};
use crate::sys::{self, R};

pub const HANDOFF_DEV: &str = "/dev/paguro-handoff";
/// Always the root device of a paguro boot.
pub const ROOT_LINK: &str = "/dev/paguro-root";
const WORK: &str = "/run/paguro";

pub fn log(msg: &str) {
    eprintln!("paguro-initrd: {msg}");
}

pub struct Image {
    pub role: Role,
    pub name: String,
    pub mft: u64,
    pub seq: u16,
}

/// What this boot needs from the handoff, copied out so the blob itself
/// can be wiped at once. The FVEK is the only secret kept, until the
/// crypt table is loaded.
pub struct Taken {
    pub volume: handoff::Volume,
    pub fvek: Option<(u16, Zeroizing<Vec<u8>>)>,
    pub layout: Option<FveLayout>,
    pub pcr_mask: u32,
    pub pcrs: Vec<u8>,
    pub config: Option<Vec<u8>>,
    pub images: Vec<Image>,
    pub state: u32,
    pub rung: Rung,
    /// A provisioning boot: the new `tpm_seal.bin`, whole.
    pub provision: Option<Vec<u8>>,
}

/// Read the handoff once, decode it, copy out what is needed, wipe it.
pub fn take(path: &Path) -> R<Taken> {
    let mut f = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut blob = Zeroizing::new(vec![0u8; handoff::MAX_LEN + 1]);
    sys::mlock(&blob);
    let mut n = 0;
    while let Some(rest) = blob.get_mut(n..).filter(|r| !r.is_empty()) {
        match f.read(rest) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) => return Err(format!("reading the handoff: {e}")),
        }
    }
    drop(f);
    let h = handoff::decode(blob.get(..n).unwrap_or(&[]))
        .map_err(|e| format!("the handoff is malformed: {e:?}"))?;
    let mut images = Vec::new();
    for (role, id) in [
        (Role::Root, h.root),
        (Role::EfiDisk, h.efi_disk),
        (Role::EfiFile, h.efi_file),
    ] {
        if let Some(i) = id {
            images.push(Image {
                role,
                name: i.name.to_string(),
                mft: i.mft_record,
                seq: i.mft_seq,
            });
        }
    }
    let provision = match &h.provision {
        Some(s) => {
            let mut out = vec![0u8; seal::MAX_FILE];
            let len = seal::write(s, &mut out).map_err(|_| "PROVISION does not fit a seal file")?;
            out.truncate(len);
            Some(out)
        }
        None => None,
    };
    let t = Taken {
        volume: h.volume,
        fvek: h.fvek.map(|k| (k.cipher, Zeroizing::new(k.key.to_vec()))),
        layout: h.fve_layout,
        pcr_mask: h.pcrs.mask,
        pcrs: h.pcrs.values.to_vec(),
        config: h.config.map(<[u8]>::to_vec),
        images,
        state: h.state,
        rung: h.rung,
        provision,
    };
    if let Some((_, k)) = &t.fvek {
        sys::mlock(k);
    }
    // `blob` (VMK, FVEK, B and all) is zeroed on drop, here.
    drop(blob);
    Ok(t)
}

fn read_sys(p: &Path) -> Option<String> {
    std::fs::read_to_string(p)
        .ok()
        .map(|s| s.trim().to_string())
}

fn read_at(f: &File, off: u64, len: usize) -> R<Vec<u8>> {
    let mut b = vec![0u8; len];
    f.read_exact_at(&mut b, off)
        .map_err(|e| format!("read {len} bytes at {off}: {e}"))?;
    Ok(b)
}

/// A whole disk's GPT: used entries with their slot.
pub fn read_gpt(dev: &Path) -> R<(u32, Vec<(u32, Entry)>)> {
    let f = File::open(dev).map_err(|e| format!("{}: {e}", dev.display()))?;
    let (size, lbs) = sys::blk_geometry(&f)?;
    let block = read_at(&f, u64::from(lbs), lbs as usize)?;
    let hdr = Header::parse(&block, size / u64::from(lbs)).map_err(|e| format!("GPT: {e:?}"))?;
    let arr = read_at(&f, hdr.entries_lba * u64::from(lbs), hdr.entries_len())?;
    let es = hdr
        .entries(&arr)
        .map_err(|e| format!("GPT entries: {e:?}"))?;
    let mut out = Vec::new();
    for i in 0..es.count() {
        let e = es.get(i).map_err(|e| format!("GPT entry {i}: {e:?}"))?;
        if !e.is_unused() {
            out.push((i, e));
        }
    }
    Ok((lbs, out))
}

/// Block devices that are partitions: (node, disk name, partition number).
fn partitions() -> Vec<(PathBuf, String, u32)> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir("/sys/class/block") else {
        return out;
    };
    for e in rd.flatten() {
        let p = e.path();
        let Some(n) = read_sys(&p.join("partition")).and_then(|s| s.parse().ok()) else {
            continue;
        };
        let Some(disk) = std::fs::canonicalize(&p).ok().and_then(|c| {
            c.parent()
                .and_then(|d| d.file_name())
                .map(|d| d.to_string_lossy().into_owned())
        }) else {
            continue;
        };
        out.push((Path::new("/dev").join(e.file_name()), disk, n));
    }
    out.sort();
    out
}

/// The NTFS partition the handoff names, by GPT partition GUID, first LBA
/// and length; waits for it to appear.
fn find_partition(v: &handoff::Volume, wait: Duration) -> R<PathBuf> {
    let t0 = Instant::now();
    loop {
        for (node, disk, n) in partitions() {
            let Ok((lbs, es)) = read_gpt(&Path::new("/dev").join(&disk)) else {
                continue;
            };
            for (slot, e) in es {
                if slot + 1 == n
                    && e.unique_guid == v.partition
                    && e.first_lba == v.first_lba
                    && e.sectors() * u64::from(lbs) == v.sectors * 512
                {
                    return Ok(node);
                }
            }
        }
        if t0.elapsed() > wait {
            return Err(format!(
                "no partition {} (first LBA {}) appeared",
                v.partition, v.first_lba
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn devt((ma, mi): (u32, u32)) -> String {
    format!("{ma}:{mi}")
}

pub struct Opts {
    pub handoff: PathBuf,
    pub env: PathBuf,
    pub wait: Duration,
    /// `paguro.root=` from the kernel command line.
    pub root_hint: Option<String>,
    pub esp: bool,
}

pub fn cmdline_arg(key: &str) -> Option<String> {
    let c = std::fs::read_to_string("/proc/cmdline").ok()?;
    c.split_whitespace()
        .find_map(|w| w.strip_prefix(key).and_then(|v| v.strip_prefix('=')))
        .map(str::to_string)
}

/// The whole boot path. Writes `opts.env` (`PAGURO_ROOT=`, `PAGURO_ROOT_RO=`,
/// `PAGURO_ROOTFSTYPE=`) for the init script that mounts it.
pub fn run(opts: &Opts) -> R<()> {
    let _ = std::fs::create_dir_all(WORK);
    let mut t = take(&opts.handoff)?;
    log(&format!(
        "handoff: volume {} rung {:?} state {:#x}{}",
        t.volume.partition,
        t.rung,
        t.state,
        if t.fvek.is_some() { " (BitLocker)" } else { "" }
    ));
    let result = boot(&mut t, opts);
    if let Some((_, k)) = &mut t.fvek {
        k.zeroize();
    }
    result
}

fn boot(t: &mut Taken, opts: &Opts) -> R<()> {
    let root = t
        .images
        .iter()
        .find(|i| i.role == Role::Root)
        .ok_or("the chosen entry has no root disk")?;
    let entry = root.name.clone();
    let part = find_partition(&t.volume, opts.wait)?;
    let raw = sys::devno(&part)?;
    log(&format!("volume: {} ({})", part.display(), devt(raw)));
    let dm = Dm::open()?;

    // 1. The decrypted volume: BitLocker's segments, or the partition itself.
    let (plain, reserved) = match (t.fvek.take(), t.layout) {
        (Some((cipher, key)), Some(l)) => {
            let segs = plan::crypt_segments(t.volume.sectors, &l)
                .map_err(|e| format!("FVE_LAYOUT refused: {e:?}"))?;
            let (name, klen) = plan::dm_cipher(cipher)
                .ok_or_else(|| format!("cipher {cipher:#x} not supported"))?;
            if key.len() != klen {
                return Err("FVEK length does not match its cipher".into());
            }
            let desc = format!("paguro:fvek-{}", std::process::id());
            let serial = sys::add_logon_key(&desc, &key)?;
            drop(key);
            let table = plan::crypt_table(
                &segs,
                &devt(raw),
                name,
                &format!(":{klen}:logon:{desc}"),
                l.sector_size,
            );
            let r = dm.setup("paguro-volume", &table, 0);
            // dm-crypt holds its own copy now; the keyring's goes.
            sys::invalidate_key(serial);
            let m = r?;
            log(&format!(
                "decrypted volume: {} segments, {}",
                segs.len(),
                m.devt()
            ));
            (m.node.clone(), plan::reserved_ranges(&l))
        }
        (None, None) => (part.clone(), Vec::new()),
        _ => return Err("FVEK and FVE_LAYOUT must come together".into()),
    };
    let plain_no = sys::devno(&plain)?;

    // 2. Register the volume with the module.
    let ctl = Ctl::open()?;
    let mut va = pg::VolumeAdd {
        raw_major: raw.0,
        raw_minor: raw.1,
        plain_major: plain_no.0,
        plain_minor: plain_no.1,
        guid: t.volume.partition.0,
        nreserved: reserved.len() as u32,
        ..Default::default()
    };
    for (slot, &(start, len)) in va.reserved.iter_mut().zip(&reserved) {
        *slot = pg::Range { start, len };
    }
    ctl.volume_add(&mut va)?;
    log(&format!(
        "PG_VOLUME_ADD: volume {} ({} sectors, flags {:#x})",
        va.volume_id, va.sectors, va.volume_flags
    ));

    // 3. ntfs3, read-only over a read-only alias: identity, format and
    //    FIEMAP of each disk to claim. Nothing can reach the volume from here.
    let claimable: Vec<&Image> = t
        .images
        .iter()
        .filter(|i| i.role != Role::EfiFile)
        .collect();
    let probes = probe_ntfs(&dm, &plain, &claimable)?;

    // 4. Claims and cross-checks: FIEMAP can only subtract.
    let degraded = t.state & (state::HIBERNATED | state::DIRTY) != 0;
    let mut root_view = None;
    for (img, p) in claimable.iter().zip(&probes) {
        let mut c = pg::Claim {
            volume_id: va.volume_id,
            format: if p.format == Format::Vhd {
                pg::FORMAT_VHD
            } else {
                pg::FORMAT_RAW
            },
            mft_record: img.mft,
            mft_seq: img.seq,
            ..Default::default()
        };
        ctl.claim(&mut c)?;
        let st = ctl.crosscheck(c.claim_id, &p.extents)?;
        if st & pg::CLAIM_CHECKED == 0 || st & pg::CLAIM_REFUSED != 0 {
            return Err(format!(
                "claim {}: ntfs3 disagrees with the module: no view A",
                c.claim_id
            ));
        }
        let ro = degraded || st & pg::CLAIM_READONLY != 0;
        log(&format!(
            "PG_CLAIM {} (MFT {} seq {}): {} extents, {} sectors, {}{}",
            c.claim_id,
            img.mft,
            img.seq,
            c.extents,
            c.sectors,
            pg::state_text(st),
            if ro { ", read-only" } else { "" }
        ));
        // 5. View A: the module asserts the payload's structure at load.
        let name = if img.role == Role::Root {
            format!("paguro-{entry}")
        } else {
            format!("paguro-{entry}-efi")
        };
        let view = dm.setup(
            &name,
            &[Target {
                start: 0,
                len: c.sectors,
                kind: "paguro-image",
                params: c.claim_id.to_string(),
            }],
            if ro { dm::READONLY } else { 0 },
        )?;
        log(&format!(
            "view A {}: {} (payload check passed)",
            name,
            view.devt()
        ));
        if img.role == Role::Root {
            root_view = Some((view, ro));
        } else {
            let _ = expose(&dm, &view, ro, None);
        }
    }
    let (view, ro) = root_view.ok_or("no root view")?;

    // 6. The root device: a GPT's partitions, or the view itself.
    let (dev, fstype) = expose(&dm, &view, ro, opts.root_hint.as_deref())?
        .ok_or("no root file system on the root disk")?;
    let env = format!(
        "PAGURO_ROOT={}\nPAGURO_ROOT_RO={}\nPAGURO_ROOTFSTYPE={}\nPAGURO_ENTRY={}\n",
        dev.display(),
        u8::from(ro),
        fstype,
        entry
    );
    std::fs::write(&opts.env, env).map_err(|e| format!("{}: {e}", opts.env.display()))?;
    // A fixed name for `root=` (dracut, or a hand-written command line).
    let _ = std::fs::remove_file(ROOT_LINK);
    let _ = std::os::unix::fs::symlink(&dev, ROOT_LINK);
    log(&format!(
        "root: {} ({fstype}{})",
        dev.display(),
        if ro { ", read-only" } else { "" }
    ));

    // 7. The ESP: recorded.bin, and a provisioning boot's files. Advisory;
    //    a failure here never stops the boot.
    if opts.esp {
        if let Err(e) = crate::esp::write(t) {
            log(&format!("ESP: {e}"));
        }
    }
    Ok(())
}

struct Probe {
    format: Format,
    extents: Vec<(u64, u64)>,
}

fn probe_ntfs(dm: &Dm, plain: &Path, imgs: &[&Image]) -> R<Vec<Probe>> {
    let f = File::open(plain).map_err(|e| format!("{}: {e}", plain.display()))?;
    let (bytes, _) = sys::blk_geometry(&f)?;
    drop(f);
    let alias = dm.setup(
        "paguro-ntfs-ro",
        &[Target {
            start: 0,
            len: bytes / 512,
            kind: "linear",
            params: format!("{} 0", devt(sys::devno(plain)?)),
        }],
        dm::READONLY,
    )?;
    let mnt = Path::new(WORK).join("ntfs");
    let _ = std::fs::create_dir_all(&mnt);
    let r = (|| {
        sys::mount(
            alias.node.to_str().unwrap_or_default(),
            &mnt,
            "ntfs3",
            libc::MS_RDONLY | libc::MS_NOATIME | libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_NOSUID,
            "",
        )?;
        let r = (|| {
            let root = File::open(&mnt).map_err(|e| format!("{}: {e}", mnt.display()))?;
            let mut out = Vec::new();
            for img in imgs {
                out.push(probe_file(&root, &mnt, img)?);
            }
            Ok(out)
        })();
        let _ = sys::umount(&mnt);
        r
    })();
    let _ = dm.remove(&alias.name);
    r
}

fn probe_file(root: &File, mnt: &Path, img: &Image) -> R<Probe> {
    let ino = u32::try_from(img.mft).map_err(|_| "MFT record beyond 32 bits")?;
    let f = match sys::open_by_ino_gen(root, ino, u32::from(img.seq)) {
        Ok(f) => f,
        Err(e) if e.raw_os_error() == Some(libc::EOPNOTSUPP) => find_by_ino(mnt, u64::from(ino))?,
        Err(e) => {
            return Err(format!(
                "MFT record {} seq {} not found on ntfs3: {e}",
                img.mft, img.seq
            ));
        }
    };
    let len = f.metadata().map_err(|e| e.to_string())?.len();
    let mut tail = [0u8; 512];
    if len >= 512 {
        f.read_exact_at(&mut tail, len - 512)
            .map_err(|e| format!("reading the disk's footer: {e}"))?;
    }
    let p = disk::detect(len, &tail);
    let extents = sys::fiemap(&f)?;
    Ok(Probe {
        format: p.format,
        extents,
    })
}

/// Fallback when ntfs3 cannot open by handle: walk for the inode number.
/// The module still checks the sequence number itself.
fn find_by_ino(dir: &Path, ino: u64) -> R<File> {
    use std::os::unix::fs::MetadataExt;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let Ok(m) = e.metadata() else { continue };
            if m.is_dir() {
                stack.push(e.path());
            } else if m.ino() == ino && m.is_file() {
                return File::open(e.path()).map_err(|e| e.to_string());
            }
        }
    }
    Err(format!("MFT record {ino} not found on ntfs3"))
}

/// What a device holds, by magic.
fn fs_type(dev: &Path) -> R<&'static str> {
    let f = File::open(dev).map_err(|e| format!("{}: {e}", dev.display()))?;
    let (size, _) = sys::blk_geometry(&f)?;
    let b = read_at(&f, 0, size.min(36 * 1024) as usize)?;
    let at = |o: usize, n: usize| b.get(o..o + n).unwrap_or(&[]);
    Ok(if at(1080, 2) == [0x53, 0xef] {
        "ext4"
    } else if at(0x8001, 5) == b"CD001" {
        "iso9660"
    } else if at(0x10040, 8) == b"_BHRfS_M" {
        "btrfs"
    } else if at(0, 4) == b"XFSB" {
        "xfs"
    } else if at(3, 8) == b"FAT32   " || at(0x52, 8) == b"FAT32   " {
        "vfat"
    } else {
        "auto"
    })
}

/// Expose a view A: its GPT partitions as dm-linear devices (the kernel
/// does not partition-scan device-mapper devices), or the view itself for
/// a bare file system. Returns the root's device when `want_root`.
fn expose(
    dm: &Dm,
    view: &Mapped,
    ro: bool,
    hint: Option<&str>,
) -> R<Option<(PathBuf, &'static str)>> {
    let f = File::open(&view.node).map_err(|e| format!("{}: {e}", view.node.display()))?;
    let (_, lbs) = sys::blk_geometry(&f)?;
    let sig = read_at(&f, u64::from(lbs), 8)?;
    drop(f);
    if sig != gpt::SIGNATURE {
        let ty = fs_type(&view.node)?;
        return Ok(Some((PathBuf::from("/dev/mapper").join(&view.name), ty)));
    }
    let (lbs, es) = read_gpt(&view.node)?;
    let per = u64::from(lbs) / 512;
    let mut nodes = Vec::new();
    for (slot, e) in &es {
        let name = format!("{}-p{}", view.name, slot + 1);
        let m = dm.setup(
            &name,
            &[Target {
                start: 0,
                len: e.sectors() * per,
                kind: "linear",
                params: format!("{} {}", view.devt(), e.first_lba * per),
            }],
            if ro { dm::READONLY } else { 0 },
        )?;
        log(&format!(
            "  partition {}: {}{}",
            slot + 1,
            name,
            if plan::is_esp(e) { " (ESP)" } else { "" }
        ));
        nodes.push(PathBuf::from("/dev/mapper").join(&m.name));
    }
    match plan::choose_root(&es, hint) {
        RootChoice::Index(i) => {
            let n = nodes.get(i).ok_or("root index")?.clone();
            let ty = fs_type(&n)?;
            Ok(Some((n, ty)))
        }
        RootChoice::None => Ok(None),
        RootChoice::Ambiguous => Err("several root candidates: set paguro.root=".into()),
    }
}

/// Status of the module, for tests and the marker service.
pub fn status() -> R<String> {
    use core::fmt::Write;
    let s = Ctl::open()?.status()?;
    let mut out = String::new();
    for v in s.volume.iter().filter(|v| v.id != 0) {
        let _ = writeln!(
            out,
            "volume {} guid {} sectors {} flags {:#x} view {} guard_hits {} readahead_hits {}",
            v.id,
            Guid(v.guid),
            v.sectors,
            v.flags,
            match v.view {
                0 => "-".to_string(),
                c => char::from_u32(c).map_or("?".into(), |c| c.to_string()),
            },
            v.guard_hits,
            v.readahead_hits
        );
    }
    for c in s.claim.iter().filter(|c| c.id != 0) {
        let _ = writeln!(
            out,
            "claim {} volume {} mft {} seq {} state {} extents {} sectors {} tables {} refused {}",
            c.id,
            c.volume_id,
            c.mft_record,
            c.mft_seq,
            pg::state_text(c.state),
            c.extents,
            c.sectors,
            c.image_tables,
            c.refused
        );
    }
    Ok(out)
}

/// The EFI system table's physical address, for `paguro-handoff systab=`.
pub fn systab() -> R<u64> {
    let b = std::fs::read("/sys/kernel/boot_params/data")
        .map_err(|e| format!("/sys/kernel/boot_params/data: {e}"))?;
    // struct boot_params: efi_info at 0x1c0 — efi_systab at +4, _hi at +24.
    let u32_at = |o: usize| {
        b.get(o..o + 4)
            .and_then(|s| s.try_into().ok())
            .map_or(0, u32::from_le_bytes)
    };
    let st = u64::from(u32_at(0x1c4)) | u64::from(u32_at(0x1d8)) << 32;
    if st == 0 {
        return Err("no EFI system table in boot_params (not an EFI boot?)".into());
    }
    Ok(st)
}
