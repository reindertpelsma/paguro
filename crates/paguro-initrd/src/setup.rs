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
/// Poll interval while waiting for the handoff's partition to appear.
const PARTITION_POLL: Duration = Duration::from_millis(200);
/// The VHD footer `disk::detect` reads from an image's tail.
const FOOTER_LEN: usize = paguro_core::vhd::FOOTER_LEN as usize;

// `fs_type`: bytes read from a device's start, and the magic each file
// system keeps at a fixed offset in them.
/// Enough to reach the deepest magic probed: btrfs's, at 64 KiB + 0x40.
const FS_PROBE_LEN: u64 = 68 * 1024;
/// ext4 superblock (at 1024) `s_magic` (+0x38): 0xEF53, little-endian.
const EXT4_MAGIC_AT: usize = 1024 + 0x38;
const EXT4_MAGIC: [u8; 2] = [0x53, 0xef];
/// ISO 9660 primary volume descriptor (sector 16) standard identifier.
const ISO9660_MAGIC_AT: usize = 0x8001;
const ISO9660_MAGIC: &[u8] = b"CD001";
/// btrfs superblock (at 64 KiB) `magic` (+0x40).
const BTRFS_MAGIC_AT: usize = 0x10040;
const _: () = assert!(BTRFS_MAGIC_AT + BTRFS_MAGIC.len() <= FS_PROBE_LEN as usize);
const BTRFS_MAGIC: &[u8] = b"_BHRfS_M";
/// XFS superblock `sb_magicnum` at the start.
const XFS_MAGIC_AT: usize = 0;
const XFS_MAGIC: &[u8] = b"XFSB";
/// FAT32: the OEM name some formatters set, and BS_FilSysType (0x52).
const FAT32_OEM_AT: usize = 3;
const FAT32_FSTYPE_AT: usize = 0x52;
const FAT32_LABEL: &[u8] = b"FAT32   ";

/// `struct efi_info` (arch/x86/include/uapi/asm/bootparam.h), at
/// `EFI_INFO_AT` in `struct boot_params`: layout only, for `offset_of!`.
#[allow(dead_code)]
#[repr(C)]
struct EfiInfo {
    efi_loader_signature: u32,
    efi_systab: u32,
    efi_memdesc_size: u32,
    efi_memdesc_version: u32,
    efi_memmap: u32,
    efi_memmap_size: u32,
    efi_systab_hi: u32,
    efi_memmap_hi: u32,
}
const EFI_INFO_AT: usize = 0x1c0;
const _: () = assert!(core::mem::offset_of!(EfiInfo, efi_systab_hi) == 24);

pub fn log(msg: &str) {
    eprintln!("paguro-initrd: {msg}");
}

pub struct Image {
    pub role: Role,
    pub name: String,
    pub mft: u64,
    pub seq: u16,
}

/// A 32-byte secret held only long enough to attempt a re-seal: zeroized on
/// drop, and deliberately **not** `Debug` (unlike `Zeroizing<[u8; 32]>`
/// alone, which still is). So `#[derive(Debug)]` ever landing on `Taken` — or
/// any future struct holding one of these — fails to compile instead of
/// silently printing `B`, the VMK or the password hash to a log
/// (INTERFACES.md §8.3: "nothing is written to disk in the clear", which a
/// log line would just as surely violate). `Deref` is implemented so call
/// sites read like a plain `&[u8; 32]`; formatting does not go through it.
pub struct Secret32(Zeroizing<[u8; 32]>);

impl Secret32 {
    pub fn new(bytes: [u8; 32]) -> Self {
        Secret32(Zeroizing::new(bytes))
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::ops::Deref for Secret32 {
    type Target = [u8; 32];
    fn deref(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The salted, stretched passphrase hash Windows wrote to
/// `%ProgramData%\paguro\<volume-guid>\tpm-auth.bin` (`paguro_core::tpm_auth`),
/// read from the NTFS volume through the same read-only ntfs3 mount
/// `probe_ntfs` already opens. Kept only for a possible re-seal
/// (INTERFACES.md §8.3, §8.4; `crate::reseal`), zeroized once the attempt
/// (successful or not) is over.
pub struct WinAuth {
    pub salt: [u8; 16],
    pub value: Secret32,
}

/// What this boot needs from the handoff, copied out so the blob itself
/// can be wiped at once. The FVEK is kept until the crypt table is loaded;
/// `b` and `vmk` are kept for a possible re-seal (INTERFACES.md §8.3, §5
/// `PaguroTpmBroken`; `crate::reseal`) and zeroized at the end of `run`
/// either way — `esp::maybe_reseal` also drops its own borrows of them (and
/// of `win_auth`) as soon as the attempt (successful or not) is over, rather
/// than holding them for the rest of the process.
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
    /// The boot-services-only firmware secret (handoff `B`), kept only for a
    /// possible re-seal.
    pub b: Secret32,
    /// BitLocker's Volume Master Key (handoff `VMK`), absent for an
    /// unencrypted volume.
    pub vmk: Option<Secret32>,
    /// Read from `tpm-auth.bin` on the NTFS volume during `boot`'s ntfs3
    /// mount (`probe_ntfs`); `None` until then, and also when the file is
    /// absent, malformed, or the volume is not BitLocker-encrypted.
    pub win_auth: Option<WinAuth>,
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
        b: Secret32::new(*h.b),
        vmk: h.vmk.map(|k| Secret32::new(*k)),
        win_auth: None,
    };
    if let Some((_, k)) = &t.fvek {
        sys::mlock(k);
    }
    sys::mlock(&t.b[..]);
    // §8.3: "B goes into a root-only logon key in the kernel keyring that
    // lives for the session, read only by the re-seal tool" — a later
    // process (a PIN change from Linux, DESIGN.md §6) can still reach it
    // after this one exits; this boot's own re-seal (below) uses the copy
    // in `Taken` directly.
    if let Err(e) = sys::add_session_logon_key("paguro:b", &t.b[..]) {
        log(&format!("keeping B in the session keyring failed: {e}"));
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

pub(crate) fn read_at(f: &File, off: u64, len: usize) -> R<Vec<u8>> {
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
                    && e.sectors() * u64::from(lbs) == v.sectors * plan::SECTOR
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
        std::thread::sleep(PARTITION_POLL);
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

    // 2. Register the volume with the module; a hibernated or dirty volume
    //    read-only in the module itself, not only in what we ask of it.
    let degraded = t.state & (state::HIBERNATED | state::DIRTY) != 0;
    let ctl = Ctl::open()?;
    let mut va = pg::VolumeAdd {
        raw_major: raw.0,
        raw_minor: raw.1,
        plain_major: plain_no.0,
        plain_minor: plain_no.1,
        guid: t.volume.partition.0,
        nreserved: reserved.len() as u32,
        flags: if degraded { pg::VOLUME_READ_ONLY } else { 0 },
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
    let (probes, win_auth) = probe_ntfs(&dm, &plain, &claimable, &t.volume.partition)?;
    t.win_auth = win_auth;

    // 4. Claims and cross-checks: FIEMAP can only subtract.
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
    //    a failure here never stops the boot. `part` (the raw, still-BitLocker
    //    partition) is what a re-seal reads BitLocker's FVE metadata from.
    if opts.esp {
        if let Err(e) = crate::esp::write(t, &part) {
            log(&format!("ESP: {e}"));
        }
    }
    Ok(())
}

struct Probe {
    format: Format,
    extents: Vec<(u64, u64)>,
}

fn probe_ntfs(
    dm: &Dm,
    plain: &Path,
    imgs: &[&Image],
    volume: &Guid,
) -> R<(Vec<Probe>, Option<WinAuth>)> {
    let f = File::open(plain).map_err(|e| format!("{}: {e}", plain.display()))?;
    let (bytes, _) = sys::blk_geometry(&f)?;
    drop(f);
    let alias = dm.setup(
        "paguro-ntfs-ro",
        &[Target {
            start: 0,
            len: bytes / plan::SECTOR,
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
            let auth = read_win_auth(&mnt, volume);
            Ok((out, auth))
        })();
        let _ = sys::umount(&mnt);
        r
    })();
    let _ = dm.remove(&alias.name);
    r
}

/// `%ProgramData%\paguro\<volume-guid>\tpm-auth.bin` (INTERFACES.md §8.4),
/// read while `mnt` (the read-only ntfs3 mount) is still up. Absent or
/// malformed: logs why and returns `None` — never fails the boot, and never
/// the whole `probe_ntfs` (a missing file is the common case: most boots
/// carry no `PaguroTpmBroken` re-seal to do).
fn read_win_auth(mnt: &Path, volume: &Guid) -> Option<WinAuth> {
    let path = mnt
        .join("ProgramData")
        .join("paguro")
        .join(volume.to_string())
        .join(paguro_core::tpm_auth::FILE_NAME);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            log(&format!("{}: {e}", path.display()));
            return None;
        }
    };
    match paguro_core::tpm_auth::parse(&bytes) {
        Ok(a) => Some(WinAuth {
            salt: a.salt,
            value: Secret32::new(a.value),
        }),
        Err(e) => {
            log(&format!("{}: malformed ({e:?})", path.display()));
            None
        }
    }
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
    let mut tail = [0u8; FOOTER_LEN];
    if len >= FOOTER_LEN as u64 {
        f.read_exact_at(&mut tail, len - FOOTER_LEN as u64)
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
    let b = read_at(&f, 0, size.min(FS_PROBE_LEN) as usize)?;
    let has = |o: usize, magic: &[u8]| b.get(o..o + magic.len()) == Some(magic);
    Ok(if has(EXT4_MAGIC_AT, &EXT4_MAGIC) {
        "ext4"
    } else if has(ISO9660_MAGIC_AT, ISO9660_MAGIC) {
        "iso9660"
    } else if has(BTRFS_MAGIC_AT, BTRFS_MAGIC) {
        "btrfs"
    } else if has(XFS_MAGIC_AT, XFS_MAGIC) {
        "xfs"
    } else if has(FAT32_OEM_AT, FAT32_LABEL) || has(FAT32_FSTYPE_AT, FAT32_LABEL) {
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
    let sig = read_at(&f, u64::from(lbs), gpt::SIGNATURE.len())?;
    drop(f);
    if sig != gpt::SIGNATURE {
        let ty = fs_type(&view.node)?;
        return Ok(Some((PathBuf::from("/dev/mapper").join(&view.name), ty)));
    }
    let (lbs, es) = read_gpt(&view.node)?;
    let per = u64::from(lbs) / plan::SECTOR;
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
    let u32_at = |o: usize| {
        b.get(o..o + size_of::<u32>())
            .and_then(|s| s.try_into().ok())
            .map_or(0, u32::from_le_bytes)
    };
    let lo = EFI_INFO_AT + core::mem::offset_of!(EfiInfo, efi_systab);
    let hi = EFI_INFO_AT + core::mem::offset_of!(EfiInfo, efi_systab_hi);
    let st = u64::from(u32_at(lo)) | u64::from(u32_at(hi)) << 32;
    if st == 0 {
        return Err("no EFI system table in boot_params (not an EFI boot?)".into());
    }
    Ok(st)
}

#[cfg(test)]
mod tests {
    use super::{Secret32, read_win_auth};
    use paguro_core::guid::Guid;

    /// `Secret32` really does zero its bytes when dropped, not only when
    /// asked (INTERFACES.md §8.3, "nothing is written ... in the clear" —
    /// the same must hold for what a process leaves behind in its own
    /// memory once it is done with a secret).
    #[test]
    fn secret32_zeroizes_on_drop() {
        let ptr;
        {
            let s = Secret32::new([0x42; 32]);
            assert_eq!(*s, [0x42; 32]);
            ptr = s.as_bytes().as_ptr();
        } // `s` drops here.
        // SAFETY: `Secret32` is not boxed, so its bytes live in this frame's
        // stack slot; reading it immediately after drop, before anything
        // else runs, is the standard way to observe zeroize-on-drop (the
        // `zeroize` crate's own tests use the same pattern).
        let after = unsafe { std::slice::from_raw_parts(ptr, 32) };
        assert_eq!(after, [0u8; 32], "Secret32 must zeroize on drop");
    }

    /// A scratch directory standing in for the ntfs3 mount root
    /// (`read_win_auth` only ever takes a `&Path`, so a plain temp dir
    /// exercises it exactly as the real mount would).
    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "paguro-initrd-winauth-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A well-formed `tpm-auth.bin` at the path Windows writes it to is
    /// read back with the same salt and value.
    #[test]
    fn present_and_well_formed_is_read() {
        let mnt = scratch("ok");
        let volume = Guid([7; 16]);
        let dir = mnt
            .join("ProgramData")
            .join("paguro")
            .join(volume.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        let a = paguro_core::tpm_auth::TpmAuth {
            salt: [0x11; 16],
            value: [0x22; 32],
        };
        let mut buf = [0u8; paguro_core::tpm_auth::LEN];
        let n = paguro_core::tpm_auth::write(&a, &mut buf).unwrap();
        std::fs::write(
            dir.join(paguro_core::tpm_auth::FILE_NAME),
            buf.get(..n).unwrap_or(&[]),
        )
        .unwrap();

        let got = read_win_auth(&mnt, &volume).expect("file present and well-formed");
        assert_eq!(got.salt, a.salt);
        assert_eq!(*got.value, a.value);
        let _ = std::fs::remove_dir_all(&mnt);
    }

    /// No file at all (the common case: most boots carry no
    /// `PaguroTpmBroken` re-seal to do) is `None`, not an error.
    #[test]
    fn absent_is_none() {
        let mnt = scratch("absent");
        let volume = Guid([8; 16]);
        assert!(read_win_auth(&mnt, &volume).is_none());
        let _ = std::fs::remove_dir_all(&mnt);
    }

    /// Garbage in place of the file is also `None` (logged, never a panic
    /// or a boot failure).
    #[test]
    fn malformed_is_none() {
        let mnt = scratch("malformed");
        let volume = Guid([9; 16]);
        let dir = mnt
            .join("ProgramData")
            .join("paguro")
            .join(volume.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(paguro_core::tpm_auth::FILE_NAME),
            b"not a tpm-auth file",
        )
        .unwrap();
        assert!(read_win_auth(&mnt, &volume).is_none());
        let _ = std::fs::remove_dir_all(&mnt);
    }
}
