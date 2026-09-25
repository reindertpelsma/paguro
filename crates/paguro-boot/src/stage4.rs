//! Stage 4 (DESIGN.md §4.1, §4.2; INTERFACES.md §3.2, §13.4): the unlocked
//! volume's NTFS, the boot entry's disks, and the next UEFI image.
//!
//! Everything here reads the volume through a [`SectorRead`] — 512-byte
//! sectors of the volume *as NTFS sees it*. [`PartitionReader`] reads an
//! unencrypted partition through [`Platform::read_blocks`]; the BitLocker
//! layer slots a decrypting reader under the same trait, and the NTFS code
//! above it does not change.
//!
//! What stage 4 decides, in order:
//!
//! 1. mount: `$MFT` mapped, `$UpCase` loaded ([`paguro_core::ntfs::dir`]);
//! 2. the safety gates: `$Volume`'s dirty bit, `hiberfil.sys`'s header;
//! 3. the entry's files by path: `root` (a hint: its identity and the
//!    module's own map check, never its contents), then either `efi_file`
//!    (read later, whole, for `LoadImage(SourceBuffer)`) or `efi_disk`:
//!    its map, its format (fixed VHD or raw, [`disk::detect`]), where its
//!    FAT32 is ([`disk::classify`]), that the FAT32 is sound and holds `efi`
//!    ([`fat::Fs::find`]);
//! 4. the disk is handed to the platform to publish as a read-only block
//!    device ([`Platform::expose_disk`]), which returns the device path the
//!    image is loaded by.
//!
//! No step writes anything, anywhere.

use paguro_core::bde::Layout;
use paguro_core::config::{self, Efi, Entry};
use paguro_core::disk::{self, DiskError, EfiFs, SECTOR};
use paguro_core::fat::{self, FatError};
use paguro_core::handoff::{FveLayout, state};
use paguro_core::ntfs::dir::{self, Data, DirError, FileRef, Scratch, UPCASE_LEN};
use paguro_core::ntfs::{self, Disk, IoError, MAX_EXTENTS};
use paguro_core::range::Extent;
use paguro_core::runlist::Run;

use crate::BootError;
use crate::platform::{DirListing, Level, Platform, PlatformError};
use crate::volume::{
    FileId, Key, Located, MAX_BLOCK, Partition, RECOVERY_KEY_LEN, Volume, VolumeKind,
};

/// The 512-byte sectors stage 4 reads, as a buffer length.
const SECTOR_LEN: usize = SECTOR as usize;
/// The hibernation file, and the bytes of it the hibernation gate reads
/// (its header's first sector).
const HIBERFIL_PATH: &str = "\\hiberfil.sys";
const HIBERFIL_HEADER_LEN: usize = SECTOR_LEN;
/// The first boot's installation directory (INTERFACES.md §3.2).
const INSTALL_DIR: &str = "\\paguro";
const INSTALL_DIR_PREFIX: &[u8] = b"\\paguro\\";
/// The entry name when the file's own name gives none.
const FALLBACK_ENTRY_NAME: &str = "linux";
/// A directory entry's name (at most `dir::MAX_NAME` UTF-16 units) as UTF-8.
const NAME_UTF8_MAX: usize = 1024;
const _: () = assert!(dir::MAX_NAME * crate::UTF8_MAX <= NAME_UTF8_MAX);
/// Bytes of an `efi_file` read per call.
const EFI_READ_CHUNK: u64 = 1 << 20;

/// Runs of `$MFT` kept (it may not have an attribute list, so its runlist
/// fits one record).
pub const MFT_RUNS: usize = 1024;
/// Largest `efi_file` read into memory.
pub const MAX_EFI_FILE: u64 = 512 << 20;

/// Why stage 4 refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage4Error {
    /// `$MFT` or `$UpCase` refused.
    Mount(DirError),
    /// The entry's `root`, `efi_disk` or `efi_file` (by [`Role`]) could not be
    /// found, or its record or map was refused.
    File(Role, DirError),
    /// The efi disk's payload has no usable FAT32 (INTERFACES.md §3.2).
    Payload(DiskError),
    /// The FAT32 is unsound.
    Fat(FatError),
    /// `efi` is not on the FAT32, or names a directory.
    EfiMissing,
    /// The `efi_file` is larger than [`MAX_EFI_FILE`], or empty.
    EfiFileSize,
    /// A disk file larger than its NTFS allocation, or smaller than a sector.
    DiskSize,
    /// The platform could not publish the disk or find the firmware's file
    /// system on it.
    Expose(PlatformError),
    /// The platform could not provide memory for the `efi_file`.
    Memory(PlatformError),
    /// The efi disk's extents cover a BitLocker non-data region (the
    /// relocated boot sectors or their copy, a metadata region, the
    /// Windows 10+ region beside them).
    Reserved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Root,
    EfiDisk,
    EfiFile,
}

impl From<Stage4Error> for BootError {
    fn from(e: Stage4Error) -> Self {
        BootError::Stage4(e)
    }
}

/// 512-byte sectors of the volume as NTFS sees it (plaintext).
pub trait SectorRead<P: Platform> {
    /// Read `buf.len() / 512` sectors from `sector`; `buf.len()` is a
    /// non-zero multiple of 512.
    fn read(&mut self, p: &mut P, sector: u64, buf: &mut [u8]) -> Result<(), PlatformError>;
    /// Sectors in the volume.
    fn sectors(&self) -> u64;
}

/// An unencrypted partition, read through the platform's block device.
/// Handles 512- and 4096-byte physical blocks.
#[derive(Clone, Copy, Debug)]
pub struct PartitionReader {
    pub part: Partition,
}

impl<P: Platform> SectorRead<P> for PartitionReader {
    fn read(&mut self, p: &mut P, sector: u64, buf: &mut [u8]) -> Result<(), PlatformError> {
        let n = (buf.len() / SECTOR_LEN) as u64;
        if buf.is_empty() || buf.len() % SECTOR_LEN != 0 {
            return Err(PlatformError::Unsupported);
        }
        let end = sector.checked_add(n).ok_or(PlatformError::TooLarge)?;
        if end > <Self as SectorRead<P>>::sectors(self) {
            return Err(PlatformError::TooLarge);
        }
        let bs = u64::from(self.part.block_size);
        let per = bs / SECTOR;
        if per <= 1 {
            let lba = self
                .part
                .first_lba
                .checked_add(sector)
                .ok_or(PlatformError::TooLarge)?;
            return p.read_blocks(self.part.disk, lba, buf);
        }
        // 4 KiB blocks: whole blocks straight through, edges via a bounce.
        let mut block = [0u8; MAX_BLOCK];
        let mut done = 0u64;
        while done < n {
            let s = sector + done;
            let lba = self.part.first_lba + s / per;
            let within = s % per;
            let at = (done * SECTOR) as usize;
            if within == 0 && n - done >= per {
                let whole = ((n - done) / per) * per;
                let dst = buf
                    .get_mut(at..at + (whole * SECTOR) as usize)
                    .ok_or(PlatformError::TooLarge)?;
                p.read_blocks(self.part.disk, lba, dst)?;
                done += whole;
            } else {
                let b = block
                    .get_mut(..bs as usize)
                    .ok_or(PlatformError::Unsupported)?;
                p.read_blocks(self.part.disk, lba, b)?;
                let take = (per - within).min(n - done);
                let src = b
                    .get((within * SECTOR) as usize..((within + take) * SECTOR) as usize)
                    .ok_or(PlatformError::TooLarge)?;
                buf.get_mut(at..at + (take * SECTOR) as usize)
                    .ok_or(PlatformError::TooLarge)?
                    .copy_from_slice(src);
                done += take;
            }
        }
        Ok(())
    }
    fn sectors(&self) -> u64 {
        self.part
            .sectors
            .saturating_mul(u64::from(self.part.block_size) / SECTOR)
    }
}

/// [`ntfs::Disk`] over a [`SectorRead`], remembering the platform error.
struct NtfsDisk<'a, P: Platform, R: SectorRead<P>> {
    p: &'a mut P,
    r: &'a mut R,
}

impl<P: Platform, R: SectorRead<P>> Disk for NtfsDisk<'_, P, R> {
    fn read(&mut self, sector: u64, buf: &mut [u8; SECTOR_LEN]) -> Result<(), IoError> {
        self.r.read(self.p, sector, buf).map_err(|_| IoError)
    }
}

/// A disk file's payload: its sectors, gathered through its extents.
struct Payload<'a, P: Platform, R: SectorRead<P>> {
    p: &'a mut P,
    r: &'a mut R,
    ext: &'a [Extent],
    /// Payload length in sectors.
    sectors: u64,
}

impl<P: Platform, R: SectorRead<P>> Payload<'_, P, R> {
    fn read(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), PlatformError> {
        let n = (buf.len() / SECTOR_LEN) as u64;
        let end = sector.checked_add(n).ok_or(PlatformError::TooLarge)?;
        if buf.len() % SECTOR_LEN != 0 || end > self.sectors {
            return Err(PlatformError::TooLarge);
        }
        let mut done = 0u64;
        while done < n {
            let (phys, left) =
                ntfs::gather(self.ext, sector + done).ok_or(PlatformError::TooLarge)?;
            let take = left.min(n - done);
            let at = (done * SECTOR) as usize;
            let dst = buf
                .get_mut(at..at + (take * SECTOR) as usize)
                .ok_or(PlatformError::TooLarge)?;
            self.r.read(self.p, phys, dst)?;
            done += take;
        }
        Ok(())
    }
}

/// The FAT32 inside a payload, for [`fat::Fs`]: file-system sectors of
/// `bps` bytes from byte `start` of the payload.
struct FatSource<'a, 'b, P: Platform, R: SectorRead<P>> {
    pay: &'a mut Payload<'b, P, R>,
    start: u64,
    bps: u64,
}

impl<P: Platform, R: SectorRead<P>> fat::Sectors for FatSource<'_, '_, P, R> {
    fn read(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), FatError> {
        let byte = sector
            .checked_mul(self.bps)
            .and_then(|b| b.checked_add(self.start))
            .ok_or(FatError::Io)?;
        if byte % SECTOR != 0 {
            return Err(FatError::Io);
        }
        self.pay.read(byte / SECTOR, buf).map_err(|_| FatError::Io)
    }
}

/// What the loader keeps of the mounted volume, and the memory stage 4
/// works in (~2.5 MiB, allocated by the caller). **All-zero is a valid
/// value** (an unmounted volume), so the UEFI loader can place it in zeroed
/// pages.
pub struct Stage4 {
    mounted: bool,
    vol: ntfs::Volume,
    mft_runs: [Run; MFT_RUNS],
    mft_n: usize,
    mft_bytes: u64,
    up: [u16; UPCASE_LEN],
    s: Scratch,
    /// A disk file's (or the `efi_file`'s) runs.
    runs: [Run; MAX_EXTENTS],
    /// The efi disk's extents (volume sectors, file order).
    ext: [Extent; MAX_EXTENTS],
    ext_n: usize,
    head: [u8; disk::HEAD_LEN],
    fat: [u8; fat::SCRATCH],
    /// The `efi_file` stage 4 located: identity and size.
    efi_file: FileRef,
    efi_file_size: u64,
    image: Option<&'static mut [u8]>,
    image_len: usize,
}

/// A located efi disk: its extents are `Stage4::ext[..ext_n]`.
#[derive(Clone, Copy, Debug)]
struct DiskFile {
    id: FileRef,
    /// Payload sectors.
    sectors: u64,
    fs: EfiFs,
}

/// `$MFT` as the parent module wants it, borrowing the kept runs.
macro_rules! mft {
    ($s:expr) => {
        ntfs::Mft {
            vol: $s.vol,
            runs: $s.mft_runs.get(..$s.mft_n).unwrap_or(&[]),
            bytes: $s.mft_bytes,
        }
    };
}

fn log<P: Platform>(p: &mut P, args: core::fmt::Arguments<'_>) {
    p.log(args);
}

impl Stage4 {
    /// An unmounted volume (tests; the loader zeroes pages instead).
    pub const fn new() -> Self {
        Stage4 {
            mounted: false,
            vol: ntfs::Volume {
                sectors: 0,
                clusters: 0,
                cluster_bytes: 0,
                record_bytes: 0,
                mft_lcn: 0,
            },
            mft_runs: [Run { lcn: 0, count: 0 }; MFT_RUNS],
            mft_n: 0,
            mft_bytes: 0,
            up: [0; UPCASE_LEN],
            s: Scratch::new(),
            runs: [Run { lcn: 0, count: 0 }; MAX_EXTENTS],
            ext: [Extent { start: 0, end: 0 }; MAX_EXTENTS],
            ext_n: 0,
            head: [0; disk::HEAD_LEN],
            fat: [0; fat::SCRATCH],
            efi_file: FileRef { record: 0, seq: 0 },
            efi_file_size: 0,
            image: None,
            image_len: 0,
        }
    }

    /// Forget the mounted volume (a new partition was opened).
    pub fn reset(&mut self) {
        self.mounted = false;
        self.ext_n = 0;
        self.efi_file_size = 0;
        self.image_len = 0;
    }

    /// Map `$MFT` and load `$UpCase`, once.
    pub fn mount<P: Platform, R: SectorRead<P>>(
        &mut self,
        p: &mut P,
        r: &mut R,
    ) -> Result<(), Stage4Error> {
        if self.mounted {
            return Ok(());
        }
        let mut d = NtfsDisk { p, r };
        let m = ntfs::open(&mut d, &mut self.s.alist, &mut self.mft_runs)
            .map_err(|e| Stage4Error::Mount(e.into()))?;
        let (vol, n, bytes) = (m.vol, m.runs.len(), m.bytes);
        if vol.sectors > <R as SectorRead<P>>::sectors(d.r) {
            return Err(Stage4Error::Mount(DirError::Ntfs(
                ntfs::NtfsError::VolumeSize,
            )));
        }
        self.vol = vol;
        self.mft_n = n;
        self.mft_bytes = bytes;
        let mft = mft!(self);
        dir::load_upcase(&mut d, &mft, &mut self.s, &mut self.up).map_err(Stage4Error::Mount)?;
        self.mounted = true;
        log(
            d.p,
            format_args!(
                "paguro: stage4 ntfs mounted ({} clusters of {} bytes)",
                vol.clusters, vol.cluster_bytes
            ),
        );
        Ok(())
    }

    fn resolve<P: Platform, R: SectorRead<P>>(
        &mut self,
        p: &mut P,
        r: &mut R,
        path: &str,
    ) -> Result<dir::Found, DirError> {
        let mut d = NtfsDisk { p, r };
        let mft = mft!(self);
        dir::resolve(&mut d, &mft, &self.up, path, &mut self.s)
    }

    /// A disk file by path: its identity and its map, checked exactly as
    /// the module checks a claim ([`ntfs::file`]); the map's extents land
    /// in `ext`.
    fn map_disk<P: Platform, R: SectorRead<P>>(
        &mut self,
        p: &mut P,
        r: &mut R,
        path: &str,
    ) -> Result<(FileRef, u64), DirError> {
        let f = self.resolve(p, r, path)?;
        if f.is_dir {
            return Err(DirError::IsDirectory);
        }
        let mut d = NtfsDisk { p, r };
        let mft = mft!(self);
        let m = ntfs::file(
            &mut d,
            &mft,
            f.file.record,
            f.file.seq,
            &mut self.s.alist,
            &mut self.runs,
        )?;
        let runs = self.runs.get(..m.runs).unwrap_or(&[]);
        self.ext_n = ntfs::extents(&self.vol, runs, &mut self.ext)?;
        Ok((f.file, m.data_size))
    }

    /// The FAT32 of the disk file at `path` (INTERFACES.md §3.2): format
    /// detected, payload classified, file system checked.
    fn open_disk<P: Platform, R: SectorRead<P>>(
        &mut self,
        p: &mut P,
        r: &mut R,
        path: &str,
    ) -> Result<(DiskFile, fat::Fs), Stage4Error> {
        let (id, size) = self
            .map_disk(p, r, path)
            .map_err(|e| Stage4Error::File(Role::EfiDisk, e))?;
        if size < SECTOR {
            return Err(Stage4Error::DiskSize);
        }
        let ext = self.ext.get(..self.ext_n).unwrap_or(&[]);
        let mut whole = Payload {
            p,
            r,
            ext,
            sectors: size / SECTOR,
        };
        let mut tail = [0u8; SECTOR_LEN];
        whole
            .read(size / SECTOR - 1, &mut tail)
            .map_err(Stage4Error::Expose)?;
        let pl = disk::detect(size, &tail);
        let sectors = pl.len / SECTOR;
        let mut pay = Payload {
            p: whole.p,
            r: whole.r,
            ext,
            sectors,
        };
        let head_len = (self.head.len() as u64).min(sectors * SECTOR) as usize;
        let head = self.head.get_mut(..head_len).unwrap_or(&mut []);
        if !head.is_empty() {
            pay.read(0, head).map_err(Stage4Error::Expose)?;
        }
        let fs = disk::classify(pl.len, head).map_err(Stage4Error::Payload)?;
        let (start, space) = fs.range();
        if start.checked_add(space).is_none_or(|e| e > pl.len) {
            return Err(Stage4Error::Payload(DiskError::TooSmall));
        }
        let mut src = FatSource {
            pay: &mut pay,
            start,
            bps: SECTOR,
        };
        let f = fat::Fs::open(&mut src, space, &mut self.fat).map_err(Stage4Error::Fat)?;
        log(
            pay.p,
            format_args!(
                "paguro: stage4 {path}: {:?} payload of {} sectors, FAT32 {}",
                pl.format,
                sectors,
                match fs {
                    EfiFs::Esp { .. } => "in its ESP",
                    EfiFs::Superfloppy(_) => "on the whole disk",
                }
            ),
        );
        Ok((DiskFile { id, sectors, fs }, f))
    }

    /// Whether `\EFI…` path `efi` is a file on the disk's FAT32.
    fn check_efi<P: Platform, R: SectorRead<P>>(
        &mut self,
        p: &mut P,
        r: &mut R,
        d: &DiskFile,
        f: &fat::Fs,
        efi: &str,
    ) -> Result<(), Stage4Error> {
        let ext = self.ext.get(..self.ext_n).unwrap_or(&[]);
        let mut pay = Payload {
            p,
            r,
            ext,
            sectors: d.sectors,
        };
        let mut src = FatSource {
            pay: &mut pay,
            start: d.fs.range().0,
            bps: u64::from(f.bpb.bytes_per_sector),
        };
        match f.find(&mut src, efi, &mut self.fat) {
            Ok(e) if !e.is_dir => Ok(()),
            Ok(_) | Err(FatError::NotFound) | Err(FatError::BadPath) => {
                Err(Stage4Error::EfiMissing)
            }
            Err(e) => Err(Stage4Error::Fat(e)),
        }
    }

    /// The safety gates (DESIGN.md §4.1): `handoff::state` flags.
    fn gates<P: Platform, R: SectorRead<P>>(&mut self, p: &mut P, r: &mut R) -> u32 {
        let mut flags = 0;
        let dirty = {
            let mft = mft!(self);
            let mut d = NtfsDisk {
                p: &mut *p,
                r: &mut *r,
            };
            ntfs::volume_flags(&mut d, &mft)
        };
        match dirty {
            Ok(f) if f & ntfs::VOLUME_DIRTY != 0 => flags |= state::DIRTY,
            Ok(_) => {}
            Err(e) => {
                // Unreadable: assume the worst, which only costs writes.
                log(
                    p,
                    format_args!("paguro: stage4 $Volume unreadable ({e:?}): treated as dirty"),
                );
                flags |= state::DIRTY;
            }
        }
        match self.resolve(p, r, HIBERFIL_PATH) {
            Err(DirError::NotFound) => {}
            Ok(f) if !f.is_dir => {
                let mut hdr = [0u8; HIBERFIL_HEADER_LEN];
                let mft = mft!(self);
                let mut d = NtfsDisk {
                    p: &mut *p,
                    r: &mut *r,
                };
                let got =
                    match dir::data(&mut d, &mft, f.file, &mut self.s, &mut hdr, &mut self.runs) {
                        Ok(Data::Resident(_)) => Ok(()),
                        Ok(Data::Runs { runs, size }) => {
                            let n = size.min(HIBERFIL_HEADER_LEN as u64) as usize;
                            let runs = self.runs.get(..runs).unwrap_or(&[]);
                            dir::read_runs(
                                &mut d,
                                &self.vol,
                                runs,
                                size,
                                0,
                                hdr.get_mut(..n).unwrap_or(&mut []),
                            )
                        }
                        Err(e) => Err(e),
                    };
                match got {
                    Ok(()) if dir::hibernation_active(&hdr) => flags |= state::HIBERNATED,
                    Ok(()) => {}
                    Err(e) => {
                        log(
                            p,
                            format_args!(
                                "paguro: stage4 hiberfil.sys unreadable ({e:?}): treated as hibernated"
                            ),
                        );
                        flags |= state::HIBERNATED;
                    }
                }
            }
            other => {
                log(
                    p,
                    format_args!(
                        "paguro: stage4 hiberfil.sys lookup: {:?}: treated as hibernated",
                        other.map(|_| ())
                    ),
                );
                flags |= state::HIBERNATED;
            }
        }
        flags
    }

    /// Stage 4 for `entry` (see [`Volume::locate`]).
    pub fn locate<P: Platform, R: SectorRead<P>>(
        &mut self,
        p: &mut P,
        r: &mut R,
        part: &Partition,
        fve: Option<(u16, &[u8], Layout)>,
        entry: Option<&Entry<'_>>,
        out: &mut Located,
    ) -> Result<(), BootError> {
        self.mount(p, r)?;
        self.efi_file_size = 0;
        out.flags = self.gates(p, r);
        log(
            p,
            format_args!("paguro: stage4 gates: state=0x{:x}", out.flags),
        );
        let mut found = Entry::EMPTY;
        let mut chosen = [0u8; config::MAX_PATH_BYTES];
        let entry = match entry {
            Some(e) => *e,
            None => {
                // A first boot: whatever \paguro\ unambiguously holds.
                match self.discover(p, r, &mut chosen)? {
                    Some(kind) => {
                        let path =
                            core::str::from_utf8(chosen.get(..kind.1).unwrap_or(&[])).unwrap_or("");
                        found.efi = match kind.0 {
                            Found::Disk => {
                                found.root = Some(path);
                                Efi::Disk {
                                    disk: path,
                                    path: config::DEFAULT_EFI,
                                }
                            }
                            Found::File => Efi::File(path),
                        };
                        found
                    }
                    None => {
                        log(
                            p,
                            format_args!("paguro: stage4 no installation in \\paguro\\"),
                        );
                        return Ok(());
                    }
                }
            }
        };
        // The name: the entry's, or (first boot) the file's.
        let mut nb = [0u8; config::MAX_NAME];
        let name = if entry.name.is_empty() {
            let file = match entry.efi {
                Efi::File(f) => f,
                Efi::Disk { disk, .. } => disk,
            };
            crate::ui::entry_name(file, &mut nb, FALLBACK_ENTRY_NAME)
        } else {
            entry.name
        };
        let nlen = name.len().min(out.name.len());
        if let Some(d) = out.name.get_mut(..nlen) {
            d.copy_from_slice(name.as_bytes().get(..nlen).unwrap_or(&[]));
        }
        out.name_len = nlen as u8;

        let set = |buf: &mut [u8; config::MAX_PATH_BYTES], len: &mut usize, s: &str| {
            let n = s.len().min(buf.len());
            if let Some(d) = buf.get_mut(..n) {
                d.copy_from_slice(s.as_bytes().get(..n).unwrap_or(&[]));
            }
            *len = n;
        };
        if let Some(root) = entry.root {
            let (id, _) = self
                .map_disk(p, r, root)
                .map_err(|e| Stage4Error::File(Role::Root, e))?;
            out.root = Some(FileId {
                mft_record: id.record,
                mft_seq: id.seq,
            });
            set(&mut out.root_path, &mut out.root_path_len, root);
            log(
                p,
                format_args!(
                    "paguro: stage4 root {root} = record {} seq {}",
                    id.record, id.seq
                ),
            );
        }
        match entry.efi {
            Efi::File(path) => {
                let f = self
                    .resolve(p, r, path)
                    .map_err(|e| Stage4Error::File(Role::EfiFile, e))?;
                if f.is_dir {
                    return Err(Stage4Error::File(Role::EfiFile, DirError::IsDirectory).into());
                }
                let mut d = NtfsDisk {
                    p: &mut *p,
                    r: &mut *r,
                };
                let mft = mft!(self);
                let size = match dir::data(
                    &mut d,
                    &mft,
                    f.file,
                    &mut self.s,
                    &mut [0u8; 0],
                    &mut self.runs,
                ) {
                    Ok(Data::Runs { size, .. }) => size,
                    // Resident: at most a record, far too small for a PE…
                    // but read it all the same (efi_image re-reads).
                    Err(DirError::BufferTooSmall) => ntfs::MAX_RECORD as u64,
                    Ok(Data::Resident(n)) => n as u64,
                    Err(e) => return Err(Stage4Error::File(Role::EfiFile, e).into()),
                };
                if size == 0 || size > MAX_EFI_FILE {
                    return Err(Stage4Error::EfiFileSize.into());
                }
                self.efi_file = f.file;
                self.efi_file_size = size;
                out.efi_file = Some(FileId {
                    mft_record: f.file.record,
                    mft_seq: f.file.seq,
                });
                set(&mut out.efi_file_path, &mut out.efi_file_path_len, path);
                log(
                    p,
                    format_args!(
                        "paguro: stage4 efi_file {path} = record {} seq {} ({size} bytes)",
                        f.file.record, f.file.seq
                    ),
                );
            }
            Efi::Disk {
                disk: dpath,
                path: efi,
            } => {
                let (d, f) = self.open_disk(p, r, dpath)?;
                self.check_efi(p, r, &d, &f, efi)?;
                let id = FileId {
                    mft_record: d.id.record,
                    mft_seq: d.id.seq,
                };
                if out.root != Some(id) {
                    out.efi_disk = Some(id);
                    set(&mut out.efi_disk_path, &mut out.efi_disk_path_len, dpath);
                }
                let at = match d.fs {
                    EfiFs::Esp { first_lba, sectors } => FatAt::Partition { first_lba, sectors },
                    EfiFs::Superfloppy(_) => FatAt::Whole,
                };
                // A disk over BitLocker's non-data regions is not the
                // disk's data in either view (INTERFACES.md §12.2): refuse.
                if let Some((_, _, l)) = fve {
                    let ext = self.ext.get(..self.ext_n).unwrap_or(&[]);
                    if l.overlaps_reserved(ext) {
                        return Err(Stage4Error::Reserved.into());
                    }
                }
                let exposed = ExposedDisk {
                    part: *part,
                    extents: self.ext.get(..self.ext_n).unwrap_or(&[]),
                    sectors: d.sectors,
                    file: id,
                    fve,
                };
                log(
                    p,
                    format_args!(
                        "paguro: stage4 efi_disk {dpath} = record {} seq {}, {} extent(s); image {efi}",
                        d.id.record, d.id.seq, self.ext_n
                    ),
                );
                let n = p
                    .expose_disk(&exposed, at, efi, &mut out.chain)
                    .map_err(Stage4Error::Expose)?;
                out.chain_len = n;
            }
        }
        Ok(())
    }

    /// First boot: the only disk in `\paguro\`, or else its only UEFI image.
    fn discover<P: Platform, R: SectorRead<P>>(
        &mut self,
        p: &mut P,
        r: &mut R,
        out: &mut [u8; config::MAX_PATH_BYTES],
    ) -> Result<Option<(Found, usize)>, BootError> {
        let f = match self.resolve(p, r, INSTALL_DIR) {
            Ok(f) if f.is_dir => f,
            Ok(_) | Err(DirError::NotFound) => return Ok(None),
            Err(e) => return Err(Stage4Error::File(Role::Root, e).into()),
        };
        let mut d = NtfsDisk { p, r };
        let mft = mft!(self);
        let idx = dir::open_index(&mut d, &mft, f.file, &mut self.s)
            .map_err(|e| Stage4Error::File(Role::Root, e))?;
        let (mut disks, mut efis) = (0u32, 0u32);
        let mut disk_name = [0u16; dir::MAX_NAME];
        let mut efi_name = [0u16; dir::MAX_NAME];
        let (mut dn, mut en) = (0usize, 0usize);
        dir::list(&mut d, &mft, &idx, &mut self.s, |e| {
            if e.is_dir {
                return true;
            }
            let mut utf8 = [0u8; NAME_UTF8_MAX];
            let Some(s) = utf16_to_str(e.name, &mut utf8) else {
                return true;
            };
            match crate::platform::file_kind(Level::Volume, s) {
                Some(crate::platform::EntryKind::Disk) => {
                    disks += 1;
                    dn = e.name.len();
                    if let Some(d) = disk_name.get_mut(..dn) {
                        d.copy_from_slice(e.name);
                    }
                }
                Some(crate::platform::EntryKind::Efi) => {
                    efis += 1;
                    en = e.name.len();
                    if let Some(d) = efi_name.get_mut(..en) {
                        d.copy_from_slice(e.name);
                    }
                }
                _ => {}
            }
            true
        })
        .map_err(|e| Stage4Error::File(Role::Root, e))?;
        let (kind, name) = match (disks, efis) {
            (1, _) => (Found::Disk, disk_name.get(..dn).unwrap_or(&[])),
            (0, 1) => (Found::File, efi_name.get(..en).unwrap_or(&[])),
            _ => return Ok(None),
        };
        let prefix = INSTALL_DIR_PREFIX;
        let mut n = prefix.len();
        if let Some(d) = out.get_mut(..n) {
            d.copy_from_slice(prefix);
        }
        let mut utf8 = [0u8; NAME_UTF8_MAX];
        let Some(s) = utf16_to_str(name, &mut utf8) else {
            return Ok(None);
        };
        let Some(dst) = out.get_mut(n..n + s.len()) else {
            return Ok(None);
        };
        dst.copy_from_slice(s.as_bytes());
        n += s.len();
        let path = core::str::from_utf8(out.get(..n).unwrap_or(&[])).unwrap_or("");
        if config::check_path(path).is_err() {
            return Ok(None);
        }
        Ok(Some((kind, n)))
    }

    /// The `efi_file` stage 4 located, read whole into platform memory.
    pub fn efi_image<P: Platform, R: SectorRead<P>>(
        &mut self,
        p: &mut P,
        r: &mut R,
    ) -> Result<&[u8], BootError> {
        let size = self.efi_file_size;
        if size == 0 {
            return Err(Stage4Error::EfiFileSize.into());
        }
        let len = usize::try_from(size).map_err(|_| Stage4Error::EfiFileSize)?;
        if self.image.as_ref().is_none_or(|b| b.len() < len) {
            self.image = Some(p.alloc_image(len).map_err(Stage4Error::Memory)?);
        }
        let Some(buf) = self.image.as_deref_mut() else {
            return Err(Stage4Error::Memory(PlatformError::Unsupported).into());
        };
        let buf = buf.get_mut(..len).ok_or(Stage4Error::EfiFileSize)?;
        let mft = mft!(self);
        let mut d = NtfsDisk {
            p: &mut *p,
            r: &mut *r,
        };
        let data = dir::data(
            &mut d,
            &mft,
            self.efi_file,
            &mut self.s,
            buf,
            &mut self.runs,
        )
        .map_err(|e| Stage4Error::File(Role::EfiFile, e))?;
        match data {
            Data::Resident(n) if n == len => {}
            Data::Resident(_) => return Err(Stage4Error::EfiFileSize.into()),
            Data::Runs { runs, size: s } => {
                if s != size {
                    return Err(Stage4Error::EfiFileSize.into());
                }
                // Whole sectors run by run through the reader (many at a
                // time); the tail through one bounce sector.
                let spc = self.vol.cluster_bytes / SECTOR;
                let mut off = 0u64;
                for run in self.runs.get(..runs).unwrap_or(&[]) {
                    if off >= size {
                        break;
                    }
                    let run_bytes = run.count.saturating_mul(self.vol.cluster_bytes);
                    let bytes = run_bytes.min(size - off);
                    let whole = bytes / SECTOR * SECTOR;
                    let first = run.lcn.saturating_mul(spc);
                    let mut done = 0u64;
                    while done < whole {
                        let chunk = (whole - done).min(EFI_READ_CHUNK);
                        let at = (off + done) as usize;
                        let dst = buf
                            .get_mut(at..at + chunk as usize)
                            .ok_or(Stage4Error::EfiFileSize)?;
                        r.read(p, first + done / SECTOR, dst).map_err(|_| {
                            Stage4Error::File(Role::EfiFile, DirError::Ntfs(ntfs::NtfsError::Io))
                        })?;
                        done += chunk;
                    }
                    if bytes > whole {
                        let mut sec = [0u8; SECTOR_LEN];
                        r.read(p, first + whole / SECTOR, &mut sec).map_err(|_| {
                            Stage4Error::File(Role::EfiFile, DirError::Ntfs(ntfs::NtfsError::Io))
                        })?;
                        let tail = (bytes - whole) as usize;
                        let at = (off + whole) as usize;
                        buf.get_mut(at..at + tail)
                            .ok_or(Stage4Error::EfiFileSize)?
                            .copy_from_slice(sec.get(..tail).unwrap_or(&[]));
                    }
                    off += bytes;
                }
                if off != size {
                    return Err(Stage4Error::EfiFileSize.into());
                }
            }
        }
        self.image_len = len;
        let img = self.image.as_deref().unwrap_or(&[]);
        Ok(img.get(..len).unwrap_or(&[]))
    }

    /// Recovery's NTFS browser: directory `path` (INTERFACES.md §13.4).
    pub fn list_dir<P: Platform, R: SectorRead<P>>(
        &mut self,
        p: &mut P,
        r: &mut R,
        path: &str,
        out: &mut DirListing,
    ) -> Result<(), BootError> {
        self.mount(p, r)?;
        log(p, format_args!("paguro: stage4 listing {path}"));
        let f = match self.resolve(p, r, path) {
            Ok(f) if f.is_dir => f,
            // A missing directory is an empty listing.
            Ok(_) | Err(DirError::NotFound) | Err(DirError::NotDirectory) => return Ok(()),
            Err(e) => return Err(Stage4Error::File(Role::Root, e).into()),
        };
        let mut d = NtfsDisk { p, r };
        let mft = mft!(self);
        let idx = dir::open_index(&mut d, &mft, f.file, &mut self.s)
            .map_err(|e| Stage4Error::File(Role::Root, e))?;
        dir::list(&mut d, &mft, &idx, &mut self.s, |e| {
            if e.file.record == f.file.record {
                return true; // the root's "." entry
            }
            out.push(e.name, e.is_dir, e.size)
        })
        .map_err(|e| Stage4Error::File(Role::Root, e))?;
        Ok(())
    }

    /// Recovery's FAT32 browser on the disk file `disk`. `Ok(false)`: the
    /// disk has no FAT32 the loader can read.
    pub fn list_efi_dir<P: Platform, R: SectorRead<P>>(
        &mut self,
        p: &mut P,
        r: &mut R,
        disk_path: &str,
        path: &str,
        out: &mut DirListing,
    ) -> Result<bool, BootError> {
        self.mount(p, r)?;
        log(p, format_args!("paguro: stage4 listing {disk_path} {path}"));
        let (d, f) = match self.open_disk(p, r, disk_path) {
            Ok(v) => v,
            Err(e) => {
                log(p, format_args!("paguro: stage4 {disk_path}: {e:?}"));
                return Ok(false);
            }
        };
        let ext = self.ext.get(..self.ext_n).unwrap_or(&[]);
        let mut pay = Payload {
            p,
            r,
            ext,
            sectors: d.sectors,
        };
        let mut src = FatSource {
            pay: &mut pay,
            start: d.fs.range().0,
            bps: u64::from(f.bpb.bytes_per_sector),
        };
        match f.list(&mut src, path, &mut self.fat, |e| {
            out.push(e.name, e.is_dir, u64::from(e.size))
        }) {
            Ok(()) | Err(FatError::NotFound) => Ok(true),
            Err(e) => {
                log(pay.p, format_args!("paguro: stage4 {disk_path} FAT: {e:?}"));
                Ok(false)
            }
        }
    }
}

impl Default for Stage4 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Found {
    Disk,
    File,
}

fn utf16_to_str<'o>(units: &[u16], out: &'o mut [u8; NAME_UTF8_MAX]) -> Option<&'o str> {
    let mut n = 0usize;
    for c in char::decode_utf16(units.iter().copied()) {
        let c = c.ok()?;
        let mut e = [0u8; crate::UTF8_MAX];
        let e = c.encode_utf8(&mut e).as_bytes();
        out.get_mut(n..n + e.len())?.copy_from_slice(e);
        n += e.len();
    }
    core::str::from_utf8(out.get(..n)?).ok()
}

/// Where the FAT32 holding the UEFI image is inside a published disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FatAt {
    /// The GPT partition starting at this payload LBA (512-byte sectors).
    Partition { first_lba: u64, sectors: u64 },
    /// The whole disk ("superfloppy").
    Whole,
}

/// A disk file to publish as a read-only block device
/// ([`Platform::expose_disk`]). Reads of payload sector `s` go to volume
/// sector `ntfs::gather(extents, s)`, then to the partition.
#[derive(Clone, Copy, Debug)]
pub struct ExposedDisk<'a> {
    /// The volume's partition (physical disk, first block, block size).
    pub part: Partition,
    /// The file's extents in 512-byte volume sectors, in file order.
    pub extents: &'a [Extent],
    /// Payload sectors (a VHD's footer excluded).
    pub sectors: u64,
    /// The file's identity, which makes the device path unique.
    pub file: FileId,
    /// For a BitLocker volume: the FVEK (cipher, key) and the layout the
    /// block device must decrypt with (`paguro_boot::bde::DecryptingReader`).
    /// `None`: an unencrypted volume.
    pub fve: Option<(u16, &'a [u8], Layout)>,
}

/// The production [`Volume`] for an **unencrypted** NTFS volume: stage 4
/// over [`PartitionReader`]. Its BitLocker (stage 3) side refuses exactly as
/// [`crate::Unimplemented`] does, so a BitLocker volume still reaches the
/// rungs and stops there until the FVE layer lands.
///
/// All-zero is a valid value (see [`Stage4`]).
pub struct NtfsVolume {
    part: Partition,
    open: bool,
    pub stage4: Stage4,
}

impl NtfsVolume {
    pub const fn new() -> Self {
        NtfsVolume {
            part: Partition {
                disk: 0,
                index: 0,
                guid: paguro_core::guid::Guid::ZERO,
                first_lba: 0,
                sectors: 0,
                block_size: 0,
            },
            open: false,
            stage4: Stage4::new(),
        }
    }

    fn reader(&self) -> Result<PartitionReader, BootError> {
        if !self.open {
            return Err(BootError::NoVolume);
        }
        Ok(PartitionReader { part: self.part })
    }
}

impl Default for NtfsVolume {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: Platform> Volume<P> for NtfsVolume {
    fn open(&mut self, _: &mut P, part: &Partition, _: VolumeKind) -> Result<(), BootError> {
        self.part = *part;
        self.open = true;
        self.stage4.reset();
        Ok(())
    }
    fn fvek_blob(&mut self, _: &mut P, _: &mut [u8]) -> Result<usize, BootError> {
        Err(BootError::NotImplemented("stage 3: FVE metadata"))
    }
    fn clear_key(&mut self, _: &mut P) -> Result<Option<Key>, BootError> {
        Ok(None)
    }
    fn try_vmk(&mut self, _: &mut P, _: &Key) -> Result<bool, BootError> {
        Err(BootError::NotImplemented("stage 3: FVEK unwrap"))
    }
    fn fvek(&self) -> Option<(u16, &[u8])> {
        None
    }
    fn layout(&self) -> Option<FveLayout> {
        None
    }
    fn recovery_key(
        &mut self,
        _: &mut P,
        _: &[u8; RECOVERY_KEY_LEN],
    ) -> Result<Option<Key>, BootError> {
        Err(BootError::NotImplemented("stage 3: recovery password"))
    }
    fn locate(
        &mut self,
        p: &mut P,
        entry: Option<&Entry<'_>>,
        out: &mut Located,
    ) -> Result<(), BootError> {
        let mut r = self.reader()?;
        let part = self.part;
        self.stage4.locate(p, &mut r, &part, None, entry, out)
    }
    fn efi_image(&mut self, p: &mut P) -> Result<&[u8], BootError> {
        let mut r = self.reader()?;
        self.stage4.efi_image(p, &mut r)
    }
    fn list_dir(&mut self, p: &mut P, path: &str, out: &mut DirListing) -> Result<(), BootError> {
        let mut r = self.reader()?;
        self.stage4.list_dir(p, &mut r, path, out)
    }
    fn list_efi_dir(
        &mut self,
        p: &mut P,
        disk: &str,
        path: &str,
        out: &mut DirListing,
    ) -> Result<bool, BootError> {
        let mut r = self.reader()?;
        self.stage4.list_efi_dir(p, &mut r, disk, path, out)
    }
}
