//! The synthetic, read-only block device a boot entry's disk file becomes
//! (INTERFACES.md §3.2; DESIGN.md §4.2, tier 1).
//!
//! The file's payload is published as an `EFI_BLOCK_IO_PROTOCOL` of 512-byte
//! blocks whose reads resolve through the file's extents to the NTFS
//! partition on the physical disk, with a device path of its own (a vendor
//! media node under the physical disk's path). `ConnectController`
//! (recursive) then lets the firmware's own partition driver parse the
//! payload's GPT and its own FAT driver bind the ESP — or the whole disk for
//! a superfloppy — so the next image is loaded **by device path** and gets a
//! real `DeviceHandle`.
//!
//! `WriteBlocks` is `EFI_WRITE_PROTECTED` and the media is read-only: the
//! loader never writes to disk, whoever asks.
//!
//! Everything the callbacks touch is copied into pages this module
//! allocates and never frees (the device outlives the loader: the chained
//! image keeps reading it).

use core::ffi::c_void;
use core::mem::size_of;
use core::ops::Range;
use core::ptr::{self, NonNull};

use log::info;
use paguro_boot::bde::{DecryptingReader, ReadError, UnitRead};
use paguro_boot::platform::PlatformError;
use paguro_boot::stage4::{ExposedDisk, FatAt};
use paguro_core::bde::Layout;
use paguro_core::ntfs;
use paguro_core::range::Extent;
use paguro_crypto::bitlocker::Xts;
use uefi::boot::{self, AllocateType, MemoryType, PAGE_SIZE, SearchType};
use uefi::proto::device_path::DevicePath;
use uefi::proto::device_path::text::{AllowShortcuts, DevicePathToText, DisplayOnly};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::{Handle, Identify, Status};
use uefi_raw::protocol::block::{BlockIoMedia, BlockIoProtocol, Lba};
use uefi_raw::protocol::device_path::{DevicePathProtocol, DeviceSubType, DeviceType};

use crate::layout::field;

/// The published disk's block size, and the volume-sector unit every read
/// is counted in.
const SECTOR: u64 = 512;
/// The largest physical block size supported (4Kn disks).
const MAX_PHYS_BLOCK: u64 = 4096;
/// `EFI_BLOCK_IO_MEDIA.MediaId` of every published disk: "pagu".
const MEDIA_ID: u32 = 0x7061_6775;

// EFI device path nodes (UEFI 2.10 §10.3), layout only (see `layout`).
/// Every node's header (§10.2 `EFI_DEVICE_PATH_PROTOCOL`).
#[allow(dead_code)]
#[repr(C, packed)]
struct NodeHeader {
    kind: u8,
    sub_type: u8,
    length: u16,
}
/// paguro's vendor-defined media node (§10.3.5.3): the header, the vendor
/// GUID, then paguro's data — the disk file's MFT record and sequence.
#[allow(dead_code)]
#[repr(C, packed)]
struct VendorNode {
    header: NodeHeader,
    guid: [u8; 16],
    mft_record: u64,
    mft_seq: u16,
}
/// Hard drive media node (§10.3.5.1).
#[allow(dead_code)]
#[repr(C, packed)]
struct HardDriveNode {
    header: NodeHeader,
    partition_number: u32,
    partition_start: u64,
    partition_size: u64,
    signature: [u8; 16],
    mbr_type: u8,
    signature_type: u8,
}
const NODE_HEADER: usize = size_of::<NodeHeader>();
const NODE_LEN: Range<usize> = field!(NodeHeader, length);
const VENDOR_GUID: Range<usize> = field!(VendorNode, guid);
const VENDOR_MFT_RECORD: Range<usize> = field!(VendorNode, mft_record);
const VENDOR_MFT_SEQ: Range<usize> = field!(VendorNode, mft_seq);
const VENDOR_NODE_LEN: usize = size_of::<VendorNode>();
const HARD_DRIVE_NODE_LEN: usize = size_of::<HardDriveNode>();
const HARD_DRIVE_PARTITION_START: Range<usize> = field!(HardDriveNode, partition_start);
const _: () = assert!(NODE_HEADER == size_of::<DevicePathProtocol>());
const _: () = assert!(NODE_LEN.start == 2);
const _: () = assert!(HARD_DRIVE_NODE_LEN == 42 && HARD_DRIVE_PARTITION_START.start == 8);

/// Vendor-defined media device path node GUID for paguro's disks.
const VENDOR: [u8; 16] = [
    0x5e, 0x2d, 0x8a, 0x3c, 0x7b, 0x1f, 0x4d, 0x9e, 0x8c, 0x61, 0x70, 0x61, 0x67, 0x75, 0x72, 0x6f,
];

/// One published disk. `proto` must stay the first field: the callbacks
/// get a pointer to it and cast back.
#[repr(C)]
struct Published {
    proto: BlockIoProtocol,
    media: BlockIoMedia,
    /// The physical disk's `EFI_BLOCK_IO_PROTOCOL`.
    phys: *const BlockIoProtocol,
    phys_media_id: u32,
    phys_block: u64,
    /// The NTFS partition's first physical block.
    part_first: u64,
    /// Volume sectors in the partition.
    part_sectors: u64,
    extents: *const Extent,
    extent_count: usize,
    /// Payload sectors.
    sectors: u64,
    bounce: *mut u8,
    /// BitLocker: the decrypted view's map and the FVEK's key schedule (in
    /// pages of their own). Null `xts`: an unencrypted volume.
    layout: Layout,
    xts: *const Xts,
}

const BOUNCE: usize = 64 * 1024;

fn pages<T>(bytes: usize) -> Option<NonNull<T>> {
    let n = bytes.div_ceil(PAGE_SIZE).max(1);
    let p = boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, n).ok()?;
    // SAFETY: a fresh allocation of `n` pages.
    unsafe { ptr::write_bytes(p.as_ptr(), 0, n * PAGE_SIZE) };
    Some(p.cast())
}

unsafe extern "efiapi" fn reset(_: *mut BlockIoProtocol, _: uefi_raw::Boolean) -> Status {
    Status::SUCCESS
}

unsafe extern "efiapi" fn write_blocks(
    _: *mut BlockIoProtocol,
    _: u32,
    _: Lba,
    _: usize,
    _: *const c_void,
) -> Status {
    Status::WRITE_PROTECTED
}

unsafe extern "efiapi" fn flush_blocks(_: *mut BlockIoProtocol) -> Status {
    Status::SUCCESS
}

/// Physical units of a BitLocker volume, for [`DecryptingReader`].
struct RawUnits<'a> {
    d: &'a Published,
    bps: u64,
}

impl UnitRead for RawUnits<'_> {
    fn read_units(&mut self, unit: u64, buf: &mut [u8]) -> Result<(), ReadError> {
        let per = self.bps / SECTOR;
        let sector = unit.checked_mul(per).ok_or(ReadError::Range)?;
        // SAFETY: `buf` is a live slice of `buf.len()` bytes.
        let st = unsafe { read_raw(self.d, sector, buf.len() as u64 / SECTOR, buf.as_mut_ptr()) };
        if st.is_error() {
            return Err(ReadError::Io);
        }
        Ok(())
    }
}

/// Read `n` volume sectors from `sector` into `dst`: the plaintext view —
/// through the BitLocker layer when the volume is encrypted.
///
/// # Safety
/// `d` is a live [`Published`]; `dst` is valid for `n * 512` bytes.
unsafe fn read_volume(d: &Published, sector: u64, n: u64, dst: *mut u8) -> Status {
    if d.xts.is_null() {
        // SAFETY: forwarded contract.
        return unsafe { read_raw(d, sector, n, dst) };
    }
    // SAFETY: `xts` points at the key schedule written at publish time,
    // never freed; `dst` holds `n * 512` bytes (the caller's contract).
    let (xts, out) = unsafe {
        (
            &*d.xts,
            core::slice::from_raw_parts_mut(dst, (n * SECTOR) as usize),
        )
    };
    let bps = u64::from(d.layout.bytes_per_sector);
    let mut r = DecryptingReader::new(RawUnits { d, bps }, d.layout, xts);
    match r.read_sectors(sector, out) {
        Ok(()) => Status::SUCCESS,
        Err(ReadError::Io) => Status::DEVICE_ERROR,
        Err(_) => Status::INVALID_PARAMETER,
    }
}

/// Read `n` volume sectors from `sector` into `dst` through the physical
/// disk (512- or 4096-byte blocks), as stored.
///
/// # Safety
/// `d` is a live [`Published`]; `dst` is valid for `n * 512` bytes.
unsafe fn read_raw(d: &Published, sector: u64, n: u64, dst: *mut u8) -> Status {
    let Some(end) = sector.checked_add(n) else {
        return Status::INVALID_PARAMETER;
    };
    if end > d.part_sectors {
        return Status::DEVICE_ERROR;
    }
    let per = d.phys_block / SECTOR;
    // SAFETY: `phys` is the physical disk's BlockIo, valid for the loader's
    // lifetime and beyond (firmware-owned).
    let phys = unsafe { &*d.phys };
    if per <= 1 {
        // SAFETY: the caller guarantees `dst` holds `n * 512` bytes.
        return unsafe {
            (phys.read_blocks)(
                d.phys,
                d.phys_media_id,
                d.part_first + sector,
                (n * SECTOR) as usize,
                dst.cast(),
            )
        };
    }
    // 4 KiB blocks: through the bounce buffer, one block at a time.
    let mut done = 0u64;
    while done < n {
        let s = sector + done;
        let lba = d.part_first + s / per;
        let within = s % per;
        let take = (per - within).min(n - done);
        // SAFETY: the bounce buffer holds BOUNCE ≥ MAX_PHYS_BLOCK bytes.
        let st = unsafe {
            (phys.read_blocks)(
                d.phys,
                d.phys_media_id,
                lba,
                d.phys_block as usize,
                d.bounce.cast(),
            )
        };
        if st.is_error() {
            return st;
        }
        // SAFETY: in-bounds of both buffers by construction.
        unsafe {
            ptr::copy_nonoverlapping(
                d.bounce.add((within * SECTOR) as usize),
                dst.add((done * SECTOR) as usize),
                (take * SECTOR) as usize,
            );
        }
        done += take;
    }
    Status::SUCCESS
}

unsafe extern "efiapi" fn read_blocks(
    this: *const BlockIoProtocol,
    media_id: u32,
    lba: Lba,
    size: usize,
    buf: *mut c_void,
) -> Status {
    if this.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: `this` is the first field of a live `Published` (repr(C)).
    let d = unsafe { &*this.cast::<Published>() };
    if media_id != d.media.media_id {
        return Status::MEDIA_CHANGED;
    }
    if size == 0 {
        return Status::SUCCESS;
    }
    if buf.is_null() || size as u64 % SECTOR != 0 {
        return Status::BAD_BUFFER_SIZE;
    }
    let n = size as u64 / SECTOR;
    if lba.checked_add(n).is_none_or(|e| e > d.sectors) {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: `extents` holds `extent_count` entries copied at publish time.
    let ext = unsafe { core::slice::from_raw_parts(d.extents, d.extent_count) };
    let dst = buf.cast::<u8>();
    let mut done = 0u64;
    while done < n {
        let Some((vs, left)) = ntfs::gather(ext, lba + done) else {
            return Status::DEVICE_ERROR;
        };
        let take = left.min(n - done);
        // SAFETY: `dst` holds `size` bytes (the caller's contract); this
        // chunk is within it.
        let st = unsafe { read_volume(d, vs, take, dst.add((done * SECTOR) as usize)) };
        if st.is_error() {
            return st;
        }
        done += take;
    }
    Status::SUCCESS
}

/// The physical disk's handle and its BlockIo, for disk index `disk`.
fn physical(h: Handle) -> Result<(*const BlockIoProtocol, u32, u64), PlatformError> {
    let bio = crate::platform::open_get::<uefi::proto::media::block::BlockIO>(h)
        .map_err(|e| PlatformError::Device(e.status().0 as u64))?;
    let m = bio.media();
    let (id, bs) = (m.media_id(), u64::from(m.block_size()));
    let raw: *const BlockIoProtocol = ptr::from_ref(&*bio).cast();
    Ok((raw, id, bs))
}

/// Bytes of a device path up to (not including) its end node.
fn path_body(dp: &DevicePath) -> &[u8] {
    let b = dp.as_bytes();
    b.get(..b.len().saturating_sub(END.len())).unwrap_or(&[])
}

fn log_path(what: &str, dp: &DevicePath) {
    let Ok(h) = boot::get_handle_for_protocol::<DevicePathToText>() else {
        info!("paguro: {what}: (no DevicePathToText)");
        return;
    };
    let Ok(t) = crate::platform::open_get::<DevicePathToText>(h) else {
        return;
    };
    match t.convert_device_path_to_text(dp, DisplayOnly(false), AllowShortcuts(false)) {
        Ok(s) => info!("paguro: {what}: {}", &*s),
        Err(_) => info!("paguro: {what}: (not convertible)"),
    }
}

/// Publish `disk` (INTERFACES.md §3.2), bind the firmware's drivers, find
/// the FAT32 `fat` names, and write the device path of `image` on it to
/// `out`. `disk_handle` is the physical disk the partition is on.
pub fn expose(
    disk_handle: Handle,
    disk: &ExposedDisk<'_>,
    fat: FatAt,
    image: &str,
    out: &mut [u8],
) -> Result<usize, PlatformError> {
    if disk.sectors == 0 || disk.extents.is_empty() {
        return Err(PlatformError::Unsupported);
    }
    // Stage 4 refused this already; the device is the last place it can be
    // caught, so a disk over BitLocker's own regions is never published.
    if let Some((_, _, layout)) = disk.fve {
        if layout.overlaps_reserved(disk.extents) {
            return Err(PlatformError::Unsupported);
        }
    }
    let (phys, phys_media_id, phys_block) = physical(disk_handle)?;
    if phys_block != SECTOR && phys_block != MAX_PHYS_BLOCK {
        return Err(PlatformError::Unsupported);
    }
    let ext_bytes = core::mem::size_of_val(disk.extents);
    let extents: NonNull<Extent> = pages(ext_bytes).ok_or(PlatformError::TooLarge)?;
    // SAFETY: `extents` is a fresh allocation of at least `ext_bytes`.
    unsafe {
        ptr::copy_nonoverlapping(disk.extents.as_ptr(), extents.as_ptr(), disk.extents.len());
    }
    let bounce: NonNull<u8> = pages(BOUNCE).ok_or(PlatformError::TooLarge)?;
    // BitLocker: the key schedule lives in pages the chained image's reads
    // can reach after the loader is gone (INTERFACES.md §12.2: tweak = unit
    // index, the relocated boot sectors, zeros over the metadata).
    let (layout, xts) = match disk.fve {
        Some((_, key, layout)) => {
            if u64::from(layout.bytes_per_sector) < phys_block {
                return Err(PlatformError::Unsupported);
            }
            let x = Xts::new(key).map_err(|_| PlatformError::Unsupported)?;
            let at: NonNull<Xts> =
                pages(core::mem::size_of::<Xts>()).ok_or(PlatformError::TooLarge)?;
            // SAFETY: a fresh allocation large enough and aligned (pages).
            unsafe { at.as_ptr().write(x) };
            info!(
                "paguro: blockio: BitLocker, {}-byte units, encrypted to {:#x}",
                layout.bytes_per_sector, layout.encrypted_size
            );
            (layout, at.as_ptr().cast_const())
        }
        None => (
            Layout {
                bytes_per_sector: SECTOR as u32,
                volume_size: 0,
                metadata_offsets: [0; 3],
                reloc_len: 0,
                reloc_offset: 0,
                extra_region: None,
                encrypted_size: 0,
                cipher: paguro_core::bde::Cipher::XtsAes128,
                partial: false,
            },
            ptr::null(),
        ),
    };
    let d: NonNull<Published> =
        pages(core::mem::size_of::<Published>()).ok_or(PlatformError::TooLarge)?;
    let part_sectors = disk
        .part
        .sectors
        .saturating_mul(u64::from(disk.part.block_size) / SECTOR);
    // SAFETY: `d` is a fresh, zeroed allocation large enough for Published;
    // every field is written before a pointer to it is handed out.
    unsafe {
        let p = d.as_ptr();
        ptr::addr_of_mut!((*p).media).write(BlockIoMedia {
            media_id: MEDIA_ID,
            removable_media: false.into(),
            media_present: true.into(),
            logical_partition: false.into(),
            read_only: true.into(),
            write_caching: false.into(),
            block_size: SECTOR as u32,
            io_align: 0,
            last_block: disk.sectors - 1,
            lowest_aligned_lba: 0,
            logical_blocks_per_physical_block: 1,
            optimal_transfer_length_granularity: 0,
        });
        ptr::addr_of_mut!((*p).proto).write(BlockIoProtocol {
            revision: BlockIoProtocol::REVISION_3,
            media: ptr::addr_of!((*p).media),
            reset,
            read_blocks,
            write_blocks,
            flush_blocks,
        });
        ptr::addr_of_mut!((*p).phys).write(phys);
        ptr::addr_of_mut!((*p).phys_media_id).write(phys_media_id);
        ptr::addr_of_mut!((*p).phys_block).write(phys_block);
        ptr::addr_of_mut!((*p).part_first).write(disk.part.first_lba);
        ptr::addr_of_mut!((*p).part_sectors).write(part_sectors);
        ptr::addr_of_mut!((*p).extents).write(extents.as_ptr());
        ptr::addr_of_mut!((*p).extent_count).write(disk.extents.len());
        ptr::addr_of_mut!((*p).sectors).write(disk.sectors);
        ptr::addr_of_mut!((*p).bounce).write(bounce.as_ptr());
        ptr::addr_of_mut!((*p).layout).write(layout);
        ptr::addr_of_mut!((*p).xts).write(xts);
    }

    // The device path: the physical disk's, then a vendor media node naming
    // the file (MFT record and sequence), then the end node.
    let parent = crate::platform::open_get::<DevicePath>(disk_handle)
        .map_err(|e| PlatformError::Device(e.status().0 as u64))?;
    let body = path_body(&parent);
    let node_len = VENDOR_NODE_LEN;
    let total = body.len() + node_len + END.len();
    let dp: NonNull<u8> = pages(total).ok_or(PlatformError::TooLarge)?;
    let mut vendor = [0u8; VENDOR_NODE_LEN];
    vendor[0] = DeviceType::MEDIA.0;
    vendor[1] = DeviceSubType::MEDIA_VENDOR.0;
    vendor[NODE_LEN].copy_from_slice(&(node_len as u16).to_le_bytes());
    vendor[VENDOR_GUID].copy_from_slice(&VENDOR);
    vendor[VENDOR_MFT_RECORD].copy_from_slice(&disk.file.mft_record.to_le_bytes());
    vendor[VENDOR_MFT_SEQ].copy_from_slice(&disk.file.mft_seq.to_le_bytes());
    // SAFETY: `dp` holds `total` bytes.
    let dp_bytes = unsafe {
        let b = core::slice::from_raw_parts_mut(dp.as_ptr(), total);
        put(b, 0, body)?;
        put(b, body.len(), &vendor)?;
        put(b, body.len() + node_len, &END)?;
        &*b
    };
    drop(parent);
    let own = <&DevicePath>::try_from(dp_bytes).map_err(|_| PlatformError::Unsupported)?;

    // SAFETY: both interfaces live in never-freed pages; the protocol
    // structs are initialised.
    let handle = unsafe {
        let h = boot::install_protocol_interface(
            None,
            &uefi::proto::media::block::BlockIO::GUID,
            d.as_ptr().cast::<c_void>(),
        )
        .map_err(|e| PlatformError::Device(e.status().0 as u64))?;
        boot::install_protocol_interface(Some(h), &DevicePath::GUID, dp.as_ptr().cast::<c_void>())
            .map_err(|e| PlatformError::Device(e.status().0 as u64))?;
        h
    };
    log_path("blockio published", own);
    if let Err(e) = boot::connect_controller(handle, &[], None, true) {
        info!("paguro: blockio: ConnectController: {:?}", e.status());
    }

    // Find the firmware's SimpleFileSystem on our disk (tier 1).
    let fs = find_fs(handle, dp_bytes, fat).ok_or_else(|| {
        info!(
            "paguro: blockio: tier 1 failed: no firmware file system bound to the published disk"
        );
        PlatformError::Unsupported
    })?;
    let fs_dp = crate::platform::open_get::<DevicePath>(fs)
        .map_err(|e| PlatformError::Device(e.status().0 as u64))?;
    log_path("tier 1: firmware FAT bound", &fs_dp);
    let fs_body = path_body(&fs_dp);

    // `fs`'s path, a file-path node for `image`, the end node.
    let units = image.encode_utf16().count() + 1;
    let fnode = NODE_HEADER + 2 * units;
    let n = fs_body.len() + fnode + END.len();
    let o = out.get_mut(..n).ok_or(PlatformError::TooLarge)?;
    let (a, rest) = o.split_at_mut(fs_body.len());
    a.copy_from_slice(fs_body);
    let (node, end) = rest.split_at_mut(fnode);
    // Media / file path (§10.3.5.4), length, the NUL-terminated UTF-16 path.
    put(
        node,
        0,
        &[DeviceType::MEDIA.0, DeviceSubType::MEDIA_FILE_PATH.0],
    )?;
    put(node, NODE_LEN.start, &(fnode as u16).to_le_bytes())?;
    for (i, u) in image.encode_utf16().chain(core::iter::once(0)).enumerate() {
        put(node, NODE_HEADER + 2 * i, &u.to_le_bytes())?;
    }
    end.copy_from_slice(&END);
    Ok(n)
}

/// The end-of-device-path node: End / End Entire, length 4 (§10.3.1).
const END: [u8; NODE_HEADER] = [
    DeviceType::END.0,
    DeviceSubType::END_ENTIRE.0,
    NODE_HEADER as u8,
    0x00,
];

fn put(b: &mut [u8], at: usize, src: &[u8]) -> Result<(), PlatformError> {
    b.get_mut(at..at + src.len())
        .ok_or(PlatformError::TooLarge)?
        .copy_from_slice(src);
    Ok(())
}

/// The SimpleFileSystem on the published disk: on the child whose hard
/// drive node starts at `first_lba` (GPT), or on the disk itself (whole).
fn find_fs(disk: Handle, own: &[u8], fat: FatAt) -> Option<Handle> {
    let prefix = own.get(..own.len().saturating_sub(END.len()))?;
    let handles =
        boot::locate_handle_buffer(SearchType::ByProtocol(&SimpleFileSystem::GUID)).ok()?;
    for h in handles.iter() {
        match fat {
            FatAt::Whole if *h == disk => return Some(*h),
            FatAt::Whole => continue,
            FatAt::Partition { first_lba, .. } => {
                let Ok(dp) = crate::platform::open_get::<DevicePath>(*h) else {
                    continue;
                };
                let b = dp.as_bytes();
                let Some(rest) = b.strip_prefix(prefix) else {
                    continue;
                };
                // Next node: media / hard drive, and its PartitionStart.
                let hd = [DeviceType::MEDIA.0, DeviceSubType::MEDIA_HARD_DRIVE.0];
                if rest.len() >= HARD_DRIVE_NODE_LEN && rest.get(..2) == Some(&hd[..]) {
                    let start =
                        u64::from_le_bytes(rest.get(HARD_DRIVE_PARTITION_START)?.try_into().ok()?);
                    if start == first_lba {
                        return Some(*h);
                    }
                }
            }
        }
    }
    None
}
