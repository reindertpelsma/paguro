//! [`Platform`] over the `uefi` crate: the only place firmware is touched.
//!
//! Deliberately thin. Every decision is in `paguro-boot`; this file converts
//! types, bounds reads, and reports failures as values. Protocols are opened
//! per call and closed on return.

use core::fmt;
use core::mem::size_of;
use core::ops::Range;
use core::ptr::NonNull;

use log::info;

use crate::front::Front;
use crate::layout::field;
use paguro_boot::platform::{DirView, DiskInfo, Input, Platform, PlatformError, Screen};
use paguro_boot::ui::Key;
use paguro_core::config::Ui;
use paguro_core::guid::{Guid, HANDOFF_TABLE};
use paguro_ui::driver::{self, Session};
use uefi::boot::{
    self, AllocateType, LoadImageSource, MemoryType, OpenProtocolAttributes, OpenProtocolParams,
    PAGE_SIZE, SearchType,
};
use uefi::proto::BootPolicy;
use uefi::proto::console::text::{Key as UKey, ScanCode};
use uefi::proto::device_path::DevicePath;
use uefi::proto::media::block::BlockIO;
use uefi::proto::media::file::{File, FileAttribute, FileMode};
use uefi::proto::rng::Rng;
use uefi::proto::tcg::PcrIndex;
use uefi::proto::tcg::v2::{HashLogExtendEventFlags, PcrEventInputs, Tcg};
use uefi::runtime::{self, ResetType, VariableAttributes, VariableVendor};
use uefi::{CStr16, Handle, Identify, Status};

const MAX_DISKS: usize = 16;
/// Bounce buffer for block reads: page-aligned, satisfies any `IoAlign`.
const BOUNCE: usize = 64 * 1024;
/// Room for a UCS-2 path or variable name (they are ASCII and short).
const NAME16_LEN: usize = 128;
/// Room for an ESP path, [`ESP_DIR`] plus the file name.
const ESP_PATH_LEN: usize = 96;
/// paguro's directory on the ESP.
const ESP_DIR: &[u8] = b"\\EFI\\paguro\\";
/// Room for a `TCG_PCClientTaggedEvent` and the `EFI_TCG2_EVENT` around it.
const TAGGED_EVENT_LEN: usize = 128;
const TCG2_EVENT_LEN: usize = 256;

/// `TCG_PCClientTaggedEvent` (TCG PC Client PFP §10.4.2.1): the fixed part,
/// then `taggedEventDataSize` bytes. Layout only (see `layout`).
#[allow(dead_code)]
#[repr(C, packed)]
struct TaggedEventHeader {
    tagged_event_id: u32,
    tagged_event_data_size: u32,
}
const TAGGED_EVENT_HEADER: usize = size_of::<TaggedEventHeader>();
const TAGGED_EVENT_ID: Range<usize> = field!(TaggedEventHeader, tagged_event_id);
const TAGGED_EVENT_DATA_SIZE: Range<usize> = field!(TaggedEventHeader, tagged_event_data_size);
const _: () = assert!(TAGGED_EVENT_HEADER == 8 && TAGGED_EVENT_DATA_SIZE.start == 4);

/// A TPM 2.0 response header (TCG TPM 2.0 Part 1 §18.3): tag, responseSize,
/// responseCode, big-endian. Layout only.
#[allow(dead_code)]
#[repr(C, packed)]
struct TpmResponseHeader {
    tag: u16,
    response_size: u32,
    response_code: u32,
}
const TPM_RESPONSE_SIZE: Range<usize> = field!(TpmResponseHeader, response_size);
const _: () = assert!(TPM_RESPONSE_SIZE.start == 2 && size_of::<TpmResponseHeader>() == 10);

pub struct Efi {
    disks: [Option<Handle>; MAX_DISKS],
    disk_count: usize,
    bounce: NonNull<u8>,
    /// The displays, consoles and inputs.
    front: Front,
    session: &'static mut Session,
}

fn dev(e: &uefi::Error<impl fmt::Debug>) -> PlatformError {
    PlatformError::Device(e.status().0 as u64)
}

fn vendor(g: &Guid) -> VariableVendor {
    VariableVendor(uefi::Guid::from_bytes(g.0))
}

/// UCS-2 name into a caller buffer; names are ASCII and short.
fn name16<'b>(s: &str, buf: &'b mut [u16; NAME16_LEN]) -> Result<&'b CStr16, PlatformError> {
    CStr16::from_str_with_buf(s, buf).map_err(|_| PlatformError::TooLarge)
}

impl Efi {
    pub fn new() -> Result<Self, PlatformError> {
        let bounce = boot::allocate_pages(
            AllocateType::AnyPages,
            MemoryType::LOADER_DATA,
            BOUNCE / PAGE_SIZE,
        )
        .map_err(|e| dev(&e))?;
        let front = Front::new();
        if front.gop.is_none() {
            info!("paguro: no usable graphics output, text console");
        }
        // The session holds a text grid: pages, not the firmware's stack.
        let size = core::mem::size_of::<Session>();
        let p: NonNull<u8> = boot::allocate_pages(
            AllocateType::AnyPages,
            MemoryType::LOADER_DATA,
            size.div_ceil(PAGE_SIZE),
        )
        .map_err(|e| dev(&e))?;
        let sp = p.as_ptr().cast::<Session>();
        // SAFETY: a fresh, page-aligned allocation of at least
        // `size_of::<Session>()` bytes, initialised before the reference is
        // formed, owned by the loader for its lifetime.
        let session = unsafe {
            sp.write(Session::new());
            &mut *sp
        };
        session.text = front.text();
        let mut me = Efi {
            disks: [None; MAX_DISKS],
            disk_count: 0,
            bounce,
            front,
            session,
        };
        me.scan_disks();
        Ok(me)
    }

    fn scan_disks(&mut self) {
        let Ok(handles) = boot::locate_handle_buffer(SearchType::ByProtocol(&BlockIO::GUID)) else {
            return;
        };
        for h in handles.iter() {
            if self.disk_count >= MAX_DISKS {
                break;
            }
            let Ok(bio) = open_get::<BlockIO>(*h) else {
                continue;
            };
            let m = bio.media();
            if m.is_logical_partition() || !m.is_media_present() {
                continue;
            }
            if let Some(slot) = self.disks.get_mut(self.disk_count) {
                *slot = Some(*h);
                self.disk_count += 1;
            }
        }
    }

    /// Give the serial consoles back to the firmware (before returning to
    /// it, or starting anything).
    pub fn release_consoles(&mut self) {
        self.front.release();
    }

    fn bounce(&mut self) -> &mut [u8] {
        // SAFETY: `bounce` is a live, exclusively owned LOADER_DATA allocation
        // of BOUNCE bytes for the loader's lifetime, zero-initialised on use.
        unsafe { core::slice::from_raw_parts_mut(self.bounce.as_ptr(), BOUNCE) }
    }

    fn tcg(&self) -> Option<boot::ScopedProtocol<Tcg>> {
        let h = boot::get_handle_for_protocol::<Tcg>().ok()?;
        boot::open_protocol_exclusive::<Tcg>(h).ok()
    }
}

/// Open a protocol without taking it from its driver (block devices are held
/// by the partition driver; exclusive opens would disconnect it).
pub(crate) fn open_get<P: uefi::proto::ProtocolPointer + ?Sized>(
    h: Handle,
) -> uefi::Result<boot::ScopedProtocol<P>> {
    // SAFETY: GetProtocol does not track the open; the handle stays valid for
    // the loader's lifetime (no driver is unloaded while it runs) and the
    // ScopedProtocol is dropped before returning to firmware.
    unsafe {
        boot::open_protocol::<P>(
            OpenProtocolParams {
                handle: h,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }
}

/// `EFI_INPUT_KEY` → [`Key`]. Scan codes: UEFI 2.10 §12.3, Table 12-4
/// (`SCAN_UP` 0x01 … `SCAN_ESC` 0x17), as the `uefi` crate names them.
pub(crate) fn decode_key(k: UKey) -> Option<Key> {
    match k {
        UKey::Special(s) => match s {
            ScanCode::ESCAPE => Some(Key::Escape),
            ScanCode::UP => Some(Key::Up),
            ScanCode::DOWN => Some(Key::Down),
            ScanCode::RIGHT => Some(Key::Right),
            ScanCode::LEFT => Some(Key::Left),
            ScanCode::HOME => Some(Key::Home),
            ScanCode::END => Some(Key::End),
            ScanCode::INSERT => Some(Key::Insert),
            ScanCode::DELETE => Some(Key::Delete),
            ScanCode::PAGE_UP => Some(Key::PageUp),
            ScanCode::PAGE_DOWN => Some(Key::PageDown),
            ScanCode(f) if (ScanCode::FUNCTION_1.0..=ScanCode::FUNCTION_12.0).contains(&f) => {
                Some(Key::Function((f - ScanCode::FUNCTION_1.0 + 1) as u8))
            }
            _ => None,
        },
        UKey::Printable(c) => {
            let c: char = c.into();
            match c {
                '\r' | '\n' => Some(Key::Enter),
                // DEL is what serial terminals send for Backspace; the Delete
                // key arrives as SCAN_DELETE.
                '\u{8}' | '\u{7f}' => Some(Key::Backspace),
                '\u{1b}' => Some(Key::Escape),
                c => Some(Key::Char(c)),
            }
        }
    }
}

impl Platform for Efi {
    fn read_esp_file(
        &mut self,
        name: &str,
        buf: &mut [u8],
    ) -> Result<Option<usize>, PlatformError> {
        let mut pathbuf = [0u8; ESP_PATH_LEN];
        let prefix = ESP_DIR;
        let n = prefix.len() + name.len();
        let p = pathbuf.get_mut(..n).ok_or(PlatformError::TooLarge)?;
        let (a, b) = p.split_at_mut(prefix.len());
        a.copy_from_slice(prefix);
        b.copy_from_slice(name.as_bytes());
        let path = core::str::from_utf8(pathbuf.get(..n).unwrap_or(&[]))
            .map_err(|_| PlatformError::Unsupported)?;
        let mut w = [0u16; NAME16_LEN];
        let path = name16(path, &mut w)?;
        let mut fs = boot::get_image_file_system(boot::image_handle()).map_err(|e| dev(&e))?;
        let mut root = fs.open_volume().map_err(|e| dev(&e))?;
        let fh = match root.open(path, FileMode::Read, FileAttribute::empty()) {
            Ok(f) => f,
            Err(e) if e.status() == Status::NOT_FOUND => return Ok(None),
            Err(e) => return Err(dev(&e)),
        };
        let mut file = fh.into_regular_file().ok_or(PlatformError::Unsupported)?;
        let mut total = 0usize;
        while let Some(rest) = buf.get_mut(total..).filter(|r| !r.is_empty()) {
            let got = file.read(rest).map_err(|e| dev(&e))?;
            if got == 0 {
                return Ok(Some(total));
            }
            total += got;
        }
        // Buffer full: anything more means the file exceeds the cap.
        let mut probe = [0u8; 1];
        match file.read(&mut probe) {
            Ok(0) => Ok(Some(total)),
            _ => Err(PlatformError::TooLarge),
        }
    }

    fn get_var(
        &mut self,
        name: &str,
        vendor_guid: &Guid,
        buf: &mut [u8],
    ) -> Result<Option<usize>, PlatformError> {
        let mut w = [0u16; NAME16_LEN];
        let n = name16(name, &mut w)?;
        match runtime::get_variable(n, &vendor(vendor_guid), buf) {
            Ok((data, _)) => Ok(Some(data.len())),
            Err(e) if e.status() == Status::NOT_FOUND => Ok(None),
            Err(e) if e.status() == Status::BUFFER_TOO_SMALL => Err(PlatformError::TooLarge),
            Err(e) => Err(dev(&e)),
        }
    }

    fn set_var(
        &mut self,
        name: &str,
        vendor_guid: &Guid,
        attrs: u32,
        data: &[u8],
    ) -> Result<(), PlatformError> {
        let mut w = [0u16; NAME16_LEN];
        let n = name16(name, &mut w)?;
        runtime::set_variable(
            n,
            &vendor(vendor_guid),
            VariableAttributes::from_bits_truncate(attrs),
            data,
        )
        .map_err(|e| dev(&e))
    }

    fn delete_var(&mut self, name: &str, vendor_guid: &Guid) -> Result<(), PlatformError> {
        let mut w = [0u16; NAME16_LEN];
        let n = name16(name, &mut w)?;
        runtime::delete_variable(n, &vendor(vendor_guid)).map_err(|e| dev(&e))
    }

    fn secure_boot(&mut self) -> bool {
        let mut b = [0u8; 1];
        let mut w = [0u16; NAME16_LEN];
        let Ok(n) = name16("SecureBoot", &mut w) else {
            return false;
        };
        matches!(runtime::get_variable(n, &VariableVendor::GLOBAL_VARIABLE, &mut b), Ok((d, _)) if d == [1])
    }

    fn tpm_present(&mut self) -> bool {
        self.tcg()
            .and_then(|mut t| t.get_capability().ok())
            .is_some_and(|c| c.tpm_present())
    }

    fn hash_log_extend(
        &mut self,
        pcr: u32,
        data: &[u8],
        event: &[u8],
    ) -> Result<(), PlatformError> {
        // TCG_PCClientTaggedEvent: taggedEventID u32 | size u32 | data.
        let mut tagged = [0u8; TAGGED_EVENT_LEN];
        let n = TAGGED_EVENT_HEADER + event.len();
        let t = tagged.get_mut(..n).ok_or(PlatformError::TooLarge)?;
        let id = u32::from_le_bytes([
            event.first().copied().unwrap_or(0),
            event.get(1).copied().unwrap_or(0),
            event.get(2).copied().unwrap_or(0),
            event.get(3).copied().unwrap_or(0),
        ]);
        let (h, body) = t.split_at_mut(TAGGED_EVENT_HEADER);
        h.get_mut(TAGGED_EVENT_ID)
            .ok_or(PlatformError::TooLarge)?
            .copy_from_slice(&id.to_le_bytes());
        h.get_mut(TAGGED_EVENT_DATA_SIZE)
            .ok_or(PlatformError::TooLarge)?
            .copy_from_slice(&(event.len() as u32).to_le_bytes());
        body.copy_from_slice(event);
        let mut evbuf = [0u8; TCG2_EVENT_LEN];
        let ev = PcrEventInputs::new_in_buffer(
            &mut evbuf,
            PcrIndex(pcr),
            uefi::proto::tcg::EventType::EVENT_TAG,
            tagged.get(..n).unwrap_or(&[]),
        )
        .map_err(|_| PlatformError::TooLarge)?;
        let mut tcg = self.tcg().ok_or(PlatformError::Unsupported)?;
        tcg.hash_log_extend_event(HashLogExtendEventFlags::empty(), data, ev)
            .map_err(|e| dev(&e))
    }

    fn tpm_submit(&mut self, cmd: &[u8], resp: &mut [u8]) -> Result<usize, PlatformError> {
        let mut tcg = self.tcg().ok_or(PlatformError::Unsupported)?;
        tcg.submit_command(cmd, resp).map_err(|e| dev(&e))?;
        // The protocol does not return a length: take it from the header,
        // bounded by the buffer (the parser re-checks it).
        let n = resp
            .get(TPM_RESPONSE_SIZE)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map(|b| u32::from_be_bytes(b) as usize)
            .ok_or(PlatformError::TooLarge)?;
        if n > resp.len() {
            return Err(PlatformError::TooLarge);
        }
        Ok(n)
    }

    fn disk_count(&mut self) -> usize {
        self.disk_count
    }

    fn disk_info(&mut self, disk: usize) -> Option<DiskInfo> {
        let h = (*self.disks.get(disk)?)?;
        let bio = open_get::<BlockIO>(h).ok()?;
        let m = bio.media();
        Some(DiskInfo {
            block_size: m.block_size(),
            blocks: m.last_block().saturating_add(1),
        })
    }

    fn read_blocks(&mut self, disk: usize, lba: u64, buf: &mut [u8]) -> Result<(), PlatformError> {
        let h = self
            .disks
            .get(disk)
            .copied()
            .flatten()
            .ok_or(PlatformError::Unsupported)?;
        let mut bio = open_get::<BlockIO>(h).map_err(|e| dev(&e))?;
        let media_id = bio.media().media_id();
        let bs = bio.media().block_size() as usize;
        if bs == 0 || buf.len() % bs != 0 || BOUNCE % bs != 0 {
            return Err(PlatformError::Unsupported);
        }
        let mut done = 0usize;
        let mut cur = lba;
        while done < buf.len() {
            let chunk = (buf.len() - done).min(BOUNCE);
            let bounce = self.bounce();
            let b = bounce.get_mut(..chunk).ok_or(PlatformError::TooLarge)?;
            bio.read_blocks(media_id, cur, b).map_err(|e| dev(&e))?;
            buf.get_mut(done..done + chunk)
                .ok_or(PlatformError::TooLarge)?
                .copy_from_slice(b);
            done += chunk;
            cur += (chunk / bs) as u64;
        }
        Ok(())
    }

    fn random(&mut self, buf: &mut [u8]) -> Result<(), PlatformError> {
        let h = boot::get_handle_for_protocol::<Rng>().map_err(|_| PlatformError::Unsupported)?;
        let mut rng = boot::open_protocol_exclusive::<Rng>(h).map_err(|e| dev(&e))?;
        rng.get_rng(None, buf).map_err(|e| dev(&e))
    }

    fn prompt(&mut self, screen: &Screen, secret: &mut [u8]) -> Input {
        driver::prompt(&mut self.front, self.session, screen, secret)
    }

    fn prompt_browse(&mut self, screen: &Screen, dir: &DirView<'_>) -> Input {
        driver::prompt_browse(&mut self.front, self.session, screen, dir)
    }

    fn ui_prefs(&mut self, ui: Ui) {
        self.session.apply(ui);
        self.front.configure(ui.mode, self.session.text);
        self.session.text = self.front.text();
    }

    fn log(&mut self, args: fmt::Arguments<'_>) {
        info!("{args}");
    }

    fn publish_handoff(&mut self, blob: &[u8]) -> Result<(), PlatformError> {
        static TABLE: uefi::Guid = uefi::Guid::from_bytes(HANDOFF_TABLE.0);
        let p = boot::allocate_pool(MemoryType::RUNTIME_SERVICES_DATA, blob.len())
            .map_err(|e| dev(&e))?;
        // SAFETY: `p` is a fresh allocation of `blob.len()` bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(blob.as_ptr(), p.as_ptr(), blob.len());
            boot::install_configuration_table(&TABLE, p.as_ptr().cast()).map_err(|e| dev(&e))
        }
    }

    fn load_start_image(&mut self, device_path: &[u8]) -> Result<(), PlatformError> {
        // The image gets the consoles as the firmware set them up; the
        // loader takes them back if it returns or is refused.
        self.front.release();
        let r = (|| {
            let dp =
                <&DevicePath>::try_from(device_path).map_err(|_| PlatformError::Unsupported)?;
            let img = boot::load_image(
                boot::image_handle(),
                LoadImageSource::FromDevicePath {
                    device_path: dp,
                    boot_policy: BootPolicy::ExactMatch,
                },
            )
            .map_err(|e| dev(&e))?;
            boot::start_image(img).map_err(|e| dev(&e))
        })();
        self.front.configure(self.session.mode, self.session.text);
        r
    }

    fn load_start_image_buffer(&mut self, image: &[u8]) -> Result<(), PlatformError> {
        self.front.release();
        // LoadImage verifies it (Secure Boot / shim) exactly as by path.
        let r = boot::load_image(
            boot::image_handle(),
            LoadImageSource::FromBuffer {
                buffer: image,
                file_path: None,
            },
        )
        .map_err(|e| dev(&e))
        .and_then(|img| boot::start_image(img).map_err(|e| dev(&e)));
        self.front.configure(self.session.mode, self.session.text);
        r
    }

    fn alloc_image(&mut self, len: usize) -> Result<&'static mut [u8], PlatformError> {
        let p = boot::allocate_pages(
            AllocateType::AnyPages,
            MemoryType::LOADER_DATA,
            len.div_ceil(PAGE_SIZE).max(1),
        )
        .map_err(|e| dev(&e))?;
        // SAFETY: a fresh allocation of at least `len` bytes, never freed,
        // exclusively handed to the caller.
        Ok(unsafe {
            core::ptr::write_bytes(p.as_ptr(), 0, len);
            core::slice::from_raw_parts_mut(p.as_ptr(), len)
        })
    }

    fn expose_disk(
        &mut self,
        disk: &paguro_boot::stage4::ExposedDisk<'_>,
        fat: paguro_boot::stage4::FatAt,
        image: &str,
        out: &mut [u8],
    ) -> Result<usize, PlatformError> {
        let h = self
            .disks
            .get(disk.part.disk)
            .copied()
            .flatten()
            .ok_or(PlatformError::Unsupported)?;
        crate::blockio::expose(h, disk, fat, image, out)
    }

    fn reset(&mut self) {
        self.front.release();
        runtime::reset(ResetType::COLD, Status::SUCCESS, None)
    }
}
