//! [`Platform`] over the `uefi` crate: the only place firmware is touched.
//!
//! Deliberately thin. Every decision is in `paguro-boot`; this file converts
//! types, bounds reads, and reports failures as values. Protocols are opened
//! per call and closed on return.

use core::fmt::{self, Write};
use core::ptr::NonNull;

use log::info;
use paguro_boot::platform::{DiskInfo, Input, Platform, PlatformError, Screen};
use paguro_boot::ui::{self, Edit, Key, SecretEditor};
use paguro_core::guid::Guid;
use uefi::boot::{
    self, AllocateType, LoadImageSource, MemoryType, OpenProtocolAttributes, OpenProtocolParams,
    SearchType,
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

pub struct Efi {
    disks: [Option<Handle>; MAX_DISKS],
    disk_count: usize,
    bounce: NonNull<u8>,
}

fn dev(e: &uefi::Error<impl fmt::Debug>) -> PlatformError {
    PlatformError::Device(e.status().0 as u64)
}

fn vendor(g: &Guid) -> VariableVendor {
    VariableVendor(uefi::Guid::from_bytes(g.0))
}

/// UCS-2 name into a caller buffer; names are ASCII and short.
fn name16<'b>(s: &str, buf: &'b mut [u16; 128]) -> Result<&'b CStr16, PlatformError> {
    CStr16::from_str_with_buf(s, buf).map_err(|_| PlatformError::TooLarge)
}

impl Efi {
    pub fn new() -> Result<Self, PlatformError> {
        let bounce = boot::allocate_pages(
            AllocateType::AnyPages,
            MemoryType::LOADER_DATA,
            BOUNCE / 4096,
        )
        .map_err(|e| dev(&e))?;
        let mut me = Efi {
            disks: [None; MAX_DISKS],
            disk_count: 0,
            bounce,
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
fn open_get<P: uefi::proto::ProtocolPointer + ?Sized>(
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

fn decode_key(k: UKey) -> Option<Key> {
    match k {
        UKey::Special(ScanCode::ESCAPE) => Some(Key::Escape),
        UKey::Special(_) => None,
        UKey::Printable(c) => {
            let c: char = c.into();
            match c {
                '\r' | '\n' => Some(Key::Enter),
                '\u{8}' | '\u{7f}' => Some(Key::Backspace),
                '\u{1b}' => Some(Key::Escape),
                c => Some(Key::Char(c)),
            }
        }
    }
}

fn read_key() -> Key {
    loop {
        let ev = uefi::system::with_stdin(|i| i.wait_for_key_event().ok());
        if let Some(ev) = ev {
            let _ = boot::wait_for_event(&[ev]);
        }
        if let Some(k) =
            uefi::system::with_stdin(|i| i.read_key().ok().flatten()).and_then(decode_key)
        {
            return k;
        }
    }
}

struct Out;

impl Write for Out {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        uefi::system::with_stdout(|o| o.write_str(s))
    }
}

impl Platform for Efi {
    fn read_esp_file(
        &mut self,
        name: &str,
        buf: &mut [u8],
    ) -> Result<Option<usize>, PlatformError> {
        let mut pathbuf = [0u8; 96];
        let prefix = b"\\EFI\\paguro\\";
        let n = prefix.len() + name.len();
        let p = pathbuf.get_mut(..n).ok_or(PlatformError::TooLarge)?;
        let (a, b) = p.split_at_mut(prefix.len());
        a.copy_from_slice(prefix);
        b.copy_from_slice(name.as_bytes());
        let path = core::str::from_utf8(pathbuf.get(..n).unwrap_or(&[]))
            .map_err(|_| PlatformError::Unsupported)?;
        let mut w = [0u16; 128];
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
        let mut w = [0u16; 128];
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
        let mut w = [0u16; 128];
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
        let mut w = [0u16; 128];
        let n = name16(name, &mut w)?;
        runtime::delete_variable(n, &vendor(vendor_guid)).map_err(|e| dev(&e))
    }

    fn secure_boot(&mut self) -> bool {
        let mut b = [0u8; 1];
        let mut w = [0u16; 128];
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
        let mut tagged = [0u8; 128];
        let n = 8 + event.len();
        let t = tagged.get_mut(..n).ok_or(PlatformError::TooLarge)?;
        let id = u32::from_le_bytes([
            event.first().copied().unwrap_or(0),
            event.get(1).copied().unwrap_or(0),
            event.get(2).copied().unwrap_or(0),
            event.get(3).copied().unwrap_or(0),
        ]);
        let (h, body) = t.split_at_mut(8);
        h.get_mut(..4)
            .ok_or(PlatformError::TooLarge)?
            .copy_from_slice(&id.to_le_bytes());
        h.get_mut(4..8)
            .ok_or(PlatformError::TooLarge)?
            .copy_from_slice(&(event.len() as u32).to_le_bytes());
        body.copy_from_slice(event);
        let mut evbuf = [0u8; 256];
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
            .get(2..6)
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
        let _ = ui::render(screen, &mut Out);
        if !ui::needs_key(screen) {
            return Input::Continue;
        }
        if let Screen::EnterSecret { .. } = screen {
            let mut ed = SecretEditor::new();
            loop {
                match ed.feed(read_key(), secret) {
                    Edit::Echo => {
                        let _ = Out.write_str("*");
                    }
                    Edit::Erase => {
                        let _ = Out.write_str("\u{8} \u{8}");
                    }
                    Edit::Nothing => {}
                    Edit::Done(i) => {
                        let _ = Out.write_str("\r\n");
                        return i;
                    }
                }
            }
        }
        loop {
            if let Some(i) = ui::map_key(screen, read_key()) {
                return i;
            }
        }
    }

    fn log(&mut self, args: fmt::Arguments<'_>) {
        info!("{args}");
    }

    fn publish_handoff(&mut self, blob: &[u8]) -> Result<(), PlatformError> {
        static TABLE: uefi::Guid = uefi::guid!("290e97f6-3835-4ea1-a6f5-847ccbc33a0a");
        let p = boot::allocate_pool(MemoryType::RUNTIME_SERVICES_DATA, blob.len())
            .map_err(|e| dev(&e))?;
        // SAFETY: `p` is a fresh allocation of `blob.len()` bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(blob.as_ptr(), p.as_ptr(), blob.len());
            boot::install_configuration_table(&TABLE, p.as_ptr().cast()).map_err(|e| dev(&e))
        }
    }

    fn load_start_image(&mut self, device_path: &[u8]) -> Result<(), PlatformError> {
        let dp = <&DevicePath>::try_from(device_path).map_err(|_| PlatformError::Unsupported)?;
        let img = boot::load_image(
            boot::image_handle(),
            LoadImageSource::FromDevicePath {
                device_path: dp,
                boot_policy: BootPolicy::ExactMatch,
            },
        )
        .map_err(|e| dev(&e))?;
        boot::start_image(img).map_err(|e| dev(&e))
    }

    fn reset(&mut self) {
        runtime::reset(ResetType::COLD, Status::SUCCESS, None)
    }
}
