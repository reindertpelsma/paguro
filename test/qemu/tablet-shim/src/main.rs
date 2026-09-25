//! Test-only (QEMU pointer scenario, `test/qemu/runner`): OVMF as packaged
//! by distributions has no USB pointer driver, so QEMU's `usb-tablet`
//! produces no `EFI_ABSOLUTE_POINTER_PROTOCOL`. This app is booted first:
//! it finds the tablet (a USB HID interface), installs an absolute pointer
//! on its handle that reads the tablet's reports (QEMU's format: buttons,
//! X, Y as 0..0x7fff, wheel) with synchronous interrupt transfers, then
//! loads and starts `\EFI\BOOT\PAGURO.EFI` from the same volume. The
//! loader under test is unchanged; it finds the pointer like any other.
//!
//! Never shipped.
#![no_main]
#![no_std]

use core::ffi::c_void;
use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{AtomicPtr, AtomicU8, Ordering};

use uefi::boot::{self, EventType, LoadImageSource, SearchType, Tpl};
use uefi::prelude::*;
use uefi::proto::BootPolicy;
use uefi::proto::device_path::DevicePath;
use uefi::proto::device_path::build::{self, DevicePathBuilder};
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::usb::io::UsbIo;
use uefi::{Event, Identify, cstr16, println};
use uefi_raw::protocol::console::{
    AbsolutePointerMode, AbsolutePointerModeAttributes, AbsolutePointerProtocol,
    AbsolutePointerState,
};

/// QEMU's usb-tablet coordinate range (hw/usb/dev-hid.c): 0..=0x7fff.
const TABLET_MAX: u64 = 0x7fff;
/// QEMU's usb-tablet report: buttons (u8), X (u16 LE), Y (u16 LE), wheel.
const REPORT_BUTTONS: usize = 0;
const REPORT_X: usize = 1;
const REPORT_Y: usize = 3;
/// A report must reach through Y.
const REPORT_MIN_LEN: usize = REPORT_Y + 2;
const REPORT_MAX_LEN: usize = 8;
/// Buttons: bit 0 is the left button.
const BUTTON_LEFT: u8 = 1;
/// Synchronous interrupt transfer timeout, ms.
const TRANSFER_TIMEOUT_MS: usize = 2;
/// USB interface class HID and its boot-keyboard protocol (USB HID 1.11 §4).
const USB_CLASS_HID: u8 = 3;
const HID_PROTOCOL_KEYBOARD: u8 = 1;
/// Endpoint descriptor fields (USB 2.0 §9.6.6): bEndpointAddress's
/// direction bit (IN) and number, bmAttributes' transfer type (interrupt).
const ENDPOINT_DIR_IN: u8 = 0x80;
const ENDPOINT_NUMBER: u8 = 0x0f;
const TRANSFER_TYPE_MASK: u8 = 3;
const TRANSFER_TYPE_INTERRUPT: u8 = 3;
/// The endpoint used when the interface lists no interrupt-in endpoint.
const DEFAULT_ENDPOINT: u8 = 1;
/// Room for this volume's device path plus the loader's file path.
const PATH_BUF: usize = 512;

static TABLET: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static ENDPOINT: AtomicU8 = AtomicU8::new(DEFAULT_ENDPOINT);

static mut MODE: AbsolutePointerMode = AbsolutePointerMode {
    absolute_min_x: 0,
    absolute_min_y: 0,
    absolute_min_z: 0,
    absolute_max_x: TABLET_MAX,
    absolute_max_y: TABLET_MAX,
    absolute_max_z: 0,
    attributes: AbsolutePointerModeAttributes::empty(),
};

static mut PROTO: AbsolutePointerProtocol = AbsolutePointerProtocol {
    reset,
    get_state,
    wait_for_input: core::ptr::null_mut(),
    mode: core::ptr::null(),
};

unsafe extern "efiapi" fn reset(
    _: *mut AbsolutePointerProtocol,
    _: uefi_raw::Boolean,
) -> uefi_raw::Status {
    uefi_raw::Status::SUCCESS
}

unsafe extern "efiapi" fn get_state(
    _: *mut AbsolutePointerProtocol,
    state: *mut AbsolutePointerState,
) -> uefi_raw::Status {
    // SAFETY: stored from a live handle; handles outlive this app's use.
    let Some(h) = (unsafe { Handle::from_ptr(TABLET.load(Ordering::Relaxed)) }) else {
        return uefi_raw::Status::NOT_READY;
    };
    // SAFETY: GetProtocol on the tablet's handle, dropped before return.
    let io = unsafe {
        boot::open_protocol::<UsbIo>(
            boot::OpenProtocolParams {
                handle: h,
                agent: boot::image_handle(),
                controller: None,
            },
            boot::OpenProtocolAttributes::GetProtocol,
        )
    };
    let Ok(mut io) = io else {
        return uefi_raw::Status::DEVICE_ERROR;
    };
    let mut buf = [0u8; REPORT_MAX_LEN];
    let ep = ENDPOINT.load(Ordering::Relaxed);
    match io.sync_interrupt_receive(ep, &mut buf, TRANSFER_TIMEOUT_MS) {
        Ok(n) if n >= REPORT_MIN_LEN && !state.is_null() => {
            let s = AbsolutePointerState {
                current_x: u64::from(u16::from_le_bytes([buf[REPORT_X], buf[REPORT_X + 1]])),
                current_y: u64::from(u16::from_le_bytes([buf[REPORT_Y], buf[REPORT_Y + 1]])),
                current_z: 0,
                active_buttons: u32::from(buf[REPORT_BUTTONS] & BUTTON_LEFT),
            };
            // SAFETY: the caller passes a writable state.
            unsafe { state.write(s) };
            uefi_raw::Status::SUCCESS
        }
        _ => uefi_raw::Status::NOT_READY,
    }
}

unsafe extern "efiapi" fn never(_: Event, _: Option<core::ptr::NonNull<c_void>>) {}

/// The first USB HID interface that is not a boot keyboard: the tablet.
fn find_tablet() -> Option<(Handle, u8)> {
    let hs = boot::locate_handle_buffer(SearchType::ByProtocol(&UsbIo::GUID)).ok()?;
    for h in hs.iter() {
        let Ok(mut io) = boot::open_protocol_exclusive::<UsbIo>(*h) else {
            continue;
        };
        let Ok(i) = io.interface_descriptor() else {
            continue;
        };
        if i.interface_class != USB_CLASS_HID || i.interface_protocol == HID_PROTOCOL_KEYBOARD {
            continue;
        }
        let ep = (0..i.num_endpoints)
            .filter_map(|e| io.endpoint_descriptor(e).ok())
            .find(|e| {
                e.endpoint_address & ENDPOINT_DIR_IN != 0
                    && e.attributes & TRANSFER_TYPE_MASK == TRANSFER_TYPE_INTERRUPT
            })
            .map_or(DEFAULT_ENDPOINT, |e| e.endpoint_address & ENDPOINT_NUMBER);
        return Some((*h, ep));
    }
    None
}

#[entry]
fn main() -> Status {
    if uefi::helpers::init().is_err() {
        return Status::ABORTED;
    }
    match find_tablet() {
        Some((h, ep)) => {
            TABLET.store(h.as_ptr(), Ordering::Relaxed);
            ENDPOINT.store(ep, Ordering::Relaxed);
            // SAFETY: a wait event with a no-op notification; the loader
            // polls get_state on its own timer.
            let ev = unsafe {
                boot::create_event(EventType::NOTIFY_WAIT, Tpl::NOTIFY, Some(never), None)
            };
            // SAFETY: the statics live for the whole boot; nothing else
            // touches them after installation.
            unsafe {
                let p = &mut *addr_of_mut!(PROTO);
                p.mode = addr_of!(MODE);
                if let Ok(ev) = ev {
                    p.wait_for_input = ev.as_ptr();
                }
                let r = boot::install_protocol_interface(
                    Some(h),
                    &AbsolutePointerProtocol::GUID,
                    addr_of_mut!(PROTO).cast(),
                );
                println!("tablet-shim: absolute pointer on the usb tablet (endpoint {ep}): {r:?}");
            }
        }
        None => println!("tablet-shim: no usb tablet"),
    }
    // Start the loader from this volume.
    let Ok(li) = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle()) else {
        return Status::LOAD_ERROR;
    };
    let Some(dev) = li.device() else {
        return Status::LOAD_ERROR;
    };
    let Ok(dp) = boot::open_protocol_exclusive::<DevicePath>(dev) else {
        return Status::LOAD_ERROR;
    };
    let mut buf = [core::mem::MaybeUninit::uninit(); PATH_BUF];
    let mut b = DevicePathBuilder::with_buf(&mut buf);
    for n in dp.node_iter() {
        b = match b.push(&n) {
            Ok(b) => b,
            Err(_) => return Status::LOAD_ERROR,
        };
    }
    let path = b
        .push(&build::media::FilePath {
            path_name: cstr16!("\\EFI\\BOOT\\PAGURO.EFI"),
        })
        .and_then(|b| b.finalize());
    let Ok(path) = path else {
        return Status::LOAD_ERROR;
    };
    drop(dp);
    drop(li);
    let img = boot::load_image(
        boot::image_handle(),
        LoadImageSource::FromDevicePath {
            device_path: path,
            boot_policy: BootPolicy::ExactMatch,
        },
    );
    match img {
        Ok(img) => match boot::start_image(img) {
            Ok(()) => Status::SUCCESS,
            Err(e) => e.status(),
        },
        Err(e) => {
            println!("tablet-shim: loading paguro.efi: {:?}", e.status());
            e.status()
        }
    }
}
