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

static TABLET: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static ENDPOINT: AtomicU8 = AtomicU8::new(1);

static mut MODE: AbsolutePointerMode = AbsolutePointerMode {
    absolute_min_x: 0,
    absolute_min_y: 0,
    absolute_min_z: 0,
    absolute_max_x: 0x7fff,
    absolute_max_y: 0x7fff,
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
    let mut buf = [0u8; 8];
    match io.sync_interrupt_receive(ENDPOINT.load(Ordering::Relaxed), &mut buf, 2) {
        Ok(n) if n >= 5 && !state.is_null() => {
            let s = AbsolutePointerState {
                current_x: u64::from(u16::from_le_bytes([buf[1], buf[2]])),
                current_y: u64::from(u16::from_le_bytes([buf[3], buf[4]])),
                current_z: 0,
                active_buttons: u32::from(buf[0] & 1),
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
        if i.interface_class != 3 || i.interface_protocol == 1 {
            continue;
        }
        let ep = (0..i.num_endpoints)
            .filter_map(|e| io.endpoint_descriptor(e).ok())
            .find(|e| e.endpoint_address & 0x80 != 0 && e.attributes & 3 == 3)
            .map_or(1, |e| e.endpoint_address & 0x0f);
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
    let mut buf = [core::mem::MaybeUninit::uninit(); 512];
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
