//! The graphical front end's firmware half: a `GraphicsOutput` to blit the
//! frame to, a keyboard, and the serial mirror. Everything that decides what
//! the frame looks like is `paguro-ui`, tested on the host.

use core::ptr::NonNull;

use log::info;
use paguro_boot::platform::Screen;
use paguro_boot::ui::{self, Key};
use paguro_ui::display::{ModeChoice, choose_mode, edid_preferred};
use paguro_ui::driver::Display;
use uefi::Handle;
use uefi::boot::{self, AllocateType, MemoryType, ScopedProtocol};
use uefi::proto::console::gop::{BltOp, BltPixel, BltRegion, EdidDiscovered, GraphicsOutput};
use uefi::proto::console::text::InputEx;

use crate::console::{self, Out};
use crate::platform::{decode_key, open_get};

pub struct Gop {
    handle: Handle,
    width: u32,
    height: u32,
    frame: NonNull<u8>,
    frame_len: usize,
}

/// The GOP on the console-out handle (the one the firmware draws its own
/// console on), else the first one.
fn gop_handle() -> Option<Handle> {
    let st = uefi::table::system_table_raw()?;
    // SAFETY: the system table pointer stays valid while boot services run,
    // which is the loader's whole life; the field is read, not written.
    let conout = unsafe { st.as_ref().stdout_handle };
    // SAFETY: a handle from the system table is a valid EFI_HANDLE or null.
    let conout = unsafe { Handle::from_ptr(conout.cast()) };
    if let Some(h) = conout.filter(|h| open_get::<GraphicsOutput>(*h).is_ok()) {
        return Some(h);
    }
    boot::get_handle_for_protocol::<GraphicsOutput>().ok()
}

impl Gop {
    /// Open the display, choosing the mode per `paguro_ui::display`.
    /// `None`: no GOP, no usable mode, or no memory — use the text console.
    pub fn new() -> Option<Gop> {
        let handle = gop_handle()?;
        let mut gop = open_get::<GraphicsOutput>(handle).ok()?;
        let cur = gop.current_mode_info().resolution();
        let current = (u32::try_from(cur.0).ok()?, u32::try_from(cur.1).ok()?);
        let preferred = open_get::<EdidDiscovered>(handle)
            .ok()
            .and_then(|e| e.edid().and_then(edid_preferred));
        // Mode numbers are the iteration order (QueryMode 0..MaxMode).
        let mut numbered = [(u32::MAX, 0u32, 0u32); 64];
        for (i, (slot, m)) in numbered.iter_mut().zip(gop.modes()).enumerate() {
            let (w, h) = m.info().resolution();
            if let (Ok(w), Ok(h)) = (u32::try_from(w), u32::try_from(h)) {
                *slot = (i as u32, w, h);
            }
        }
        let list = numbered.iter().copied().filter(|m| m.0 != u32::MAX);
        match choose_mode(current, list, preferred) {
            ModeChoice::Keep => {}
            ModeChoice::Text => return None,
            ModeChoice::Set(n) => {
                let mode = gop.modes().nth(n as usize)?;
                gop.set_mode(&mode).ok()?;
            }
        }
        let (w, h) = gop.current_mode_info().resolution();
        let (width, height) = (u32::try_from(w).ok()?, u32::try_from(h).ok()?);
        if !paguro_ui::supported(width, height) {
            return None;
        }
        let frame_len = (width as usize)
            .checked_mul(height as usize)?
            .checked_mul(4)?;
        let frame = boot::allocate_pages(
            AllocateType::AnyPages,
            MemoryType::LOADER_DATA,
            frame_len.div_ceil(4096),
        )
        .ok()?;
        drop(gop);
        info!(
            "paguro: graphics {width}x{height} (was {}x{}, display prefers {preferred:?})",
            current.0, current.1
        );
        Some(Gop {
            handle,
            width,
            height,
            frame,
            frame_len,
        })
    }

    fn open(&self) -> Option<ScopedProtocol<GraphicsOutput>> {
        open_get::<GraphicsOutput>(self.handle).ok()
    }
}

/// The console-in handle, for `EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL`.
fn conin_handle() -> Option<Handle> {
    let st = uefi::table::system_table_raw()?;
    // SAFETY: as in `gop_handle`.
    let h = unsafe { st.as_ref().stdin_handle };
    // SAFETY: a handle from the system table is a valid EFI_HANDLE or null.
    unsafe { Handle::from_ptr(h.cast()) }
}

/// A key from `SimpleTextInputEx` when the console has it (modifiers: a
/// printable key with Ctrl, Alt or the logo key held is not text), else
/// from `SimpleTextInput`.
pub fn read_key() -> Key {
    let ex = conin_handle().and_then(|h| open_get::<InputEx>(h).ok());
    let Some(mut ex) = ex else {
        return crate::platform::read_key();
    };
    loop {
        if let Ok(ev) = ex.wait_for_key_event() {
            let _ = boot::wait_for_event(&[ev]);
        }
        let Ok(Some(k)) = ex.read_key() else {
            continue;
        };
        // EFI_KEY_STATE.KeyShiftState: RIGHT/LEFT_CONTROL 0x04/0x08,
        // RIGHT/LEFT_ALT 0x10/0x20, RIGHT/LEFT_LOGO 0x40/0x80 (UEFI 2.10
        // §12.2.3). Shift (0x01/0x02) is part of typing text.
        let chord = k
            .key_state
            .key_shift_state
            .is_some_and(|s| s.bits() & 0xfc != 0);
        match decode_key(k.key) {
            Some(Key::Char(_)) if chord => {}
            Some(key) => return key,
            None => {}
        }
    }
}

impl Display for Gop {
    fn size(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    fn frame(&mut self) -> &mut [u8] {
        // SAFETY: `frame` is a LOADER_DATA allocation of at least
        // `frame_len` bytes, owned by this Gop for the loader's lifetime and
        // only ever borrowed through `&mut self`.
        unsafe { core::slice::from_raw_parts_mut(self.frame.as_ptr(), self.frame_len) }
    }

    fn present(&mut self) {
        let (w, h) = (self.width as usize, self.height as usize);
        // SAFETY: BltPixel is `repr(C)` of four `u8` (blue, green, red,
        // reserved) with alignment 1 — the canvas's byte layout — and the
        // frame holds exactly w×h of them.
        let px: &[BltPixel] =
            unsafe { core::slice::from_raw_parts(self.frame.as_ptr().cast::<BltPixel>(), w * h) };
        if let Some(mut gop) = self.open() {
            let _ = gop.blt(BltOp::BufferToVideo {
                buffer: px,
                src: BltRegion::Full,
                dest: (0, 0),
                dims: (w, h),
            });
        }
    }

    fn read_key(&mut self) -> Key {
        read_key()
    }

    fn mirror(&mut self, screen: &Screen) {
        // The serial log carries the same text the console fallback shows
        // (QEMU tests read it); never a field's contents.
        let _ = ui::render(screen, &mut Out);
        let _ = core::fmt::Write::write_str(&mut Out, "\n");
    }
}

/// Switch the log to serial-only while the graphical front end is used.
pub fn take_display() -> Option<Gop> {
    let g = Gop::new()?;
    console::set_graphical(true);
    Some(g)
}
