//! The displays (INTERFACES.md §13.2a "Several displays"): every GOP
//! device, each at its own preferred mode — never one spanning two panels
//! (`paguro_ui::display::choose_mode`, host-tested) — and one frame per
//! distinct resolution, blitted to every device of that resolution. The
//! pointer's cursor is composited at blit time onto the first display only
//! (`paguro_ui::pointer::composite`).

use core::ptr::NonNull;

use log::info;
use paguro_ui::canvas::Rect;
use paguro_ui::display::{ModeChoice, choose_mode};
use paguro_ui::pointer::{Cursor, composite};
use uefi::boot::{self, AllocateType, MemoryType, SearchType};
use uefi::proto::console::gop::{BltOp, BltPixel, BltRegion, EdidDiscovered, GraphicsOutput};
use uefi::proto::device_path::DevicePath;
use uefi::proto::unsafe_protocol;
use uefi::{Handle, Identify};

use crate::console;
use crate::platform::open_get;

pub const MAX_DEVICES: usize = 8;
/// The cursor's scratch buffer: the largest cursor image, BGRA.
const SCRATCH: usize = 128 * 128 * 4;

/// `EFI_EDID_ACTIVE_PROTOCOL` (UEFI 2.10 §12.9): the EDID the driver uses,
/// overrides applied. Same layout as the discovered one.
#[repr(C)]
struct EdidActiveRaw {
    size_of_edid: u32,
    edid: *const u8,
}

#[repr(transparent)]
#[unsafe_protocol("bd8c1056-9f36-44ec-92a8-a6337f817986")]
struct EdidActive(EdidActiveRaw);

impl EdidActive {
    fn edid(&self) -> Option<&[u8]> {
        if self.0.edid.is_null() {
            return None;
        }
        // SAFETY: the firmware provides `size_of_edid` readable bytes at
        // `edid` for the protocol's lifetime (UEFI 2.10 §12.9); the slice
        // borrows `self`.
        Some(unsafe { core::slice::from_raw_parts(self.0.edid, self.0.size_of_edid as usize) })
    }
}

/// The display's preferred resolution from its EDID: the active one, else
/// the discovered one (`paguro_core::edid`, bounded and fuzzed).
fn edid_preferred(h: Handle) -> Option<(u32, u32)> {
    let active = open_get::<EdidActive>(h)
        .ok()
        .and_then(|e| e.edid().and_then(|b| paguro_core::edid::preferred(b).ok()));
    active.or_else(|| {
        open_get::<EdidDiscovered>(h)
            .ok()
            .and_then(|e| e.edid().and_then(|b| paguro_core::edid::preferred(b).ok()))
    })
}

#[derive(Clone, Copy)]
struct Device {
    handle: Handle,
    w: u32,
    h: u32,
    mode: u32,
    frame: usize,
    covered: bool,
}

#[derive(Clone, Copy)]
struct Frame {
    w: u32,
    h: u32,
    px: NonNull<u8>,
    len: usize,
}

pub struct Displays {
    devices: [Option<Device>; MAX_DEVICES],
    frames: [Option<Frame>; MAX_DEVICES],
    n_frames: usize,
    scratch: NonNull<u8>,
    /// Text mode: only the displays ConOut does not cover are ours.
    text: bool,
}

/// The GOP handles of physical devices: those with a device path (the
/// console splitter's virtual GOP has none and would double every blit),
/// one per frame buffer. Falls back to any GOP when there is none.
fn gop_handles(out: &mut [Option<Handle>; MAX_DEVICES]) -> usize {
    let Ok(hs) = boot::locate_handle_buffer(SearchType::ByProtocol(&GraphicsOutput::GUID)) else {
        return 0;
    };
    let mut bases = [0u64; MAX_DEVICES];
    let mut n = 0;
    for h in hs.iter() {
        if open_get::<DevicePath>(*h).is_err() {
            continue;
        }
        let Ok(mut gop) = open_get::<GraphicsOutput>(*h) else {
            continue;
        };
        let base = gop.frame_buffer().as_mut_ptr() as u64;
        if base != 0 && bases.iter().take(n).any(|b| *b == base) {
            continue;
        }
        if let (Some(slot), Some(b)) = (out.get_mut(n), bases.get_mut(n)) {
            *slot = Some(*h);
            *b = base;
            n += 1;
        }
    }
    if n == 0 {
        if let (Some(h), Some(slot)) = (hs.first(), out.first_mut()) {
            *slot = Some(*h);
            n = 1;
        }
    }
    n
}

impl Displays {
    /// Open every display, choosing each one's mode. `None`: no usable
    /// display (the text console then).
    pub fn new() -> Option<Displays> {
        let mut handles = [None; MAX_DEVICES];
        let n = gop_handles(&mut handles);
        let scratch = boot::allocate_pages(
            AllocateType::AnyPages,
            MemoryType::LOADER_DATA,
            SCRATCH.div_ceil(4096),
        )
        .ok()?;
        let mut d = Displays {
            devices: [None; MAX_DEVICES],
            frames: [None; MAX_DEVICES],
            n_frames: 0,
            scratch,
            text: false,
        };
        let mut k = 0;
        for (i, h) in handles.iter().take(n).flatten().enumerate() {
            let Some(dev) = d.open(*h, i) else {
                continue;
            };
            if let Some(slot) = d.devices.get_mut(k) {
                *slot = Some(dev);
                k += 1;
            }
        }
        (k > 0).then_some(d)
    }

    /// Choose and set one device's mode; give it a frame.
    fn open(&mut self, handle: Handle, index: usize) -> Option<Device> {
        let mut gop = open_get::<GraphicsOutput>(handle).ok()?;
        let cur = gop.current_mode_info().resolution();
        let current = (u32::try_from(cur.0).ok()?, u32::try_from(cur.1).ok()?);
        let preferred = edid_preferred(handle);
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
            ModeChoice::Text => {
                info!(
                    "paguro: display {index}: no usable mode (at {}x{}, display prefers {preferred:?}), left dark",
                    current.0, current.1
                );
                return None;
            }
            ModeChoice::Set(n) => {
                let mode = gop.modes().nth(n as usize)?;
                gop.set_mode(&mode).ok()?;
            }
        }
        let (w, h) = gop.current_mode_info().resolution();
        let (w, h) = (u32::try_from(w).ok()?, u32::try_from(h).ok()?);
        if !paguro_ui::supported(w, h) {
            return None;
        }
        let mode = gop.current_mode_info();
        let mode_n = gop
            .modes()
            .position(|m| m.info().resolution() == mode.resolution())
            .and_then(|i| u32::try_from(i).ok())
            .unwrap_or(0);
        drop(gop);
        let frame = self.frame_for(w, h)?;
        let covered = console::in_conout(handle);
        info!(
            "paguro: graphics {w}x{h} on display {index} (was {}x{}, display prefers {preferred:?}{})",
            current.0,
            current.1,
            if covered { ", firmware console" } else { "" }
        );
        Some(Device {
            handle,
            w,
            h,
            mode: mode_n,
            frame,
            covered,
        })
    }

    /// The frame for `w`×`h`, allocated on first use.
    fn frame_for(&mut self, w: u32, h: u32) -> Option<usize> {
        if let Some(i) = self
            .frames
            .iter()
            .take(self.n_frames)
            .position(|f| f.is_some_and(|f| (f.w, f.h) == (w, h)))
        {
            return Some(i);
        }
        let len = (w as usize).checked_mul(h as usize)?.checked_mul(4)?;
        let px = boot::allocate_pages(
            AllocateType::AnyPages,
            MemoryType::LOADER_DATA,
            len.div_ceil(4096),
        )
        .ok()?;
        let i = self.n_frames;
        *self.frames.get_mut(i)? = Some(Frame { w, h, px, len });
        self.n_frames += 1;
        Some(i)
    }

    pub fn frames(&self) -> usize {
        self.n_frames
    }

    pub fn size(&self, i: usize) -> (u32, u32) {
        self.frames
            .get(i)
            .copied()
            .flatten()
            .map_or((0, 0), |f| (f.w, f.h))
    }

    pub fn frame(&mut self, i: usize) -> &mut [u8] {
        match self.frames.get(i).copied().flatten() {
            // SAFETY: `px` is a LOADER_DATA allocation of `len` bytes owned
            // by these displays for the loader's lifetime, only borrowed
            // through `&mut self`.
            Some(f) => unsafe { core::slice::from_raw_parts_mut(f.px.as_ptr(), f.len) },
            None => &mut [],
        }
    }

    pub fn covered(&self, i: usize) -> bool {
        self.devices
            .iter()
            .flatten()
            .filter(|d| d.frame == i)
            .all(|d| d.covered)
    }

    /// Text mode (`true`): blits reach only displays ConOut does not
    /// cover. Back to graphics: every display gets its mode back, in case
    /// the firmware console changed it.
    pub fn set_text(&mut self, text: bool) {
        self.text = text;
        if text {
            return;
        }
        for d in self.devices.iter().flatten() {
            let Ok(mut gop) = open_get::<GraphicsOutput>(d.handle) else {
                continue;
            };
            let (w, h) = gop.current_mode_info().resolution();
            if (w, h) != (d.w as usize, d.h as usize) {
                if let Some(m) = gop.modes().nth(d.mode as usize) {
                    let _ = gop.set_mode(&m);
                }
            }
        }
    }

    /// Blit `r` of frame `i`, with the cursor on the first display.
    pub fn present(&mut self, i: usize, r: Rect, cursor: Option<&Cursor>) {
        let Some(f) = self.frames.get(i).copied().flatten() else {
            return;
        };
        let r = r.intersect(&Rect::new(0, 0, f.w as i32, f.h as i32));
        if r.is_empty() {
            return;
        }
        // SAFETY: BltPixel is `repr(C)` of four `u8` (blue, green, red,
        // reserved) with alignment 1 — the frame's byte layout — and the
        // frame holds exactly w×h of them.
        let px: &[BltPixel] = unsafe {
            core::slice::from_raw_parts(f.px.as_ptr().cast::<BltPixel>(), (f.w * f.h) as usize)
        };
        let first = self.devices.iter().flatten().next().map(|d| d.handle);
        for d in self.devices.iter().flatten().filter(|d| d.frame == i) {
            if self.text && d.covered {
                continue;
            }
            let Ok(mut gop) = open_get::<GraphicsOutput>(d.handle) else {
                continue;
            };
            let _ = gop.blt(BltOp::BufferToVideo {
                buffer: px,
                src: BltRegion::SubRectangle {
                    coords: (r.x as usize, r.y as usize),
                    px_stride: f.w as usize,
                },
                dest: (r.x as usize, r.y as usize),
                dims: (r.w as usize, r.h as usize),
            });
            let Some(c) = cursor.filter(|_| Some(d.handle) == first) else {
                continue;
            };
            let cr = c.rect().intersect(&r);
            if cr.is_empty() || (cr.w * cr.h * 4) as usize > SCRATCH {
                continue;
            }
            // SAFETY: the scratch buffer is SCRATCH bytes, exclusively ours.
            let scratch =
                unsafe { core::slice::from_raw_parts_mut(self.scratch.as_ptr(), SCRATCH) };
            // SAFETY: `frame` is `len` bytes owned by these displays.
            let frame = unsafe { core::slice::from_raw_parts(f.px.as_ptr(), f.len) };
            let done = composite(frame, f.w, f.h, cr, Some(c), scratch);
            if done.is_empty() {
                continue;
            }
            // SAFETY: as above; `done.w × done.h` pixels were written.
            let spx: &[BltPixel] = unsafe {
                core::slice::from_raw_parts(
                    self.scratch.as_ptr().cast::<BltPixel>(),
                    (done.w * done.h) as usize,
                )
            };
            let _ = gop.blt(BltOp::BufferToVideo {
                buffer: spx,
                src: BltRegion::Full,
                dest: (done.x as usize, done.y as usize),
                dims: (done.w as usize, done.h as usize),
            });
        }
    }
}
