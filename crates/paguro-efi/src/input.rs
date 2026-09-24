//! Input from every console at once (INTERFACES.md §13.2a, §13.2b): the
//! firmware keyboard (ConIn, with modifiers through
//! `SimpleTextInputEx`), the owned serial ports (VT100, decoded by
//! `paguro_boot::vt100`), and pointers (`EFI_SIMPLE_POINTER_PROTOCOL`,
//! `EFI_ABSOLUTE_POINTER_PROTOCOL`), any of which may be missing or fail —
//! then they are ignored.

use paguro_boot::keymap::Typed;
use paguro_boot::ui::Key;
use paguro_ui::driver::Event;
use paguro_ui::pointer::Report;
use uefi::Handle;
use uefi::boot::{self, EventType, SearchType, TimerTrigger, Tpl};
use uefi::proto::console::pointer::{AbsolutePointer, Pointer};
use uefi::proto::console::text::{Input as TextInput, InputEx, Key as UKey};
use uefi::proto::device_path::DevicePath;

use crate::console::Serials;
use crate::platform::{decode_key, open_get};

const MAX_POINTERS: usize = 4;
const QUEUE: usize = 16;

pub struct Inputs {
    conin: Option<Handle>,
    simple: [Option<(Handle, u64)>; MAX_POINTERS],
    absolute: [Option<Handle>; MAX_POINTERS],
    timer: Option<uefi::Event>,
    queue: [Option<Event>; QUEUE],
}

/// The console-in handle.
fn conin_handle() -> Option<Handle> {
    let st = uefi::table::system_table_raw()?;
    // SAFETY: the system table pointer stays valid while boot services run,
    // which is the loader's whole life; the field is read, not written.
    let h = unsafe { st.as_ref().stdin_handle };
    // SAFETY: a handle from the system table is a valid EFI_HANDLE or null.
    unsafe { Handle::from_ptr(h.cast()) }
}

/// Pointer handles: each device's (a device path marks a real one), else
/// the console splitter's on ConIn (every device it aggregates at once).
fn pointer_handles<P: uefi::proto::ProtocolPointer + ?Sized>(
    out: &mut [Option<Handle>; MAX_POINTERS],
) {
    if let Ok(hs) = boot::locate_handle_buffer(SearchType::ByProtocol(&P::GUID)) {
        for (slot, h) in out
            .iter_mut()
            .zip(hs.iter().filter(|h| open_get::<DevicePath>(**h).is_ok()))
        {
            *slot = Some(*h);
        }
    }
    if out.iter().all(Option::is_none) {
        if let Some(h) = conin_handle().filter(|h| open_get::<P>(*h).is_ok()) {
            if let Some(slot) = out.first_mut() {
                *slot = Some(h);
            }
        }
    }
}

impl Inputs {
    pub fn new() -> Inputs {
        let mut simple_h = [None; MAX_POINTERS];
        pointer_handles::<Pointer>(&mut simple_h);
        let mut absolute = [None; MAX_POINTERS];
        pointer_handles::<AbsolutePointer>(&mut absolute);
        let mut simple = [None; MAX_POINTERS];
        for (slot, h) in simple.iter_mut().zip(simple_h.iter().flatten()) {
            let res = open_get::<Pointer>(*h).map_or(0, |mut p| {
                let _ = p.reset(false);
                p.mode().resolution_x
            });
            *slot = Some((*h, res));
        }
        for h in absolute.iter().flatten() {
            if let Ok(mut p) = open_get::<AbsolutePointer>(*h) {
                let _ = p.reset(false);
            }
        }
        // SAFETY: a plain timer event with no notification function.
        let timer = unsafe { boot::create_event(EventType::TIMER, Tpl::CALLBACK, None, None) }.ok();
        if let Some(t) = &timer {
            // 10 ms: serial polling and the lone-Esc timeout.
            let _ = boot::set_timer(
                t,
                TimerTrigger::Periodic(core::time::Duration::from_millis(10)),
            );
        }
        Inputs {
            conin: conin_handle(),
            simple,
            absolute,
            timer,
            queue: [None; QUEUE],
        }
    }

    /// Pointer handles found: (simple, absolute, of which on ConIn).
    pub fn describe(&self) -> (usize, usize, bool) {
        let on_conin = self.conin.is_some_and(|c| {
            self.simple.iter().flatten().any(|(h, _)| *h == c)
                || self.absolute.iter().flatten().any(|h| *h == c)
        });
        (
            self.simple.iter().flatten().count(),
            self.absolute.iter().flatten().count(),
            on_conin,
        )
    }

    fn push(&mut self, e: Event) {
        if let Some(slot) = self.queue.iter_mut().find(|s| s.is_none()) {
            *slot = Some(e);
        }
    }

    fn pop(&mut self) -> Option<Event> {
        let e = self.queue.first_mut()?.take()?;
        self.queue.rotate_left(1);
        Some(e)
    }

    /// A key from ConIn, if one is waiting.
    fn conin(&mut self) -> Option<Event> {
        let h = self.conin?;
        if let Ok(mut ex) = open_get::<InputEx>(h) {
            let k = ex.read_key().ok().flatten()?;
            return key_event(
                k.key,
                k.key_state.key_shift_state.map(|s| s.bits()),
                k.key_state.key_toggle_state.map(|t| t.bits()),
            );
        }
        let mut i = open_get::<TextInput>(h).ok()?;
        let k = i.read_key().ok().flatten()?;
        key_event(k, None, None)
    }

    fn pointer(&mut self) -> Option<Event> {
        for (h, res) in self.simple.iter().flatten() {
            let Ok(mut p) = open_get::<Pointer>(*h) else {
                continue;
            };
            if let Ok(Some(s)) = p.read_state() {
                return Some(Event::Pointer(Report::Relative {
                    dx: s.relative_movement_x,
                    dy: s.relative_movement_y,
                    dz: s.relative_movement_z,
                    resolution: *res,
                    left: s.left_button.into(),
                }));
            }
        }
        for h in self.absolute.iter().flatten() {
            let Ok(mut p) = open_get::<AbsolutePointer>(*h) else {
                continue;
            };
            let m = p.mode();
            let (min, max) = (
                (m.absolute_min_x, m.absolute_min_y),
                (m.absolute_max_x, m.absolute_max_y),
            );
            if let Ok(Some(s)) = p.read_state() {
                return Some(Event::Pointer(Report::Absolute {
                    x: s.current_x,
                    y: s.current_y,
                    min,
                    max,
                    touch: s.active_buttons & 1 != 0,
                }));
            }
        }
        None
    }

    /// The next event from any console (blocks).
    pub fn next(&mut self, serials: &mut Serials) -> Event {
        loop {
            if let Some(e) = self.pop() {
                return e;
            }
            if let Some(e) = self.conin() {
                return e;
            }
            let mut got = [None; QUEUE];
            let mut n = 0;
            serials.poll(|k| {
                if let Some(slot) = got.get_mut(n) {
                    *slot = Some(Event::Key(k));
                    n += 1;
                }
            });
            for e in got.into_iter().flatten() {
                self.push(e);
            }
            if let Some(e) = self.pop() {
                return e;
            }
            if let Some(e) = self.pointer() {
                return e;
            }
            self.wait();
        }
    }

    /// Sleep until a key, a pointer or the next timer tick.
    fn wait(&mut self) {
        const N: usize = 2 + 2 * MAX_POINTERS;
        let Some(timer) = self.timer.as_ref() else {
            // No timer: poll again.
            return;
        };
        let mut evs: [Option<uefi::Event>; N] = [const { None }; N];
        let mut n = 0;
        let mut add = |e: Option<uefi::Event>| {
            if let (Some(e), Some(slot)) = (e, evs.get_mut(n)) {
                *slot = Some(e);
                n += 1;
            }
        };
        // SAFETY (every `unsafe_clone` here): the events stay owned by their
        // protocols or by `self` for the whole wait; the clones are dropped
        // without closing the events.
        add(Some(unsafe { timer.unsafe_clone() }));
        if let Some(h) = self.conin {
            let ev = open_get::<InputEx>(h)
                .ok()
                .and_then(|ex| ex.wait_for_key_event().ok())
                .or_else(|| {
                    open_get::<TextInput>(h)
                        .ok()
                        .and_then(|i| i.wait_for_key_event().ok())
                });
            add(ev);
        }
        for (h, _) in self.simple.iter().flatten() {
            add(open_get::<Pointer>(*h)
                .ok()
                .and_then(|p| p.wait_for_input_event().ok()));
        }
        for h in self.absolute.iter().flatten() {
            add(open_get::<AbsolutePointer>(*h)
                .ok()
                .and_then(|p| p.wait_for_input_event().ok()));
        }
        // Packed at the front; the tail (never waited on) repeats the timer.
        let arr: [uefi::Event; N] = core::array::from_fn(|i| {
            evs.get_mut(i)
                .and_then(Option::take)
                .unwrap_or_else(|| unsafe { timer.unsafe_clone() })
        });
        let _ = boot::wait_for_event(arr.get(..n).unwrap_or(&[]));
    }
}

/// An `EFI_INPUT_KEY` with its modifier state as an [`Event`].
/// `shift` and `toggle` are `EFI_KEY_STATE`'s KeyShiftState and
/// KeyToggleState when valid (UEFI 2.10 §12.2.3): RIGHT/LEFT_SHIFT
/// 0x01/0x02, RIGHT/LEFT_CONTROL 0x04/0x08, RIGHT/LEFT_ALT 0x10/0x20,
/// RIGHT/LEFT_LOGO 0x40/0x80; CAPS_LOCK_ACTIVE 0x04.
fn key_event(k: UKey, shift: Option<u32>, toggle: Option<u8>) -> Option<Event> {
    let decoded = decode_key(k)?;
    let Key::Char(c) = decoded else {
        return Some(Event::Key(decoded));
    };
    let bits = shift.unwrap_or(0);
    // Ctrl, left Alt, the logo keys: a chord, not text. Right Alt is AltGr.
    if bits & 0xec != 0 {
        return None;
    }
    Some(Event::Typed(Typed {
        ch: c,
        shift: shift.map(|s| s & 0x03 != 0),
        altgr: bits & 0x10 != 0,
        caps: toggle.map(|t| t & 0x04 != 0),
    }))
}
