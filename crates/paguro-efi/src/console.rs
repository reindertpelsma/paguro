//! Text consoles: the diagnostic log, the firmware text console (ConOut)
//! as a text-UI sink, and the serial consoles the text UI is mirrored to
//! (INTERFACES.md §13.2a).
//!
//! - While graphics are shown, nothing may write to ConOut: its graphics
//!   console would draw over the frame. The log then goes to the serial
//!   port(s) through `EFI_SERIAL_IO_PROTOCOL`.
//! - In `auto` mode with graphics, every serial console found in ConOut
//!   (a terminal whose device path has a UART node) is **owned**: opened
//!   exclusively, which disconnects the firmware's terminal driver from
//!   it, so the loader alone reads its bytes (VT100 keys) and writes the
//!   text UI to it. [`Serials::release`] gives the ports back (and
//!   reconnects the terminal driver) before anything else runs.
//! - When a port cannot be owned, the text UI is still written to it
//!   directly, and its keys still arrive through ConIn.

use core::fmt::{self, Write};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use paguro_ui::driver::TextSink;
use paguro_ui::textui::{self, COLS, Grid, ROWS, Tone};
use uefi::boot::{self, AllocateType, MemoryType, ScopedProtocol, SearchType};
use uefi::proto::console::serial::{ControlBits, Serial};
use uefi::proto::console::text::{Color, Output};
use uefi::proto::device_path::{DevicePath, DeviceSubType, DeviceType};
use uefi::{CStr16, Handle, Identify};

use crate::platform::open_get;

/// Where the log goes.
const TO_CONOUT: u8 = 0;
/// The first serial port, shared with the firmware's terminal driver.
const TO_SERIAL: u8 = 1;
/// The ports the loader owns.
const TO_OWNED: u8 = 2;

static LOG_TO: AtomicU8 = AtomicU8::new(TO_CONOUT);

/// At most this many serial consoles are mirrored.
pub const MAX_SERIALS: usize = 4;

/// The owned ports' handles, for the log (opened with GetProtocol, which an
/// exclusive open by this image does not prevent).
static OWNED: [AtomicUsize; MAX_SERIALS] = [
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
];

/// From now on the log goes to ConOut (`false`) or the serial port(s).
pub fn set_graphical(on: bool) {
    let to = if !on {
        TO_CONOUT
    } else if OWNED.iter().any(|h| h.load(Ordering::Relaxed) != 0) {
        TO_OWNED
    } else {
        TO_SERIAL
    };
    LOG_TO.store(to, Ordering::Relaxed);
}

fn first_serial() -> Option<Handle> {
    let hs = boot::locate_handle_buffer(SearchType::ByProtocol(&Serial::GUID)).ok()?;
    hs.first().copied()
}

fn handle_of(raw: usize) -> Option<Handle> {
    // SAFETY: only ever stored from `Handle::as_ptr` of a live handle; a
    // serial handle stays valid while boot services run.
    unsafe { Handle::from_ptr(raw as *mut core::ffi::c_void) }
}

/// Write `bytes` to a serial port, LF as CRLF when `crlf`.
fn put(h: Handle, bytes: &[u8], crlf: bool) {
    let Ok(mut port) = open_get::<Serial>(h) else {
        return;
    };
    if !crlf {
        let _ = port.write(bytes);
        return;
    }
    let mut rest = bytes;
    while !rest.is_empty() {
        let (line, nl) = match rest.iter().position(|&b| b == b'\n') {
            Some(i) => (rest.get(..i).unwrap_or(&[]), true),
            None => (rest, false),
        };
        let _ = port.write(line);
        if nl {
            let _ = port.write(b"\r\n");
        }
        rest = rest.get(line.len() + usize::from(nl)..).unwrap_or(&[]);
    }
}

/// The log's text output.
pub struct Out;

impl Write for Out {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        match LOG_TO.load(Ordering::Relaxed) {
            TO_CONOUT => uefi::system::with_stdout(|o| o.write_str(s)),
            TO_OWNED => {
                for h in OWNED
                    .iter()
                    .filter_map(|a| handle_of(a.load(Ordering::Relaxed)))
                {
                    put(h, s.as_bytes(), true);
                }
                Ok(())
            }
            _ => {
                if let Some(h) = first_serial() {
                    put(h, s.as_bytes(), true);
                }
                Ok(())
            }
        }
    }
}

/// The `log` backend: one line per record.
struct Logger;

impl log::Log for Logger {
    fn enabled(&self, m: &log::Metadata<'_>) -> bool {
        m.level() <= log::Level::Info
    }
    fn log(&self, r: &log::Record<'_>) {
        if self.enabled(r.metadata()) {
            let _ = writeln!(Out, "{}", r.args());
        }
    }
    fn flush(&self) {}
}

static LOGGER: Logger = Logger;

pub fn init_logger() {
    if log::set_logger(&LOGGER).is_ok() {
        log::set_max_level(log::LevelFilter::Info);
    }
}

// ---------------------------------------------------------------------------
// Which handles ConOut covers

/// EDK2's tag for a handle in ConOut (`gEfiConsoleOutDeviceGuid`, set by
/// ConPlatformDxe from the `ConOut` variable).
const CONOUT_DEVICE: uefi::Guid = uefi::guid!("d3b36f2c-d551-11d4-9a46-0090273fc14d");

fn has(h: Handle, g: &uefi::Guid) -> bool {
    boot::protocols_per_handle(h).is_ok_and(|ps| ps.contains(&g))
}

fn any_tagged() -> bool {
    boot::locate_handle_buffer(SearchType::ByProtocol(&CONOUT_DEVICE))
        .is_ok_and(|hs| !hs.is_empty())
}

/// Whether the firmware text console draws on `h` (a GOP or terminal
/// handle): it carries a text output, and — where the firmware tags
/// console devices — the ConOut tag.
pub fn in_conout(h: Handle) -> bool {
    has(h, &Output::GUID) && (has(h, &CONOUT_DEVICE) || !any_tagged())
}

fn has_uart(dp: &DevicePath) -> bool {
    dp.node_iter().any(|n| {
        n.device_type() == DeviceType::MESSAGING && n.sub_type() == DeviceSubType::MESSAGING_UART
    })
}

// ---------------------------------------------------------------------------
// Serial consoles

pub struct Port {
    handle: Handle,
    /// The terminal's device path below the serial device (its terminal
    /// type): the terminal driver is reconnected with it, so the console it
    /// creates matches the `ConIn`/`ConOut` variables again.
    rest: [u8; 64],
    rest_len: usize,
    /// Held while the port is owned.
    owned: Option<ScopedProtocol<Serial>>,
    decoder: paguro_boot::vt100::Decoder,
    /// Polls since the last byte (a lone Esc waits for a quiet line).
    quiet: u32,
}

/// The serial consoles in ConOut.
pub struct Serials {
    ports: [Option<Port>; MAX_SERIALS],
    /// What the ports show now (for redrawing only what changed).
    shown: Option<&'static mut Grid>,
}

impl Serials {
    /// Find the serial devices behind the terminals in ConOut.
    pub fn find() -> Serials {
        let mut s = Serials {
            ports: [const { None }; MAX_SERIALS],
            shown: alloc_grid(),
        };
        let Ok(terms) = boot::locate_handle_buffer(SearchType::ByProtocol(&Output::GUID)) else {
            return s;
        };
        let mut n = 0;
        for t in terms.iter() {
            let Ok(dp) = open_get::<DevicePath>(*t) else {
                continue;
            };
            if !has_uart(&dp) || !in_conout(*t) {
                continue;
            }
            let mut rest: &DevicePath = &dp;
            let Ok(h) = boot::locate_device_path::<Serial>(&mut rest) else {
                continue;
            };
            if s.ports.iter().flatten().any(|p| p.handle == h) {
                continue;
            }
            let mut saved = [0u8; 64];
            let bytes = rest.as_bytes();
            let rest_len = match saved.get_mut(..bytes.len()) {
                Some(d) => {
                    d.copy_from_slice(bytes);
                    bytes.len()
                }
                None => 0,
            };
            if let Some(slot) = s.ports.get_mut(n) {
                *slot = Some(Port {
                    handle: h,
                    rest: saved,
                    rest_len,
                    owned: None,
                    decoder: paguro_boot::vt100::Decoder::new(),
                    quiet: 0,
                });
                n += 1;
            }
        }
        s
    }

    pub fn count(&self) -> usize {
        self.ports.iter().flatten().count()
    }

    /// How many ports the loader owns.
    pub fn owned(&self) -> usize {
        self.ports
            .iter()
            .flatten()
            .filter(|p| p.owned.is_some())
            .count()
    }

    /// Take the ports from the firmware's terminal driver. Those that
    /// cannot be taken stay shared (written to, read through ConIn).
    pub fn own(&mut self) {
        for (i, p) in self.ports.iter_mut().enumerate() {
            let Some(p) = p else { continue };
            if p.owned.is_none() {
                p.owned = boot::open_protocol_exclusive::<Serial>(p.handle).ok();
            }
            if let Some(slot) = OWNED.get(i) {
                let raw = if p.owned.is_some() {
                    p.handle.as_ptr() as usize
                } else {
                    0
                };
                slot.store(raw, Ordering::Relaxed);
            }
        }
    }

    /// Give the ports back and let the firmware's terminal driver bind to
    /// them again.
    pub fn release(&mut self) {
        if LOG_TO.load(Ordering::Relaxed) == TO_OWNED {
            LOG_TO.store(TO_SERIAL, Ordering::Relaxed);
        }
        for (i, p) in self.ports.iter_mut().enumerate() {
            let Some(p) = p else { continue };
            if let Some(slot) = OWNED.get(i) {
                slot.store(0, Ordering::Relaxed);
            }
            if p.owned.take().is_some() {
                // Twice: the terminal's new console handle is tagged as a
                // console device during the first pass, and the console
                // splitter binds to it on the second (as BDS's repeated
                // connect-all does).
                let rest = p
                    .rest
                    .get(..p.rest_len)
                    .and_then(|b| <&DevicePath>::try_from(b).ok());
                let _ = boot::connect_controller(p.handle, &[], rest, true);
                let r = boot::connect_controller(p.handle, &[], rest, true);
                log::info!(
                    "paguro: serial console given back ({:?})",
                    r.map_err(|e| e.status())
                );
            }
        }
        if let Some(g) = self.shown.as_mut() {
            g.clear();
        }
    }

    /// Keys from the owned ports (`idle`: a poll found nothing new; after
    /// a few, a pending lone Esc is the Esc key).
    pub fn poll(&mut self, mut key: impl FnMut(paguro_boot::ui::Key)) {
        for p in self.ports.iter_mut().flatten() {
            let Some(port) = p.owned.as_mut() else {
                continue;
            };
            let mut got = false;
            for _ in 0..64 {
                let empty = port
                    .get_control_bits()
                    .map_or(true, |b| b.contains(ControlBits::INPUT_BUFFER_EMPTY));
                if empty {
                    break;
                }
                let mut b = [0u8; 1];
                if port.read(&mut b).is_err() {
                    break;
                }
                got = true;
                if let Some(k) = p.decoder.feed(b[0]) {
                    key(k);
                }
            }
            if got {
                p.quiet = 0;
            } else if p.decoder.pending() {
                p.quiet += 1;
                // ~50 ms at the 10 ms poll.
                if p.quiet >= 5 {
                    p.quiet = 0;
                    if let Some(k) = p.decoder.idle() {
                        key(k);
                    }
                }
            }
        }
    }

    fn write_all(&mut self, bytes: &[u8]) {
        for p in self.ports.iter_mut().flatten() {
            match p.owned.as_mut() {
                Some(port) => {
                    let _ = port.write(bytes);
                }
                None => put(p.handle, bytes, false),
            }
        }
    }
}

/// A small write buffer in front of the ports.
struct Buffered<'s> {
    s: &'s mut Serials,
    buf: [u8; 512],
    n: usize,
}

impl Buffered<'_> {
    fn flush(&mut self) {
        let n = self.n;
        let data = self.buf;
        self.s.write_all(data.get(..n).unwrap_or(&[]));
        self.n = 0;
    }
}

impl Write for Buffered<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            if self.n == self.buf.len() {
                self.flush();
            }
            if let Some(slot) = self.buf.get_mut(self.n) {
                *slot = b;
                self.n += 1;
            }
        }
        Ok(())
    }
}

impl TextSink for Serials {
    fn show(&mut self, grid: &Grid, full: bool) {
        let mut prev = self.shown.take();
        let before = if full { None } else { prev.as_deref() };
        let mut w = Buffered {
            s: self,
            buf: [0; 512],
            n: 0,
        };
        let _ = textui::write_vt100(before, grid, &mut w);
        w.flush();
        if let Some(p) = prev.as_mut() {
            p.clone_from(grid);
        }
        self.shown = prev;
    }
}

/// A grid in pages (the stack is the firmware's and small).
fn alloc_grid() -> Option<&'static mut Grid> {
    let size = core::mem::size_of::<Grid>();
    let p: NonNull<u8> = boot::allocate_pages(
        AllocateType::AnyPages,
        MemoryType::LOADER_DATA,
        size.div_ceil(4096),
    )
    .ok()?;
    let g = p.as_ptr().cast::<Grid>();
    // SAFETY: a fresh, page-aligned allocation large enough for a Grid,
    // initialised before the reference is formed and never freed.
    unsafe {
        g.write(Grid::new());
        Some(&mut *g)
    }
}

// ---------------------------------------------------------------------------
// ConOut

/// The firmware text console as a text-UI sink.
pub struct ConOut {
    shown: Option<&'static mut Grid>,
}

impl ConOut {
    pub fn new() -> ConOut {
        ConOut {
            shown: alloc_grid(),
        }
    }

    /// Forget what is shown (the next grid is drawn whole).
    pub fn reset(&mut self) {
        if let Some(g) = self.shown.as_mut() {
            g.clear();
        }
    }
}

fn efi_color(n: u8) -> Color {
    match n {
        0 => Color::Black,
        1 => Color::Blue,
        2 => Color::Green,
        3 => Color::Cyan,
        4 => Color::Red,
        5 => Color::Magenta,
        6 => Color::Brown,
        7 => Color::LightGray,
        8 => Color::DarkGray,
        9 => Color::LightBlue,
        10 => Color::LightGreen,
        11 => Color::LightCyan,
        12 => Color::LightRed,
        13 => Color::LightMagenta,
        14 => Color::Yellow,
        _ => Color::White,
    }
}

impl TextSink for ConOut {
    fn show(&mut self, grid: &Grid, full: bool) {
        let prev = self.shown.as_deref();
        uefi::system::with_stdout(|o| {
            let _ = o.enable_cursor(false);
            if full || prev.is_none() {
                let _ = o.set_color(Color::LightGray, Color::Black);
                let _ = o.clear();
            }
            let (cols, rows) = o
                .current_mode()
                .ok()
                .flatten()
                .map_or((80, 25), |m| (m.columns(), m.rows()));
            for r in 0..ROWS.min(rows) {
                let row = grid.row(r);
                if !full && prev.is_some_and(|p| p.row(r) == row) {
                    continue;
                }
                let _ = o.set_cursor_position(0, r);
                // Runs of one tone, as UCS-2.
                let mut c = 0usize;
                let width = COLS.min(cols.saturating_sub(1));
                while c < width {
                    let tone = row.get(c).map_or(Tone::Normal, |x| x.tone);
                    let mut buf = [0u16; COLS + 1];
                    let mut n = 0usize;
                    while c < width && row.get(c).is_some_and(|x| x.tone == tone) {
                        let ch = row.get(c).map_or(' ', |x| x.ch);
                        let u = u16::try_from(u32::from(ch)).unwrap_or(u16::from(b'?'));
                        if let Some(slot) = buf.get_mut(n) {
                            *slot = if (0xd800..0xe000).contains(&u) {
                                u16::from(b'?')
                            } else {
                                u
                            };
                            n += 1;
                        }
                        c += 1;
                    }
                    let (fg, bg) = textui::conout_attr(tone);
                    // The protocol takes backgrounds 0..=7 only (the uefi
                    // crate asserts it).
                    let _ = o.set_color(efi_color(fg), efi_color(bg.min(7)));
                    if let Ok(s) = CStr16::from_u16_with_nul(buf.get(..=n).unwrap_or(&[0])) {
                        let _ = o.output_string(s);
                    }
                }
            }
            let _ = o.set_color(Color::LightGray, Color::Black);
            if let Some((r, c)) = grid.cursor {
                let _ = o.set_cursor_position(usize::from(c), usize::from(r));
                let _ = o.enable_cursor(true);
            }
        });
        if let Some(p) = self.shown.as_mut() {
            p.clone_from(grid);
        }
    }
}
