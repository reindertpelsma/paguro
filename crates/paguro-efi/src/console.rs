//! Where text goes: the diagnostic log and the text mirror of each screen.
//!
//! In text mode everything goes to ConOut, as before. Once the graphical
//! front end owns the display, nothing may write to ConOut — the firmware's
//! graphics console would draw it over the frame — so the log and the
//! mirror go to the serial port only (`EFI_SERIAL_IO_PROTOCOL`, opened
//! without taking it from the terminal driver). No serial port: dropped.

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, Ordering};

use uefi::boot::{self, SearchType};
use uefi::proto::console::serial::Serial;
use uefi::{Handle, Identify};

static GRAPHICAL: AtomicBool = AtomicBool::new(false);

/// From now on, text goes to the serial port only.
pub fn set_graphical(on: bool) {
    GRAPHICAL.store(on, Ordering::Relaxed);
}

fn serial_handle() -> Option<Handle> {
    let hs = boot::locate_handle_buffer(SearchType::ByProtocol(&Serial::GUID)).ok()?;
    hs.first().copied()
}

/// Text to the console: ConOut in text mode, the serial port otherwise.
pub struct Out;

impl Write for Out {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if !GRAPHICAL.load(Ordering::Relaxed) {
            return uefi::system::with_stdout(|o| o.write_str(s));
        }
        let Some(h) = serial_handle() else {
            return Ok(());
        };
        let Ok(mut port) = crate::platform::open_get::<Serial>(h) else {
            return Ok(());
        };
        // Terminals want CRLF; the log uses LF.
        let mut rest = s.as_bytes();
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
        Ok(())
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
