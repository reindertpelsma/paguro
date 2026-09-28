//! Which kind of Windows program a `.exe` is (DESIGN.md §5d "Running the
//! other system's programs"): console programs run over the user's SSH
//! channel, GUI programs through the in-session agent, and the PE header's
//! `Subsystem` field is what tells them apart. Nothing else is read.
//!
//! Untrusted input (any file `binfmt_misc` hands over for its `MZ`): every
//! offset is checked, nothing is allocated. Fuzzed by
//! `fuzz/fuzz_targets/pe.rs`.

use crate::bytes::{Reader, Short};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Short,
    /// No `MZ`, or `e_lfanew` does not lead to `PE\0\0`.
    NotPe,
    /// An optional-header magic other than PE32 (0x10b) or PE32+ (0x20b).
    BadOptionalHeader,
}

impl From<Short> for Error {
    fn from(_: Short) -> Self {
        Error::Short
    }
}

/// What the handler needs to know.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `IMAGE_SUBSYSTEM_WINDOWS_CUI` (3): stdio, an exit status, Ctrl-C.
    Console,
    /// `IMAGE_SUBSYSTEM_WINDOWS_GUI` (2): windows on the user's desktop.
    Gui,
    /// Anything else (native, EFI, POSIX, a DLL-only image): not started.
    Other(u16),
}

/// `e_lfanew` beyond this is not a program any linker makes; refusing it
/// keeps a hostile file from sending the reader far into a large input.
pub const MAX_LFANEW: u32 = 0x1000_0000;

pub const IMAGE_FILE_DLL: u16 = 0x2000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub machine: u16,
    pub kind: Kind,
    /// `IMAGE_FILE_DLL`: a library, not a program.
    pub dll: bool,
}

pub fn parse(data: &[u8]) -> Result<Info, Error> {
    if data.get(..2) != Some(b"MZ") {
        return Err(Error::NotPe);
    }
    let lfanew = Reader::new(data.get(0x3C..).ok_or(Error::Short)?).u32_le()?;
    if lfanew > MAX_LFANEW {
        return Err(Error::NotPe);
    }
    let mut r = Reader::new(data.get(lfanew as usize..).ok_or(Error::Short)?);
    if r.array::<4>()? != b"PE\0\0" {
        return Err(Error::NotPe);
    }
    let machine = r.u16_le()?;
    r.take(2 + 4 + 4 + 4)?; // sections, timestamp, symbol table, symbols
    let optional_size = r.u16_le()?;
    let characteristics = r.u16_le()?;
    let opt = r.take(usize::from(optional_size))?;
    let mut o = Reader::new(opt);
    match o.u16_le()? {
        0x10b | 0x20b => {}
        _ => return Err(Error::BadOptionalHeader),
    }
    // Subsystem is at the same offset (68) in PE32 and PE32+.
    let subsystem = Reader::new(opt.get(68..).ok_or(Error::Short)?).u16_le()?;
    let kind = match subsystem {
        2 => Kind::Gui,
        3 => Kind::Console,
        s => Kind::Other(s),
    };
    Ok(Info {
        machine,
        kind,
        dll: characteristics & IMAGE_FILE_DLL != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec::Vec;

    fn image(magic: u16, subsystem: u16, characteristics: u16) -> Vec<u8> {
        let mut v = std::vec![0u8; 0x80];
        v[..2].copy_from_slice(b"MZ");
        v[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        v.extend_from_slice(b"PE\0\0");
        v.extend_from_slice(&0x8664u16.to_le_bytes());
        v.extend_from_slice(&[0; 14]); // sections, timestamp, symbols
        let opt_size: u16 = if magic == 0x20b { 240 } else { 224 };
        v.extend_from_slice(&opt_size.to_le_bytes());
        v.extend_from_slice(&characteristics.to_le_bytes());
        let mut opt = std::vec![0u8; usize::from(opt_size)];
        opt[..2].copy_from_slice(&magic.to_le_bytes());
        opt[68..70].copy_from_slice(&subsystem.to_le_bytes());
        v.extend(opt);
        v
    }

    #[test]
    fn console_gui_and_others() {
        let c = parse(&image(0x20b, 3, 0x22)).unwrap();
        assert_eq!(
            c,
            Info {
                machine: 0x8664,
                kind: Kind::Console,
                dll: false
            }
        );
        assert_eq!(parse(&image(0x10b, 2, 0x102)).unwrap().kind, Kind::Gui);
        assert_eq!(parse(&image(0x20b, 10, 0)).unwrap().kind, Kind::Other(10));
        assert!(parse(&image(0x20b, 2, 0x2022)).unwrap().dll);
    }

    #[test]
    fn refusals() {
        assert_eq!(parse(b"#!/bin/sh"), Err(Error::NotPe));
        assert_eq!(parse(b"MZ"), Err(Error::Short));
        let good = image(0x20b, 3, 0);
        for n in 0..good.len() {
            assert!(parse(&good[..n]).is_err(), "{n}");
        }
        let mut bad = good.clone();
        bad[0x80] = b'N';
        assert_eq!(parse(&bad), Err(Error::NotPe));
        let mut bad = good.clone();
        bad[0x3C..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(parse(&bad), Err(Error::NotPe));
        let mut bad = good.clone();
        let opt = 0x80 + 24;
        bad[opt..opt + 2].copy_from_slice(&0x107u16.to_le_bytes());
        assert_eq!(parse(&bad), Err(Error::BadOptionalHeader));
        // An optional header too small to hold Subsystem.
        let mut bad = good;
        bad[0x80 + 20..0x80 + 22].copy_from_slice(&8u16.to_le_bytes());
        assert_eq!(parse(&bad), Err(Error::Short));
    }
}
