//! Windows shortcuts (`.lnk`, [MS-SHLLINK]) — the name and the icon only
//! (DESIGN.md §5d "Shortcuts: `.lnk` on Linux, `.desktop` on Windows").
//!
//! Linux shows a `.lnk` natively and opens it by forwarding the file to the
//! VM, where Windows' own parser resolves it. So this reader extracts only
//! what a file manager draws: the description, the target's path (whose
//! icon is used when no icon is named), the icon location and index, and
//! the environment-variable forms of both (`%SystemRoot%\…`). ID lists are
//! skipped by their length, never interpreted.
//!
//! A `.lnk` is untrusted input from any folder Linux can see. Every length
//! and offset is checked against the bytes actually present; strings are
//! returned as borrowed slices ([`Str`]), nothing is allocated; the
//! extra-data walk is bounded. Fuzzed by `fuzz/fuzz_targets/win_formats.rs`.

use crate::bytes::{Reader, Short};

/// `ShellLinkHeader.HeaderSize`.
pub const HEADER_SIZE: u32 = 0x4C;
/// `LinkCLSID`, 00021401-0000-0000-C000-000000000046, as stored.
pub const LINK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

// LinkFlags (MS-SHLLINK 2.1.1).
pub const HAS_LINK_TARGET_ID_LIST: u32 = 1 << 0;
pub const HAS_LINK_INFO: u32 = 1 << 1;
pub const HAS_NAME: u32 = 1 << 2;
pub const HAS_RELATIVE_PATH: u32 = 1 << 3;
pub const HAS_WORKING_DIR: u32 = 1 << 4;
pub const HAS_ARGUMENTS: u32 = 1 << 5;
pub const HAS_ICON_LOCATION: u32 = 1 << 6;
pub const IS_UNICODE: u32 = 1 << 7;

/// ExtraData signatures (MS-SHLLINK 2.5).
pub const ENVIRONMENT_VARIABLE_BLOCK: u32 = 0xA000_0001;
pub const ICON_ENVIRONMENT_BLOCK: u32 = 0xA000_0007;
/// Both blocks: size, signature, `TargetAnsi[260]`, `TargetUnicode[520]`.
const ENV_BLOCK_SIZE: usize = 0x314;

/// At most this many extra-data blocks are looked at (real shortcuts carry
/// a handful).
pub const MAX_EXTRA_BLOCKS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Short,
    /// Not a shell link: wrong header size or CLSID.
    NotALink,
    /// A LinkInfo offset or size that points outside it.
    BadLinkInfo,
}

impl From<Short> for Error {
    fn from(_: Short) -> Self {
        Error::Short
    }
}

/// A string as stored: UTF-16LE, or bytes in the system's ANSI code page
/// (unknown here; shown as Latin-1, which is right for ASCII).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Str<'a> {
    Utf16(&'a [u8]),
    Ansi(&'a [u8]),
}

impl<'a> Str<'a> {
    /// The characters; an unpaired surrogate becomes U+FFFD.
    pub fn chars(&self) -> impl Iterator<Item = char> + 'a {
        let (utf16, ansi): (&'a [u8], &'a [u8]) = match *self {
            Str::Utf16(b) => (b, &[]),
            Str::Ansi(b) => (&[], b),
        };
        let units = utf16.chunks_exact(2).map(|c| match c {
            [a, b] => u16::from_le_bytes([*a, *b]),
            _ => 0xFFFD,
        });
        char::decode_utf16(units)
            .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
            .chain(ansi.iter().map(|&b| char::from(b)))
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Str::Utf16(b) | Str::Ansi(b) => b.is_empty(),
        }
    }

    /// Up to (and not including) the first NUL.
    fn until_nul(self) -> Self {
        match self {
            Str::Ansi(b) => Str::Ansi(b.split(|&c| c == 0).next().unwrap_or(b)),
            Str::Utf16(b) => {
                let n = b
                    .chunks_exact(2)
                    .position(|c| c == [0, 0])
                    .map_or(b.len() - b.len() % 2, |i| i * 2);
                Str::Utf16(b.get(..n).unwrap_or(b))
            }
        }
    }
}

/// What a file manager needs from a shortcut. Absent fields are `None`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Link<'a> {
    pub flags: u32,
    /// The target's `FILE_ATTRIBUTE_*` at the time the link was made.
    pub target_attributes: u32,
    pub icon_index: i32,
    pub show_command: u32,
    /// The shortcut's description (the "Comment" field).
    pub name: Option<Str<'a>>,
    pub relative_path: Option<Str<'a>>,
    pub working_dir: Option<Str<'a>>,
    pub arguments: Option<Str<'a>>,
    pub icon_location: Option<Str<'a>>,
    /// LinkInfo's local path of the target (Unicode form preferred).
    pub local_base_path: Option<Str<'a>>,
    pub common_path_suffix: Option<Str<'a>>,
    /// `EnvironmentVariableDataBlock`: the target with `%VAR%`s.
    pub env_target: Option<Str<'a>>,
    /// `IconEnvironmentDataBlock`: the icon location with `%VAR%`s.
    pub env_icon: Option<Str<'a>>,
}

/// Reads a shell link. The extra data is read on a best-effort basis: a
/// malformed trailing block ends the walk rather than failing the file
/// (shortcuts in the wild carry blocks this reader does not know).
pub fn parse(data: &[u8]) -> Result<Link<'_>, Error> {
    let mut r = Reader::new(data);
    if r.u32_le()? != HEADER_SIZE || r.array::<16>()? != &LINK_CLSID {
        return Err(Error::NotALink);
    }
    let flags = r.u32_le()?;
    let target_attributes = r.u32_le()?;
    r.take(24 + 4)?; // three FILETIMEs, FileSize
    let icon_index = i32::from_le_bytes(*r.array()?);
    let show_command = r.u32_le()?;
    r.take(2 + 10)?; // HotKey, reserved
    let mut link = Link {
        flags,
        target_attributes,
        icon_index,
        show_command,
        ..Link::default()
    };

    if flags & HAS_LINK_TARGET_ID_LIST != 0 {
        let n = usize::from(r.u16_le()?);
        r.take(n)?;
    }
    if flags & HAS_LINK_INFO != 0 {
        let size = r.u32_le()? as usize;
        let body = r.take(size.checked_sub(4).ok_or(Error::BadLinkInfo)?)?;
        link_info(&mut link, body)?;
    }
    let unicode = flags & IS_UNICODE != 0;
    for (bit, slot) in [
        (HAS_NAME, &mut link.name),
        (HAS_RELATIVE_PATH, &mut link.relative_path),
        (HAS_WORKING_DIR, &mut link.working_dir),
        (HAS_ARGUMENTS, &mut link.arguments),
        (HAS_ICON_LOCATION, &mut link.icon_location),
    ] {
        if flags & bit != 0 {
            let n = usize::from(r.u16_le()?);
            *slot = Some(if unicode {
                Str::Utf16(r.take(n * 2)?)
            } else {
                Str::Ansi(r.take(n)?)
            });
        }
    }
    extra_data(&mut link, r.rest());
    Ok(link)
}

/// LinkInfo (MS-SHLLINK 2.3), `body` being everything after its size
/// field; offsets in it count from the size field.
fn link_info<'a>(link: &mut Link<'a>, body: &'a [u8]) -> Result<(), Error> {
    let mut r = Reader::new(body);
    let header_size = r.u32_le()? as usize;
    let info_flags = r.u32_le()?;
    let _volume_id = r.u32_le()?;
    let local = r.u32_le()? as usize;
    let _net = r.u32_le()?;
    let suffix = r.u32_le()? as usize;
    let (local_u, suffix_u) = if header_size >= 0x24 {
        (Some(r.u32_le()? as usize), Some(r.u32_le()? as usize))
    } else {
        (None, None)
    };
    // A string at `off` (from the start of LinkInfo), NUL-terminated
    // within it.
    let at = |off: usize, wide: bool| -> Result<Str<'a>, Error> {
        let s = off
            .checked_sub(4)
            .and_then(|o| body.get(o..))
            .filter(|s| !s.is_empty())
            .ok_or(Error::BadLinkInfo)?;
        Ok(if wide { Str::Utf16(s) } else { Str::Ansi(s) }.until_nul())
    };
    if info_flags & 1 != 0 {
        link.local_base_path = Some(match local_u {
            Some(o) if o != 0 => at(o, true)?,
            _ => at(local, false)?,
        });
    }
    if suffix != 0 || suffix_u.is_some_and(|o| o != 0) {
        link.common_path_suffix = Some(match suffix_u {
            Some(o) if o != 0 => at(o, true)?,
            _ => at(suffix, false)?,
        });
    }
    Ok(())
}

fn extra_data<'a>(link: &mut Link<'a>, mut rest: &'a [u8]) {
    for _ in 0..MAX_EXTRA_BLOCKS {
        let mut r = Reader::new(rest);
        let Ok(size) = r.u32_le() else { return };
        let size = size as usize;
        if size < 8 {
            return; // TerminalBlock, or garbage
        }
        let Some((block, tail)) = rest.split_at_checked(size) else {
            return;
        };
        let sig = block
            .get(4..8)
            .and_then(|s| s.try_into().ok())
            .map_or(0, u32::from_le_bytes);
        if size == ENV_BLOCK_SIZE
            && (sig == ENVIRONMENT_VARIABLE_BLOCK || sig == ICON_ENVIRONMENT_BLOCK)
        {
            let ansi = block.get(8..8 + 260).map(|b| Str::Ansi(b).until_nul());
            let wide = block
                .get(8 + 260..ENV_BLOCK_SIZE)
                .map(|b| Str::Utf16(b).until_nul());
            let v = match (wide, ansi) {
                (Some(w), _) if !w.is_empty() => Some(w),
                (_, Some(a)) if !a.is_empty() => Some(a),
                _ => None,
            };
            if sig == ENVIRONMENT_VARIABLE_BLOCK {
                link.env_target = v;
            } else {
                link.env_icon = v;
            }
        }
        rest = tail;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::string::String;
    use std::vec::Vec;

    fn s(x: &Option<Str<'_>>) -> String {
        x.map(|v| v.chars().collect()).unwrap_or_default()
    }

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn counted(v: &mut Vec<u8>, s: &str) {
        v.extend_from_slice(&(s.encode_utf16().count() as u16).to_le_bytes());
        v.extend(utf16(s));
    }

    fn header(flags: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&HEADER_SIZE.to_le_bytes());
        v.extend_from_slice(&LINK_CLSID);
        v.extend_from_slice(&flags.to_le_bytes());
        v.extend_from_slice(&0x20u32.to_le_bytes()); // ARCHIVE
        v.extend_from_slice(&[0; 28]);
        v.extend_from_slice(&(-3i32).to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes());
        v.extend_from_slice(&[0; 12]);
        assert_eq!(v.len(), 0x4C);
        v
    }

    fn env_block(sig: u32, s: &str) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&(ENV_BLOCK_SIZE as u32).to_le_bytes());
        v.extend_from_slice(&sig.to_le_bytes());
        let mut ansi = [0u8; 260];
        ansi[..s.len()].copy_from_slice(s.as_bytes());
        v.extend_from_slice(&ansi);
        let mut w = utf16(s);
        w.resize(520, 0);
        v.extend(w);
        v
    }

    /// A shortcut like Explorer writes: ID list, LinkInfo with a local
    /// path, description, working dir, icon location, both env blocks.
    fn sample() -> Vec<u8> {
        let flags = HAS_LINK_TARGET_ID_LIST
            | HAS_LINK_INFO
            | HAS_NAME
            | HAS_WORKING_DIR
            | HAS_ICON_LOCATION
            | IS_UNICODE;
        let mut v = header(flags);
        v.extend_from_slice(&4u16.to_le_bytes());
        v.extend_from_slice(&[2, 0, 0, 0]); // an ID list, skipped
        // LinkInfo, header 0x1C: local path (ANSI) and an empty suffix.
        let path = b"C:\\Program Files\\App\\app.exe\0";
        let li_len = 0x1C + path.len() + 1;
        let mut li = Vec::new();
        li.extend_from_slice(&(li_len as u32).to_le_bytes());
        li.extend_from_slice(&0x1Cu32.to_le_bytes());
        li.extend_from_slice(&1u32.to_le_bytes()); // VolumeIDAndLocalBasePath
        li.extend_from_slice(&0u32.to_le_bytes());
        li.extend_from_slice(&0x1Cu32.to_le_bytes());
        li.extend_from_slice(&0u32.to_le_bytes());
        li.extend_from_slice(&((0x1C + path.len()) as u32).to_le_bytes());
        li.extend_from_slice(path);
        li.push(0);
        v.extend(li);
        counted(&mut v, "Start the app ✓");
        counted(&mut v, "C:\\Program Files\\App");
        counted(&mut v, "%ProgramFiles%\\App\\app.ico");
        v.extend(env_block(
            ENVIRONMENT_VARIABLE_BLOCK,
            "%ProgramFiles%\\App\\app.exe",
        ));
        v.extend(env_block(
            ICON_ENVIRONMENT_BLOCK,
            "%ProgramFiles%\\App\\app.ico",
        ));
        v.extend_from_slice(&0u32.to_le_bytes()); // TerminalBlock
        v
    }

    #[test]
    fn reads_what_a_file_manager_shows() {
        let d = sample();
        let l = parse(&d).unwrap();
        assert_eq!(s(&l.name), "Start the app ✓");
        assert_eq!(s(&l.working_dir), "C:\\Program Files\\App");
        assert_eq!(s(&l.icon_location), "%ProgramFiles%\\App\\app.ico");
        assert_eq!(l.icon_index, -3);
        assert_eq!(l.show_command, 1);
        assert_eq!(l.target_attributes, 0x20);
        assert_eq!(s(&l.local_base_path), "C:\\Program Files\\App\\app.exe");
        assert_eq!(s(&l.common_path_suffix), "");
        assert_eq!(s(&l.env_target), "%ProgramFiles%\\App\\app.exe");
        assert_eq!(s(&l.env_icon), "%ProgramFiles%\\App\\app.ico");
        assert!(l.arguments.is_none() && l.relative_path.is_none());
    }

    #[test]
    fn ansi_strings() {
        let mut v = header(HAS_ARGUMENTS);
        v.extend_from_slice(&3u16.to_le_bytes());
        v.extend_from_slice(b"/q\xe9");
        let l = parse(&v).unwrap();
        assert_eq!(s(&l.arguments), "/qé");
    }

    #[test]
    fn refusals_and_truncation() {
        let d = sample();
        assert_eq!(parse(&d[..0x40]), Err(Error::Short));
        let mut bad = d.clone();
        bad[4] ^= 1;
        assert_eq!(parse(&bad), Err(Error::NotALink));
        // Every prefix either parses or fails cleanly.
        for n in 0..d.len() {
            let _ = parse(&d[..n]);
        }
        // A LinkInfo offset past its end.
        let mut bad = d.clone();
        let li = 0x4C + 2 + 4;
        bad[li + 16..li + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        assert_eq!(parse(&bad), Err(Error::BadLinkInfo));
        // LinkInfoSize below its own field.
        let mut bad = d.clone();
        bad[li..li + 4].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(parse(&bad), Err(Error::BadLinkInfo));
    }

    #[test]
    fn extra_data_is_best_effort_and_bounded() {
        let mut v = header(0);
        // A huge declared block: the walk stops, the link still parses.
        v.extend_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
        v.extend_from_slice(&ENVIRONMENT_VARIABLE_BLOCK.to_le_bytes());
        assert_eq!(parse(&v).unwrap().env_target, None);
        // Many tiny unknown blocks: bounded.
        let mut v = header(0);
        for _ in 0..1000 {
            v.extend_from_slice(&8u32.to_le_bytes());
            v.extend_from_slice(&0xA000_0003u32.to_le_bytes());
        }
        v.extend(env_block(ENVIRONMENT_VARIABLE_BLOCK, "late"));
        assert_eq!(parse(&v).unwrap().env_target, None, "past MAX_EXTRA_BLOCKS");
    }

    #[test]
    fn utf16_edge_cases() {
        assert_eq!(
            Str::Utf16(&[0x00, 0xD8]).chars().collect::<String>(),
            "\u{FFFD}"
        );
        assert_eq!(
            Str::Utf16(&[b'a', 0, b'b']).until_nul(),
            Str::Utf16(&[b'a', 0])
        );
        assert_eq!(
            Str::Utf16(&[b'a', 0, 0, 0, b'b', 0]).until_nul(),
            Str::Utf16(&[b'a', 0])
        );
    }
}
