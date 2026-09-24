//! The installer's one-shot bootstrap entry (INTERFACES.md §9) and the
//! `EFI_LOAD_OPTION` container it travels in (UEFI 2.10 §3.1.3).
//!
//! `Boot####` variables are runtime-writable by any OS administrator, so both
//! layers are parsed as hostile input: the whole option is capped at
//! [`MAX_LOAD_OPTION`], the description must terminate inside the declared
//! bounds, the device path is walked node by node and must end in an
//! End-Entire node exactly at `FilePathListLength`, and the paguro payload is a
//! fixed 72-byte layout. The wrapped VMK needs the passphrase to open and
//! nothing can test a guess against it, so a forged entry yields a wrong key,
//! never a decision.
//!
//! ```text
//! OptionalData   magic "PGRBST\0\x01" | volume GUID[16] | salt[16] | wrapped_vmk[32]
//! wrapped_vmk  = VMK XOR HMAC(pass_hash, "paguro/bootstrap" || salt)
//! ```
//!
//! The volume GUID names the NTFS volume to unlock on the first boot (there is
//! no configuration yet), and the configuration the loader authors on that
//! boot names it too. Forging it only points the loader at another volume,
//! where the wrapped VMK opens nothing.

use crate::bytes::{Full, Reader, Writer};
use crate::guid::Guid;

pub const MAGIC: &[u8; 8] = b"PGRBST\x00\x01";
pub const OPTIONAL_DATA_LEN: usize = 8 + 16 + 16 + 32;
/// Largest `Boot####` value the loader reads.
pub const MAX_LOAD_OPTION: usize = 8192;
/// `LOAD_OPTION_ACTIVE`.
pub const LOAD_OPTION_ACTIVE: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapError {
    /// Load option larger than [`MAX_LOAD_OPTION`].
    TooLarge,
    Truncated,
    /// No NUL terminator for the description inside the option.
    UnterminatedDescription,
    /// `FilePathListLength` is zero or runs past the end.
    BadFilePathLength,
    /// A device-path node is shorter than 4 bytes or overruns the list.
    BadDevicePathNode,
    /// The list does not end with exactly one End-Entire node at its end.
    MissingEndNode,
    /// OptionalData is not the paguro bootstrap magic.
    NotBootstrap,
    /// OptionalData carries the magic but has the wrong length.
    BadLength,
}

/// A parsed `EFI_LOAD_OPTION`, borrowed from the variable's bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoadOption<'a> {
    pub attributes: u32,
    /// UTF-16LE description without its terminator.
    pub description: &'a [u8],
    /// Device path list, End node included.
    pub file_path: &'a [u8],
    pub optional_data: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bootstrap<'a> {
    /// GPT partition GUID of the NTFS volume this entry unlocks.
    pub volume: Guid,
    pub salt: &'a [u8; 16],
    pub wrapped_vmk: &'a [u8; 32],
}

/// One device-path node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Node<'a> {
    pub kind: u8,
    pub sub: u8,
    pub data: &'a [u8],
}

pub const DP_MEDIA: u8 = 0x04;
pub const DP_MEDIA_HARD_DRIVE: u8 = 0x01;
pub const DP_MEDIA_FILE_PATH: u8 = 0x04;
pub const DP_END: u8 = 0x7f;
pub const DP_END_ENTIRE: u8 = 0xff;

/// Walk a device-path list, checking every node's length. Returns the number
/// of nodes before the End-Entire node.
pub fn walk_device_path<'a>(
    list: &'a [u8],
    mut visit: impl FnMut(Node<'a>),
) -> Result<usize, BootstrapError> {
    let mut r = Reader::new(list);
    let mut n = 0usize;
    loop {
        let kind = r.u8().map_err(|_| BootstrapError::MissingEndNode)?;
        let sub = r.u8().map_err(|_| BootstrapError::BadDevicePathNode)?;
        let len = usize::from(r.u16_le().map_err(|_| BootstrapError::BadDevicePathNode)?);
        let data_len = len
            .checked_sub(4)
            .ok_or(BootstrapError::BadDevicePathNode)?;
        let data = r
            .take(data_len)
            .map_err(|_| BootstrapError::BadDevicePathNode)?;
        if kind == DP_END && sub == DP_END_ENTIRE {
            return if r.is_empty() {
                Ok(n)
            } else {
                Err(BootstrapError::MissingEndNode)
            };
        }
        visit(Node { kind, sub, data });
        n += 1;
    }
}

/// Parse an `EFI_LOAD_OPTION`.
pub fn parse_load_option(var: &[u8]) -> Result<LoadOption<'_>, BootstrapError> {
    if var.len() > MAX_LOAD_OPTION {
        return Err(BootstrapError::TooLarge);
    }
    let mut r = Reader::new(var);
    let attributes = r.u32_le().map_err(|_| BootstrapError::Truncated)?;
    let fpl = usize::from(r.u16_le().map_err(|_| BootstrapError::Truncated)?);
    let rest = r.rest();
    let mut desc_len = None;
    let mut i = 0usize;
    while let Some(pair) = rest.get(i..i + 2) {
        if pair == [0, 0] {
            desc_len = Some(i);
            break;
        }
        i += 2;
    }
    let desc_len = desc_len.ok_or(BootstrapError::UnterminatedDescription)?;
    let description = r.take(desc_len).map_err(|_| BootstrapError::Truncated)?;
    r.take(2).map_err(|_| BootstrapError::Truncated)?;
    if fpl == 0 {
        return Err(BootstrapError::BadFilePathLength);
    }
    let file_path = r.take(fpl).map_err(|_| BootstrapError::BadFilePathLength)?;
    walk_device_path(file_path, |_| {})?;
    Ok(LoadOption {
        attributes,
        description,
        file_path,
        optional_data: r.rest(),
    })
}

/// The paguro payload of a bootstrap entry's OptionalData.
pub fn parse_optional_data(data: &[u8]) -> Result<Bootstrap<'_>, BootstrapError> {
    if data.get(..8) != Some(&MAGIC[..]) {
        return Err(BootstrapError::NotBootstrap);
    }
    if data.len() != OPTIONAL_DATA_LEN {
        return Err(BootstrapError::BadLength);
    }
    let mut r = Reader::new(data.get(8..).unwrap_or(&[]));
    let volume = Guid(*r.array::<16>().map_err(|_| BootstrapError::BadLength)?);
    let salt = r.array::<16>().map_err(|_| BootstrapError::BadLength)?;
    let wrapped_vmk = r.array::<32>().map_err(|_| BootstrapError::BadLength)?;
    Ok(Bootstrap {
        volume,
        salt,
        wrapped_vmk,
    })
}

/// Parse a whole `Boot####` value and its bootstrap payload.
pub fn parse(var: &[u8]) -> Result<Bootstrap<'_>, BootstrapError> {
    parse_optional_data(parse_load_option(var)?.optional_data)
}

fn eq_ignore_case_utf16(a: &[u8], ascii: &str) -> bool {
    a.len() == ascii.len() * 2
        && a.chunks_exact(2).zip(ascii.bytes()).all(|(u, c)| {
            let u = u16::from_le_bytes([
                u.first().copied().unwrap_or(0),
                u.get(1).copied().unwrap_or(0),
            ]);
            u < 0x80 && (u as u8).eq_ignore_ascii_case(&c)
        })
}

impl LoadOption<'_> {
    /// Whether this entry starts Windows Boot Manager: a File Path node ending
    /// in `\EFI\Microsoft\Boot\bootmgfw.efi` (case-insensitive). Used only to
    /// pick a `BootNext` target for "Start Windows" — the loader never
    /// chainloads it (DESIGN.md §6).
    pub fn is_windows_boot_manager(&self) -> bool {
        const TAIL: &str = "\\EFI\\Microsoft\\Boot\\bootmgfw.efi";
        let mut found = false;
        let _ = walk_device_path(self.file_path, |n| {
            if n.kind == DP_MEDIA && n.sub == DP_MEDIA_FILE_PATH {
                // NUL-terminated UTF-16; compare the tail before the NUL.
                let mut d = n.data;
                if d.len() >= 2 && d.get(d.len() - 2..) == Some(&[0, 0][..]) {
                    d = d.get(..d.len() - 2).unwrap_or(&[]);
                }
                if let Some(tail) = d
                    .len()
                    .checked_sub(TAIL.len() * 2)
                    .and_then(|at| d.get(at..))
                {
                    found |= eq_ignore_case_utf16(tail, TAIL);
                }
            }
        });
        found
    }
}

/// Serialise an `EFI_LOAD_OPTION` whose device path is a single File Path node
/// (tests, the mock platform and the QEMU tooling).
pub fn write_load_option(
    attributes: u32,
    description: &str,
    path: &str,
    optional: &[u8],
    out: &mut [u8],
) -> Result<usize, Full> {
    let mut w = Writer::new(out);
    w.u32_le(attributes)?;
    let path_units = path.encode_utf16().count() + 1;
    let fpl = 4 + path_units * 2 + 4;
    w.u16_le(u16::try_from(fpl).map_err(|_| Full)?)?;
    for u in description.encode_utf16() {
        w.u16_le(u)?;
    }
    w.u16_le(0)?;
    w.u8(DP_MEDIA)?;
    w.u8(DP_MEDIA_FILE_PATH)?;
    w.u16_le(u16::try_from(4 + path_units * 2).map_err(|_| Full)?)?;
    for u in path.encode_utf16() {
        w.u16_le(u)?;
    }
    w.u16_le(0)?;
    w.put(&[DP_END, DP_END_ENTIRE, 4, 0])?;
    w.put(optional)?;
    Ok(w.len())
}

/// Serialise the bootstrap OptionalData.
pub fn write_optional_data(
    volume: &Guid,
    salt: &[u8; 16],
    wrapped_vmk: &[u8; 32],
) -> [u8; OPTIONAL_DATA_LEN] {
    let mut out = [0u8; OPTIONAL_DATA_LEN];
    let mut w = Writer::new(&mut out);
    // 72 bytes into a 72-byte buffer cannot fail.
    let _ = w.put(MAGIC);
    let _ = w.put(&volume.0);
    let _ = w.put(salt);
    let _ = w.put(wrapped_vmk);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn option(desc: &str, path: &str, opt: &[u8]) -> ([u8; 512], usize) {
        let mut b = [0u8; 512];
        let n = write_load_option(LOAD_OPTION_ACTIVE, desc, path, opt, &mut b).unwrap();
        (b, n)
    }

    #[test]
    fn roundtrip() {
        let od = write_optional_data(&Guid([9; 16]), &[1; 16], &[2; 32]);
        assert_eq!(od.len(), 72);
        assert_eq!(&od[8..24], &[9; 16], "the volume follows the magic");
        let (b, n) = option("paguro setup", "\\EFI\\paguro\\paguro.efi", &od);
        let lo = parse_load_option(&b[..n]).unwrap();
        assert_eq!(lo.attributes, LOAD_OPTION_ACTIVE);
        assert_eq!(lo.description.len(), 24);
        assert!(!lo.is_windows_boot_manager());
        let bs = parse(&b[..n]).unwrap();
        assert_eq!(bs.volume, Guid([9; 16]));
        assert_eq!((bs.salt, bs.wrapped_vmk), (&[1; 16], &[2; 32]));
    }

    #[test]
    fn recognises_windows_boot_manager() {
        let (b, n) = option(
            "Windows Boot Manager",
            "\\EFI\\MICROSOFT\\Boot\\BOOTMGFW.EFI",
            &[],
        );
        let lo = parse_load_option(&b[..n]).unwrap();
        assert!(lo.is_windows_boot_manager());
        assert_eq!(parse(&b[..n]), Err(BootstrapError::NotBootstrap));
        let (b, n) = option("x", "\\bootmgfw.efi", &[]);
        assert!(
            !parse_load_option(&b[..n])
                .unwrap()
                .is_windows_boot_manager()
        );
        let (b, n) = option("x", "\\EFI\\Microsoft\\Boot\\bootmgfw.efé", &[]);
        assert!(
            !parse_load_option(&b[..n])
                .unwrap()
                .is_windows_boot_manager()
        );
    }

    #[test]
    fn every_error_variant() {
        let od = write_optional_data(&Guid([9; 16]), &[1; 16], &[2; 32]);
        let (b, n) = option("d", "\\p", &od);
        assert_eq!(
            parse(&[0; MAX_LOAD_OPTION + 1]),
            Err(BootstrapError::TooLarge)
        );
        assert_eq!(parse(&b[..5]), Err(BootstrapError::Truncated));
        assert_eq!(parse(&b[..7]), Err(BootstrapError::UnterminatedDescription));
        let mut z = b;
        z[4..6].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(parse(&z[..n]), Err(BootstrapError::BadFilePathLength));
        let mut z = b;
        z[4..6].copy_from_slice(&500u16.to_le_bytes());
        assert_eq!(parse(&z[..n]), Err(BootstrapError::BadFilePathLength));
        // node length 3 (< 4)
        let mut z = b;
        z[12..14].copy_from_slice(&3u16.to_le_bytes());
        assert_eq!(parse(&z[..n]), Err(BootstrapError::BadDevicePathNode));
        // node length overruns the list
        let mut z = b;
        z[12..14].copy_from_slice(&200u16.to_le_bytes());
        assert_eq!(parse(&z[..n]), Err(BootstrapError::BadDevicePathNode));
        // list shortened by 4: End node dropped
        let mut z = b;
        let fpl = u16::from_le_bytes([z[4], z[5]]);
        z[4..6].copy_from_slice(&(fpl - 4).to_le_bytes());
        assert_eq!(parse(&z[..n]), Err(BootstrapError::MissingEndNode));
        // list lengthened: bytes after End inside the list
        let mut z = b;
        z[4..6].copy_from_slice(&(fpl + 4).to_le_bytes());
        assert_eq!(parse(&z[..n]), Err(BootstrapError::MissingEndNode));
        // list ends mid-node header
        let mut z = b;
        z[4..6].copy_from_slice(&(fpl - 3).to_le_bytes());
        assert_eq!(parse(&z[..n]), Err(BootstrapError::BadDevicePathNode));
        assert_eq!(parse(&b[..n - 1]), Err(BootstrapError::BadLength));
        let (b2, n2) = option("d", "\\p", b"PGRBST\x00\x02rest");
        assert_eq!(parse(&b2[..n2]), Err(BootstrapError::NotBootstrap));
        assert_eq!(
            parse_optional_data(&od[..8]),
            Err(BootstrapError::BadLength)
        );
        // The pre-volume 56-byte layout is refused, not misread.
        assert_eq!(
            parse_optional_data(&od[..56]),
            Err(BootstrapError::BadLength)
        );
        assert_eq!(
            write_load_option(0, "d", "\\p", &od, &mut [0u8; 10]),
            Err(Full)
        );
    }

    #[test]
    fn device_path_walk_counts_nodes() {
        let list = [
            4,
            1,
            5,
            0,
            9,
            DP_MEDIA,
            DP_MEDIA_FILE_PATH,
            6,
            0,
            0,
            0,
            0x7f,
            0xff,
            4,
            0,
        ];
        let mut kinds = [0u8; 4];
        let mut i = 0;
        assert_eq!(
            walk_device_path(&list, |n| {
                kinds[i] = n.sub;
                i += 1;
            }),
            Ok(2)
        );
        assert_eq!(kinds[..2], [1, 4]);
        assert_eq!(
            walk_device_path(&[], |_| {}),
            Err(BootstrapError::MissingEndNode)
        );
        assert_eq!(
            walk_device_path(&[4], |_| {}),
            Err(BootstrapError::BadDevicePathNode)
        );
    }
}
