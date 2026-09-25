//! The installer's bootstrap payload (INTERFACES.md §9), the
//! `EFI_LOAD_OPTION` container of `Boot####` entries (UEFI 2.10 §3.1.3), and
//! the recognition of paguro's own one-shot entry.
//!
//! The payload travels in the `PaguroBootstrap` firmware variable, not in the
//! entry: under Secure Boot the entry points at shim, which reads the entry's
//! load options as its second-stage path. The loader reads the variable and
//! deletes it as its first action, malformed or not.
//!
//! Runtime variables are writable by any OS administrator, so both the
//! payload and `Boot####` values are parsed as hostile input: the variable is
//! capped at [`MAX_VAR`] and must be exactly the fixed 72-byte layout; a load
//! option is capped at [`MAX_LOAD_OPTION`], the description must terminate
//! inside the declared bounds, the device path is walked node by node and
//! must end in an End-Entire node exactly at `FilePathListLength`. The
//! wrapped VMK needs the passphrase to open and nothing can test a guess
//! against it, so a forged payload yields a wrong key, never a decision.
//!
//! ```text
//! PaguroBootstrap  magic "PGRBST\0\x01" | volume GUID[16] | salt[16] | wrapped_vmk[32]
//! wrapped_vmk    = VMK XOR HMAC(pass_hash, "paguro/bootstrap" || salt)
//! ```
//!
//! The volume GUID names the NTFS volume to unlock on the first boot (there is
//! no configuration yet), and the configuration the loader authors on that
//! boot names it too. Forging it only points the loader at another volume,
//! where the wrapped VMK opens nothing.

use crate::bytes::{Full, Reader, Writer};
use crate::guid::Guid;

pub const MAGIC: &[u8; 8] = b"PGRBST\x00\x01";
pub const PAYLOAD_LEN: usize = 8 + 16 + 16 + 32;
/// The payload's firmware variable (INTERFACES.md §5, §9), under the paguro
/// vendor GUID.
pub const VAR_NAME: &str = "PaguroBootstrap";
/// Largest `PaguroBootstrap` value (INTERFACES.md §5).
pub const MAX_VAR: usize = 128;
/// Largest `Boot####` value the loader reads.
pub const MAX_LOAD_OPTION: usize = 8192;
/// `LOAD_OPTION_ACTIVE`.
pub const LOAD_OPTION_ACTIVE: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapError {
    /// Load option larger than [`MAX_LOAD_OPTION`], or payload larger than
    /// [`MAX_VAR`].
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
    /// The payload does not start with the bootstrap magic.
    NotBootstrap,
    /// The payload carries the magic but has the wrong length.
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

/// The `PaguroBootstrap` payload.
pub fn parse_payload(data: &[u8]) -> Result<Bootstrap<'_>, BootstrapError> {
    if data.len() > MAX_VAR {
        return Err(BootstrapError::TooLarge);
    }
    if data.get(..8) != Some(&MAGIC[..]) {
        return Err(BootstrapError::NotBootstrap);
    }
    if data.len() != PAYLOAD_LEN {
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

/// The UCS-2 text of a File Path node, without its terminator, when the
/// node is one.
fn file_path_text<'a>(n: &Node<'a>) -> Option<&'a [u8]> {
    if n.kind != DP_MEDIA || n.sub != DP_MEDIA_FILE_PATH {
        return None;
    }
    let d = n.data;
    Some(match d.len().checked_sub(2) {
        Some(end) if d.get(end..) == Some(&[0, 0][..]) => d.get(..end).unwrap_or(&[]),
        _ => d,
    })
}

impl LoadOption<'_> {
    /// Whether this entry starts a file under `\EFI\paguro\` (shim or
    /// `paguro.efi`, case-insensitive): paguro's own entries, standing or
    /// one-shot. The loader deletes only such an entry as the bootstrap's
    /// one-shot entry.
    pub fn is_paguro(&self) -> bool {
        const DIR: &str = "\\EFI\\paguro\\";
        let mut found = false;
        let _ = walk_device_path(self.file_path, |n| {
            if let Some(t) = file_path_text(&n) {
                found |= t
                    .get(..DIR.len() * 2)
                    .is_some_and(|head| eq_ignore_case_utf16(head, DIR));
            }
        });
        found
    }

    /// Whether this entry starts Windows Boot Manager: a File Path node ending
    /// in `\EFI\Microsoft\Boot\bootmgfw.efi` (case-insensitive). Used only to
    /// pick a `BootNext` target for "Start Windows" — the loader never
    /// chainloads it (DESIGN.md §6).
    pub fn is_windows_boot_manager(&self) -> bool {
        const TAIL: &str = "\\EFI\\Microsoft\\Boot\\bootmgfw.efi";
        let mut found = false;
        let _ = walk_device_path(self.file_path, |n| {
            // NUL-terminated UTF-16; compare the tail before the NUL.
            if let Some(d) = file_path_text(&n) {
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

/// Serialise the `PaguroBootstrap` payload.
pub fn write_payload(volume: &Guid, salt: &[u8; 16], wrapped_vmk: &[u8; 32]) -> [u8; PAYLOAD_LEN] {
    let mut out = [0u8; PAYLOAD_LEN];
    let mut w = Writer::new(&mut out);
    // 72 bytes into a 72-byte buffer cannot fail.
    let _ = w.put(MAGIC);
    let _ = w.put(&volume.0);
    let _ = w.put(salt);
    let _ = w.put(wrapped_vmk);
    out
}

/// A GPT Hard Drive media node (UEFI 2.10 §10.3.5.1): the partition a
/// `Boot####` entry's file lives on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HardDrive {
    /// 1-based GPT partition number.
    pub partition_number: u32,
    pub start_lba: u64,
    pub size_lba: u64,
    /// The partition's unique GUID (GPT on-disk byte order).
    pub partition_guid: Guid,
}

/// Length of a Hard Drive node's data (42-byte node minus its 4-byte header).
const HD_DATA_LEN: usize = 38;
/// `MBRType` 2 = GPT, `SignatureType` 2 = GUID.
const HD_GPT: [u8; 2] = [2, 2];

/// The GPT Hard Drive node in `node`, if it is one. Only the GPT form is
/// accepted: paguro's ESP is always on a GPT disk.
pub fn parse_hard_drive(node: &Node<'_>) -> Option<HardDrive> {
    if node.kind != DP_MEDIA || node.sub != DP_MEDIA_HARD_DRIVE || node.data.len() != HD_DATA_LEN {
        return None;
    }
    let mut r = Reader::new(node.data);
    let partition_number = r.u32_le().ok()?;
    let start_lba = r.u64_le().ok()?;
    let size_lba = r.u64_le().ok()?;
    let partition_guid = Guid(*r.array::<16>().ok()?);
    (r.rest() == HD_GPT).then_some(HardDrive {
        partition_number,
        start_lba,
        size_lba,
        partition_guid,
    })
}

/// Serialise an `EFI_LOAD_OPTION` whose device path is a GPT Hard Drive node
/// followed by a File Path node: the shape firmware and `bcdboot` write for
/// an entry on the ESP, and what `paguro efi boot-entry create` writes.
pub fn write_load_option_hd(
    attributes: u32,
    description: &str,
    hd: &HardDrive,
    path: &str,
    optional: &[u8],
    out: &mut [u8],
) -> Result<usize, Full> {
    let mut w = Writer::new(out);
    w.u32_le(attributes)?;
    let path_units = path.encode_utf16().count() + 1;
    let fp_node = 4 + path_units * 2;
    let fpl = (4 + HD_DATA_LEN) + fp_node + 4;
    w.u16_le(u16::try_from(fpl).map_err(|_| Full)?)?;
    for u in description.encode_utf16() {
        w.u16_le(u)?;
    }
    w.u16_le(0)?;
    w.u8(DP_MEDIA)?;
    w.u8(DP_MEDIA_HARD_DRIVE)?;
    w.u16_le(4 + HD_DATA_LEN as u16)?;
    w.u32_le(hd.partition_number)?;
    w.u64_le(hd.start_lba)?;
    w.u64_le(hd.size_lba)?;
    w.put(&hd.partition_guid.0)?;
    w.put(&HD_GPT)?;
    w.u8(DP_MEDIA)?;
    w.u8(DP_MEDIA_FILE_PATH)?;
    w.u16_le(u16::try_from(fp_node).map_err(|_| Full)?)?;
    for u in path.encode_utf16() {
        w.u16_le(u)?;
    }
    w.u16_le(0)?;
    w.put(&[DP_END, DP_END_ENTIRE, 4, 0])?;
    w.put(optional)?;
    Ok(w.len())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn option(desc: &str, path: &str, opt: &[u8]) -> ([u8; 512], usize) {
        let mut b = [0u8; 512];
        let n = write_load_option(LOAD_OPTION_ACTIVE, desc, path, opt, &mut b).unwrap();
        (b, n)
    }

    #[test]
    fn hard_drive_option_roundtrips() {
        let hd = HardDrive {
            partition_number: 1,
            start_lba: 2048,
            size_lba: 204_800,
            partition_guid: Guid([0x5a; 16]),
        };
        let second: std::vec::Vec<u8> = "\\EFI\\paguro\\paguro.efi\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut b = [0u8; 512];
        let n = write_load_option_hd(
            LOAD_OPTION_ACTIVE,
            "paguro",
            &hd,
            "\\EFI\\paguro\\shimx64.efi",
            &second,
            &mut b,
        )
        .unwrap();
        let lo = parse_load_option(&b[..n]).unwrap();
        let mut nodes = std::vec::Vec::new();
        assert_eq!(walk_device_path(lo.file_path, |nd| nodes.push(nd)), Ok(2));
        assert_eq!(parse_hard_drive(&nodes[0]), Some(hd));
        assert_eq!(parse_hard_drive(&nodes[1]), None);
        assert_eq!(lo.optional_data, &second[..]);
        assert!(lo.is_paguro());
        // An MBR-signature node is not ours.
        let mut data = [0u8; 38];
        data[36] = 1;
        let mbr = Node {
            kind: DP_MEDIA,
            sub: DP_MEDIA_HARD_DRIVE,
            data: &data,
        };
        assert_eq!(parse_hard_drive(&mbr), None);
    }

    #[test]
    fn roundtrip() {
        let od = write_payload(&Guid([9; 16]), &[1; 16], &[2; 32]);
        assert_eq!(od.len(), 72);
        assert_eq!(&od[8..24], &[9; 16], "the volume follows the magic");
        let bs = parse_payload(&od).unwrap();
        assert_eq!(bs.volume, Guid([9; 16]));
        assert_eq!((bs.salt, bs.wrapped_vmk), (&[1; 16], &[2; 32]));
        let (b, n) = option("paguro setup", "\\EFI\\paguro\\paguro.efi", &[]);
        let lo = parse_load_option(&b[..n]).unwrap();
        assert_eq!(lo.attributes, LOAD_OPTION_ACTIVE);
        assert_eq!(lo.description.len(), 24);
        assert!(!lo.is_windows_boot_manager());
        assert!(lo.is_paguro());
    }

    #[test]
    fn recognises_paguro_entries_only() {
        for (path, ours) in [
            ("\\EFI\\paguro\\shimx64.efi", true),
            ("\\efi\\PAGURO\\paguro.efi", true),
            ("\\EFI\\paguro", false),
            ("\\EFI\\paguro2\\x.efi", false),
            ("\\EFI\\Microsoft\\Boot\\bootmgfw.efi", false),
            ("\\x\\EFI\\paguro\\paguro.efi", false),
        ] {
            let (b, n) = option("d", path, &[]);
            assert_eq!(
                parse_load_option(&b[..n]).unwrap().is_paguro(),
                ours,
                "{path}"
            );
        }
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
        assert!(!lo.is_paguro());
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
        let od = write_payload(&Guid([9; 16]), &[1; 16], &[2; 32]);
        let (b, n) = option("d", "\\p", &od);
        // The load option alone, then its optional data as a payload.
        let parse = |v: &[u8]| -> Result<(), BootstrapError> {
            parse_payload(parse_load_option(v)?.optional_data).map(|_| ())
        };
        assert_eq!(parse(&b[..n]), Ok(()));
        assert_eq!(
            parse(&[0; MAX_LOAD_OPTION + 1]),
            Err(BootstrapError::TooLarge)
        );
        assert_eq!(
            parse_payload(&[0; MAX_VAR + 1]),
            Err(BootstrapError::TooLarge)
        );
        let mut long = [0u8; MAX_VAR];
        long[..72].copy_from_slice(&od);
        assert_eq!(parse_payload(&long), Err(BootstrapError::BadLength));
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
        assert_eq!(parse_payload(&od[..8]), Err(BootstrapError::BadLength));
        // The pre-volume 56-byte layout is refused, not misread.
        assert_eq!(parse_payload(&od[..56]), Err(BootstrapError::BadLength));
        assert_eq!(parse_payload(&[]), Err(BootstrapError::NotBootstrap));
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
