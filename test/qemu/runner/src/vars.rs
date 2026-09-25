//! Add a variable to an OVMF `VARS.fd` before boot, the way the Windows tool
//! or the initrd would have set it at runtime (e.g. `PaguroConfigHash`), and
//! read one back after the VM stopped (what the loader left behind).
//!
//! Layout (EDK II `MdeModulePkg/Include/Guid/VariableFormat.h`): a firmware
//! volume header, then a `VARIABLE_STORE_HEADER`, then variable records
//! `0x55AA`-tagged and 4-byte aligned. A record is appended after the last one
//! with state `VAR_ADDED`; the store has no checksum over its records.

use crate::layout::field;
use paguro_core::guid::Guid;
use std::mem::size_of;
use std::ops::Range;
use std::path::Path;

// The structures below are layout-only mirrors of VariableFormat.h and the
// PI spec's firmware volume header: never instantiated, only measured.

/// `EFI_FIRMWARE_VOLUME_HEADER` (PI 1.8 Vol. 3 §3.2.1), up to the block map.
#[allow(dead_code)]
#[repr(C, packed)]
struct FvHeader {
    zero_vector: [u8; 16],
    file_system_guid: [u8; 16],
    fv_length: u64,
    signature: [u8; 4],
    attributes: u32,
    header_length: u16,
    checksum: u16,
    ext_header_offset: u16,
    reserved: u8,
    revision: u8,
}
const FV_SIGNATURE: Range<usize> = field!(FvHeader, signature);
const FV_HEADER_LENGTH: usize = field!(FvHeader, header_length).start;
const _: () = assert!(FV_SIGNATURE.start == 40 && FV_HEADER_LENGTH == 48);
/// `EFI_FVH_SIGNATURE`.
const FVH_SIGNATURE: &[u8; 4] = b"_FVH";

/// `VARIABLE_STORE_HEADER`: the store's format GUID, its size, then records.
#[allow(dead_code)]
#[repr(C, packed)]
struct VariableStoreHeader {
    signature: [u8; 16],
    size: u32,
    format: u8,
    state: u8,
    reserved: u16,
    reserved1: u32,
}
const STORE_SIGNATURE: Range<usize> = field!(VariableStoreHeader, signature);
const STORE_SIZE: usize = field!(VariableStoreHeader, size).start;
const STORE_HEADER_LEN: usize = size_of::<VariableStoreHeader>();
const _: () = assert!(STORE_SIZE == 16 && STORE_HEADER_LEN == 28);

/// `VARIABLE_HEADER` (the plain store format).
#[allow(dead_code)]
#[repr(C, packed)]
struct VariableHeader {
    start_id: u16,
    state: u8,
    reserved: u8,
    attributes: u32,
    name_size: u32,
    data_size: u32,
    vendor_guid: [u8; 16],
}
/// `AUTHENTICATED_VARIABLE_HEADER` (the authenticated store format).
#[allow(dead_code)]
#[repr(C, packed)]
struct AuthenticatedVariableHeader {
    start_id: u16,
    state: u8,
    reserved: u8,
    attributes: u32,
    monotonic_count: u64,
    time_stamp: [u8; 16],
    pub_key_index: u32,
    name_size: u32,
    data_size: u32,
    vendor_guid: [u8; 16],
}
// The fields both formats share, at the same offsets.
const VAR_START_ID: usize = field!(VariableHeader, start_id).start;
const VAR_STATE: usize = field!(VariableHeader, state).start;
const VAR_ATTRIBUTES: usize = field!(VariableHeader, attributes).start;
const _: () = assert!(
    VAR_STATE == field!(AuthenticatedVariableHeader, state).start
        && VAR_ATTRIBUTES == field!(AuthenticatedVariableHeader, attributes).start
        && VAR_ATTRIBUTES == 4
);
const PLAIN_HEADER_LEN: usize = size_of::<VariableHeader>();
const AUTH_HEADER_LEN: usize = size_of::<AuthenticatedVariableHeader>();
const _: () = assert!(PLAIN_HEADER_LEN == 32 && AUTH_HEADER_LEN == 60);
/// Both headers end with the vendor GUID.
const VENDOR_GUID_LEN: usize = 16;
/// The fields between the attributes and the sizes in the authenticated
/// format (monotonic count, timestamp, public key index), written as zeros.
const AUTH_ONLY_LEN: usize =
    field!(AuthenticatedVariableHeader, name_size).start - field!(VariableHeader, name_size).start;
/// `VARIABLE_DATA`: every record's `StartId`.
const VARIABLE_DATA: u16 = 0x55aa;
/// Records are `HEADER_ALIGNMENT` (4) aligned.
const HEADER_ALIGNMENT: usize = 4;
/// Erased flash.
const ERASED: u8 = 0xff;

const AUTH_VARIABLE: Guid = Guid([
    0x78, 0x2c, 0xf3, 0xaa, 0x7b, 0x94, 0x9a, 0x43, 0xa1, 0x80, 0x2e, 0x14, 0x4e, 0xc3, 0x77, 0x92,
]);
const PLAIN_VARIABLE: Guid = Guid([
    0x16, 0x36, 0xcf, 0xdd, 0x75, 0x32, 0x64, 0x41, 0x98, 0xb6, 0xfe, 0x85, 0x70, 0x7f, 0xfe, 0x7d,
]);
const VAR_ADDED: u8 = 0x3f;
/// `VAR_ADDED & VAR_IN_DELETED_TRANSITION`: still the live copy until the
/// new one lands.
const VAR_ADDED_IN_TRANSITION: u8 = 0x3e;

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// The variable store in `fv`: where its first record starts, where it
/// ends, and the record header size (authenticated or plain format).
fn store(fv: &[u8]) -> Result<(usize, usize, usize), String> {
    if fv.get(FV_SIGNATURE) != Some(FVH_SIGNATURE) {
        return Err("VARS: no firmware volume header".into());
    }
    let hlen = usize::from(u16_at(fv, FV_HEADER_LENGTH).ok_or("VARS: short")?);
    let sig = Guid(
        fv.get(hlen + STORE_SIGNATURE.start..hlen + STORE_SIGNATURE.end)
            .ok_or("VARS: short")?
            .try_into()
            .map_err(|_| "VARS")?,
    );
    let header_size = if sig == AUTH_VARIABLE {
        AUTH_HEADER_LEN
    } else if sig == PLAIN_VARIABLE {
        PLAIN_HEADER_LEN
    } else {
        return Err("VARS: unknown variable store".into());
    };
    let store_size = u32_at(fv, hlen + STORE_SIZE).ok_or("VARS: short")? as usize;
    Ok((hlen + STORE_HEADER_LEN, hlen + store_size, header_size))
}

/// One record: `(state, attributes, name UTF-16 bytes, vendor, data)` and
/// the next record's offset.
#[allow(clippy::type_complexity)]
fn record(fv: &[u8], at: usize, hs: usize) -> Option<((u8, u32, &[u8], Guid, &[u8]), usize)> {
    if u16_at(fv, at + VAR_START_ID)? != VARIABLE_DATA {
        return None;
    }
    let state = *fv.get(at + VAR_STATE)?;
    let attrs = u32_at(fv, at + VAR_ATTRIBUTES)?;
    let (name_size, data_size) = if hs == AUTH_HEADER_LEN {
        (
            field!(AuthenticatedVariableHeader, name_size).start,
            field!(AuthenticatedVariableHeader, data_size).start,
        )
    } else {
        (
            field!(VariableHeader, name_size).start,
            field!(VariableHeader, data_size).start,
        )
    };
    let (ns, ds) = (u32_at(fv, at + name_size)?, u32_at(fv, at + data_size)?);
    let (ns, ds) = (ns as usize, ds as usize);
    let vendor = Guid(
        fv.get(at + hs - VENDOR_GUID_LEN..at + hs)?
            .try_into()
            .ok()?,
    );
    let name = fv.get(at + hs..at + hs + ns)?;
    let data = fv.get(at + hs + ns..at + hs + ns + ds)?;
    Some((
        (state, attrs, name, vendor, data),
        (at + hs + ns + ds).next_multiple_of(HEADER_ALIGNMENT),
    ))
}

fn name16(name: &str) -> Vec<u8> {
    let mut n: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    n.extend([0, 0]);
    n
}

/// The live value of `name` in the VARS file: `(attributes, data)`.
pub fn read(path: &Path, name: &str, vendor: &Guid) -> Result<Option<(u32, Vec<u8>)>, String> {
    let fv = std::fs::read(path).map_err(|e| e.to_string())?;
    let (mut at, end, hs) = store(&fv)?;
    let want = name16(name);
    let mut found = None;
    while at < end {
        let Some(((state, attrs, n, v, data), next)) = record(&fv, at, hs) else {
            break;
        };
        if n == want && v == *vendor {
            match state {
                VAR_ADDED => found = Some((attrs, data.to_vec())),
                // Superseded unless nothing newer follows.
                VAR_ADDED_IN_TRANSITION if found.is_none() => found = Some((attrs, data.to_vec())),
                _ => {}
            }
        }
        at = next;
    }
    Ok(found)
}

pub fn inject(
    path: &Path,
    name: &str,
    vendor: &Guid,
    attrs: u32,
    data: &[u8],
) -> Result<(), String> {
    let mut fv = std::fs::read(path).map_err(|e| e.to_string())?;
    let (mut at, end, header_size) = store(&fv)?;
    while let Some((_, next)) = record(&fv, at, header_size) {
        at = next;
    }
    let name16 = name16(name);
    let mut rec = VARIABLE_DATA.to_le_bytes().to_vec();
    rec.extend([VAR_ADDED, 0]);
    rec.extend(attrs.to_le_bytes());
    if header_size == AUTH_HEADER_LEN {
        // Monotonic count, timestamp, public key index.
        rec.extend([0u8; AUTH_ONLY_LEN]);
    }
    rec.extend((name16.len() as u32).to_le_bytes());
    rec.extend((data.len() as u32).to_le_bytes());
    rec.extend(vendor.0);
    rec.extend(&name16);
    rec.extend(data);
    if at + rec.len() > end {
        return Err("VARS: store full".into());
    }
    if fv[at..at + rec.len()].iter().any(|b| *b != ERASED) {
        return Err("VARS: free space is not erased".into());
    }
    fv[at..at + rec.len()].copy_from_slice(&rec);
    std::fs::write(path, fv).map_err(|e| e.to_string())
}
