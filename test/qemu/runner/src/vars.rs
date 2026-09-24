//! Add a variable to an OVMF `VARS.fd` before boot, the way the Windows tool
//! or the initrd would have set it at runtime (e.g. `PaguroConfigHash`).
//!
//! Layout (EDK II `MdeModulePkg/Include/Guid/VariableFormat.h`): a firmware
//! volume header, then a `VARIABLE_STORE_HEADER`, then variable records
//! `0x55AA`-tagged and 4-byte aligned. A record is appended after the last one
//! with state `VAR_ADDED`; the store has no checksum over its records.

use paguro_core::guid::Guid;
use std::path::Path;

const AUTH_VARIABLE: Guid = Guid([
    0x78, 0x2c, 0xf3, 0xaa, 0x7b, 0x94, 0x9a, 0x43, 0xa1, 0x80, 0x2e, 0x14, 0x4e, 0xc3, 0x77, 0x92,
]);
const PLAIN_VARIABLE: Guid = Guid([
    0x16, 0x36, 0xcf, 0xdd, 0x75, 0x32, 0x64, 0x41, 0x98, 0xb6, 0xfe, 0x85, 0x70, 0x7f, 0xfe, 0x7d,
]);
const VAR_ADDED: u8 = 0x3f;

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

pub fn inject(
    path: &Path,
    name: &str,
    vendor: &Guid,
    attrs: u32,
    data: &[u8],
) -> Result<(), String> {
    let mut fv = std::fs::read(path).map_err(|e| e.to_string())?;
    if fv.get(40..44) != Some(b"_FVH") {
        return Err("VARS: no firmware volume header".into());
    }
    let hlen = usize::from(u16_at(&fv, 48).ok_or("VARS: short")?);
    let sig = Guid(
        fv.get(hlen..hlen + 16)
            .ok_or("VARS: short")?
            .try_into()
            .map_err(|_| "VARS")?,
    );
    let header_size = if sig == AUTH_VARIABLE {
        60
    } else if sig == PLAIN_VARIABLE {
        32
    } else {
        return Err("VARS: unknown variable store".into());
    };
    let store_size = u32_at(&fv, hlen + 16).ok_or("VARS: short")? as usize;
    let end = hlen + store_size;
    let mut at = hlen + 28;
    while u16_at(&fv, at) == Some(0x55aa) {
        let (ns, ds) = if header_size == 60 {
            (u32_at(&fv, at + 36), u32_at(&fv, at + 40))
        } else {
            (u32_at(&fv, at + 8), u32_at(&fv, at + 12))
        };
        let (ns, ds) = (
            ns.ok_or("VARS: short")? as usize,
            ds.ok_or("VARS: short")? as usize,
        );
        at = (at + header_size + ns + ds + 3) & !3;
    }
    let mut name16: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    name16.extend([0, 0]);
    let mut rec = vec![0xaa, 0x55, VAR_ADDED, 0];
    rec.extend(attrs.to_le_bytes());
    if header_size == 60 {
        rec.extend([0u8; 8]); // monotonic count
        rec.extend([0u8; 16]); // timestamp
        rec.extend([0u8; 4]); // pubkey index
    }
    rec.extend((name16.len() as u32).to_le_bytes());
    rec.extend((data.len() as u32).to_le_bytes());
    rec.extend(vendor.0);
    rec.extend(&name16);
    rec.extend(data);
    if at + rec.len() > end {
        return Err("VARS: store full".into());
    }
    if fv[at..at + rec.len()].iter().any(|b| *b != 0xff) {
        return Err("VARS: free space is not erased".into());
    }
    fv[at..at + rec.len()].copy_from_slice(&rec);
    std::fs::write(path, fv).map_err(|e| e.to_string())
}
