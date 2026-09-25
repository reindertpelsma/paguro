//! `paguro disk create|inspect` — the image file (DESIGN.md §2, §8b).
//!
//! A paguro image is a **fixed** VHD: its payload is a plain run of bytes the
//! kernel module maps extent by extent, and `wsl --mount --vhd` accepts it
//! as is. What the module cannot follow is refused here, before anything
//! depends on it: sparse, compressed and EFS-encrypted files have extents
//! that are not the file's bytes (holes, compression units, ciphertext).

use paguro_core::disk::{self, Format};
use paguro_core::vhd;
use serde_json::{Value, json};

use crate::api::{Extents, FileFacts, WinApi, fattr};
use crate::ctx::Ctx;
use crate::out::{At, CmdError, CmdResult, Exit, Report};

pub const MIN_SIZE: u64 = 64 << 20;
pub const ALIGN: u64 = 1 << 20;

/// `20G`, `20GiB`, `512M`, `1T`, or bytes. Binary units.
pub fn parse_size(s: &str) -> Result<u64, CmdError> {
    let t = s.trim();
    let split = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
    let (num, unit) = t.split_at(split);
    let n: u64 = num
        .parse()
        .map_err(|_| CmdError::new(Exit::Usage, format!("not a size: {s:?}")))?;
    let mul: u64 = match unit.trim().to_ascii_uppercase().as_str() {
        "" | "B" => 1,
        "K" | "KB" | "KIB" => 1 << 10,
        "M" | "MB" | "MIB" => 1 << 20,
        "G" | "GB" | "GIB" => 1 << 30,
        "T" | "TB" | "TIB" => 1 << 40,
        _ => {
            return Err(CmdError::new(
                Exit::Usage,
                format!("unknown size unit in {s:?}"),
            ));
        }
    };
    n.checked_mul(mul)
        .ok_or_else(|| CmdError::new(Exit::Usage, format!("size too large: {s:?}")))
}

/// Why a file cannot be a paguro disk, if it cannot.
pub fn attribute_problems(f: &FileFacts) -> Vec<&'static str> {
    let mut p = Vec::new();
    if f.attributes & fattr::SPARSE != 0 {
        p.push("sparse");
    }
    if f.attributes & fattr::COMPRESSED != 0 {
        p.push("compressed");
    }
    if f.attributes & fattr::ENCRYPTED != 0 {
        p.push("EFS-encrypted");
    }
    p
}

/// Holes and clusters of an extent list; `(fragments, holes, clusters)`.
pub fn extent_summary(e: &Extents) -> (usize, usize, u64) {
    let holes = e.extents.iter().filter(|x| x.lcn.is_none()).count();
    let clusters = e.extents.iter().map(|x| x.clusters).sum();
    (e.extents.len(), holes, clusters)
}

/// NTFS file id → (MFT record, sequence): the identity the loader forwards
/// in the handoff's `IMAGE` record (INTERFACES.md §8).
pub fn mft_identity(id: &[u8; 16]) -> (u64, u16) {
    let mut rec = [0u8; 8];
    rec[..6].copy_from_slice(&id[..6]);
    (u64::from_le_bytes(rec), u16::from_le_bytes([id[6], id[7]]))
}

pub struct Inspection {
    pub json: Value,
    pub problems: Vec<String>,
}

pub fn inspect_path(api: &dyn WinApi, path: &str) -> Result<Inspection, CmdError> {
    let facts = api
        .file_facts(path)?
        .ok_or_else(|| CmdError::not_found(format!("{path}: no such file")))?;
    let mut problems: Vec<String> = attribute_problems(&facts)
        .into_iter()
        .map(String::from)
        .collect();
    let extents = api.retrieval_pointers(path)?;
    let (fragments, holes, clusters) = extent_summary(&extents);
    if holes > 0 {
        problems.push(format!("{holes} unallocated run(s)"));
    }
    let cluster = u64::from(extents.cluster_size);
    if clusters.saturating_mul(cluster) < facts.len {
        problems.push("fewer clusters than the file's length".into());
    }
    let (format, payload, footer_error) = if facts.len >= vhd::FOOTER_LEN {
        let tail = api.read_file_at(path, facts.len - vhd::FOOTER_LEN, 512)?;
        let mut t = [0u8; 512];
        t.copy_from_slice(tail.get(..512).unwrap_or(&[0; 512]));
        let p = disk::detect(facts.len, &t);
        let err = match vhd::fixed_payload_len(&t, facts.len) {
            Ok(_) => None,
            Err(e) => Some(format!("{e:?}")),
        };
        (p.format, p.len, err)
    } else {
        (
            Format::Raw,
            facts.len,
            Some("shorter than a VHD footer".into()),
        )
    };
    let head_len = usize::try_from(payload.min(disk::HEAD_LEN as u64)).unwrap_or(0);
    let efi = if head_len >= 512 {
        let head = api.read_file_at(path, 0, head_len)?;
        match disk::classify(payload, &head) {
            Ok(fs) => {
                let (off, len) = fs.range();
                json!({ "kind": match fs { disk::EfiFs::Esp { .. } => "gpt_esp", disk::EfiFs::Superfloppy(_) => "superfloppy" }, "offset": off, "length": len })
            }
            Err(e) => json!({ "kind": "none", "reason": format!("{e:?}") }),
        }
    } else {
        json!({ "kind": "none", "reason": "empty" })
    };
    let (mft_record, mft_seq) = mft_identity(&facts.file_id);
    let vol = api.volume_for_path(path).ok();
    if let Some(v) = &vol {
        if !v.filesystem.eq_ignore_ascii_case("NTFS") {
            problems.push(format!("on {}, not NTFS", v.filesystem));
        }
    }
    let json = json!({
        "path": path,
        "len": facts.len,
        "allocated": facts.allocated,
        "format": match format { Format::Vhd => "fixed_vhd", Format::Raw => "raw" },
        "payload_len": payload,
        "vhd_footer_error": footer_error,
        "attributes": facts.attributes,
        "sparse": facts.attributes & fattr::SPARSE != 0,
        "compressed": facts.attributes & fattr::COMPRESSED != 0,
        "encrypted": facts.attributes & fattr::ENCRYPTED != 0,
        "file_id": crate::out::to_hex(&facts.file_id),
        "mft_record": mft_record,
        "mft_sequence": mft_seq,
        "cluster_size": extents.cluster_size,
        "fragments": fragments,
        "holes": holes,
        "clusters": clusters,
        "efi_fs": efi,
        "volume": vol.as_ref().map(|v| &v.guid_path),
        "problems": problems,
    });
    Ok(Inspection { json, problems })
}

pub fn inspect(ctx: &Ctx<'_>, path: &str) -> CmdResult {
    let i = inspect_path(ctx.api, path)?;
    let j = &i.json;
    let mut r = Report::new(i.json.clone())
        .line(path.to_string())
        .line(format!(
            "  {} , {} bytes payload, {} fragment(s), cluster {} bytes",
            j.at("format").as_str().unwrap_or("?"),
            j.at("payload_len"),
            j.at("fragments"),
            j.at("cluster_size")
        ))
        .line(format!(
            "  MFT record {} seq {}",
            j.at("mft_record"),
            j.at("mft_sequence")
        ))
        .line(format!(
            "  UEFI file system: {}",
            j.at("efi_fs").at("kind").as_str().unwrap_or("?")
        ));
    if i.problems.is_empty() {
        r = r.line("  usable as a paguro disk");
        Ok(r)
    } else {
        Err(CmdError::check_failed(
            format!("{path} cannot be a paguro disk: {}", i.problems.join(", ")),
            i.json,
        ))
    }
}

pub fn create(ctx: &Ctx<'_>, path: &str, size_arg: &str) -> CmdResult {
    let size = parse_size(size_arg)?;
    if size < MIN_SIZE || size % ALIGN != 0 {
        return Err(CmdError::refused(format!(
            "size must be a multiple of 1 MiB and at least 64 MiB (got {size} bytes)"
        )));
    }
    if !path.to_ascii_lowercase().ends_with(".vhd") {
        return Err(CmdError::refused(
            "the image must be a .vhd file (fixed VHD; VHDX is refused)",
        ));
    }
    if ctx.api.file_facts(path)?.is_some() {
        return Err(CmdError::refused(format!(
            "{path} already exists; paguro never overwrites a disk"
        )));
    }
    let vol = ctx.api.volume_for_path(path)?;
    if !vol.filesystem.eq_ignore_ascii_case("NTFS") {
        return Err(CmdError::refused(format!(
            "{path} is on {}; paguro disks live on NTFS",
            vol.filesystem
        )));
    }
    if vol.free < size + (1 << 30) {
        return Err(CmdError::refused(format!(
            "not enough free space on {} ({} bytes free, {} needed plus 1 GiB headroom)",
            vol.guid_path, vol.free, size
        )));
    }
    let plan =
        json!({ "path": path, "size": size, "volume": vol.guid_path, "format": "fixed_vhd" });
    if ctx.dry_run {
        return Ok(
            Report::new(plan).line(format!("would create a {size}-byte fixed VHD at {path}"))
        );
    }
    ctx.need_admin()?;
    if let Some(parent) = path.rfind('\\').and_then(|i| path.get(..i)) {
        if parent.len() > 2 {
            ctx.api.create_dir_all(parent)?;
        }
    }
    ctx.api.vhd_create_fixed(path, size)?;
    let i = inspect_path(ctx.api, path)?;
    let payload_ok = i.json.at("format") == "fixed_vhd" && i.json.at("payload_len") == size;
    if !i.problems.is_empty() || !payload_ok {
        // Install only adds (DESIGN.md §6b): take back what we just made.
        let _ = ctx.api.remove_file(path);
        return Err(CmdError::check_failed(
            format!(
                "the new disk failed verification and was removed: {}",
                if i.problems.is_empty() {
                    "not a fixed VHD of the requested size".into()
                } else {
                    i.problems.join(", ")
                }
            ),
            i.json,
        ));
    }
    Ok(Report::new(i.json).line(format!("created {path}: fixed VHD, {size} bytes, verified")))
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(parse_size("20G").unwrap(), 20 << 30);
        assert_eq!(parse_size("512MiB").unwrap(), 512 << 20);
        assert_eq!(parse_size("1t").unwrap(), 1 << 40);
        assert_eq!(parse_size("4096").unwrap(), 4096);
        assert!(parse_size("G").is_err());
        assert!(parse_size("12X").is_err());
        assert!(parse_size("99999999999999999999T").is_err());
        assert!(parse_size("20000000T").is_err());
    }

    #[test]
    fn mft_identity_splits_the_file_id() {
        let mut id = [0u8; 16];
        id[0] = 0x2a;
        id[6] = 3;
        assert_eq!(mft_identity(&id), (42, 3));
    }
}
