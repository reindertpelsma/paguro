//! The ESP and paguro's files on it (INTERFACES.md §2, DESIGN.md §7).
//!
//! ```text
//! \EFI\paguro\shim<arch>.efi   a distribution's signed shim, unchanged
//! \EFI\paguro\mm<arch>.efi     its MokManager
//! \EFI\paguro\paguro.efi       the loader (MOK-signed)
//! \EFI\paguro\grub<arch>.efi   the loader again, under shim's default
//!                              second-stage name (§2.1: for shims that
//!                              ignore the entry's load options)
//! ```
//!
//! Install keeps a byte-identical copy of each file and its SHA-256 under
//! `%ProgramData%\paguro\esp\` (the manifest), so repair restores exactly
//! what was installed and verification compares against the recorded hash,
//! not against "is it signed" (DESIGN.md §7). Every ESP write is
//! write-new-then-rename.

use paguro_core::guid::Guid;
use paguro_core::seal;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::api::{Volume, WinApi, join};
use crate::out::{CmdError, Exit, guid_text, to_hex};

/// Largest ESP file the tool reads (shim and the loader are a few MiB).
pub const MAX_ESP_FILE: usize = 64 << 20;
/// Largest `manifest.json` read.
const MAX_MANIFEST: usize = 1 << 20;
/// The DOS header's `e_magic` a PE image starts with (PE/COFF spec §3).
const PE_DOS_MAGIC: &[u8] = b"MZ";
pub const DIR: &str = "EFI\\paguro";
pub const INI: &str = "paguro.ini";
pub const LOADER: &str = "paguro.efi";

/// Find the ESP: the one GPT partition of the ESP type, or when there are
/// several, the one on the disk holding the system drive.
pub fn find(api: &dyn WinApi, explicit: Option<&str>) -> Result<Volume, CmdError> {
    let vols = api.volumes()?;
    if let Some(e) = explicit {
        return vols
            .into_iter()
            .find(|v| {
                v.guid_path.eq_ignore_ascii_case(e)
                    || v.mount_points.iter().any(|m| m.eq_ignore_ascii_case(e))
            })
            .ok_or_else(|| CmdError::not_found(format!("no volume {e}")));
    }
    let esps: Vec<&Volume> = vols.iter().filter(|v| v.is_esp()).collect();
    match esps.as_slice() {
        [] => Err(CmdError::not_found(
            "no EFI System Partition found (is this a UEFI/GPT system?)",
        )),
        [one] => Ok((*one).clone()),
        many => {
            let sys = api.system_drive();
            let disk = vols
                .iter()
                .find(|v| v.drive().is_some_and(|d| d.eq_ignore_ascii_case(&sys)))
                .and_then(|v| v.location.as_ref().map(|l| l.disk_number));
            let on_sys: Vec<&&Volume> = many
                .iter()
                .filter(|v| v.location.as_ref().map(|l| l.disk_number) == disk)
                .collect();
            match on_sys.as_slice() {
                [one] => Ok((**one).clone()),
                _ => Err(CmdError::refused(
                    "several EFI System Partitions; choose one with --esp",
                )),
            }
        }
    }
}

pub fn dir(esp: &Volume) -> String {
    join(&esp.guid_path, DIR)
}

pub fn path(esp: &Volume, name: &str) -> String {
    join(&dir(esp), name)
}

pub fn shim_name(arch: &str) -> String {
    format!("shim{arch}.efi")
}
pub fn mm_name(arch: &str) -> String {
    format!("mm{arch}.efi")
}
pub fn fallback_name(arch: &str) -> String {
    format!("grub{arch}.efi")
}

/// Install-time names, in install order: shim and MokManager before the
/// loader, so a half-finished install never has a loader without its shim.
pub fn installed_names(arch: &str) -> [String; 4] {
    [
        shim_name(arch),
        mm_name(arch),
        LOADER.to_string(),
        fallback_name(arch),
    ]
}

pub fn sha256_hex(b: &[u8]) -> String {
    to_hex(&Sha256::digest(b))
}

/// Write `path` through `path.new` and a rename (INTERFACES.md §3.3's rule,
/// applied to every file paguro writes on the ESP).
pub fn write_atomic(api: &dyn WinApi, path: &str, data: &[u8]) -> Result<(), CmdError> {
    let tmp = format!("{path}.new");
    api.write_file(&tmp, data)?;
    api.rename(&tmp, path)?;
    Ok(())
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestFile {
    pub name: String,
    pub sha256: String,
    pub len: u64,
}

/// `%ProgramData%\paguro\esp\manifest.json`. Windows-private (no other
/// component reads it); versioned like everything else.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub arch: String,
    pub installed_unix: u64,
    pub files: Vec<ManifestFile>,
}

pub fn store_dir(api: &dyn WinApi) -> String {
    join(&api.program_data(), "paguro\\esp")
}

pub fn read_manifest(api: &dyn WinApi) -> Result<Option<Manifest>, CmdError> {
    let p = join(&store_dir(api), "manifest.json");
    let Some(b) = api.read_file(&p, MAX_MANIFEST)? else {
        return Ok(None);
    };
    let m: Manifest = serde_json::from_slice(&b)
        .map_err(|e| CmdError::new(Exit::Platform, format!("{p}: {e}")))?;
    if m.version != 1 {
        return Err(CmdError::refused(format!(
            "{p}: unknown manifest version {}",
            m.version
        )));
    }
    Ok(Some(m))
}

/// The files `esp install` takes, as bytes.
pub struct Inputs {
    pub shim: Vec<u8>,
    pub mm: Vec<u8>,
    pub loader: Vec<u8>,
}

fn looks_like_pe(b: &[u8]) -> bool {
    b.get(..PE_DOS_MAGIC.len()) == Some(PE_DOS_MAGIC)
}

/// Install or refresh the ESP files and the saved copies.
pub fn install(
    api: &dyn WinApi,
    esp: &Volume,
    inp: &Inputs,
    dry_run: bool,
) -> Result<Value, CmdError> {
    for (what, b) in [
        ("shim", &inp.shim),
        ("MokManager", &inp.mm),
        ("loader", &inp.loader),
    ] {
        if !looks_like_pe(b) {
            return Err(CmdError::refused(format!(
                "the {what} is not a PE/COFF image"
            )));
        }
    }
    let arch = api.arch();
    let names = installed_names(arch);
    let bodies = [&inp.shim, &inp.mm, &inp.loader, &inp.loader];
    let files: Vec<ManifestFile> = names
        .iter()
        .zip(bodies)
        .map(|(n, b)| ManifestFile {
            name: n.clone(),
            sha256: sha256_hex(b),
            len: b.len() as u64,
        })
        .collect();
    let plan = json!({
        "esp": esp.guid_path,
        "directory": dir(esp),
        "files": files,
        "store": store_dir(api),
    });
    if dry_run {
        return Ok(plan);
    }
    // Saved copies first: the ESP is the part feature updates rewrite.
    let store = store_dir(api);
    api.create_dir_all(&store)?;
    for (n, b) in names.iter().zip(bodies) {
        write_atomic(api, &join(&store, n), b)?;
    }
    api.create_dir_all(&dir(esp))?;
    for (n, b) in names.iter().zip(bodies) {
        write_atomic(api, &path(esp, n), b)?;
    }
    let m = Manifest {
        version: 1,
        arch: arch.to_string(),
        installed_unix: api.now_unix(),
        files,
    };
    let body = serde_json::to_vec_pretty(&m).map_err(|e| CmdError::internal(e.to_string()))?;
    write_atomic(api, &join(&store, "manifest.json"), &body)?;
    Ok(plan)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileState {
    Ok,
    Missing,
    Modified,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FileCheck {
    pub name: String,
    pub state: FileState,
    pub expected_sha256: String,
    pub actual_sha256: Option<String>,
}

/// Compare the ESP with the manifest.
pub fn verify(api: &dyn WinApi, esp: &Volume) -> Result<Vec<FileCheck>, CmdError> {
    let m = read_manifest(api)?.ok_or_else(|| {
        CmdError::not_found("paguro's ESP files were never installed (no manifest)")
    })?;
    let mut out = Vec::new();
    for f in &m.files {
        let actual = api.read_file(&path(esp, &f.name), MAX_ESP_FILE)?;
        let actual = actual.map(|b| sha256_hex(&b));
        let state = match &actual {
            None => FileState::Missing,
            Some(h) if *h == f.sha256 => FileState::Ok,
            Some(_) => FileState::Modified,
        };
        out.push(FileCheck {
            name: f.name.clone(),
            state,
            expected_sha256: f.sha256.clone(),
            actual_sha256: actual,
        });
    }
    Ok(out)
}

/// Restore every file that is missing or differs, from the saved copies —
/// byte-identical restorations only (DESIGN.md §7, "Auto-repair silently").
pub fn repair(api: &dyn WinApi, esp: &Volume, dry_run: bool) -> Result<Vec<FileCheck>, CmdError> {
    let checks = verify(api, esp)?;
    let store = store_dir(api);
    let mut restored = Vec::new();
    for c in checks.iter().filter(|c| c.state != FileState::Ok) {
        let saved = api
            .read_file(&join(&store, &c.name), MAX_ESP_FILE)?
            .ok_or_else(|| {
                CmdError::not_found(format!(
                    "saved copy of {} is missing; run `paguro esp install`",
                    c.name
                ))
            })?;
        if sha256_hex(&saved) != c.expected_sha256 {
            return Err(CmdError::refused(format!(
                "saved copy of {} does not match its recorded hash; refusing to restore it",
                c.name
            )));
        }
        if !dry_run {
            api.create_dir_all(&dir(esp))?;
            write_atomic(api, &path(esp, &c.name), &saved)?;
        }
        restored.push(c.clone());
    }
    Ok(restored)
}

/// One `\EFI\paguro\<volume-guid>\` directory and the seal files in it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VolumeDir {
    pub volume: String,
    pub seals: Vec<SealState>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SealState {
    pub file: String,
    pub present: bool,
    /// `None` when absent; `Some(false)` when present but malformed.
    pub well_formed: Option<bool>,
    /// PIN bypass only: its TPM clock deadline.
    pub deadline: Option<u64>,
}

pub fn volume_dir(esp: &Volume, volume: &Guid) -> String {
    join(&dir(esp), &guid_text(volume))
}

/// The per-volume seal directories and what they hold.
pub fn seal_dirs(api: &dyn WinApi, esp: &Volume) -> Result<Vec<VolumeDir>, CmdError> {
    let Some(entries) = api.list_dir(&dir(esp))? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for e in entries.iter().filter(|e| e.is_dir) {
        let Ok(g) = Guid::parse(&e.name) else {
            continue;
        };
        let mut seals = Vec::new();
        for kind in seal::Kind::ALL {
            let p = join(&volume_dir(esp, &g), kind.file_name());
            let b = api.read_file(&p, seal::MAX_FILE)?;
            let parsed = b.as_deref().map(|b| seal::read(kind, b));
            seals.push(SealState {
                file: kind.file_name().to_string(),
                present: b.is_some(),
                well_formed: parsed.map(|p| p.is_ok()),
                deadline: parsed.and_then(|p| p.ok()).and_then(|s| s.deadline),
            });
        }
        out.push(VolumeDir {
            volume: guid_text(&g),
            seals,
        });
    }
    Ok(out)
}
