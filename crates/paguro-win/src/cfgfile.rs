//! `paguro.ini` on the ESP: read, edit, and write with its firmware hash
//! (INTERFACES.md §3). The grammar, schema and serialisation are
//! `paguro_core::config`'s; this module only owns the strings an edit needs
//! and the §3.3 write protocol:
//!
//! ```text
//! copy paguro.ini -> paguro.ini.bak     (the writer's own rollback)
//! write paguro.ini.new
//! PaguroConfigHash <- SHA-256(new bytes)
//! rename paguro.ini.new -> paguro.ini
//! ```
//!
//! A crash between the hash and the rename leaves a hash that matches
//! `.new`, not the primary; the loader then refuses the primary (Secure Boot
//! on) and recovery takes over, and re-running the command completes it.

use paguro_core::config::{self, Config, Efi, Entry, MAX_ENTRIES, Ui, UiMode, UiTheme};
use paguro_core::guid::{Guid, PAGURO_VENDOR};
use paguro_core::ini;
use serde::Serialize;
use serde_json::{Value, json};

use crate::api::{Volume, WinApi, attr, join};
use crate::esp;
use crate::keys::ini_hash;
use crate::out::{CmdError, Exit, guid_text, to_hex};

pub const HASH_VAR: &str = "PaguroConfigHash";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum OwnedEfi {
    Disk { disk: String, path: String },
    File { file: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OwnedEntry {
    pub name: String,
    #[serde(serialize_with = "ser_guid")]
    pub volume: Guid,
    pub root: Option<String>,
    pub efi: OwnedEfi,
}

fn ser_guid<S: serde::Serializer>(g: &Guid, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&guid_text(g))
}

/// An editable `paguro.ini`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OwnedConfig {
    pub default: String,
    pub entries: Vec<OwnedEntry>,
    pub tpm: bool,
    pub setup_tpm: bool,
    pub passphrase: bool,
    pub theme: String,
    pub mode: String,
}

impl OwnedConfig {
    /// What the loader authors on a provisioning boot, minus entries.
    pub fn empty() -> Self {
        OwnedConfig {
            default: String::new(),
            entries: Vec::new(),
            tpm: true,
            setup_tpm: true,
            passphrase: false,
            theme: UiTheme::Dark.name().into(),
            mode: UiMode::Auto.name().into(),
        }
    }

    pub fn from_core(c: &Config<'_>) -> Self {
        OwnedConfig {
            default: c
                .default_entry()
                .map(|e| e.name.to_string())
                .unwrap_or_default(),
            entries: c
                .entries()
                .iter()
                .map(|e| OwnedEntry {
                    name: e.name.into(),
                    volume: e.volume,
                    root: e.root.map(Into::into),
                    efi: match e.efi {
                        Efi::Disk { disk, path } => OwnedEfi::Disk {
                            disk: disk.into(),
                            path: path.into(),
                        },
                        Efi::File(f) => OwnedEfi::File { file: f.into() },
                    },
                })
                .collect(),
            tpm: c.tpm,
            setup_tpm: c.setup_tpm,
            passphrase: c.passphrase,
            theme: c.ui.theme.name().into(),
            mode: c.ui.mode.name().into(),
        }
    }

    /// Serialise through `paguro_core::config::write` (which refuses
    /// anything that would not parse back).
    pub fn to_bytes(&self) -> Result<Vec<u8>, CmdError> {
        if self.entries.is_empty() {
            return Err(CmdError::refused(
                "a configuration needs at least one [Boot.*] entry",
            ));
        }
        if self.entries.len() > MAX_ENTRIES {
            return Err(CmdError::refused(format!("at most {MAX_ENTRIES} entries")));
        }
        let mut entries = [Entry::EMPTY; MAX_ENTRIES];
        for (slot, e) in entries.iter_mut().zip(&self.entries) {
            *slot = Entry {
                name: &e.name,
                volume: e.volume,
                root: e.root.as_deref(),
                efi: match &e.efi {
                    OwnedEfi::Disk { disk, path } => Efi::Disk { disk, path },
                    OwnedEfi::File { file } => Efi::File(file),
                },
            };
        }
        let default = self
            .entries
            .iter()
            .position(|e| e.name == self.default)
            .ok_or_else(|| {
                CmdError::refused(format!("default entry {:?} does not exist", self.default))
            })?;
        let ui = Ui {
            theme: UiTheme::from_name(&self.theme)
                .ok_or_else(|| CmdError::refused(format!("unknown theme {:?}", self.theme)))?,
            mode: UiMode::from_name(&self.mode)
                .ok_or_else(|| CmdError::refused(format!("unknown mode {:?}", self.mode)))?,
        };
        let cfg = Config {
            default,
            entries,
            entry_count: self.entries.len(),
            tpm: self.tpm,
            setup_tpm: self.setup_tpm,
            passphrase: self.passphrase,
            ui,
        };
        let mut buf = vec![0u8; ini::MAX_LEN];
        let n = config::write(&cfg, &mut buf).map_err(|e| {
            CmdError::refused(format!(
                "the configuration is not valid ({e:?}): check entry names ([A-Za-z0-9_-], ≤32) and paths (absolute, \\-separated)"
            ))
        })?;
        buf.truncate(n);
        Ok(buf)
    }
}

/// A configuration as found on the ESP.
pub struct Found {
    pub bytes: Vec<u8>,
    pub parsed: Result<OwnedConfig, String>,
    pub hash: [u8; 32],
    /// `PaguroConfigHash`: `None` absent, `Some(false)` wrong size.
    pub var: Option<Vec<u8>>,
}

impl Found {
    pub fn hash_matches(&self) -> bool {
        self.var.as_deref() == Some(&self.hash[..])
    }
    pub fn to_json(&self) -> Value {
        json!({
            "sha256": to_hex(&self.hash),
            "firmware_hash": self.var.as_ref().map(|v| to_hex(v)),
            "hash_matches": self.hash_matches(),
            "valid": self.parsed.is_ok(),
            "error": self.parsed.as_ref().err(),
            "config": self.parsed.as_ref().ok(),
        })
    }
}

pub fn ini_path(esp: &Volume) -> String {
    esp::path(esp, esp::INI)
}

pub fn read(api: &dyn WinApi, esp: &Volume) -> Result<Option<Found>, CmdError> {
    let Some(bytes) = api.read_file(&ini_path(esp), ini::MAX_LEN)? else {
        return Ok(None);
    };
    let parsed = config::parse(&bytes)
        .map(|c| OwnedConfig::from_core(&c))
        .map_err(|e| format!("{e:?}"));
    let var = api.fw_get(HASH_VAR, &PAGURO_VENDOR)?.map(|v| v.data);
    Ok(Some(Found {
        hash: ini_hash(&bytes),
        bytes,
        parsed,
        var,
    }))
}

/// Write `bytes` as the new `paguro.ini` with the §3.3 protocol.
pub fn commit(api: &dyn WinApi, esp: &Volume, bytes: &[u8]) -> Result<(), CmdError> {
    // Belt and braces: never write what the loader would refuse.
    config::parse(bytes)
        .map_err(|e| CmdError::internal(format!("authored config does not parse: {e:?}")))?;
    let primary = ini_path(esp);
    api.create_dir_all(&esp::dir(esp))?;
    if let Some(old) = api.read_file(&primary, ini::MAX_LEN)? {
        api.write_file(&format!("{primary}.bak"), &old)?;
    }
    let new = format!("{primary}.new");
    api.write_file(&new, bytes)?;
    api.fw_set(HASH_VAR, &PAGURO_VENDOR, &ini_hash(bytes), attr::NV_BS_RT)?;
    api.rename(&new, &primary)?;
    Ok(())
}

/// A Windows path (`C:\paguro\debian.vhd`) → the entry's volume GUID and
/// its NTFS path on that volume (`\paguro\debian.vhd`).
pub fn resolve_windows_path(api: &dyn WinApi, p: &str) -> Result<(Guid, String), CmdError> {
    let v = api.volume_for_path(p)?;
    if !v.filesystem.eq_ignore_ascii_case("NTFS") {
        return Err(CmdError::refused(format!(
            "{p} is on {}, not NTFS",
            v.filesystem
        )));
    }
    let guid = v
        .partition_guid()
        .ok_or_else(|| CmdError::refused(format!("{p}: its volume is not a GPT partition")))?;
    let rest = v
        .mount_points
        .iter()
        .chain(std::iter::once(&v.guid_path))
        .find_map(|m| {
            p.get(..m.len())
                .filter(|h| h.eq_ignore_ascii_case(m))
                .and_then(|_| p.get(m.len()..))
        })
        .ok_or_else(|| CmdError::refused(format!("{p}: cannot express relative to its volume")))?;
    let ntfs = format!("\\{}", rest.trim_start_matches('\\'));
    config::check_path(&ntfs).map_err(|e| CmdError::refused(format!("{p}: {e:?}")))?;
    Ok((guid, ntfs))
}

/// The Windows path of an entry's NTFS path, when its volume is mounted.
pub fn windows_path(
    api: &dyn WinApi,
    volume: &Guid,
    ntfs: &str,
) -> Result<Option<String>, CmdError> {
    let vols = api.volumes()?;
    Ok(vols
        .iter()
        .find(|v| v.partition_guid() == Some(*volume))
        .map(|v| {
            let base = v
                .mount_points
                .first()
                .cloned()
                .unwrap_or_else(|| v.guid_path.clone());
            join(&base, ntfs)
        }))
}

pub fn parse_bool(s: &str) -> Result<bool, CmdError> {
    match s {
        "1" | "on" | "true" | "yes" => Ok(true),
        "0" | "off" | "false" | "no" => Ok(false),
        _ => Err(CmdError::new(
            Exit::Usage,
            format!("expected 0 or 1, got {s:?}"),
        )),
    }
}
