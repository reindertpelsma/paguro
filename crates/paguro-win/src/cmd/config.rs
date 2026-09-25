//! `paguro config show|validate|set` — the only editor of `paguro.ini`
//! (INTERFACES.md §3, §11.2).

use paguro_core::guid::Guid;
use serde_json::json;

use crate::cfgfile::{self, OwnedConfig, OwnedEfi, OwnedEntry, resolve_windows_path};
use crate::ctx::Ctx;
use crate::out::{CmdError, CmdResult, Exit, Report, guid_text};

pub fn show(ctx: &Ctx<'_>) -> CmdResult {
    let esp = ctx.esp()?;
    let Some(f) = cfgfile::read(ctx.api, &esp)? else {
        return Err(CmdError::not_found("no paguro.ini on the ESP"));
    };
    let mut r = Report::new(f.to_json());
    r = r.lines(String::from_utf8_lossy(&f.bytes).lines().map(String::from));
    if !f.hash_matches() {
        r = r.warn("PaguroConfigHash does not match paguro.ini: with Secure Boot on the loader will refuse it");
    }
    Ok(r)
}

pub fn validate(ctx: &Ctx<'_>) -> CmdResult {
    let esp = ctx.esp()?;
    let Some(f) = cfgfile::read(ctx.api, &esp)? else {
        return Err(CmdError::not_found("no paguro.ini on the ESP"));
    };
    let mut problems = Vec::new();
    if let Err(e) = &f.parsed {
        problems.push(format!("does not parse: {e}"));
    }
    match &f.var {
        None => {
            problems.push("PaguroConfigHash is absent (NVRAM cleared, or never written)".into())
        }
        Some(v) if v.len() != crate::cmd::efi::DIGEST_LEN => {
            problems.push("PaguroConfigHash has the wrong size".into())
        }
        Some(_) if !f.hash_matches() => {
            problems.push("PaguroConfigHash does not match the file".into())
        }
        Some(_) => {}
    }
    if let Ok(c) = &f.parsed {
        for e in &c.entries {
            let files = [
                e.root.as_deref(),
                match &e.efi {
                    OwnedEfi::Disk { disk, .. } => Some(disk.as_str()),
                    OwnedEfi::File { file } => Some(file.as_str()),
                },
            ];
            for p in files.into_iter().flatten() {
                match cfgfile::windows_path(ctx.api, &e.volume, p)? {
                    None => problems.push(format!(
                        "[Boot.{}] volume {} is not mounted in Windows",
                        e.name,
                        guid_text(&e.volume)
                    )),
                    Some(w) if ctx.api.file_facts(&w)?.is_none() => {
                        problems.push(format!("[Boot.{}] {w} does not exist", e.name));
                    }
                    Some(_) => {}
                }
            }
        }
    }
    let data = json!({ "file": f.to_json(), "problems": problems });
    if problems.is_empty() {
        Ok(Report::new(data).line("paguro.ini is valid and its firmware hash matches"))
    } else {
        Err(CmdError::check_failed(
            format!("paguro.ini: {}", problems.join("; ")),
            data,
        ))
    }
}

/// `paguro config set` arguments; every field optional.
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct SetArgs {
    pub entry: Option<String>,
    pub volume: Option<String>,
    pub root: Option<String>,
    pub efi_disk: Option<String>,
    pub efi: Option<String>,
    pub efi_file: Option<String>,
    pub default: Option<String>,
    pub remove_entry: Option<String>,
    pub tpm: Option<bool>,
    pub setup_tpm: Option<bool>,
    pub passphrase: Option<bool>,
    pub theme: Option<String>,
    pub mode: Option<String>,
    pub keyboard: Option<String>,
}

fn is_windows_path(p: &str) -> bool {
    p.get(1..2) == Some(":") || p.starts_with("\\\\")
}

/// Resolve one path argument to (volume, NTFS path).
fn resolve(ctx: &Ctx<'_>, p: &str, volume: &mut Option<Guid>) -> Result<String, CmdError> {
    if is_windows_path(p) {
        let (g, ntfs) = resolve_windows_path(ctx.api, p)?;
        if let Some(v) = volume {
            if *v != g {
                return Err(CmdError::refused(format!(
                    "{p} is on volume {}, but the entry's files must share one volume ({})",
                    guid_text(&g),
                    guid_text(v)
                )));
            }
        }
        *volume = Some(g);
        Ok(ntfs)
    } else {
        Ok(p.to_string())
    }
}

/// A `[UI] keyboard` name (INTERFACES.md §13.5).
pub fn keyboard(name: &str) -> Result<paguro_core::config::Keyboard, CmdError> {
    paguro_core::config::Keyboard::ALL
        .iter()
        .copied()
        .find(|k| k.name().eq_ignore_ascii_case(name))
        .ok_or_else(|| {
            let all: Vec<&str> = paguro_core::config::Keyboard::ALL
                .iter()
                .map(|k| k.name())
                .collect();
            CmdError::new(
                Exit::Usage,
                format!("unknown keyboard {name:?} (one of {})", all.join(", ")),
            )
        })
}

/// Apply `a` to `c` (pure but for path resolution).
pub fn apply(ctx: &Ctx<'_>, c: &mut OwnedConfig, a: &SetArgs) -> Result<Vec<String>, CmdError> {
    let mut changes = Vec::new();
    if let Some(name) = &a.remove_entry {
        let before = c.entries.len();
        c.entries.retain(|e| &e.name != name);
        if c.entries.len() == before {
            return Err(CmdError::not_found(format!("no entry {name:?}")));
        }
        if c.default == *name {
            c.default = c
                .entries
                .first()
                .map(|e| e.name.clone())
                .unwrap_or_default();
        }
        changes.push(format!("removed [Boot.{name}]"));
    }
    let touches_entry = a.volume.is_some()
        || a.root.is_some()
        || a.efi_disk.is_some()
        || a.efi.is_some()
        || a.efi_file.is_some();
    if touches_entry && a.entry.is_none() {
        return Err(CmdError::new(
            Exit::Usage,
            "--entry NAME is required to change an entry",
        ));
    }
    if let Some(name) = &a.entry {
        let existing = c.entries.iter().position(|e| &e.name == name);
        let mut volume = match &a.volume {
            Some(v) => Some(
                Guid::parse(v)
                    .map_err(|e| CmdError::new(Exit::Usage, format!("--volume: {e:?}")))?,
            ),
            None => existing.and_then(|i| c.entries.get(i)).map(|e| e.volume),
        };
        let old = existing.and_then(|i| c.entries.get(i)).cloned();
        let root = match &a.root {
            Some(r) => Some(resolve(ctx, r, &mut volume)?),
            None => old.as_ref().and_then(|o| o.root.clone()),
        };
        let efi = if let Some(f) = &a.efi_file {
            if a.efi_disk.is_some() || a.efi.is_some() {
                return Err(CmdError::new(
                    Exit::Usage,
                    "--efi-file excludes --efi-disk and --efi",
                ));
            }
            OwnedEfi::File {
                file: resolve(ctx, f, &mut volume)?,
            }
        } else {
            let (old_disk, old_path) = match old.as_ref().map(|o| &o.efi) {
                Some(OwnedEfi::Disk { disk, path }) => (Some(disk.clone()), Some(path.clone())),
                _ => (None, None),
            };
            let disk = match &a.efi_disk {
                Some(d) => Some(resolve(ctx, d, &mut volume)?),
                // A changed root carries an efi_disk that was the old root.
                None => match (old_disk, &old) {
                    (Some(d), Some(o)) if Some(&d) != o.root.as_ref() => Some(d),
                    _ => None,
                },
            }
            .or_else(|| root.clone());
            match (disk, old.as_ref().map(|o| &o.efi)) {
                (Some(disk), _) => OwnedEfi::Disk {
                    disk,
                    path: a.efi.clone().or(old_path).unwrap_or_else(|| {
                        format!(
                            "\\EFI\\BOOT\\BOOT{}.EFI",
                            ctx.api.arch().to_ascii_uppercase()
                        )
                    }),
                },
                (None, Some(OwnedEfi::File { file })) => OwnedEfi::File { file: file.clone() },
                (None, _) => {
                    return Err(CmdError::refused(format!(
                        "[Boot.{name}] needs --root or --efi-file"
                    )));
                }
            }
        };
        let volume = volume.ok_or_else(|| {
            CmdError::refused(format!(
                "[Boot.{name}] needs --volume, or a Windows path (C:\\…) to take it from"
            ))
        })?;
        let entry = OwnedEntry {
            name: name.clone(),
            volume,
            root,
            efi,
        };
        match existing.and_then(|i| c.entries.get_mut(i)) {
            Some(slot) => {
                if *slot != entry {
                    changes.push(format!("changed [Boot.{name}]"));
                }
                *slot = entry;
            }
            None => {
                c.entries.push(entry);
                changes.push(format!("added [Boot.{name}]"));
            }
        }
        if c.default.is_empty() {
            c.default = name.clone();
        }
    }
    if let Some(d) = &a.default {
        if !c.entries.iter().any(|e| &e.name == d) {
            return Err(CmdError::not_found(format!(
                "no entry {d:?} to make the default"
            )));
        }
        if c.default != *d {
            changes.push(format!("default = {d}"));
        }
        c.default = d.clone();
    }
    for (flag, field, name) in [
        (&a.tpm, &mut c.tpm, "TPM"),
        (&a.setup_tpm, &mut c.setup_tpm, "SetupTPM"),
        (&a.passphrase, &mut c.passphrase, "Passphrase"),
    ] {
        if let Some(b) = *flag {
            if *field != b {
                changes.push(format!("[{name}] enabled = {}", u8::from(b)));
            }
            *field = b;
        }
    }
    if let Some(t) = &a.theme {
        c.theme = t.clone();
        changes.push(format!("[UI] theme = {t}"));
    }
    if let Some(m) = &a.mode {
        c.mode = m.clone();
        changes.push(format!("[UI] mode = {m}"));
    }
    if let Some(k) = &a.keyboard {
        let k = keyboard(k)?;
        if c.keyboard != k.name() {
            changes.push(format!("[UI] keyboard = {}", k.name()));
        }
        c.keyboard = k.name().into();
    }
    Ok(changes)
}

pub fn set(ctx: &Ctx<'_>, a: &SetArgs) -> CmdResult {
    edit(ctx, |c| apply(ctx, c, a))
}

/// Read `paguro.ini` (or start from an empty one), apply `f`, and write the
/// result with the §3.3 protocol. `f` returns the changes it made, in words.
pub fn edit(
    ctx: &Ctx<'_>,
    f: impl FnOnce(&mut OwnedConfig) -> Result<Vec<String>, CmdError>,
) -> CmdResult {
    let esp = ctx.esp()?;
    let found = cfgfile::read(ctx.api, &esp)?;
    let mut c = match &found {
        Some(f) => f.parsed.clone().map_err(|e| {
            CmdError::refused(format!(
                "the existing paguro.ini does not parse ({e}); fix or remove it first"
            ))
        })?,
        None => OwnedConfig::empty(),
    };
    let changes = f(&mut c)?;
    let bytes = c.to_bytes()?;
    let unchanged = found
        .as_ref()
        .is_some_and(|f| f.bytes == bytes && f.hash_matches());
    let data = json!({
        "changes": changes,
        "config": c,
        "sha256": crate::out::to_hex(&crate::keys::ini_hash(&bytes)),
        "written": !ctx.dry_run && !unchanged,
    });
    let mut r = Report::new(data).lines(changes.iter().cloned());
    if unchanged {
        return Ok(r.line("paguro.ini unchanged"));
    }
    if !ctx.dry_run {
        ctx.need_admin()?;
        cfgfile::commit(ctx.api, &esp, &bytes)?;
        r = r.line("paguro.ini written; PaguroConfigHash updated");
    }
    if found.is_some() {
        r = r.warn(
            "the configuration changed, so PCR 12 will too: the TPM seal no longer matches. \
             Run `paguro stage-setup` before restarting into Linux, or the loader asks for the recovery path",
        );
    }
    Ok(r)
}
