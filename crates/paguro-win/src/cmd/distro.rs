//! `paguro distro list|rename|remove|grow|enter|leave` — the distributions
//! screen (INTERFACES.md §11.8 item 2): paguro's bootable images (the
//! `[Boot.*]` entries of `paguro.ini`) next to the machine's WSL2
//! distributions, which `paguro install --from-wsl` makes bootable.
//!
//! - `grow` is a **stub**: growing an image needs the Linux side (DESIGN
//!   §5.6), which does not exist yet.
//! - `enter` attaches an image to WSL2 bare and names the shell to run; the
//!   privileged, chroot-ready container of §11.7 is Linux-side work, so the
//!   shell is **for now** a root shell in the default WSL2 distribution
//!   with the disk visible as a block device.

use serde::Serialize;
use serde_json::{Value, json};

use crate::cfgfile::{self, OwnedEfi};
use crate::cmd::config;
use crate::ctx::Ctx;
use crate::out::{CmdError, CmdResult, Exit, Report, guid_text};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WslDistro {
    pub name: String,
    pub state: String,
    pub version: u32,
    pub default: bool,
}

/// `wsl.exe -l -v`, which writes UTF-16: tolerate the NULs a byte-wise
/// decode leaves, and a BOM.
pub fn parse_wsl_list(out: &str) -> Vec<WslDistro> {
    let clean: String = out
        .chars()
        .filter(|&c| c != '\0' && c != '\u{feff}')
        .collect();
    clean
        .lines()
        .skip_while(|l| !l.trim_start_matches('*').trim_start().starts_with("NAME"))
        .skip(1)
        .filter_map(|l| {
            let default = l.trim_start().starts_with('*');
            let mut it = l.trim_start().trim_start_matches('*').split_whitespace();
            let name = it.next()?.to_string();
            let state = it.next()?.to_string();
            let version = it.next()?.parse().ok()?;
            Some(WslDistro {
                name,
                state,
                version,
                default,
            })
        })
        .collect()
}

pub fn wsl_distros(ctx: &Ctx<'_>) -> Vec<WslDistro> {
    match ctx.api.run("wsl.exe", &["--list", "--verbose"], None) {
        Ok(o) if o.ok() => parse_wsl_list(&o.stdout),
        _ => Vec::new(),
    }
}

/// One row of the list: an image paguro boots, or a WSL2 distribution.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Distribution {
    pub name: String,
    /// `image` (a `[Boot.*]` entry) or `wsl`.
    pub kind: &'static str,
    pub default: bool,
    /// The image's Windows path (`None`: its volume is not mounted, or WSL).
    pub path: Option<String>,
    /// Bytes on disk (the image file; `None` for WSL or a missing file).
    pub size: Option<u64>,
    pub exists: bool,
    /// Boots on the metal through paguro.
    pub bootable: bool,
    pub volume: Option<String>,
    pub wsl_state: Option<String>,
    pub wsl_version: Option<u32>,
}

pub fn distributions(ctx: &Ctx<'_>) -> Result<Vec<Distribution>, CmdError> {
    let mut out = Vec::new();
    if let Ok(esp) = ctx.esp() {
        if let Some(found) = cfgfile::read(ctx.api, &esp)? {
            if let Ok(c) = &found.parsed {
                for e in &c.entries {
                    let ntfs = e.root.clone().or_else(|| match &e.efi {
                        OwnedEfi::File { file } => Some(file.clone()),
                        OwnedEfi::Disk { disk, .. } => Some(disk.clone()),
                    });
                    let path = match &ntfs {
                        Some(p) => cfgfile::windows_path(ctx.api, &e.volume, p)?,
                        None => None,
                    };
                    let facts = match &path {
                        Some(p) => ctx.api.file_facts(p).ok().flatten(),
                        None => None,
                    };
                    out.push(Distribution {
                        name: e.name.clone(),
                        kind: "image",
                        default: c.default == e.name,
                        exists: facts.is_some(),
                        size: facts.map(|f| f.len),
                        path,
                        bootable: true,
                        volume: Some(guid_text(&e.volume)),
                        wsl_state: None,
                        wsl_version: None,
                    });
                }
            }
        }
    }
    for w in wsl_distros(ctx) {
        out.push(Distribution {
            name: w.name,
            kind: "wsl",
            default: false,
            path: None,
            size: None,
            exists: true,
            bootable: false,
            volume: None,
            wsl_state: Some(w.state),
            wsl_version: Some(w.version),
        });
    }
    Ok(out)
}

pub fn list(ctx: &Ctx<'_>) -> CmdResult {
    let d = distributions(ctx)?;
    let lines: Vec<String> = d
        .iter()
        .map(|x| {
            format!(
                "{}{:<20} {:<6} {:>8} {}",
                if x.default { "* " } else { "  " },
                x.name,
                x.kind,
                x.size
                    .map_or("-".to_string(), |s| format!("{} GB", s >> 30)),
                x.path.as_deref().unwrap_or(""),
            )
        })
        .collect();
    Ok(Report::new(json!({ "distributions": d })).lines(lines))
}

fn image<'d>(all: &'d [Distribution], name: &str) -> Result<&'d Distribution, CmdError> {
    all.iter()
        .find(|d| d.kind == "image" && d.name == name)
        .ok_or_else(|| CmdError::not_found(format!("no distribution {name:?} in paguro.ini")))
}

pub fn rename(ctx: &Ctx<'_>, name: &str, new_name: &str) -> CmdResult {
    if !paguro_core::config::check_name(new_name) {
        return Err(CmdError::new(
            Exit::Usage,
            "a distribution name must match [A-Za-z0-9_-]{1,32}",
        ));
    }
    config::edit(ctx, |c| {
        if c.entries.iter().any(|e| e.name == new_name) {
            return Err(CmdError::refused(format!("{new_name:?} exists already")));
        }
        let e = c
            .entries
            .iter_mut()
            .find(|e| e.name == name)
            .ok_or_else(|| CmdError::not_found(format!("no distribution {name:?}")))?;
        e.name = new_name.into();
        if c.default == name {
            c.default = new_name.into();
        }
        Ok(vec![format!("renamed [Boot.{name}] to [Boot.{new_name}]")])
    })
}

pub fn remove(ctx: &Ctx<'_>, name: &str, delete_image: bool, yes: bool) -> CmdResult {
    let all = distributions(ctx)?;
    let d = image(&all, name)?.clone();
    if delete_image && !yes && !ctx.dry_run {
        return Err(CmdError::refused(
            "deleting the image destroys that Linux installation: pass --yes (or --dry-run to see the plan)",
        ));
    }
    let edit = config::SetArgs {
        remove_entry: Some(name.into()),
        ..config::SetArgs::default()
    };
    let mut r = config::edit(ctx, |c| config::apply(ctx, c, &edit))?;
    let mut deleted = false;
    if delete_image {
        if let Some(p) = &d.path {
            if !ctx.dry_run {
                deleted = ctx.api.remove_file(p)?;
            }
            r = r.line(format!(
                "{} {p}",
                if ctx.dry_run {
                    "would delete"
                } else {
                    "deleted"
                }
            ));
        }
    }
    if let Some(o) = r.data.as_object_mut() {
        o.insert("removed".into(), json!(name));
        o.insert("image".into(), json!(d.path));
        o.insert("image_deleted".into(), json!(deleted));
    }
    Ok(r)
}

pub fn grow(_ctx: &Ctx<'_>, name: &str, size: &str) -> CmdResult {
    Err(CmdError::refused(format!(
        "STUB: growing {name} to {size} needs the Linux side (DESIGN §5.6: the new extents are claimed and verified by Linux), which is not built yet"
    ))
    .with_data(json!({ "stub": true, "name": name, "size": size })))
}

/// The image to attach: a distribution's, or a `.vhd`/`.vhdx` path.
fn target(ctx: &Ctx<'_>, name: Option<&str>, path: Option<&str>) -> Result<String, CmdError> {
    match (name, path) {
        (Some(n), None) => {
            let all = distributions(ctx)?;
            image(&all, n)?
                .path
                .clone()
                .ok_or_else(|| CmdError::not_found(format!("{n}: its volume is not mounted")))
        }
        (None, Some(p)) => Ok(p.to_string()),
        _ => Err(CmdError::new(
            Exit::Usage,
            "give a distribution name or --path, not both",
        )),
    }
}

/// The shell `enter` names (run by the front end, attached to its console).
pub const SHELL: [&str; 3] = ["wsl.exe", "--user", "root"];

pub fn enter(ctx: &Ctx<'_>, name: Option<&str>, path: Option<&str>) -> CmdResult {
    let p = target(ctx, name, path)?;
    let lower = p.to_ascii_lowercase();
    if !(lower.ends_with(".vhd") || lower.ends_with(".vhdx")) {
        return Err(CmdError::refused(format!(
            "{p}: only .vhd and .vhdx files can be attached"
        )));
    }
    let data = json!({
        "path": p,
        "attached": !ctx.dry_run,
        "command": SHELL,
        "stub": "a root shell in the default WSL2 distribution with the disk attached bare (lsblk shows it); the privileged chroot-ready container (INTERFACES §11.7) is Linux-side work",
    });
    if ctx.dry_run {
        return Ok(Report::new(data).line(format!("would attach {p} to WSL2")));
    }
    ctx.need_admin()?;
    let o = ctx
        .api
        .run("wsl.exe", &["--mount", "--vhd", &p, "--bare"], None)?;
    if !o.ok() {
        return Err(CmdError::new(
            Exit::Platform,
            format!("wsl --mount failed ({}): {}", o.status, o.stderr.trim()),
        ));
    }
    Ok(Report::new(data)
        .line(format!("{p} attached to WSL2 (bare)"))
        .line(format!("shell: {}", SHELL.join(" ")))
        .warn("STUB: a plain root shell in WSL2, not yet the privileged container of INTERFACES §11.7"))
}

pub fn leave(ctx: &Ctx<'_>, name: Option<&str>, path: Option<&str>) -> CmdResult {
    let p = target(ctx, name, path)?;
    let data = json!({ "path": p, "detached": !ctx.dry_run });
    if ctx.dry_run {
        return Ok(Report::new(data).line(format!("would detach {p} from WSL2")));
    }
    ctx.need_admin()?;
    let o = ctx.api.run("wsl.exe", &["--unmount", &p], None)?;
    if !o.ok() {
        return Err(CmdError::new(
            Exit::Platform,
            format!("wsl --unmount failed ({}): {}", o.status, o.stderr.trim()),
        ));
    }
    Ok(Report::new(data).line(format!("{p} detached from WSL2")))
}

/// For the JSON of other commands.
pub fn to_value(d: &[Distribution]) -> Value {
    serde_json::to_value(d).unwrap_or(Value::Null)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn wsl_list_utf16_and_default() {
        let text = "  NAME      STATE           VERSION\r\n* Ubuntu    Running         2\r\n  Debian    Stopped         2\r\n";
        let utf16ish: String = text.chars().flat_map(|c| [c, '\0']).collect();
        for t in [text.to_string(), format!("\u{feff}{utf16ish}")] {
            let l = parse_wsl_list(&t);
            assert_eq!(l.len(), 2);
            assert_eq!(l[0].name, "Ubuntu");
            assert!(l[0].default);
            assert_eq!(l[1].state, "Stopped");
            assert_eq!(l[1].version, 2);
            assert!(!l[1].default);
        }
        assert!(parse_wsl_list("no distributions").is_empty());
    }
}
