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

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::api::join;
use crate::cfgfile::{self, OwnedEfi};
use crate::cmd::config;
use crate::ctx::Ctx;
use crate::out::{CmdError, CmdResult, Exit, Report, guid_text};

/// The private link's host address (DESIGN.md §5c). Kept as its own literal
/// rather than a dependency on `paguro-vm`: that crate is Linux-only (netns,
/// `setns`) and does not build for Windows. Must match `paguro_vm::net::HOST_ADDR`.
const LINK_HOST_ADDR: &str = "169.254.244.1";

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

/// Where `paguro service` writes what forwarding needs, at the same time it
/// runs the Windows-side SSH provisioning script
/// (`paguro_vm::net::windows_ssh_provision_ps1`, DESIGN.md §The paguro
/// service in the VM item 3): the private key generated for this
/// installation's Windows → Linux direction, and the Linux account name the
/// host's `sshd_config` restricts logins to (`AllowUsers`).
pub const SSH_LINK_CONFIG_FILE: &str = "link\\ssh.json";

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct SshLinkConfig {
    pub linux_user: String,
    pub key_path: String,
}

fn read_ssh_link_config(ctx: &Ctx<'_>) -> Result<SshLinkConfig, CmdError> {
    let path = join(&ctx.data_dir(), SSH_LINK_CONFIG_FILE);
    let bytes = ctx.api.read_file(&path, 1 << 16)?.ok_or_else(|| {
        CmdError::refused(format!(
            "{path}: the private link's SSH is not provisioned yet (paguro service runs once per boot)"
        ))
    })?;
    serde_json::from_slice(&bytes).map_err(|e| CmdError::refused(format!("{path}: {e}")))
}

/// `ssh -i <key> <user>@169.254.244.1 paguro distro enter <name>`
/// (DESIGN.md §5c "Shells, the same command both ways"): from the Windows
/// VM, paguro's own Linux images are refused to Windows at the block layer
/// (§4.3), so entering one is always the host doing it on Windows' behalf,
/// over the private link's SSH channel.
pub fn ssh_forward_command(key_path: &str, user: &str, name: &str) -> Vec<String> {
    [
        "ssh",
        "-i",
        key_path,
        "-o",
        "StrictHostKeyChecking=accept-new",
        &format!("{user}@{LINK_HOST_ADDR}"),
        "paguro",
        "distro",
        "enter",
        name,
    ]
    .map(str::to_string)
    .to_vec()
}

/// Pure: `distro enter <name>` forwards to the host instead of running
/// locally exactly when this is paguro's Windows VM and `name` is one of
/// paguro's own Linux images (never a plain WSL distribution, and never on
/// native Windows — DESIGN.md §5c's table, "From the Windows VM" column).
fn should_forward(in_vm: bool, all: &[Distribution], name: &str) -> bool {
    in_vm && image(all, name).is_ok()
}

/// `distro enter`/`shell` of one of paguro's own Linux images, forwarded to
/// the host over SSH when this process is running inside paguro's Windows
/// VM (`ctx.in_vm()`); `None` when `name` is not one (native, or a `path`
/// target, or a plain WSL distribution), which keeps the existing local
/// WSL2 flow unchanged.
fn forward_to_host(
    ctx: &Ctx<'_>,
    all: &[Distribution],
    name: Option<&str>,
) -> Result<Option<CmdResult>, CmdError> {
    let Some(n) = name else { return Ok(None) };
    if !should_forward(ctx.in_vm(), all, n) {
        return Ok(None);
    }
    let cfg = read_ssh_link_config(ctx)?;
    let cmd = ssh_forward_command(&cfg.key_path, &cfg.linux_user, n);
    let data = json!({ "name": n, "forwarded": true, "command": cmd });
    Ok(Some(if ctx.dry_run {
        Ok(Report::new(data).line(format!("would forward over SSH: {}", cmd.join(" "))))
    } else {
        Ok(Report::new(data)
            .line("forwarded to the host over the private link (paguro's images are never touched directly from the VM)")
            .line(format!("shell: {}", cmd.join(" "))))
    }))
}

pub fn enter(ctx: &Ctx<'_>, name: Option<&str>, path: Option<&str>) -> CmdResult {
    let all = distributions(ctx)?;
    if let Some(r) = forward_to_host(ctx, &all, name)? {
        return r;
    }
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

    fn sample_distros() -> Vec<Distribution> {
        vec![
            Distribution {
                name: "myimage".into(),
                kind: "image",
                default: true,
                path: Some(r"C:\myimage.vhdx".into()),
                size: Some(1 << 30),
                exists: true,
                bootable: true,
                volume: None,
                wsl_state: None,
                wsl_version: None,
            },
            Distribution {
                name: "Ubuntu".into(),
                kind: "wsl",
                default: false,
                path: None,
                size: None,
                exists: true,
                bootable: false,
                volume: None,
                wsl_state: Some("Running".into()),
                wsl_version: Some(2),
            },
        ]
    }

    #[test]
    fn should_forward_only_in_vm_and_only_for_images() {
        let d = sample_distros();
        assert!(should_forward(true, &d, "myimage"));
        assert!(!should_forward(false, &d, "myimage"), "native: unchanged");
        assert!(
            !should_forward(true, &d, "Ubuntu"),
            "a WSL distribution is not one of paguro's Linux images"
        );
        assert!(!should_forward(true, &d, "nope"));
    }

    #[test]
    fn ssh_forward_command_shape() {
        let c = ssh_forward_command(r"C:\key", "anna", "myimage");
        assert_eq!(
            c,
            vec![
                "ssh",
                "-i",
                r"C:\key",
                "-o",
                "StrictHostKeyChecking=accept-new",
                "anna@169.254.244.1",
                "paguro",
                "distro",
                "enter",
                "myimage",
            ]
        );
    }

    /// A minimal `GetSystemFirmwareTable('RSMB', 0)`-shaped blob: an OEM
    /// Strings (type 11) structure carrying `marker`, then end-of-table.
    fn fake_smbios(marker: Option<&str>) -> Vec<u8> {
        let mut table = Vec::new();
        if let Some(m) = marker {
            table.extend([11u8, 5, 0, 0, 1u8]);
            table.extend(m.as_bytes());
            table.extend([0, 0]);
        }
        table.extend([127u8, 4, 0, 0, 0, 0]);
        let mut blob = vec![0u8, 3, 4, 0];
        blob.extend((table.len() as u32).to_le_bytes());
        blob.extend(table);
        blob
    }

    #[test]
    fn in_vm_reads_the_smbios_marker() {
        let api = crate::mock::MockApi::empty();
        let ctx = Ctx::new(&api);
        assert!(!ctx.in_vm(), "no SMBIOS at all: native");
        *api.smbios_blob.borrow_mut() = fake_smbios(None);
        assert!(!ctx.in_vm(), "a table without the marker: native");
        *api.smbios_blob.borrow_mut() = fake_smbios(Some("paguro-vm/1"));
        assert!(ctx.in_vm());
    }

    #[test]
    fn ssh_link_config_roundtrip_and_missing() {
        let api = crate::mock::MockApi::empty();
        let ctx = Ctx::new(&api);
        assert!(read_ssh_link_config(&ctx).is_err(), "not provisioned yet");
        api.put_file(
            &join(&ctx.data_dir(), SSH_LINK_CONFIG_FILE),
            br#"{"linux_user":"anna","key_path":"C:\\ProgramData\\paguro\\link\\id_ed25519"}"#,
        );
        let c = read_ssh_link_config(&ctx).unwrap();
        assert_eq!(c.linux_user, "anna");
        assert_eq!(c.key_path, r"C:\ProgramData\paguro\link\id_ed25519");
    }

    #[test]
    fn enter_forwards_an_image_in_vm_and_stays_local_natively() {
        let api = crate::mock::MockApi::empty();
        *api.smbios_blob.borrow_mut() = fake_smbios(Some("paguro-vm/1"));
        api.put_file(
            &join("C:\\ProgramData", "paguro\\link\\ssh.json"),
            br#"{"linux_user":"anna","key_path":"C:\\key"}"#,
        );
        let mut ctx = Ctx::new(&api);
        ctx.dry_run = true;
        let all = sample_distros();
        assert!(should_forward(ctx.in_vm(), &all, "myimage"));
        let r = forward_to_host(&ctx, &all, Some("myimage"))
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(r.data["forwarded"], json!(true));
        assert_eq!(
            r.data["command"],
            json!(ssh_forward_command("C:\\key", "anna", "myimage"))
        );

        // Native: forward_to_host stands aside (None), so `enter` would run
        // its existing WSL2 path unchanged.
        *api.smbios_blob.borrow_mut() = fake_smbios(None);
        assert!(
            forward_to_host(&ctx, &all, Some("myimage"))
                .unwrap()
                .is_none()
        );
    }
}
