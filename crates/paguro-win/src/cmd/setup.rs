//! `paguro install | repair | uninstall` for paguro itself (INTERFACES.md
//! §11.7a): the program is its own installer.
//!
//! ```text
//! C:\Program Files\paguro\            paguro.exe (CLI, service, installer)
//!                          app\       paguro-app.exe (the GUI, .NET)
//!                          minifilter\ paguro_flt.sys/.inf/.cat
//!                          esp\       shim, MokManager, paguro.efi (inputs)
//! C:\ProgramData\paguro\setup\       paguro.exe again: Apps & Features runs
//!                                     this copy, so repair and uninstall work
//!                                     when the installed files are broken
//! HKLM\…\Uninstall\paguro             the Apps & Features entry
//! ```
//!
//! The payloads are `RT_RCDATA` resources of `paguro.exe` itself: resource
//! [`MANIFEST_ID`] lists them ([`Manifest`]), each file one resource. A build
//! without them (development, the CLI-only build without the GUI) installs
//! what it has and says what is missing.
//!
//! Install and uninstall run in `paguro.exe` itself, elevated, never in the
//! service: installing registers the service, and uninstalling removes it.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::api::{WinApi, join};
use crate::cmd::service;
use crate::ctx::Ctx;
use crate::out::{At, CmdError, CmdResult, Exit, Report, to_hex};

/// The resource that lists the payloads.
pub const MANIFEST_ID: u16 = 1000;
pub const PRODUCT: &str = "paguro";
pub const PUBLISHER: &str = "paguro";
pub const ARP_KEY: &str = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\paguro";
pub const RUNONCE_KEY: &str = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
pub const RUNONCE_VALUE: &str = "paguro-uninstall";
pub const SHORTCUT: &str = "Microsoft\\Windows\\Start Menu\\Programs\\paguro.lnk";
/// The GUI, relative to the install directory.
pub const APP: &str = "app\\paguro-app.exe";
pub const MINIFILTER_INF: &str = "minifilter\\paguro_flt.inf";
/// Largest paguro.exe copied (with its payloads).
const MAX_EXE: usize = 1 << 30;
const MAX_MANIFEST: usize = 1 << 20;

/// One embedded file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payload {
    /// Relative path with `/` (`app/paguro-app.exe`).
    pub name: String,
    pub id: u16,
    pub len: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    /// The paguro version the payloads were built with.
    pub build: String,
    pub files: Vec<Payload>,
}

pub fn manifest(api: &dyn WinApi) -> Result<Option<Manifest>, CmdError> {
    let Some(b) = api.resource(MANIFEST_ID)? else {
        return Ok(None);
    };
    if b.len() > MAX_MANIFEST {
        return Err(CmdError::internal("payload manifest too large"));
    }
    serde_json::from_slice(&b)
        .map(Some)
        .map_err(|e| CmdError::internal(format!("payload manifest: {e}")))
}

pub fn install_dir(api: &dyn WinApi) -> String {
    join(&api.program_files(), PRODUCT)
}

pub fn exe_path(api: &dyn WinApi) -> String {
    join(&install_dir(api), "paguro.exe")
}

pub fn setup_dir(api: &dyn WinApi) -> String {
    join(&api.program_data(), "paguro\\setup")
}

pub fn setup_exe(api: &dyn WinApi) -> String {
    join(&setup_dir(api), "paguro.exe")
}

pub fn app_path(api: &dyn WinApi) -> String {
    join(&install_dir(api), APP)
}

fn win_rel(name: &str) -> String {
    name.replace('/', "\\")
}

fn same(a: &str, b: &str) -> bool {
    a.replace('/', "\\")
        .eq_ignore_ascii_case(&b.replace('/', "\\"))
}

fn sha(b: &[u8]) -> String {
    to_hex(&Sha256::digest(b))
}

fn parent(p: &str) -> Option<&str> {
    p.rfind('\\').and_then(|i| p.get(..i))
}

/// Write `path`, also when it is a running program: the old file is moved
/// aside (a running .exe can be renamed, not overwritten) and removed at the
/// next start.
pub fn replace_file(api: &dyn WinApi, path: &str, data: &[u8]) -> Result<(), CmdError> {
    if let Some(d) = parent(path) {
        api.create_dir_all(d)?;
    }
    if api.file_facts(path)?.is_some() {
        let old = format!("{path}.old");
        let _ = api.remove_file(&old);
        if api.remove_file(path).is_err() {
            api.rename(path, &old)?;
            api.delete_on_reboot(&old)?;
        }
    }
    api.write_file(path, data)?;
    Ok(())
}

fn reg(ctx: &Ctx<'_>, args: &[&str]) -> Result<crate::api::Output, CmdError> {
    Ok(ctx.api.run("reg.exe", args, None)?)
}

fn checked(ctx: &Ctx<'_>, prog: &str, args: &[&str]) -> Result<(), CmdError> {
    let o = ctx.api.run(prog, args, None)?;
    if o.ok() {
        Ok(())
    } else {
        Err(CmdError::new(
            Exit::Platform,
            format!(
                "{prog} {} failed ({}): {}{}",
                args.join(" "),
                o.status,
                o.stdout.trim(),
                o.stderr.trim()
            ),
        ))
    }
}

/// What is installed, and what this paguro.exe carries.
pub fn state(ctx: &Ctx<'_>) -> Result<Value, CmdError> {
    let api = ctx.api;
    let installed = api.file_facts(&exe_path(api))?.is_some();
    let setup_copy = api.file_facts(&setup_exe(api))?.is_some();
    let app = api.file_facts(&app_path(api))?.is_some();
    let arp = reg(ctx, &["query", ARP_KEY])?.ok();
    let svc = service::installed(ctx)?;
    let m = manifest(api)?;
    let exe = api.current_exe()?;
    Ok(json!({
        "installed": installed,
        "version": env!("CARGO_PKG_VERSION"),
        "install_dir": install_dir(api),
        "setup_copy": setup_copy,
        "app": app,
        "apps_and_features": arp,
        "service": svc,
        "running_from": exe,
        "running_installed": same(&exe, &exe_path(api)) || same(&exe, &setup_exe(api)),
        "payloads": m.as_ref().map(|m| m.files.iter().map(|f| json!({ "name": f.name, "len": f.len })).collect::<Vec<_>>()).unwrap_or_default(),
        "has_gui": m.as_ref().is_some_and(|m| m.files.iter().any(|f| f.name.starts_with("app/"))),
    }))
}

pub fn status(ctx: &Ctx<'_>) -> CmdResult {
    let s = state(ctx)?;
    let yn = |b: &Value| if *b == true { "yes" } else { "no" };
    Ok(Report::new(s.clone())
        .line(format!(
            "paguro {}: {}",
            s.at("version").as_str().unwrap_or(""),
            if s.at("installed") == true {
                "installed"
            } else {
                "not installed"
            }
        ))
        .line(format!(
            "  program files  {}",
            s.at("install_dir").as_str().unwrap_or("")
        ))
        .line(format!("  service        {}", yn(s.at("service"))))
        .line(format!(
            "  Apps & Features {}",
            yn(s.at("apps_and_features"))
        ))
        .line(format!("  repair copy    {}", yn(s.at("setup_copy"))))
        .line(format!("  GUI            {}", yn(s.at("app"))))
        .line(format!(
            "  this paguro.exe carries {} payload file(s)",
            s.at("payloads").as_array().map_or(0, Vec::len)
        )))
}

/// What `paguro.exe` without arguments does (a double-click, the Start
/// menu): open the GUI, or offer to install paguro first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Launch {
    /// Start this GUI (a child process).
    Gui(String),
    /// paguro is not installed: offer to.
    OfferInstall,
    /// Installed, but no GUI (the CLI-only build): explain the CLI.
    NoGui,
}

pub fn launch(api: &dyn WinApi) -> Result<Launch, CmdError> {
    let me = api.current_exe()?;
    // Next to this paguro.exe first (an unpacked tree), then the install.
    let beside = parent(&me).map(|d| join(d, APP));
    for p in beside.into_iter().chain([app_path(api)]) {
        if api.file_facts(&p)?.is_some() {
            return Ok(Launch::Gui(p));
        }
    }
    if api.file_facts(&exe_path(api))?.is_some() {
        Ok(Launch::NoGui)
    } else {
        Ok(Launch::OfferInstall)
    }
}

/// Step results (JSON) and their lines of text.
pub type Steps = (Vec<Value>, Vec<String>);

/// The steps of installing paguro (and, but for `service`, of repairing it).
pub const STEPS: [&str; 6] = [
    "files",
    "setup-copy",
    "driver",
    "service",
    "apps-and-features",
    "shortcut",
];

fn extract(ctx: &Ctx<'_>, check_only_changed: bool) -> Result<(usize, Vec<String>), CmdError> {
    let api = ctx.api;
    let dir = install_dir(api);
    let mut written = 0;
    let mut missing = Vec::new();
    let m = manifest(api)?;
    if m.is_none() {
        missing.push("the embedded payloads (a development build carries none)".into());
    }
    for f in m.map(|m| m.files).unwrap_or_default() {
        let dest = join(&dir, &win_rel(&f.name));
        if check_only_changed {
            if let Ok(Some(cur)) = api.read_file(
                &dest,
                usize::try_from(f.len)
                    .unwrap_or(usize::MAX)
                    .saturating_add(1),
            ) {
                if sha(&cur) == f.sha256 {
                    continue;
                }
            }
        }
        let data = api.resource(f.id)?.ok_or_else(|| {
            CmdError::internal(format!("payload {} (resource {}) is missing", f.name, f.id))
        })?;
        if sha(&data) != f.sha256 {
            return Err(CmdError::internal(format!(
                "payload {} does not match its checksum",
                f.name
            )));
        }
        replace_file(api, &dest, &data)?;
        written += 1;
    }
    Ok((written, missing))
}

fn copy_self(ctx: &Ctx<'_>, dest: &str) -> Result<bool, CmdError> {
    let api = ctx.api;
    let me = api.current_exe()?;
    if same(&me, dest) {
        return Ok(false);
    }
    let data = api
        .read_file(&me, MAX_EXE)?
        .ok_or_else(|| CmdError::not_found(format!("{me}: cannot read this program")))?;
    if api
        .read_file(dest, MAX_EXE)
        .ok()
        .flatten()
        .is_some_and(|d| d == data)
    {
        return Ok(false);
    }
    replace_file(api, dest, &data)?;
    Ok(true)
}

fn quoted(p: &str) -> String {
    format!("\"{p}\"")
}

fn step(ctx: &Ctx<'_>, id: &str, repair: bool) -> Result<(&'static str, String), CmdError> {
    let api = ctx.api;
    match id {
        "files" => {
            let copied = copy_self(ctx, &exe_path(api))?;
            let (n, missing) = extract(ctx, repair)?;
            let mut d = format!(
                "{}paguro.exe, {n} payload file(s) written to {}",
                if copied { "" } else { "(same) " },
                install_dir(api)
            );
            if !missing.is_empty() {
                d.push_str(&format!("; missing: {}", missing.join(", ")));
            }
            Ok(("done", d))
        }
        "setup-copy" => {
            let copied = copy_self(ctx, &setup_exe(api))?;
            Ok((
                "done",
                format!(
                    "{} {}",
                    if copied { "copied to" } else { "already at" },
                    setup_exe(api)
                ),
            ))
        }
        "driver" => {
            let inf = join(&install_dir(api), MINIFILTER_INF);
            if api.file_facts(&inf)?.is_none() {
                return Ok(("skipped", "no minifilter package in this build".into()));
            }
            let o = api.run("pnputil.exe", &["/add-driver", &inf, "/install"], None)?;
            if o.ok() {
                Ok((
                    "done",
                    "minifilter package added (it stays inert until an image is attached)".into(),
                ))
            } else {
                // Not fatal: paguro works without it until an image exists
                // (DESIGN §4.4), and a test-signed build needs test signing on.
                Ok((
                    "skipped",
                    format!(
                        "pnputil could not add the minifilter ({}): {}",
                        o.status,
                        o.stdout.trim()
                    ),
                ))
            }
        }
        "service" => {
            let r = service::install(ctx, &exe_path(api))?;
            Ok(("done", r.human.join("; ")))
        }
        "apps-and-features" => {
            let setup = setup_exe(api);
            let icon = if api.file_facts(&app_path(api))?.is_some() {
                app_path(api)
            } else {
                exe_path(api)
            };
            let size_kb = api.file_facts(&exe_path(api))?.map_or(0, |f| f.len / 1024);
            let size = size_kb.to_string();
            let uninstall = format!("{} uninstall", quoted(&setup));
            let modify = format!("{} repair", quoted(&setup));
            let dir = install_dir(api);
            for (name, ty, val) in [
                ("DisplayName", "REG_SZ", "paguro"),
                ("DisplayVersion", "REG_SZ", env!("CARGO_PKG_VERSION")),
                ("Publisher", "REG_SZ", PUBLISHER),
                ("InstallLocation", "REG_SZ", dir.as_str()),
                ("DisplayIcon", "REG_SZ", icon.as_str()),
                ("UninstallString", "REG_SZ", uninstall.as_str()),
                ("ModifyPath", "REG_SZ", modify.as_str()),
                ("NoRepair", "REG_DWORD", "1"),
                ("EstimatedSize", "REG_DWORD", size.as_str()),
                (
                    "URLInfoAbout",
                    "REG_SZ",
                    "https://github.com/reindertpelsma/paguro",
                ),
            ] {
                checked(
                    ctx,
                    "reg.exe",
                    &["add", ARP_KEY, "/v", name, "/t", ty, "/d", val, "/f"],
                )?;
            }
            Ok((
                "done",
                format!("Apps & Features: uninstall and modify run {setup}"),
            ))
        }
        "shortcut" => {
            let lnk = join(&api.program_data(), SHORTCUT);
            let script = format!(
                "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{lnk}');$s.TargetPath='{}';$s.IconLocation='{},0';$s.Description='paguro';$s.Save()",
                exe_path(api),
                if api.file_facts(&app_path(api))?.is_some() {
                    app_path(api)
                } else {
                    exe_path(api)
                }
            );
            checked(
                ctx,
                "powershell.exe",
                &["-NoProfile", "-NonInteractive", "-Command", &script],
            )?;
            Ok(("done", format!("Start menu: {lnk} starts paguro.exe")))
        }
        _ => Err(CmdError::internal(format!("unknown setup step {id}"))),
    }
}

fn run_steps(
    ctx: &Ctx<'_>,
    op: &'static str,
    ids: &[&str],
    repair: bool,
) -> Result<(Vec<Value>, Vec<String>), CmdError> {
    let mut steps = Vec::new();
    let mut lines = Vec::new();
    for (i, id) in ids.iter().enumerate() {
        ctx.step(op, i, ids.len(), id, "running", "");
        match step(ctx, id, repair) {
            Ok((st, detail)) => {
                ctx.step(op, i, ids.len(), id, st, &detail);
                lines.push(format!("{id}: {detail}"));
                steps.push(json!({ "id": id, "state": st, "detail": detail }));
            }
            Err(e) => {
                ctx.step(op, i, ids.len(), id, "failed", &e.message);
                steps.push(json!({ "id": id, "state": "failed", "detail": e.message }));
                return Err(CmdError::new(
                    e.exit,
                    format!(
                        "{op} step {id} failed: {} (fix it and run the same command again)",
                        e.message
                    ),
                )
                .with_data(json!({ "steps": steps })));
            }
        }
    }
    Ok((steps, lines))
}

/// `paguro install` (no distribution): install paguro itself.
pub fn install(ctx: &Ctx<'_>) -> CmdResult {
    ctx.need_admin_or_plan()?;
    if ctx.dry_run {
        let s = state(ctx)?;
        return Ok(Report::new(json!({ "state": s, "steps": STEPS.iter().map(|id| json!({ "id": id, "state": "pending" })).collect::<Vec<_>>() }))
            .lines(STEPS.iter().map(|s| format!("would run: {s}"))));
    }
    let (steps, lines) = run_steps(ctx, "setup", &STEPS, false)?;
    let s = state(ctx)?;
    Ok(
        Report::new(json!({ "state": s, "steps": steps, "app": app_path(ctx.api) }))
            .lines(lines)
            .line("paguro is installed"),
    )
}

/// The app-level part of `paguro repair`: files, repair copy, driver,
/// service registration, Apps & Features, Start menu. Never the images.
pub fn repair_app(ctx: &Ctx<'_>) -> Result<Option<Steps>, CmdError> {
    let api = ctx.api;
    let installed =
        api.file_facts(&exe_path(api))?.is_some() || api.file_facts(&setup_exe(api))?.is_some();
    if !installed {
        return Ok(None);
    }
    if ctx.dry_run {
        return Ok(Some((
            STEPS
                .iter()
                .map(|id| json!({ "id": id, "state": "pending" }))
                .collect(),
            STEPS.iter().map(|s| format!("would repair: {s}")).collect(),
        )));
    }
    run_steps(ctx, "repair", &STEPS, true).map(Some)
}

/// Uninstall's app-level steps (phase 2): what `install` added.
pub fn remove(ctx: &Ctx<'_>, id: &str) -> Result<(&'static str, String), CmdError> {
    let api = ctx.api;
    match id {
        "app-files" => {
            let (n, later) = remove_tree_or_later(api, &install_dir(api))?;
            Ok((
                "done",
                format!(
                    "{n} file(s) removed from {}{}",
                    install_dir(api),
                    if later > 0 {
                        format!(", {later} in use: removed at the next start")
                    } else {
                        String::new()
                    }
                ),
            ))
        }
        "shortcut" => {
            api.remove_file(&join(&api.program_data(), SHORTCUT))?;
            Ok(("done", "Start menu entry removed".into()))
        }
        "apps-and-features" => {
            let _ = reg(ctx, &["delete", ARP_KEY, "/f"])?;
            let _ = reg(ctx, &["delete", RUNONCE_KEY, "/v", RUNONCE_VALUE, "/f"])?;
            Ok(("done", "Apps & Features entry removed".into()))
        }
        _ => Err(CmdError::internal(format!("unknown step {id}"))),
    }
}

/// Remove a tree; files in use (the running paguro.exe) are removed at the
/// next start instead. Returns (removed now, removed later).
pub fn remove_tree_or_later(api: &dyn WinApi, dir: &str) -> Result<(usize, usize), CmdError> {
    let Some(entries) = api.list_dir(dir)? else {
        return Ok((0, 0));
    };
    let (mut now, mut later) = (0, 0);
    for e in entries {
        let p = join(dir, &e.name);
        if e.is_dir {
            let (a, b) = remove_tree_or_later(api, &p)?;
            now += a;
            later += b;
        } else if api.remove_file(&p).is_ok() {
            now += 1;
        } else {
            api.delete_on_reboot(&p)?;
            later += 1;
        }
    }
    if api.remove_dir(dir).is_err() {
        api.delete_on_reboot(dir)?;
    }
    Ok((now, later))
}

/// After phase 1 of an uninstall: finish it at the next administrator
/// logon (HKLM RunOnce runs elevated), with the same image choice.
pub fn schedule_phase2(ctx: &Ctx<'_>, delete_images: bool) -> Result<(), CmdError> {
    let exe = setup_exe(ctx.api);
    if ctx.api.file_facts(&exe)?.is_none() {
        return Ok(());
    }
    let cmd = format!(
        "{} --direct uninstall --yes {}",
        quoted(&exe),
        if delete_images {
            "--delete-images"
        } else {
            "--keep-images"
        }
    );
    checked(
        ctx,
        "reg.exe",
        &[
            "add",
            RUNONCE_KEY,
            "/v",
            RUNONCE_VALUE,
            "/t",
            "REG_SZ",
            "/d",
            &cmd,
            "/f",
        ],
    )
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::mock::MockApi;

    pub fn with_payloads(m: &MockApi) {
        let files: Vec<(&str, &[u8])> = vec![
            ("app/paguro-app.exe", b"MZapp"),
            ("minifilter/paguro_flt.inf", b"[Version]"),
            ("minifilter/paguro_flt.sys", b"MZsys"),
            ("esp/shimx64.efi", b"MZshim"),
        ];
        let mut list = Vec::new();
        for (i, (n, d)) in files.iter().enumerate() {
            let id = MANIFEST_ID + 1 + i as u16;
            m.resources.borrow_mut().insert(id, d.to_vec());
            list.push(Payload {
                name: (*n).into(),
                id,
                len: d.len() as u64,
                sha256: sha(d),
            });
        }
        let man = Manifest {
            version: 1,
            build: "test".into(),
            files: list,
        };
        m.resources
            .borrow_mut()
            .insert(MANIFEST_ID, serde_json::to_vec(&man).unwrap());
        m.put_file("C:\\Users\\me\\Downloads\\paguro.exe", b"MZpaguro");
    }

    #[test]
    fn install_extracts_registers_and_is_idempotent() {
        let m = MockApi::standard();
        with_payloads(&m);
        m.set_runner(|prog, args| {
            (prog == "sc.exe" && args.first() == Some(&"query")).then(|| crate::api::Output {
                status: 1060,
                stdout: String::new(),
                stderr: String::new(),
            })
        });
        let ctx = Ctx::new(&m);
        let r = install(&ctx).unwrap();
        assert_eq!(
            m.file("C:\\Program Files\\paguro\\paguro.exe").unwrap(),
            b"MZpaguro"
        );
        assert_eq!(
            m.file("C:\\Program Files\\paguro\\app\\paguro-app.exe")
                .unwrap(),
            b"MZapp"
        );
        assert_eq!(
            m.file("C:\\ProgramData\\paguro\\setup\\paguro.exe")
                .unwrap(),
            b"MZpaguro"
        );
        let cmds = m.commands.borrow().join("\n");
        assert!(cmds.contains("pnputil.exe /add-driver C:\\Program Files\\paguro\\minifilter\\paguro_flt.inf /install"), "{cmds}");
        assert!(
            cmds.contains(
                "sc.exe create paguro binPath= \"C:\\Program Files\\paguro\\paguro.exe\" service"
            ),
            "{cmds}"
        );
        assert!(cmds.contains("UninstallString /t REG_SZ /d \"C:\\ProgramData\\paguro\\setup\\paguro.exe\" uninstall"), "{cmds}");
        assert!(
            cmds.contains(
                "ModifyPath /t REG_SZ /d \"C:\\ProgramData\\paguro\\setup\\paguro.exe\" repair"
            ),
            "{cmds}"
        );
        assert_eq!(r.data["steps"].as_array().unwrap().len(), STEPS.len());
        // Again: nothing breaks.
        install(&ctx).unwrap();
    }

    #[test]
    fn a_tampered_payload_is_refused() {
        let m = MockApi::standard();
        with_payloads(&m);
        m.resources
            .borrow_mut()
            .insert(MANIFEST_ID + 1, b"MZevil".to_vec());
        let e = install(&Ctx::new(&m)).unwrap_err();
        assert!(e.message.contains("checksum"), "{}", e.message);
        assert!(
            m.file("C:\\Program Files\\paguro\\app\\paguro-app.exe")
                .is_none()
        );
    }

    #[test]
    fn repair_rewrites_only_what_changed() {
        let m = MockApi::standard();
        with_payloads(&m);
        let ctx = Ctx::new(&m);
        install(&ctx).unwrap();
        m.put_file("C:\\Program Files\\paguro\\app\\paguro-app.exe", b"broken");
        m.mutations.borrow_mut().clear();
        let (steps, _) = repair_app(&ctx).unwrap().unwrap();
        assert_eq!(
            m.file("C:\\Program Files\\paguro\\app\\paguro-app.exe")
                .unwrap(),
            b"MZapp"
        );
        assert!(
            steps[0]["detail"]
                .as_str()
                .unwrap()
                .contains("1 payload file(s)"),
            "{steps:?}"
        );
        let muts = m.mutations.borrow().join("\n");
        assert!(
            !muts.contains("paguro_flt.sys"),
            "unchanged files are not rewritten: {muts}"
        );
    }

    #[test]
    fn no_arguments_opens_the_gui_or_offers_to_install() {
        let m = MockApi::standard();
        assert_eq!(launch(&m).unwrap(), Launch::OfferInstall);
        with_payloads(&m);
        install(&Ctx::new(&m)).unwrap();
        assert_eq!(
            launch(&m).unwrap(),
            Launch::Gui("C:\\Program Files\\paguro\\app\\paguro-app.exe".into())
        );
        m.remove_file("C:\\Program Files\\paguro\\app\\paguro-app.exe")
            .unwrap();
        assert_eq!(launch(&m).unwrap(), Launch::NoGui);
    }

    #[test]
    fn a_running_exe_is_moved_aside() {
        let m = MockApi::standard();
        m.put_file("C:\\x\\paguro.exe", b"old");
        replace_file(&m, "C:\\x\\paguro.exe", b"new").unwrap();
        assert_eq!(m.file("C:\\x\\paguro.exe").unwrap(), b"new");
    }

    #[test]
    fn a_development_build_says_what_is_missing() {
        let m = MockApi::standard();
        m.put_file("C:\\Users\\me\\Downloads\\paguro.exe", b"MZpaguro");
        let r = install(&Ctx::new(&m)).unwrap();
        assert!(
            r.human[0].contains("missing: the embedded payloads"),
            "{:?}",
            r.human
        );
        assert_eq!(r.data["steps"][2]["state"], "skipped");
    }
}
