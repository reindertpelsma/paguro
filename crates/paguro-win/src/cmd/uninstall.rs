//! `paguro uninstall` — DESIGN.md §6b as a resumable checklist.
//!
//! Install only adds, so uninstall is "delete what is present", in an order
//! that keeps every intermediate state safe: nothing that starts Linux
//! outlives the loader it starts, and the driver stops enforcing before an
//! image is deleted. Two things cannot be done from a running Windows, and
//! both are arranged for **one** reboot:
//!
//! - the minifilter refuses to unload by design (§4.4): it is disabled now
//!   and gone after the reboot;
//! - `PaguroB` is boot-services-only and a `MokList` entry is removed only by
//!   MokManager: the **final boot** goes through our shim with
//!   `PaguroUninstall` set (INTERFACES.md §5) and the machine certificate
//!   queued in `MokDel`; MokManager asks once, and the loader deletes
//!   `PaguroB` and resets into Windows.
//!
//! ```text
//! phase 1  inventory        paguro.ini's image list, into the journal
//!          windows-tasks    scheduled task \paguro\repair, service paguro
//!          driver-disable   sc config paguroflt start= disabled
//!          final-boot       PaguroUninstall, MokDel/MokDelAuth, BootNext
//!          -- reboot (exit code 8, Pending) --
//! phase 2  boot-entries     our Boot####, BootOrder, BootNext
//!          esp              \EFI\paguro\, PaguroConfigHash, PaguroSetup,
//!                           PaguroTpmBroken, PaguroBootstrap,
//!                           PaguroUninstall, the MOK key
//!          driver-remove    sc delete; pnputil /delete-driver
//!          images           only with --delete-images (--keep-images keeps them;
//!                           one of the two is required: never silently)
//!          app-files        C:\Program Files\paguro (INTERFACES §11.7a)
//!          shortcut         the Start menu entry
//!          apps-and-features the Apps & Features entry
//!          store            %ProgramData%\paguro
//!          setup-copy       %ProgramData%\paguro\setup (this program, when it
//!                           runs from there: removed at the next start)
//! ```
//!
//! Phase 1 schedules phase 2 for the next administrator logon (HKLM
//! RunOnce, the repair copy with the same image choice). Uninstall runs in
//! `paguro.exe` itself, never in the service it removes.
//! ```text
//! ```
//!
//! `--skip-final-boot` leaves `PaguroB` as 32 inert bytes and the
//! certificate enrolled, and says so. The order is DESIGN.md §6b's with the
//! driver's reboot and the final boot folded into one.

use paguro_core::guid::PAGURO_VENDOR;
use serde_json::{Value, json};

use crate::api::{WinApi, attr, join};
use crate::bootent;
use crate::cfgfile::{self, OwnedEfi};
use crate::cmd::mok;
use crate::ctx::Ctx;
use crate::esp;
use crate::journal::{Journal, StepState};
use crate::out::{At, CmdError, CmdResult, Exit, Report};

pub const PHASE1: [&str; 4] = ["inventory", "windows-tasks", "driver-disable", "final-boot"];
pub const PHASE2: [&str; 9] = [
    "boot-entries",
    "esp",
    "driver-remove",
    "images",
    "app-files",
    "shortcut",
    "apps-and-features",
    "store",
    "setup-copy",
];
pub const TASK: &str = "\\paguro\\repair";
pub const SERVICE: &str = "paguro";
pub const DRIVER: &str = "paguroflt";
pub const DRIVER_INF: &str = "paguro_flt.inf";
pub const UNINSTALL_VAR: &str = "PaguroUninstall";
const KEY: &str = "machine";

pub fn steps() -> Vec<&'static str> {
    PHASE1.iter().chain(PHASE2.iter()).copied().collect()
}

fn exists_service(api: &dyn WinApi, name: &str) -> Result<bool, CmdError> {
    Ok(api.run("sc.exe", &["query", name], None)?.ok())
}

fn driver_loaded(api: &dyn WinApi) -> Result<bool, CmdError> {
    Ok(api
        .run("fltmc.exe", &["instances", "-f", DRIVER], None)?
        .ok())
}

/// Remove a directory tree we own (the ESP's `\EFI\paguro`, the store).
pub fn remove_tree(api: &dyn WinApi, dir: &str) -> Result<usize, CmdError> {
    let Some(entries) = api.list_dir(dir)? else {
        return Ok(0);
    };
    let mut n = 0;
    for e in entries {
        let p = join(dir, &e.name);
        if e.is_dir {
            n += remove_tree(api, &p)?;
        } else if api.remove_file(&p)? {
            n += 1;
        }
    }
    api.remove_dir(dir)?;
    Ok(n)
}

/// `pnputil /enum-drivers` → the published `oemNN.inf` of our driver.
pub fn published_inf(listing: &str) -> Option<String> {
    let mut published = None;
    for line in listing.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        if k.eq_ignore_ascii_case("Published Name") {
            published = Some(v.to_string());
        } else if k.eq_ignore_ascii_case("Original Name") && v.eq_ignore_ascii_case(DRIVER_INF) {
            return published;
        }
    }
    None
}

struct Opts {
    delete_images: bool,
    skip_final_boot: bool,
}

fn step(
    ctx: &Ctx<'_>,
    id: &str,
    j: &mut Journal,
    o: &Opts,
) -> Result<(StepState, String), CmdError> {
    let api = ctx.api;
    match id {
        "inventory" => {
            let mut images = Vec::new();
            if let Ok(e) = ctx.esp() {
                if let Some(Ok(c)) = cfgfile::read(api, &e)?.map(|f| f.parsed) {
                    for en in &c.entries {
                        let mut files: Vec<&str> = en.root.iter().map(String::as_str).collect();
                        match &en.efi {
                            OwnedEfi::Disk { disk, .. } => files.push(disk),
                            OwnedEfi::File { file } => files.push(file),
                        }
                        for p in files {
                            if let Some(w) = cfgfile::windows_path(api, &en.volume, p)? {
                                if !images.contains(&w) {
                                    images.push(w);
                                }
                            }
                        }
                    }
                }
            }
            if let Some(obj) = j.args.as_object_mut() {
                obj.insert("images".into(), json!(images));
            }
            Ok((
                StepState::Done,
                format!("{} image file(s) named by paguro.ini", images.len()),
            ))
        }
        "windows-tasks" => {
            let mut done = Vec::new();
            if api
                .run("schtasks.exe", &["/Query", "/TN", TASK], None)?
                .ok()
            {
                api.run("schtasks.exe", &["/Delete", "/TN", TASK, "/F"], None)?;
                done.push("scheduled task");
            }
            if exists_service(api, SERVICE)? {
                api.run("sc.exe", &["stop", SERVICE], None)?;
                let out = api.run("sc.exe", &["delete", SERVICE], None)?;
                if !out.ok() {
                    return Err(CmdError::new(
                        Exit::Platform,
                        format!("sc delete {SERVICE}: {}", out.stdout.trim()),
                    ));
                }
                done.push("service");
            }
            Ok((
                StepState::Done,
                if done.is_empty() {
                    "none present".into()
                } else {
                    done.join(", ")
                },
            ))
        }
        "driver-disable" => {
            if !exists_service(api, DRIVER)? {
                return Ok((StepState::Skipped, "minifilter not installed".into()));
            }
            let out = api.run("sc.exe", &["config", DRIVER, "start=", "disabled"], None)?;
            if !out.ok() {
                return Err(CmdError::new(
                    Exit::Platform,
                    format!("sc config {DRIVER}: {}", out.stdout.trim()),
                ));
            }
            Ok((
                StepState::AwaitingReboot,
                "disabled; it is gone after the reboot".into(),
            ))
        }
        "final-boot" => {
            if o.skip_final_boot || !api.firmware_is_uefi() {
                return Ok((
                    StepState::Skipped,
                    "skipped: PaguroB stays as 32 inert bytes, the machine key stays enrolled"
                        .into(),
                ));
            }
            let Ok(esp_vol) = ctx.esp() else {
                return Ok((StepState::Skipped, "no ESP: nothing can boot".into()));
            };
            if api
                .read_file(&esp::path(&esp_vol, esp::LOADER), esp::MAX_ESP_FILE)?
                .is_none()
            {
                return Ok((
                    StepState::Skipped,
                    "paguro.efi is gone already: PaguroB stays as 32 inert bytes".into(),
                ));
            }
            let (n, _) = bootent::ensure_standing(api, &esp_vol, false)?;
            let mut detail = String::from("PaguroUninstall set");
            let cert = api.read_file(&mok::cert_path(ctx), mok::MAX_CERT)?;
            if let Some(der) = cert.filter(|d| mok::is_enrolled(api, d).unwrap_or(false)) {
                let pw = mok::generate_password(api)?;
                mok::queue(api, mok::Request::Delete, &der, &pw)?;
                detail.push_str(&format!(
                    "; machine key queued for removal: MokManager asks once (\"Delete MOK\"), password {}",
                    pw.as_str()
                ));
            }
            api.fw_set(UNINSTALL_VAR, &PAGURO_VENDOR, &[1], attr::NV_BS_RT)?;
            bootent::set_boot_next(api, n)?;
            Ok((StepState::AwaitingReboot, detail))
        }
        "boot-entries" => {
            if !api.firmware_is_uefi() {
                return Ok((StepState::Skipped, "not UEFI".into()));
            }
            let ours: Vec<_> = bootent::list(api)?.into_iter().filter(|e| e.ours).collect();
            for e in &ours {
                bootent::delete(api, e.number)?;
            }
            Ok((
                StepState::Done,
                format!(
                    "{} paguro entr(y/ies) removed; the rest of BootOrder untouched",
                    ours.len()
                ),
            ))
        }
        "esp" => {
            let mut n = 0;
            if let Ok(e) = ctx.esp() {
                n = remove_tree(api, &esp::dir(&e))?;
            }
            if api.firmware_is_uefi() {
                for v in [
                    cfgfile::HASH_VAR,
                    "PaguroSetup",
                    "PaguroTpmBroken",
                    paguro_core::bootstrap::VAR_NAME,
                    UNINSTALL_VAR,
                ] {
                    // Only what exists: a machine without paguro's
                    // variables sees no firmware write at all.
                    if api.fw_get(v, &PAGURO_VENDOR)?.is_some() {
                        api.fw_delete(v, &PAGURO_VENDOR)?;
                    }
                }
            }
            // The machine's MOK private key (INTERFACES.md §11.6) goes with it.
            let k = remove_tree(api, &join(&ctx.data_dir(), "mok"))?;
            Ok((
                StepState::Done,
                format!(
                    "{n} file(s) removed from \\EFI\\paguro; variables deleted; {k} key file(s) removed"
                ),
            ))
        }
        "driver-remove" => {
            if j.state("driver-disable") == Some(StepState::Skipped) {
                return Ok((StepState::Skipped, "minifilter not installed".into()));
            }
            api.run("sc.exe", &["delete", DRIVER], None)?;
            let listing = api.run("pnputil.exe", &["/enum-drivers"], None)?;
            if let Some(oem) = published_inf(&listing.stdout) {
                let out = api.run(
                    "pnputil.exe",
                    &["/delete-driver", &oem, "/uninstall", "/force"],
                    None,
                )?;
                if !out.ok() {
                    return Err(CmdError::new(
                        Exit::Platform,
                        format!("pnputil /delete-driver {oem}: {}", out.stdout.trim()),
                    ));
                }
            }
            Ok((
                StepState::Done,
                "service deleted and removed from the DriverStore".into(),
            ))
        }
        "images" => {
            let images: Vec<String> = j
                .args
                .at("images")
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            if !o.delete_images {
                return Ok((
                    StepState::Skipped,
                    format!(
                        "kept {} image file(s); pass --delete-images to delete them",
                        images.len()
                    ),
                ));
            }
            let mut n = 0;
            for p in &images {
                if api.remove_file(p)? {
                    n += 1;
                }
            }
            Ok((StepState::Done, format!("{n} image file(s) deleted")))
        }
        "app-files" | "shortcut" | "apps-and-features" => {
            let (st, d) = crate::cmd::setup::remove(ctx, id)?;
            Ok((
                if st == "done" {
                    StepState::Done
                } else {
                    StepState::Skipped
                },
                d,
            ))
        }
        "setup-copy" => {
            let (n, later) =
                crate::cmd::setup::remove_tree_or_later(api, &crate::cmd::setup::setup_dir(api))?;
            Ok((
                StepState::Done,
                format!(
                    "{n} file(s) removed{}",
                    if later > 0 {
                        format!(", {later} in use: removed at the next start")
                    } else {
                        String::new()
                    }
                ),
            ))
        }
        "store" => {
            let n = remove_tree(api, &esp::store_dir(api))?;
            api.remove_file(&join(&ctx.data_dir(), "host-hardware.json"))?;
            Ok((StepState::Done, format!("{n} saved file(s) removed")))
        }
        _ => Err(CmdError::internal(format!("unknown step {id}"))),
    }
}

/// Settle steps that were waiting for the reboot. `Ok(true)`: still waiting.
fn settle(ctx: &Ctx<'_>, j: &mut Journal, o: &Opts) -> Result<bool, CmdError> {
    let api = ctx.api;
    let mut waiting = false;
    if j.state("driver-disable") == Some(StepState::AwaitingReboot) {
        if driver_loaded(api)? {
            waiting = true;
        } else {
            j.set(
                api,
                "driver-disable",
                StepState::Done,
                "unloaded after the reboot",
            );
        }
    }
    if j.state("final-boot") == Some(StepState::AwaitingReboot) {
        let still = api.fw_get(UNINSTALL_VAR, &PAGURO_VENDOR)?.is_some();
        if !still {
            j.set(
                api,
                "final-boot",
                StepState::Done,
                "the loader deleted PaguroB and the request",
            );
        } else if o.skip_final_boot {
            api.fw_delete(UNINSTALL_VAR, &PAGURO_VENDOR)?;
            for v in ["MokDel", "MokDelAuth"] {
                api.fw_delete(v, &paguro_core::efisig::SHIM_LOCK)?;
            }
            j.set(
                api,
                "final-boot",
                StepState::Skipped,
                "abandoned: PaguroB stays as 32 inert bytes",
            );
        } else {
            waiting = true;
        }
    }
    Ok(waiting)
}

fn run_step(
    ctx: &Ctx<'_>,
    j: &mut Journal,
    id: &str,
    o: &Opts,
    lines: &mut Vec<String>,
) -> Result<(), CmdError> {
    let ids = steps();
    let total = ids.len();
    let index = ids.iter().position(|s| *s == id).unwrap_or(0);
    ctx.step("uninstall", index, total, id, "running", "");
    let r = step(ctx, id, j, o);
    match &r {
        Ok((st, detail)) => ctx.step(
            "uninstall",
            index,
            total,
            id,
            serde_json::to_value(st)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .as_deref()
                .unwrap_or("done"),
            detail,
        ),
        Err(e) => ctx.step("uninstall", index, total, id, "failed", &e.message),
    }
    match r {
        Ok((st, detail)) => {
            lines.push(format!("{id}: {detail}"));
            j.set(ctx.api, id, st, detail);
            j.save(ctx.api)
        }
        Err(e) => {
            j.set(ctx.api, id, StepState::Failed, e.message.clone());
            j.save(ctx.api)?;
            Err(CmdError::new(
                e.exit,
                format!(
                    "uninstall step {id} failed: {} (run again to resume)",
                    e.message
                ),
            )
            .with_data(serde_json::to_value(&*j).unwrap_or(Value::Null)))
        }
    }
}

pub fn uninstall(
    ctx: &Ctx<'_>,
    delete_images: bool,
    keep_images: bool,
    skip_final_boot: bool,
    yes: bool,
) -> CmdResult {
    if delete_images && keep_images {
        return Err(CmdError::new(
            Exit::Usage,
            "--keep-images or --delete-images, not both",
        ));
    }
    let o = Opts {
        delete_images,
        skip_final_boot,
    };
    if ctx.dry_run {
        let j = Journal::load(ctx.api, "uninstall", KEY)?;
        let steps: Vec<Value> = steps()
            .iter()
            .map(|id| json!({ "id": id, "state": j.as_ref().and_then(|j| j.state(id)).unwrap_or(StepState::Pending) }))
            .collect();
        return Ok(Report::new(json!({ "steps": steps, "delete_images": delete_images, "skip_final_boot": skip_final_boot }))
            .lines(self::steps().iter().map(|s| format!("would run: {s}"))));
    }
    if !yes {
        return Err(CmdError::refused(
            "uninstall removes paguro from this machine: pass --yes (or --dry-run to see the plan)",
        ));
    }
    if !delete_images && !keep_images {
        return Err(CmdError::refused(
            "the Linux images are never deleted silently: choose --keep-images or --delete-images",
        )
        .with_data(json!({ "needs_choice": "images" })));
    }
    if ctx.in_service {
        return Err(CmdError::refused(
            "uninstall removes the paguro service, so it runs in paguro.exe itself (elevated), not in the service: `paguro uninstall`",
        ));
    }
    ctx.need_admin()?;
    let ids = steps();
    let mut j = match Journal::load(ctx.api, "uninstall", KEY)? {
        Some(j) => j,
        None => Journal::new(ctx.api, "uninstall", KEY, json!({ "images": [] }), &ids),
    };
    let mut lines = Vec::new();
    for id in PHASE1 {
        if matches!(j.state(id), Some(StepState::Pending | StepState::Failed)) {
            run_step(ctx, &mut j, id, &o, &mut lines)?;
        }
    }
    let waiting = settle(ctx, &mut j, &o)?;
    j.save(ctx.api)?;
    if waiting {
        crate::cmd::setup::schedule_phase2(ctx, delete_images)?;
        let data = json!({ "journal": j, "finished": false });
        return Ok(Report::new(data)
            .lines(lines)
            .line("restart now (paguro's entry is BootNext): the loader removes PaguroB and returns to Windows; then run `paguro uninstall --yes` again")
            .exit(Exit::Pending));
    }
    for id in PHASE2 {
        if matches!(j.state(id), Some(StepState::Pending | StepState::Failed)) {
            run_step(ctx, &mut j, id, &o, &mut lines)?;
        }
    }
    let mut r = Report::new(json!({ "journal": j, "finished": j.finished() })).lines(lines);
    if j.state("final-boot") == Some(StepState::Skipped) {
        r = r.warn("PaguroB stays in firmware as 32 inert bytes, and the machine key stays enrolled in MokList");
    }
    Journal::remove(ctx.api, "uninstall", KEY)?;
    // Last: everything left under %ProgramData%\paguro (the service's log
    // and boot marker, the journal directory); what is in use goes at the
    // next start.
    let _ = crate::cmd::setup::remove_tree_or_later(ctx.api, &ctx.data_dir());
    Ok(r.line("paguro is uninstalled"))
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_published_inf() {
        let l = "Microsoft PnP Utility\n\nPublished Name:     oem3.inf\nOriginal Name:      netfoo.inf\n\nPublished Name:     oem7.inf\nOriginal Name:      paguro_flt.inf\nProvider Name:      paguro\n";
        assert_eq!(published_inf(l).as_deref(), Some("oem7.inf"));
        assert_eq!(published_inf("nothing"), None);
    }
}
