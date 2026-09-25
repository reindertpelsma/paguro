//! The Windows service's own lifecycle (INTERFACES.md §11.7, §5).
//!
//! - [`startup_cleanup`]: "one-shot variables never dangle" — at service
//!   start, delete `PaguroSetup`, `PaguroBootTarget` and `PaguroBootstrap`
//!   (the user chose Windows at the firmware menu instead of going through
//!   paguro). Once per Windows boot: a service restarted later in the same
//!   boot must not delete what was staged for the coming restart.
//! - `paguro service install|uninstall|start|stop`: direct mode only (the
//!   service cannot install itself), through `sc.exe`.

use paguro_core::guid::PAGURO_VENDOR;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::api::{WinApi, join};
use crate::ctx::Ctx;
use crate::out::{CmdError, CmdResult, Exit, Report};

pub const NAME: &str = "paguro";
pub const DISPLAY: &str = "paguro";
pub const DESCRIPTION: &str =
    "paguro: firmware variables, the ESP, images and the way into Linux (INTERFACES §11.7)";
pub const BOOTSTRAP_VAR: &str = "PaguroBootstrap";
pub const BOOT_TARGET_VAR: &str = "PaguroBootTarget";
pub const SETUP_VAR: &str = "PaguroSetup";
/// The one-shot variables of INTERFACES.md §5.
pub const ONE_SHOTS: [&str; 3] = [SETUP_VAR, BOOT_TARGET_VAR, BOOTSTRAP_VAR];
/// Two boot-time estimates this close are the same boot (uptime and the
/// clock are read a moment apart; the clock may be adjusted slightly).
const SAME_BOOT_SLACK_SECS: u64 = 120;
const MAX_MARKER: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Marker {
    boot_unix: u64,
}

fn marker_path(api: &dyn WinApi) -> String {
    join(&api.program_data(), "paguro\\service-boot.json")
}

/// Run at service start. Returns what was deleted, or that this boot was
/// already cleaned.
pub fn startup_cleanup(api: &dyn WinApi) -> Result<Value, CmdError> {
    let boot = api.now_unix().saturating_sub(api.uptime_secs());
    let path = marker_path(api);
    let seen = api
        .read_file(&path, MAX_MARKER)
        .ok()
        .flatten()
        .and_then(|b| serde_json::from_slice::<Marker>(&b).ok());
    if seen.is_some_and(|m| m.boot_unix.abs_diff(boot) <= SAME_BOOT_SLACK_SECS) {
        return Ok(json!({ "boot_unix": boot, "already_done": true, "deleted": [] }));
    }
    if !api.firmware_is_uefi() {
        return Ok(
            json!({ "boot_unix": boot, "already_done": false, "deleted": [], "uefi": false }),
        );
    }
    let mut deleted = Vec::new();
    for name in ONE_SHOTS {
        if api.fw_get(name, &PAGURO_VENDOR)?.is_some() {
            api.fw_delete(name, &PAGURO_VENDOR)?;
            deleted.push(name);
        }
    }
    api.create_dir_all(&join(&api.program_data(), "paguro"))?;
    let body = serde_json::to_vec(&Marker { boot_unix: boot })
        .map_err(|e| CmdError::internal(e.to_string()))?;
    api.write_file(&path, &body)?;
    Ok(json!({ "boot_unix": boot, "already_done": false, "deleted": deleted }))
}

fn sc(ctx: &Ctx<'_>, args: &[&str]) -> Result<crate::api::Output, CmdError> {
    Ok(ctx.api.run("sc.exe", args, None)?)
}

/// `sc.exe query` exit code for "the service does not exist".
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;

pub fn installed(ctx: &Ctx<'_>) -> Result<bool, CmdError> {
    let o = sc(ctx, &["query", NAME])?;
    Ok(o.status != ERROR_SERVICE_DOES_NOT_EXIST && o.ok())
}

fn checked(ctx: &Ctx<'_>, args: &[&str]) -> Result<(), CmdError> {
    let o = sc(ctx, args)?;
    if o.ok() {
        Ok(())
    } else {
        Err(CmdError::new(
            Exit::Platform,
            format!(
                "sc.exe {} failed ({}): {}{}",
                args.join(" "),
                o.status,
                o.stdout.trim(),
                o.stderr.trim()
            ),
        ))
    }
}

/// Register `exe` (`paguro.exe`, run as `paguro.exe service`) as an auto-start LocalSystem
/// service, restarted on failure, and start it.
pub fn install(ctx: &Ctx<'_>, exe: &str) -> CmdResult {
    let bin = format!("\"{exe}\" service");
    let plan = json!({ "name": NAME, "binary": exe, "command_line": bin });
    if ctx.dry_run {
        return Ok(Report::new(plan).line(format!("would install the service {NAME} ({exe})")));
    }
    ctx.need_admin()?;
    if installed(ctx)? {
        checked(ctx, &["config", NAME, "binPath=", &bin, "start=", "auto"])?;
    } else {
        checked(
            ctx,
            &[
                "create",
                NAME,
                "binPath=",
                &bin,
                "start=",
                "auto",
                "obj=",
                "LocalSystem",
                "DisplayName=",
                DISPLAY,
            ],
        )?;
    }
    checked(ctx, &["description", NAME, DESCRIPTION])?;
    checked(
        ctx,
        &[
            "failure",
            NAME,
            "reset=",
            "86400",
            "actions=",
            "restart/5000/restart/5000//",
        ],
    )?;
    // Already running is fine (1056).
    let _ = sc(ctx, &["start", NAME])?;
    Ok(Report::new(plan).line(format!("service {NAME} installed and started")))
}

pub fn uninstall(ctx: &Ctx<'_>) -> CmdResult {
    if ctx.dry_run {
        return Ok(
            Report::new(json!({ "name": NAME })).line(format!("would remove the service {NAME}"))
        );
    }
    ctx.need_admin()?;
    if !installed(ctx)? {
        return Ok(Report::new(json!({ "name": NAME, "removed": false }))
            .line("the service is not installed"));
    }
    let _ = sc(ctx, &["stop", NAME])?;
    checked(ctx, &["delete", NAME])?;
    Ok(Report::new(json!({ "name": NAME, "removed": true }))
        .line(format!("service {NAME} removed")))
}

pub fn control(ctx: &Ctx<'_>, start: bool) -> CmdResult {
    let verb = if start { "start" } else { "stop" };
    if ctx.dry_run {
        return Ok(Report::new(json!({ "name": NAME, "action": verb }))
            .line(format!("would {verb} {NAME}")));
    }
    ctx.need_admin()?;
    checked(ctx, &[verb, NAME])?;
    Ok(Report::new(json!({ "name": NAME, "action": verb })).line(format!("{verb}: {NAME}")))
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::api::attr;
    use crate::mock::MockApi;

    #[test]
    fn one_shots_are_deleted_once_per_boot() {
        let m = MockApi::standard();
        for v in ONE_SHOTS {
            m.set_var_raw(v, &PAGURO_VENDOR, &[1], attr::NV_BS_RT);
        }
        m.set_var_raw("PaguroTpmBroken", &PAGURO_VENDOR, &[1], attr::NV_BS_RT);
        let r = startup_cleanup(&m).unwrap();
        assert_eq!(r["deleted"].as_array().unwrap().len(), 3);
        for v in ONE_SHOTS {
            assert!(m.var(v, &PAGURO_VENDOR).is_none(), "{v}");
        }
        // A state, not a one-shot.
        assert!(m.var("PaguroTpmBroken", &PAGURO_VENDOR).is_some());
        // Staged later in the same boot, then the service restarts: kept.
        m.set_var_raw(BOOT_TARGET_VAR, &PAGURO_VENDOR, b"debian", attr::NV_BS_RT);
        m.now.set(m.now.get() + 3600);
        m.uptime.set(m.uptime.get() + 3600);
        let r = startup_cleanup(&m).unwrap();
        assert_eq!(r["already_done"], true);
        assert!(m.var(BOOT_TARGET_VAR, &PAGURO_VENDOR).is_some());
        // The next boot: deleted.
        m.now.set(m.now.get() + 600);
        m.uptime.set(30);
        let r = startup_cleanup(&m).unwrap();
        assert_eq!(r["deleted"][0], BOOT_TARGET_VAR);
        assert!(m.var(BOOT_TARGET_VAR, &PAGURO_VENDOR).is_none());
    }
}
