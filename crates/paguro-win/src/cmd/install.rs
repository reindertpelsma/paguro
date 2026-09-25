//! `paguro install <distro>` — the orchestration skeleton of INTERFACES.md
//! §11.4, as a resumable state machine (see [`crate::journal`]).
//!
//! ```text
//! host        UEFI, elevated, WSL2 present
//! hw-export   %ProgramData%\paguro\host-hardware.json          (§11.5)
//! disk        fixed VHD, verified                              (§11.4 step 2)
//! wsl-mount   wsl --mount --vhd <path> --bare                  (step 3)
//! build       STUB: runs --script inside WSL as root           (step 4)
//! wsl-unmount wsl --unmount <path>                             (step 5)
//! esp         shim, MokManager, paguro.efi                     (§2)
//! mok         MokNew/MokAuth for --mok-cert                    (§11.6)
//! bootstrap   PaguroBootstrap (the wrapped VMK), one-shot Boot####, BootNext
//!             (§9, DESIGN §6)
//! ```
//!
//! **The build step is a stub**: the distribution's ISO in a privileged
//! container (§11.4 step 4) is later work. What runs now is a script the
//! caller provides, inside WSL as root, with the host-hardware export and
//! the distribution name in its environment; it must find the bare VHD
//! (`lsblk`) and install onto it.
//!
//! **`paguro.ini` is not written here** (INTERFACES.md §11.2, §11.4 step 6):
//! the loader authors the first one on its bootstrap boot and the initrd
//! stores it with its hash (§8.1). `paguro config` edits it afterwards.

use serde_json::{Value, json};

use crate::bootent;
use crate::cfgfile;
use crate::cmd::{disk, mok, transition};
use crate::ctx::Ctx;
use crate::esp;
use crate::journal::{Journal, StepState};
use crate::keys;
use crate::out::{At, CmdError, CmdResult, Exit, Report, guid_text};


pub const STEPS: [&str; 9] = [
    "host",
    "hw-export",
    "disk",
    "wsl-mount",
    "build",
    "wsl-unmount",
    "esp",
    "mok",
    "bootstrap",
];

/// Where the system comes from (INTERFACES.md §11.4, §11.8 item 2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// A script run as root inside WSL2 (the scripted fallback).
    #[default]
    Script,
    /// The distribution's ISO and its own installer in a WSL2 container.
    Iso,
    /// An existing WSL2 distribution, made bootable on the metal.
    Wsl,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct InstallArgs {
    pub distro: String,
    pub path: String,
    pub size: String,
    pub source: Source,
    pub script: Option<String>,
    pub iso: Option<String>,
    pub wsl_distro: Option<String>,
    /// Manual mode: stop after attaching the disk and hand over a root shell.
    pub shell: bool,
    /// Manual mode, second half: check what the user built and complete.
    pub finish: bool,
    pub shim: Option<String>,
    pub mm: Option<String>,
    pub loader: Option<String>,
    pub mok_cert: Option<String>,
    /// Restart at the end.
    pub yes: bool,
}

/// What `--finish` checks, and whether each could be checked (INTERFACES
/// §11.7 "manual" mode).
fn finish_checks(ctx: &Ctx<'_>, a: &InstallArgs) -> Result<(Vec<Value>, Vec<String>), CmdError> {
    let mut checks = Vec::new();
    let mut missing = Vec::new();
    match disk::inspect_path(ctx.api, &a.path) {
        Ok(i) => {
            let ok = i.problems.is_empty();
            if !ok {
                missing.push(format!("the disk file: {}", i.problems.join("; ")));
            }
            checks.push(json!({ "id": "disk", "state": if ok { "ok" } else { "fail" }, "detail": i.problems }));
            let kind = i.json.at("efi_fs").at("kind").as_str().unwrap_or("none").to_string();
            let esp_ok = kind == "gpt_esp" || kind == "superfloppy";
            if !esp_ok {
                missing.push("a nested ESP with the bootloader (no GPT ESP or FAT32 found on the disk)".into());
            }
            checks.push(json!({ "id": "nested_esp", "state": if esp_ok { "ok" } else { "fail" }, "detail": kind }));
        }
        Err(e) => {
            missing.push(format!("the disk file: {}", e.message));
            checks.push(json!({ "id": "disk", "state": "fail", "detail": e.message }));
        }
    }
    for id in ["paguro_package", "initramfs_dm_paguro", "bootloader_settings"] {
        checks.push(json!({ "id": id, "state": "unverified", "detail": "STUB: checked from inside the image by the Linux side, which is not built yet" }));
    }
    Ok((checks, missing))
}

/// `C:\a\b.sh` → `/mnt/c/a/b.sh` (WSL's default automount).
pub fn wsl_path(p: &str) -> Option<String> {
    let mut chars = p.chars();
    let drive = chars.next()?.to_ascii_lowercase();
    if !drive.is_ascii_alphabetic() || chars.next()? != ':' {
        return None;
    }
    let rest: String = chars.as_str().replace('\\', "/");
    Some(format!("/mnt/{drive}{rest}"))
}

fn run_ok(ctx: &Ctx<'_>, prog: &str, args: &[&str]) -> Result<String, CmdError> {
    let o = ctx.api.run(prog, args, None)?;
    if o.ok() {
        Ok(o.stdout)
    } else {
        Err(CmdError::new(
            Exit::Platform,
            format!(
                "{prog} {} failed ({}): {}",
                args.join(" "),
                o.status,
                o.stderr.trim()
            ),
        ))
    }
}

/// Write the `PaguroBootstrap` payload for `volume` and a one-shot entry
/// (shim, `paguro.efi` as its second stage), and point `BootNext` at it
/// (INTERFACES.md §9; DESIGN.md §6 "Bootstrap", §7's NVRAM-clear repair).
pub fn write_bootstrap(
    ctx: &Ctx<'_>,
    esp_vol: &crate::api::Volume,
    volume: &paguro_core::guid::Guid,
) -> Result<Value, CmdError> {
    let vol = transition::entry_volume(ctx, volume)?;
    let keys = keys::from_windows(ctx.api, &vol)?.ok_or_else(|| {
        CmdError::refused("the volume is not BitLocker-encrypted: the loader needs no key to start (nothing to bootstrap)")
    })?;
    let plan = json!({ "volume": guid_text(volume), "vmk_source": keys.source });
    if ctx.dry_run {
        return Ok(plan);
    }
    let pass = ctx.passphrase("Choose the Linux passphrase")?;
    let mut salt = [0u8; paguro_core::seal::SALT_LEN];
    ctx.api.random(&mut salt)?;
    let ph = keys::pass_hash(&pass, &salt);
    let wrapped = keys::wrap_bootstrap(&keys.vmk, &salt, &ph);
    let payload = zeroize::Zeroizing::new(paguro_core::bootstrap::write_payload(
        volume, &salt, &wrapped,
    ));
    // Idempotent: at most one bootstrap entry exists.
    for e in bootent::list(ctx.api)?
        .iter()
        .filter(|e| e.ours && e.bootstrap)
    {
        bootent::delete(ctx.api, e.number)?;
    }
    ctx.api.fw_set(
        paguro_core::bootstrap::VAR_NAME,
        &paguro_core::guid::PAGURO_VENDOR,
        &payload[..],
        crate::api::attr::NV_BS_RT,
    )?;
    let n = bootent::create_bootstrap(ctx.api, esp_vol)?;
    bootent::set_boot_next(ctx.api, n)?;
    Ok(
        json!({ "volume": guid_text(volume), "vmk_source": keys.source, "entry": bootent::var_name(n), "variable": paguro_core::bootstrap::VAR_NAME }),
    )
}

fn step(
    ctx: &Ctx<'_>,
    a: &InstallArgs,
    id: &str,
    j: &Journal,
) -> Result<(StepState, String), CmdError> {
    let api = ctx.api;
    match id {
        "host" => {
            ctx.need_uefi()?;
            ctx.need_admin()?;
            let o = api.run("wsl.exe", &["--status"], None)?;
            if !o.ok() {
                return Err(CmdError::refused("WSL2 is not installed (`wsl --install`, then reboot); it is required (INTERFACES.md §11.4)"));
            }
            Ok((StepState::Done, "UEFI, administrator, WSL2 present".into()))
        }
        "hw-export" => {
            let p = crate::api::join(&ctx.data_dir(), "host-hardware.json");
            api.create_dir_all(&ctx.data_dir())?;
            crate::cmd::hw::export(ctx, Some(&p))?;
            Ok((StepState::Done, p))
        }
        "disk" => {
            if api.file_facts(&a.path)?.is_some() {
                return Err(CmdError::refused(format!("{} already exists; paguro never overwrites a disk", a.path)));
            }
            disk::create(ctx, &a.path, &a.size)?;
            Ok((StepState::Done, format!("{} ({})", a.path, a.size)))
        }
        "wsl-mount" => {
            run_ok(ctx, "wsl.exe", &["--mount", "--vhd", &a.path, "--bare"])?;
            Ok((StepState::Done, "attached to WSL2 as a bare disk".into()))
        }
        "build" if a.finish => {
            let (_, missing) = finish_checks(ctx, a)?;
            if missing.is_empty() {
                Ok((StepState::Done, "finished by hand; the disk checks passed (package, initramfs and bootloader checks are STUB: unverified)".into()))
            } else {
                Err(CmdError::check_failed(format!("not finished: missing {}", missing.join("; ")), json!({ "missing": missing })))
            }
        }
        "build" if a.shell => Ok((
            StepState::AwaitingUser,
            format!("the disk is attached to WSL2: install by hand in the shell, then run `paguro install {} --path {} --finish`", a.distro, a.path),
        )),
        "build" if a.source == Source::Iso => Err(CmdError::refused(
            "STUB: the distribution's ISO in a WSL2 container (INTERFACES §11.4 step 4) is Linux-side work that is not built yet; use --shell to install by hand, or --script",
        ).with_data(json!({ "stub": true }))),
        "build" if a.source == Source::Wsl => Err(CmdError::refused(
            "STUB: making a WSL2 distribution bootable (its rootfs copied into the image, INTERFACES §11.4) is Linux-side work that is not built yet",
        ).with_data(json!({ "stub": true }))),
        "build" => match &a.script {
            None => Ok((
                StepState::Skipped,
                "STUB: the distribution installer in a WSL2 container is not implemented (INTERFACES.md §11.4 step 4); pass --script".into(),
            )),
            Some(s) => {
                let wp = wsl_path(s).ok_or_else(|| CmdError::refused(format!("{s}: needs a drive-letter path")))?;
                let hw = wsl_path(&crate::api::join(&ctx.data_dir(), "host-hardware.json")).unwrap_or_default();
                let d = format!("PAGURO_DISTRO={}", a.distro);
                let h = format!("PAGURO_HOST_HARDWARE={hw}");
                let v = format!("PAGURO_VHD={}", a.path);
                run_ok(ctx, "wsl.exe", &["-u", "root", "-e", "env", &d, &h, &v, "sh", &wp])?;
                Ok((StepState::Done, format!("ran {s} in WSL2")))
            }
        },
        "wsl-unmount" => {
            if j.state("wsl-mount") == Some(StepState::Done) {
                run_ok(ctx, "wsl.exe", &["--unmount", &a.path])?;
                Ok((StepState::Done, "detached from WSL2".into()))
            } else {
                Ok((StepState::Skipped, "was not mounted".into()))
            }
        }
        "esp" => match (&a.shim, &a.mm, &a.loader) {
            (Some(s), Some(m), Some(l)) => {
                crate::cmd::esp::install(ctx, s, m, l)?;
                Ok((StepState::Done, "shim, MokManager, paguro.efi installed".into()))
            }
            _ if esp::read_manifest(api)?.is_some() => Ok((StepState::Skipped, "already installed".into())),
            _ => Err(CmdError::refused("the ESP files are not installed: pass --shim, --mm and --loader")),
        },
        "mok" => match &a.mok_cert {
            None => Ok((StepState::Skipped, "no --mok-cert (machine key generation is not implemented)".into())),
            Some(c) => {
                if !transition::secure_boot(ctx)? {
                    return Ok((StepState::Skipped, "Secure Boot off".into()));
                }
                let r = mok::enroll(ctx, c, false)?;
                let pw = r.data.at("one_time_password").as_str().unwrap_or("").to_string();
                Ok((StepState::Done, format!("enrolment requested; one-time password {pw}")))
            }
        },
        "bootstrap" => {
            let esp_vol = ctx.esp()?;
            let (volume, _) = cfgfile::resolve_windows_path(api, &a.path)?;
            let v = write_bootstrap(ctx, &esp_vol, &volume)?;
            Ok((StepState::Done, format!("bootstrap {}; BootNext set", v.at("entry").as_str().unwrap_or("?"))))
        }
        _ => Err(CmdError::internal(format!("unknown step {id}"))),
    }
}

fn key_ok(distro: &str) -> bool {
    paguro_core::config::check_name(distro)
}

pub fn install(ctx: &Ctx<'_>, a: &InstallArgs) -> CmdResult {
    if !key_ok(&a.distro) {
        return Err(CmdError::new(
            Exit::Usage,
            "the distribution name must match [A-Za-z0-9_-]{1,32}",
        ));
    }
    if a.shell && a.finish {
        return Err(CmdError::new(Exit::Usage, "--shell and --finish are the two halves of a manual install: one at a time"));
    }
    match a.source {
        Source::Iso if a.iso.is_none() => return Err(CmdError::new(Exit::Usage, "--iso needs the ISO file")),
        Source::Wsl if a.wsl_distro.is_none() => return Err(CmdError::new(Exit::Usage, "--from-wsl needs the WSL distribution's name")),
        _ => {}
    }
    let size = if a.size.is_empty() { "32G" } else { a.size.as_str() };
    let a = &InstallArgs { size: size.into(), ..a.clone() };
    let args = json!({
        "distro": a.distro, "path": a.path, "size": a.size, "script": a.script,
        "mok_cert": a.mok_cert, "source": a.source, "iso": a.iso, "wsl_distro": a.wsl_distro,
    });
    let existing = Journal::load(ctx.api, "install", &a.distro)?;
    if a.finish && existing.as_ref().and_then(|j| j.state("build")) != Some(StepState::AwaitingUser) {
        return Err(CmdError::refused(format!(
            "nothing to finish: start with `paguro install {} --path … --shell`",
            a.distro
        )));
    }
    if !a.finish && !a.shell && existing.as_ref().and_then(|j| j.state("build")) == Some(StepState::AwaitingUser) {
        return Err(CmdError::refused(format!(
            "this install waits for the manual step: `paguro install {} --path {} --finish` (or --shell again)",
            a.distro, a.path
        )));
    }
    if ctx.dry_run {
        let steps: Vec<Value> = STEPS
            .iter()
            .map(|id| {
                json!({ "id": id, "state": existing.as_ref().and_then(|j| j.state(id)).unwrap_or(StepState::Pending) })
            })
            .collect();
        let mut data = json!({ "args": args, "steps": steps });
        if a.finish {
            let (checks, missing) = finish_checks(ctx, a)?;
            if let Some(o) = data.as_object_mut() {
                o.insert("finish_checks".into(), json!(checks));
                o.insert("missing".into(), json!(missing));
            }
        }
        return Ok(Report::new(data)
            .lines(STEPS.iter().map(|s| format!("would run: {s}"))));
    }
    let mut j = match existing {
        Some(j) => j,
        None => Journal::new(ctx.api, "install", &a.distro, args, &STEPS),
    };
    let mut lines = Vec::new();
    let total = STEPS.len();
    for (i, id) in STEPS.into_iter().enumerate() {
        if let Some(StepState::Done | StepState::Skipped) = j.state(id) {
            lines.push(format!("{id}: already done"));
            ctx.step("install", i, total, id, "done", "already done");
            continue;
        }
        ctx.step("install", i, total, id, "running", "");
        match step(ctx, a, id, &j) {
            Ok((StepState::AwaitingUser, detail)) => {
                lines.push(format!("{id}: {detail}"));
                j.set(ctx.api, id, StepState::AwaitingUser, detail.clone());
                j.save(ctx.api)?;
                ctx.step("install", i, total, id, "awaiting_user", &detail);
                let mut data = serde_json::to_value(&j).unwrap_or(Value::Null);
                if let Some(o) = data.as_object_mut() {
                    o.insert("shell".into(), json!(crate::cmd::distro::SHELL));
                }
                return Ok(Report::new(data)
                    .lines(lines)
                    .line(format!("shell: {}", crate::cmd::distro::SHELL.join(" ")))
                    .warn("STUB: a plain root shell in WSL2 with the disk attached bare; the installer's container with /target mounted (INTERFACES §11.7) is Linux-side work")
                    .exit(Exit::Pending));
            }
            Ok((st, detail)) => {
                lines.push(format!("{id}: {detail}"));
                ctx.step("install", i, total, id, state_name(st), &detail);
                j.set(ctx.api, id, st, detail);
                j.save(ctx.api)?;
            }
            Err(e) => {
                ctx.step("install", i, total, id, "failed", &e.message);
                j.set(ctx.api, id, StepState::Failed, e.message.clone());
                // Never leave the disk attached to WSL behind a failure
                // (except while the user works on it by hand).
                if !a.finish
                    && j.state("wsl-mount") == Some(StepState::Done)
                    && j.state("wsl-unmount") != Some(StepState::Done)
                    && ctx
                        .api
                        .run("wsl.exe", &["--unmount", &a.path], None)
                        .is_ok_and(|o| o.ok())
                {
                    j.set(
                        ctx.api,
                        "wsl-mount",
                        StepState::Pending,
                        "unmounted after a failure",
                    );
                }
                if a.finish && id == "build" {
                    j.set(ctx.api, id, StepState::AwaitingUser, e.message.clone());
                }
                j.save(ctx.api)?;
                let mut data = serde_json::to_value(&j).unwrap_or(Value::Null);
                if let (Some(o), Some(d)) = (data.as_object_mut(), &e.data) {
                    o.insert("failure".into(), d.clone());
                }
                return Err(CmdError::new(e.exit, format!("install step {id} failed: {} (fix it and run the same command again to resume)", e.message)).with_data(data));
            }
        }
    }
    let data = serde_json::to_value(&j).unwrap_or(Value::Null);
    let mut r = Report::new(data)
        .lines(lines)
        .line("installed. The install is not finished until Linux has booted once (it seals itself on that boot).");
    if a.yes {
        ctx.api.restart()?;
        r = r.line("restarting");
    }
    Ok(r)
}

fn state_name(s: StepState) -> &'static str {
    match s {
        StepState::Pending => "pending",
        StepState::Done => "done",
        StepState::Skipped => "skipped",
        StepState::Failed => "failed",
        StepState::AwaitingReboot => "awaiting_reboot",
        StepState::AwaitingUser => "awaiting_user",
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn wsl_paths() {
        assert_eq!(
            wsl_path("C:\\paguro\\x.sh").as_deref(),
            Some("/mnt/c/paguro/x.sh")
        );
        assert_eq!(wsl_path("\\\\?\\Volume{x}\\a"), None);
        assert_eq!(wsl_path(""), None);
    }
}
