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

#[derive(Clone, Debug, Default)]
pub struct InstallArgs {
    pub distro: String,
    pub path: String,
    pub size: String,
    pub script: Option<String>,
    pub shim: Option<String>,
    pub mm: Option<String>,
    pub loader: Option<String>,
    pub mok_cert: Option<String>,
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
    let mut salt = [0u8; 16];
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
    let args = json!({
        "distro": a.distro, "path": a.path, "size": a.size, "script": a.script,
        "mok_cert": a.mok_cert,
    });
    if ctx.dry_run {
        let existing = Journal::load(ctx.api, "install", &a.distro)?;
        let steps: Vec<Value> = STEPS
            .iter()
            .map(|id| {
                json!({ "id": id, "state": existing.as_ref().and_then(|j| j.state(id)).unwrap_or(StepState::Pending) })
            })
            .collect();
        return Ok(Report::new(json!({ "args": args, "steps": steps }))
            .lines(STEPS.iter().map(|s| format!("would run: {s}"))));
    }
    let mut j = match Journal::load(ctx.api, "install", &a.distro)? {
        Some(j) => j,
        None => Journal::new(ctx.api, "install", &a.distro, args, &STEPS),
    };
    let mut lines = Vec::new();
    for id in STEPS {
        if let Some(StepState::Done | StepState::Skipped) = j.state(id) {
            lines.push(format!("{id}: already done"));
            continue;
        }
        match step(ctx, a, id, &j) {
            Ok((st, detail)) => {
                lines.push(format!("{id}: {detail}"));
                j.set(ctx.api, id, st, detail);
                j.save(ctx.api)?;
            }
            Err(e) => {
                j.set(ctx.api, id, StepState::Failed, e.message.clone());
                // Never leave the disk attached to WSL behind a failure.
                if j.state("wsl-mount") == Some(StepState::Done)
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
                j.save(ctx.api)?;
                let data = serde_json::to_value(&j).unwrap_or(Value::Null);
                return Err(CmdError::new(e.exit, format!("install step {id} failed: {} (fix it and run the same command again to resume)", e.message)).with_data(data));
            }
        }
    }
    let data = serde_json::to_value(&j).unwrap_or(Value::Null);
    let mut r = Report::new(data)
        .lines(lines)
        .line("installed. The install is not finished until Linux has booted once (it seals itself on that boot).");
    if ctx.yes {
        ctx.api.restart()?;
        r = r.line("restarting");
    }
    Ok(r)
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
