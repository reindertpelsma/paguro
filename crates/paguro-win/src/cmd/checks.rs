//! `paguro checks [fix <id>]` — the installer's first screen (INTERFACES.md
//! §11.8 item 1): each check explained in one sentence, and fixable from the
//! screen (or the terminal) where Windows allows it.
//!
//! | id | ok | warn | fail |
//! |---|---|---|---|
//! | `uefi` | UEFI | — | legacy BIOS |
//! | `wsl2` | `wsl --status` succeeds | — | absent (fix: `wsl --install --no-distribution`) |
//! | `disk_space` | ≥ 40 GiB free on the system drive | ≥ 20 GiB | less |
//! | `bitlocker` | on, or off | encrypting/decrypting, used-space-only | suspended (fix: resume) |
//! | `tpm` | present | absent (passphrase only) | — |
//! | `secure_boot` | on | off (nothing is verified) | — |
//! | `microsoft_uefi_ca` | in `db` | unknown | missing (§2.1) |
//! | `fast_startup` | off | on (fix: turn it off) | — |

use serde::Serialize;
use serde_json::json;

use crate::cmd::secureboot;
use crate::ctx::Ctx;
use crate::out::{CmdError, CmdResult, Exit, Report};

pub const IDS: [&str; 8] = [
    "uefi",
    "wsl2",
    "disk_space",
    "bitlocker",
    "tpm",
    "secure_boot",
    "microsoft_uefi_ca",
    "fast_startup",
];

/// Free space for a comfortable image, and the least that works.
const SPACE_OK: u64 = 40 << 30;
const SPACE_MIN: u64 = 20 << 30;

const POWER_KEY: &str = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power";
const HIBERBOOT: &str = "HiberbootEnabled";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Ok,
    Warn,
    Fail,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Fix {
    /// `paguro checks fix <id>` does it (as administrator).
    pub automatic: bool,
    /// What it does, or what the user must do, in one sentence.
    pub instruction: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Check {
    pub id: &'static str,
    pub state: State,
    /// One sentence for a non-expert.
    pub detail: String,
    pub fix: Option<Fix>,
}

fn check(id: &'static str, state: State, detail: impl Into<String>) -> Check {
    Check {
        id,
        state,
        detail: detail.into(),
        fix: None,
    }
}

fn with_fix(mut c: Check, automatic: bool, instruction: &str) -> Check {
    c.fix = Some(Fix {
        automatic,
        instruction: instruction.into(),
    });
    c
}

fn gib(b: u64) -> String {
    format!("{:.0} GB", b as f64 / f64::from(1u32 << 30))
}

/// `HiberbootEnabled` from `reg query` output; `None` when absent.
pub fn parse_hiberboot(out: &str) -> Option<bool> {
    out.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        (it.next()? == HIBERBOOT).then_some(())?;
        let _ty = it.next()?;
        let v = it.next()?;
        u32::from_str_radix(v.trim_start_matches("0x"), 16)
            .ok()
            .map(|n| n != 0)
    })
}

fn fast_startup(ctx: &Ctx<'_>) -> Option<bool> {
    let o = ctx
        .api
        .run("reg.exe", &["query", POWER_KEY, "/v", HIBERBOOT], None)
        .ok()?;
    if !o.ok() {
        // The value is absent: Windows' default, which is on.
        return Some(true);
    }
    parse_hiberboot(&o.stdout)
}

pub fn run_checks(ctx: &Ctx<'_>) -> Vec<Check> {
    let api = ctx.api;
    let mut v = Vec::new();
    let uefi = api.firmware_is_uefi();
    v.push(if uefi {
        check("uefi", State::Ok, "The computer starts in UEFI mode, which paguro needs.")
    } else {
        with_fix(
            check("uefi", State::Fail, "The computer starts in legacy BIOS mode; paguro needs UEFI."),
            false,
            "Switch the firmware to UEFI mode (this usually needs Windows converted with mbr2gpt first).",
        )
    });
    let wsl = api
        .run("wsl.exe", &["--status"], None)
        .is_ok_and(|o| o.ok());
    v.push(if wsl {
        check("wsl2", State::Ok, "WSL2 is installed: distributions are installed inside it.")
    } else {
        with_fix(
            check("wsl2", State::Fail, "WSL2 is missing; the installer runs inside it."),
            true,
            "Install WSL2 (wsl --install --no-distribution); Windows then asks for a restart.",
        )
    });
    let sys = api.system_drive();
    let free = api
        .volumes()
        .ok()
        .and_then(|vs| vs.into_iter().find(|x| x.drive().is_some_and(|d| d.eq_ignore_ascii_case(&sys))))
        .map(|x| x.free);
    v.push(match free {
        Some(f) if f >= SPACE_OK => check("disk_space", State::Ok, format!("{} free on {sys}, enough for a Linux image.", gib(f))),
        Some(f) if f >= SPACE_MIN => with_fix(
            check("disk_space", State::Warn, format!("{} free on {sys}: enough for a small image only.", gib(f))),
            false,
            "Free up space on the system drive (Settings > System > Storage).",
        ),
        Some(f) => with_fix(
            check("disk_space", State::Fail, format!("Only {} free on {sys}; a Linux image needs at least {}.", gib(f), gib(SPACE_MIN))),
            false,
            "Free up space on the system drive (Settings > System > Storage).",
        ),
        None => check("disk_space", State::Warn, format!("The free space on {sys} could not be read.")),
    });
    let bl = api.bitlocker(&sys).ok().flatten();
    v.push(match &bl {
        None => check("bitlocker", State::Ok, "BitLocker is not available here: Linux is not encrypted by paguro."),
        Some(b) if !b.is_encrypted() => check("bitlocker", State::Ok, "BitLocker is off: Linux is not encrypted by paguro."),
        Some(b) if b.is_suspended() => with_fix(
            check("bitlocker", State::Fail, "BitLocker is suspended: Windows' key is stored unprotected until it is resumed."),
            true,
            "Resume BitLocker protection (manage-bde -protectors -enable).",
        ),
        Some(b) if matches!(b.conversion_status, 2..=5) => check(
            "bitlocker",
            State::Warn,
            format!("BitLocker is still converting the drive ({}%); wait until it finishes.", b.encryption_percentage),
        ),
        Some(b) if b.used_space_only() == Some(true) => check(
            "bitlocker",
            State::Warn,
            "BitLocker encrypted only the used space: free space may still hold old data in the clear.",
        ),
        Some(_) => check("bitlocker", State::Ok, "BitLocker is on: Linux is protected the same way as Windows."),
    });
    v.push(if api.tpm_present() {
        check("tpm", State::Ok, "A TPM is present: Linux can unlock with it, like Windows.")
    } else {
        check("tpm", State::Warn, "No TPM: Linux unlocks with a passphrase only.")
    });
    match secureboot::describe(ctx) {
        Ok((sb, ca)) => {
            v.push(if sb {
                check("secure_boot", State::Ok, "Secure Boot is on: every step of starting Linux is verified.")
            } else {
                check("secure_boot", State::Warn, "Secure Boot is off: it works, but nothing verifies what starts.")
            });
            v.push(match (sb, ca) {
                (false, _) => check("microsoft_uefi_ca", State::Ok, "Not needed with Secure Boot off."),
                (true, Some(true)) => check("microsoft_uefi_ca", State::Ok, "The firmware trusts Microsoft's third-party CA, which signs Linux's shim."),
                (true, Some(false)) => with_fix(
                    check("microsoft_uefi_ca", State::Fail, "The firmware does not trust Microsoft's third-party CA, so no Linux shim can start."),
                    false,
                    "Enable \"Microsoft 3rd-party UEFI CA\" (or \"Allow Microsoft UEFI CA\") in the firmware's Secure Boot settings; under BitLocker, suspend it for that one reboot.",
                ),
                (true, None) => check("microsoft_uefi_ca", State::Warn, "The Secure Boot database could not be read."),
            });
        }
        Err(e) => {
            v.push(check("secure_boot", State::Warn, format!("Secure Boot state unknown: {}", e.message)));
            v.push(check("microsoft_uefi_ca", State::Warn, "Unknown (Secure Boot state unknown)."));
        }
    }
    v.push(match fast_startup(ctx) {
        Some(false) => check("fast_startup", State::Ok, "Fast Startup is off: Windows' drive is always closed cleanly."),
        Some(true) => with_fix(
            check("fast_startup", State::Warn, "Fast Startup is on: Windows' drive stays half-open, so Linux can only read it."),
            true,
            "Turn Fast Startup off (HiberbootEnabled = 0).",
        ),
        None => check("fast_startup", State::Warn, "The Fast Startup setting could not be read."),
    });
    v
}

pub fn list(ctx: &Ctx<'_>) -> CmdResult {
    let checks = run_checks(ctx);
    let ready = checks.iter().all(|c| c.state != State::Fail);
    let lines: Vec<String> = checks
        .iter()
        .map(|c| format!("{:<18} {:<5} {}", c.id, format!("{:?}", c.state).to_lowercase(), c.detail))
        .collect();
    Ok(Report::new(json!({ "ready": ready, "checks": checks })).lines(lines))
}

pub fn fix(ctx: &Ctx<'_>, id: &str) -> CmdResult {
    if !IDS.contains(&id) {
        return Err(CmdError::new(Exit::Usage, format!("unknown check {id:?} (one of {})", IDS.join(", "))));
    }
    let before = run_checks(ctx)
        .into_iter()
        .find(|c| c.id == id)
        .ok_or_else(|| CmdError::internal("check vanished"))?;
    if before.state == State::Ok {
        return Ok(Report::new(json!({ "id": id, "changed": false, "check": before })).line(format!("{id}: nothing to fix")));
    }
    let fix = before.fix.clone().filter(|f| f.automatic).ok_or_else(|| {
        CmdError::refused(format!(
            "{id} cannot be fixed from here: {}",
            before.fix.as_ref().map_or("see the check's explanation", |f| f.instruction.as_str())
        ))
    })?;
    let (prog, args): (&str, Vec<String>) = match id {
        "wsl2" => ("wsl.exe", vec!["--install".into(), "--no-distribution".into()]),
        "fast_startup" => (
            "reg.exe",
            ["add", POWER_KEY, "/v", HIBERBOOT, "/t", "REG_DWORD", "/d", "0", "/f"]
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        ),
        "bitlocker" => (
            "manage-bde.exe",
            vec!["-protectors".into(), "-enable".into(), ctx.api.system_drive()],
        ),
        _ => return Err(CmdError::internal(format!("{id}: automatic fix without a command"))),
    };
    let plan = json!({ "id": id, "command": std::iter::once(prog.to_string()).chain(args.iter().cloned()).collect::<Vec<_>>() });
    if ctx.dry_run {
        return Ok(Report::new(json!({ "id": id, "changed": false, "plan": plan })).line(format!("would run: {}", fix.instruction)));
    }
    ctx.need_admin()?;
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let o = ctx.api.run(prog, &argv, None)?;
    if !o.ok() {
        return Err(CmdError::new(
            Exit::Platform,
            format!("{prog} failed ({}): {}", o.status, o.stderr.trim()),
        ));
    }
    let after = run_checks(ctx).into_iter().find(|c| c.id == id);
    let mut r = Report::new(json!({ "id": id, "changed": true, "plan": plan, "check": after })).line(format!("{id}: {}", fix.instruction));
    if id == "wsl2" {
        r = r.line("restart Windows to finish installing WSL2");
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hiberboot_parse() {
        let out = "\r\nHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power\r\n    HiberbootEnabled    REG_DWORD    0x1\r\n\r\n";
        assert_eq!(parse_hiberboot(out), Some(true));
        assert_eq!(parse_hiberboot(&out.replace("0x1", "0x0")), Some(false));
        assert_eq!(parse_hiberboot("nothing"), None);
    }
}
