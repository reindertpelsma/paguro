//! `paguro esp install|verify|repair` (INTERFACES.md §2, DESIGN.md §7).

use serde_json::json;

use crate::ctx::Ctx;
use crate::esp::{self, FileState, Inputs};
use crate::out::{At, CmdError, CmdResult, Report};

fn read_input(ctx: &Ctx<'_>, path: &str) -> Result<Vec<u8>, CmdError> {
    ctx.api
        .read_file(path, esp::MAX_ESP_FILE)?
        .ok_or_else(|| CmdError::not_found(format!("{path}: no such file")))
}

pub fn install(ctx: &Ctx<'_>, shim: &str, mm: &str, loader: &str) -> CmdResult {
    ctx.need_uefi()?;
    let esp_vol = ctx.esp()?;
    let inp = Inputs {
        shim: read_input(ctx, shim)?,
        mm: read_input(ctx, mm)?,
        loader: read_input(ctx, loader)?,
    };
    if !ctx.dry_run {
        ctx.need_admin()?;
    }
    let plan = esp::install(ctx.api, &esp_vol, &inp, ctx.dry_run)?;
    let n = plan.at("files").as_array().map_or(0, Vec::len);
    Ok(Report::new(plan).line(format!(
        "{} {n} files in \\EFI\\paguro\\ and recorded their hashes",
        if ctx.dry_run {
            "would install"
        } else {
            "installed"
        }
    )))
}

pub fn verify(ctx: &Ctx<'_>) -> CmdResult {
    let esp_vol = ctx.esp()?;
    let checks = esp::verify(ctx.api, &esp_vol)?;
    let seals = esp::seal_dirs(ctx.api, &esp_vol)?;
    let bad: Vec<_> = checks.iter().filter(|c| c.state != FileState::Ok).collect();
    let data = json!({ "files": checks, "volumes": seals });
    let lines = checks
        .iter()
        .map(|c| format!("{:<16} {:?}", c.name, c.state))
        .collect::<Vec<_>>();
    if bad.is_empty() {
        Ok(Report::new(data)
            .lines(lines)
            .line("the ESP matches what was installed"))
    } else {
        Err(CmdError::check_failed(
            format!(
                "{} file(s) missing or modified: {}; `paguro esp repair` restores them",
                bad.len(),
                bad.iter()
                    .map(|c| c.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            data,
        ))
    }
}

pub fn repair(ctx: &Ctx<'_>) -> CmdResult {
    ctx.need_uefi()?;
    let esp_vol = ctx.esp()?;
    if !ctx.dry_run {
        ctx.need_admin()?;
    }
    let restored = esp::repair(ctx.api, &esp_vol, ctx.dry_run)?;
    let lines = if restored.is_empty() {
        vec!["nothing to repair".to_string()]
    } else {
        restored
            .iter()
            .map(|c| {
                format!(
                    "{} {}",
                    if ctx.dry_run {
                        "would restore"
                    } else {
                        "restored"
                    },
                    c.name
                )
            })
            .collect()
    };
    Ok(Report::new(json!({ "restored": restored })).lines(lines))
}
