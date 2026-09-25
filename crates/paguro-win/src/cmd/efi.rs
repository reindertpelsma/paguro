//! `paguro efi vars|boot-entry|bootnext` — paguro's firmware variables
//! (INTERFACES.md §5) and boot entries (§9).
//!
//! `PaguroSetup` (`S`) is key material: it is never printed, and only
//! `stage-setup` writes it. `PaguroB` is boot-services-only and invisible to
//! any OS by design; it is listed as such.

use paguro_core::guid::PAGURO_VENDOR;
use serde_json::{Value, json};

use crate::api::attr;
use crate::bootent;
use crate::ctx::Ctx;
use crate::out::{At, CmdError, CmdResult, Exit, Report, from_hex, to_hex};

pub struct VarSpec {
    pub name: &'static str,
    pub size: usize,
    /// Printable (not key material).
    pub public: bool,
    /// Settable with `efi vars set`.
    pub settable: bool,
    pub note: &'static str,
}

pub const VARS: [VarSpec; 5] = [
    VarSpec {
        name: "PaguroB",
        size: 32,
        public: false,
        settable: false,
        note: "boot-services only: never visible to an OS",
    },
    VarSpec {
        name: "PaguroConfigHash",
        size: 32,
        public: true,
        settable: true,
        note: "SHA-256 of paguro.ini",
    },
    VarSpec {
        name: "PaguroSetup",
        size: 32,
        public: false,
        settable: false,
        note: "S, one-shot setupTPM secret: written by `paguro stage-setup` only",
    },
    VarSpec {
        name: "PaguroTpmBroken",
        size: 1,
        public: true,
        settable: true,
        note: "set by the loader when the TPM seal failed",
    },
    VarSpec {
        name: "PaguroUninstall",
        size: 1,
        public: true,
        settable: true,
        note: "uninstall request: the loader deletes PaguroB on the next boot",
    },
];

pub fn spec(name: &str) -> Result<&'static VarSpec, CmdError> {
    VARS.iter()
        .find(|v| v.name.eq_ignore_ascii_case(name))
        .ok_or_else(|| {
            CmdError::new(
                Exit::Usage,
                format!(
                    "{name} is not a paguro variable ({})",
                    VARS.map(|v| v.name).join(", ")
                ),
            )
        })
}

fn describe(ctx: &Ctx<'_>, v: &VarSpec) -> Result<Value, CmdError> {
    let got = ctx.api.fw_get(v.name, &PAGURO_VENDOR)?;
    Ok(json!({
        "name": v.name,
        "present": got.is_some(),
        "size": got.as_ref().map(|g| g.data.len()),
        "size_ok": got.as_ref().map(|g| g.data.len() == v.size),
        "attributes": got.as_ref().map(|g| g.attributes),
        "value": got.as_ref().filter(|_| v.public).map(|g| to_hex(&g.data)),
        "note": v.note,
    }))
}

pub fn vars_list(ctx: &Ctx<'_>) -> CmdResult {
    ctx.need_uefi()?;
    let mut all = Vec::new();
    let mut lines = Vec::new();
    for v in &VARS {
        let d = describe(ctx, v)?;
        lines.push(format!(
            "{:<18} {}",
            v.name,
            if d.at("present") == true {
                d.at("value")
                    .as_str()
                    .unwrap_or("(present, not shown)")
                    .to_string()
            } else {
                "absent".into()
            }
        ));
        all.push(d);
    }
    Ok(Report::new(json!({ "variables": all })).lines(lines))
}

pub fn vars_get(ctx: &Ctx<'_>, name: &str) -> CmdResult {
    ctx.need_uefi()?;
    let v = spec(name)?;
    let d = describe(ctx, v)?;
    if d.at("present") != true {
        return Err(CmdError::not_found(format!("{} is absent ({})", v.name, v.note)).with_data(d));
    }
    let line = d
        .at("value")
        .as_str()
        .unwrap_or("(present; key material is not shown)")
        .to_string();
    Ok(Report::new(d).line(line))
}

pub fn vars_set(ctx: &Ctx<'_>, name: &str, hex: &str) -> CmdResult {
    ctx.need_uefi()?;
    let v = spec(name)?;
    if !v.settable {
        return Err(CmdError::refused(format!(
            "{} cannot be set by hand: {}",
            v.name, v.note
        )));
    }
    let data = from_hex(hex).ok_or_else(|| CmdError::new(Exit::Usage, "the value must be hex"))?;
    if data.len() != v.size {
        return Err(CmdError::refused(format!(
            "{} is {} bytes, got {}",
            v.name,
            v.size,
            data.len()
        )));
    }
    let out = json!({ "name": v.name, "value": to_hex(&data) });
    if !ctx.dry_run {
        ctx.need_admin()?;
        ctx.api
            .fw_set(v.name, &PAGURO_VENDOR, &data, attr::NV_BS_RT)?;
    }
    Ok(Report::new(out).line(format!("{} = {}", v.name, to_hex(&data))))
}

pub fn vars_delete(ctx: &Ctx<'_>, name: &str) -> CmdResult {
    ctx.need_uefi()?;
    let v = spec(name)?;
    if !ctx.dry_run {
        ctx.need_admin()?;
        ctx.api.fw_delete(v.name, &PAGURO_VENDOR)?;
    }
    Ok(Report::new(json!({ "name": v.name, "deleted": true })).line(format!("{} deleted", v.name)))
}

pub fn entries_list(ctx: &Ctx<'_>) -> CmdResult {
    ctx.need_uefi()?;
    let list = bootent::list(ctx.api)?;
    let next = bootent::boot_next(ctx.api)?;
    let order = bootent::boot_order(ctx.api)?;
    let lines = list.iter().map(|e| {
        format!(
            "{}{} {:<24} {}{}",
            e.name,
            if e.in_boot_order { "*" } else { " " },
            e.description,
            e.path.as_deref().unwrap_or("-"),
            if e.ours { "  (paguro)" } else { "" }
        )
    });
    Ok(Report::new(json!({
        "entries": list,
        "boot_order": order.iter().map(|n| format!("{n:04X}")).collect::<Vec<_>>(),
        "boot_next": next.map(|n| format!("{n:04X}")),
    }))
    .lines(lines))
}

pub fn entry_create(ctx: &Ctx<'_>) -> CmdResult {
    ctx.need_uefi()?;
    let esp = ctx.esp()?;
    if !ctx.dry_run {
        ctx.need_admin()?;
    }
    let (n, changed) = bootent::ensure_standing(ctx.api, &esp, ctx.dry_run)?;
    let name = bootent::var_name(n);
    Ok(
        Report::new(json!({ "entry": name, "changed": changed })).line(if changed {
            format!("{name}: paguro entry written, in BootOrder")
        } else {
            format!("{name}: already correct")
        }),
    )
}

pub fn entry_delete(ctx: &Ctx<'_>, which: &str) -> CmdResult {
    ctx.need_uefi()?;
    let n = bootent::parse_number(which)?;
    let list = bootent::list(ctx.api)?;
    let e = list
        .iter()
        .find(|e| e.number == n)
        .ok_or_else(|| CmdError::not_found(format!("{} does not exist", bootent::var_name(n))))?;
    if !e.ours {
        return Err(CmdError::refused(format!(
            "{} is not a paguro entry; paguro only removes its own",
            e.name
        )));
    }
    if !ctx.dry_run {
        ctx.need_admin()?;
        bootent::delete(ctx.api, n)?;
    }
    Ok(
        Report::new(json!({ "entry": e.name, "deleted": true }))
            .line(format!("{} deleted", e.name)),
    )
}

/// `efi bootnext [NUMBER|--clear]`; without a number, paguro's standing entry.
pub fn bootnext(ctx: &Ctx<'_>, which: Option<&str>, clear: bool) -> CmdResult {
    ctx.need_uefi()?;
    if clear {
        if !ctx.dry_run {
            ctx.need_admin()?;
            ctx.api
                .fw_delete("BootNext", &paguro_core::guid::EFI_GLOBAL_VARIABLE)?;
        }
        return Ok(Report::new(json!({ "boot_next": null })).line("BootNext cleared"));
    }
    let n = match which {
        Some(w) => bootent::parse_number(w)?,
        None => bootent::list(ctx.api)?
            .into_iter()
            .find(|e| e.ours && !e.bootstrap && e.description == bootent::STANDING_DESCRIPTION)
            .map(|e| e.number)
            .ok_or_else(|| {
                CmdError::not_found("no paguro boot entry; run `paguro efi boot-entry create`")
            })?,
    };
    if ctx
        .api
        .fw_get(
            &bootent::var_name(n),
            &paguro_core::guid::EFI_GLOBAL_VARIABLE,
        )?
        .is_none()
    {
        return Err(CmdError::not_found(format!(
            "{} does not exist",
            bootent::var_name(n)
        )));
    }
    if !ctx.dry_run {
        ctx.need_admin()?;
        bootent::set_boot_next(ctx.api, n)?;
    }
    Ok(Report::new(json!({ "boot_next": format!("{n:04X}") })).line(format!("BootNext = {n:04X}")))
}
