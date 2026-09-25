//! `paguro hw export|modalias` (INTERFACES.md §11.5).

use serde_json::json;

use crate::ctx::Ctx;
use crate::hw::{self, HostHardware};
use crate::out::{CmdError, CmdResult, Report};

pub fn export(ctx: &Ctx<'_>, output: Option<&str>) -> CmdResult {
    let c = hw::collect(ctx.api)?;
    let h = hw::convert(&c);
    let data = serde_json::to_value(&h).map_err(|e| CmdError::internal(e.to_string()))?;
    let mut r = Report::new(data.clone()).line(format!(
        "{} {} — {} PCI, {} USB, {} ACPI, {} disk(s)",
        h.dmi.sys_vendor,
        h.dmi.product_name,
        h.pci.len(),
        h.usb.len(),
        h.acpi.len(),
        h.storage.len()
    ));
    if c.smbios.is_none() {
        r = r.warn("SMBIOS unavailable: the dmi fields are empty");
    }
    if let Some(p) = output {
        if !ctx.dry_run {
            let mut body =
                serde_json::to_vec_pretty(&h).map_err(|e| CmdError::internal(e.to_string()))?;
            body.push(b'\n');
            ctx.api.write_file(p, &body)?;
        }
        r = r.line(format!("written to {p}"));
    } else {
        r = r.line(serde_json::to_string_pretty(&data).unwrap_or_default());
    }
    Ok(r)
}

/// The modaliases an export presents (the synthetic sysfs's view).
pub fn modalias(ctx: &Ctx<'_>, input: &str) -> CmdResult {
    let b = ctx
        .api
        .read_file(input, 16 << 20)?
        .ok_or_else(|| CmdError::not_found(format!("{input}: no such file")))?;
    let h: HostHardware =
        serde_json::from_slice(&b).map_err(|e| CmdError::refused(format!("{input}: {e}")))?;
    if h.version != hw::VERSION {
        return Err(CmdError::refused(format!(
            "{input}: unknown version {}",
            h.version
        )));
    }
    let m = hw::modaliases(&h);
    Ok(Report::new(json!({ "modaliases": m })).lines(m.clone()))
}
