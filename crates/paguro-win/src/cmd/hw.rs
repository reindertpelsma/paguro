//! `paguro hw export|modalias` (INTERFACES.md §11.5).

use serde_json::json;

use crate::ctx::Ctx;
use crate::hw::{self, HostHardware};
use crate::out::{CmdError, CmdResult, Report};

/// Largest hardware export read.
const MAX_EXPORT: usize = 16 << 20;

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

/// The modaliases an export presents (the synthetic sysfs's view). The
/// export travels as JSON: front ends read the file, the service never
/// opens a caller's path.
pub fn modalias(_ctx: &Ctx<'_>, hardware: &serde_json::Value) -> CmdResult {
    let h: HostHardware = serde_json::from_value(hardware.clone())
        .map_err(|e| CmdError::refused(format!("not a host-hardware export: {e}")))?;
    if h.version != hw::VERSION {
        return Err(CmdError::refused(format!(
            "unknown host-hardware version {}",
            h.version
        )));
    }
    let m = hw::modaliases(&h);
    Ok(Report::new(json!({ "modaliases": m })).lines(m.clone()))
}

/// Read an export file for [`modalias`] (front-end side).
pub fn read_export(
    api: &dyn crate::api::WinApi,
    input: &str,
) -> Result<serde_json::Value, CmdError> {
    let b = api
        .read_file(input, MAX_EXPORT)?
        .ok_or_else(|| CmdError::not_found(format!("{input}: no such file")))?;
    serde_json::from_slice(&b).map_err(|e| CmdError::refused(format!("{input}: {e}")))
}
