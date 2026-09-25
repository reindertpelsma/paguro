//! `Boot####`, `BootOrder` and `BootNext` (UEFI 2.10 §3.1) for paguro's
//! entries. Parsing and serialisation are `paguro_core::bootstrap`'s.
//!
//! paguro owns two kinds of entry, both recognised by their file path
//! (under `\EFI\paguro\`), never by description alone:
//!
//! - the **standing entry** (`paguro`): GPT Hard Drive node of the ESP +
//!   `\EFI\paguro\shim<arch>.efi`, load options = the UCS-2 string
//!   `\EFI\paguro\paguro.efi`, shim's second-stage argument (shim
//!   `load-options.c` `parse_load_options`: the first UCS-2 string of the
//!   optional data becomes `second_stage`; a path starting `\EFI\` is taken
//!   as absolute on shim's device, `generate_path_from_image_path`);
//! - the **bootstrap entry** (`paguro setup`, INTERFACES.md §9): the same
//!   shape as the standing entry (shim, `paguro.efi` as its second stage),
//!   told apart by its description. One-shot: `BootNext` only, never in
//!   `BootOrder` — which is also how the loader knows it may delete it. The
//!   payload travels in the `PaguroBootstrap` variable, not in the entry.
//!
//! Install only adds (DESIGN.md §6b): a new entry is appended to
//! `BootOrder`, and removal takes out exactly our numbers.

use paguro_core::bootstrap::{
    self, DP_MEDIA, DP_MEDIA_FILE_PATH, HardDrive, LOAD_OPTION_ACTIVE, MAX_LOAD_OPTION,
};
use paguro_core::guid::EFI_GLOBAL_VARIABLE;
use serde::Serialize;

use crate::api::{Volume, WinApi, attr};
use crate::out::{CmdError, guid_text};

pub const STANDING_DESCRIPTION: &str = "paguro";
pub const BOOTSTRAP_DESCRIPTION: &str = "paguro setup";
/// Highest `Boot####` number probed when listing (entries beyond it are
/// still found through `BootOrder`).
pub const PROBE_MAX: u16 = 0x00ff;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BootEntry {
    pub number: u16,
    pub name: String,
    pub description: String,
    pub active: bool,
    /// The File Path node's path, when there is one.
    pub path: Option<String>,
    /// GPT partition GUID of the Hard Drive node, when there is one.
    pub partition: Option<String>,
    pub in_boot_order: bool,
    /// Its file lives under `\EFI\paguro\`.
    pub ours: bool,
    /// paguro's one-shot bootstrap entry (ours, described `paguro setup`).
    pub bootstrap: bool,
    /// The variable parsed as an `EFI_LOAD_OPTION`.
    pub well_formed: bool,
}

pub fn var_name(n: u16) -> String {
    format!("Boot{n:04X}")
}

fn utf16(b: &[u8]) -> String {
    let u: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| {
            u16::from_le_bytes([
                c.first().copied().unwrap_or(0),
                c.get(1).copied().unwrap_or(0),
            ])
        })
        .take_while(|&c| c != 0)
        .collect();
    String::from_utf16_lossy(&u)
}

pub fn boot_order(api: &dyn WinApi) -> Result<Vec<u16>, CmdError> {
    Ok(api
        .fw_get("BootOrder", &EFI_GLOBAL_VARIABLE)?
        .map(|v| {
            v.data
                .chunks_exact(2)
                .map(|c| {
                    u16::from_le_bytes([
                        c.first().copied().unwrap_or(0),
                        c.get(1).copied().unwrap_or(0),
                    ])
                })
                .collect()
        })
        .unwrap_or_default())
}

fn set_boot_order(api: &dyn WinApi, order: &[u16]) -> Result<(), CmdError> {
    let b: Vec<u8> = order.iter().flat_map(|n| n.to_le_bytes()).collect();
    api.fw_set("BootOrder", &EFI_GLOBAL_VARIABLE, &b, attr::NV_BS_RT)?;
    Ok(())
}

pub fn describe(number: u16, data: &[u8], order: &[u16]) -> BootEntry {
    let mut e = BootEntry {
        number,
        name: var_name(number),
        description: String::new(),
        active: false,
        path: None,
        partition: None,
        in_boot_order: order.contains(&number),
        ours: false,
        bootstrap: false,
        well_formed: false,
    };
    if data.len() > MAX_LOAD_OPTION {
        return e;
    }
    let Ok(lo) = bootstrap::parse_load_option(data) else {
        return e;
    };
    e.well_formed = true;
    e.description = utf16(lo.description);
    e.active = lo.attributes & LOAD_OPTION_ACTIVE != 0;
    let _ = bootstrap::walk_device_path(lo.file_path, |n| {
        if let Some(hd) = bootstrap::parse_hard_drive(&n) {
            e.partition = Some(guid_text(&hd.partition_guid));
        } else if n.kind == DP_MEDIA && n.sub == DP_MEDIA_FILE_PATH {
            e.path = Some(utf16(n.data));
        }
    });
    e.ours = e
        .path
        .as_deref()
        .is_some_and(|p| p.to_ascii_lowercase().starts_with("\\efi\\paguro\\"));
    e.bootstrap = e.ours && e.description == BOOTSTRAP_DESCRIPTION;
    e
}

/// Every `Boot####` in `BootOrder` or numbered up to [`PROBE_MAX`].
pub fn list(api: &dyn WinApi) -> Result<Vec<BootEntry>, CmdError> {
    let order = boot_order(api)?;
    let mut nums: Vec<u16> = (0..=PROBE_MAX).chain(order.iter().copied()).collect();
    nums.sort_unstable();
    nums.dedup();
    let mut out = Vec::new();
    for n in nums {
        if let Some(v) = api.fw_get(&var_name(n), &EFI_GLOBAL_VARIABLE)? {
            out.push(describe(n, &v.data, &order));
        }
    }
    Ok(out)
}

fn free_number(api: &dyn WinApi) -> Result<u16, CmdError> {
    let order = boot_order(api)?;
    for n in 0..=u16::MAX {
        if order.contains(&n) {
            continue;
        }
        if api.fw_get(&var_name(n), &EFI_GLOBAL_VARIABLE)?.is_none() {
            return Ok(n);
        }
    }
    Err(CmdError::refused("no free Boot#### number"))
}

/// The ESP as a Hard Drive node.
pub fn esp_node(esp: &Volume) -> Result<HardDrive, CmdError> {
    let loc = esp
        .location
        .as_ref()
        .ok_or_else(|| CmdError::refused("the ESP's partition is unknown"))?;
    let guid = loc
        .partition_guid
        .ok_or_else(|| CmdError::refused("the ESP is not on a GPT disk"))?;
    Ok(HardDrive {
        partition_number: loc.partition_number,
        start_lba: loc.offset / 512,
        size_lba: loc.length / 512,
        partition_guid: guid,
    })
}

pub fn ucs2z(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// Serialise an entry for the ESP.
pub fn load_option(
    esp: &Volume,
    description: &str,
    path: &str,
    optional: &[u8],
) -> Result<Vec<u8>, CmdError> {
    let hd = esp_node(esp)?;
    let mut b = vec![0u8; MAX_LOAD_OPTION];
    let n = bootstrap::write_load_option_hd(
        LOAD_OPTION_ACTIVE,
        description,
        &hd,
        path,
        optional,
        &mut b,
    )
    .map_err(|_| CmdError::refused("boot entry too large"))?;
    b.truncate(n);
    Ok(b)
}

/// shim with `paguro.efi` as its second stage (shim `load-options.c`).
fn shim_option(api: &dyn WinApi, esp: &Volume, description: &str) -> Result<Vec<u8>, CmdError> {
    let shim = format!("\\EFI\\paguro\\{}", crate::esp::shim_name(api.arch()));
    load_option(esp, description, &shim, &ucs2z("\\EFI\\paguro\\paguro.efi"))
}

pub fn standing_option(api: &dyn WinApi, esp: &Volume) -> Result<Vec<u8>, CmdError> {
    shim_option(api, esp, STANDING_DESCRIPTION)
}

/// Create (or rewrite in place) the standing entry and make sure it is in
/// `BootOrder` (appended: Windows stays the default). Returns its number
/// and whether anything was written.
pub fn ensure_standing(
    api: &dyn WinApi,
    esp: &Volume,
    dry_run: bool,
) -> Result<(u16, bool), CmdError> {
    let want = standing_option(api, esp)?;
    let entries = list(api)?;
    let existing = entries
        .iter()
        .find(|e| e.ours && !e.bootstrap && e.description == STANDING_DESCRIPTION);
    let mut changed = false;
    let n = match existing {
        Some(e) => {
            let cur = api.fw_get(&e.name, &EFI_GLOBAL_VARIABLE)?.map(|v| v.data);
            if cur.as_deref() != Some(&want[..]) {
                changed = true;
                if !dry_run {
                    api.fw_set(&e.name, &EFI_GLOBAL_VARIABLE, &want, attr::NV_BS_RT)?;
                }
            }
            e.number
        }
        None => {
            let n = free_number(api)?;
            changed = true;
            if !dry_run {
                api.fw_set(&var_name(n), &EFI_GLOBAL_VARIABLE, &want, attr::NV_BS_RT)?;
            }
            n
        }
    };
    let mut order = boot_order(api)?;
    if !order.contains(&n) {
        changed = true;
        order.push(n);
        if !dry_run {
            set_boot_order(api, &order)?;
        }
    }
    Ok((n, changed))
}

/// Write a one-shot bootstrap entry (not in `BootOrder`) and return its
/// number. The payload goes in `PaguroBootstrap`, not here (INTERFACES.md §9).
pub fn create_bootstrap(api: &dyn WinApi, esp: &Volume) -> Result<u16, CmdError> {
    let opt = shim_option(api, esp, BOOTSTRAP_DESCRIPTION)?;
    let n = free_number(api)?;
    api.fw_set(&var_name(n), &EFI_GLOBAL_VARIABLE, &opt, attr::NV_BS_RT)?;
    Ok(n)
}

/// Delete one entry and take it out of `BootOrder` and `BootNext`.
pub fn delete(api: &dyn WinApi, n: u16) -> Result<(), CmdError> {
    let order = boot_order(api)?;
    if order.contains(&n) {
        let kept: Vec<u16> = order.into_iter().filter(|&x| x != n).collect();
        set_boot_order(api, &kept)?;
    }
    if boot_next(api)? == Some(n) {
        api.fw_delete("BootNext", &EFI_GLOBAL_VARIABLE)?;
    }
    api.fw_delete(&var_name(n), &EFI_GLOBAL_VARIABLE)?;
    Ok(())
}

pub fn boot_next(api: &dyn WinApi) -> Result<Option<u16>, CmdError> {
    Ok(api
        .fw_get("BootNext", &EFI_GLOBAL_VARIABLE)?
        .and_then(|v| <[u8; 2]>::try_from(v.data.as_slice()).ok())
        .map(u16::from_le_bytes))
}

pub fn set_boot_next(api: &dyn WinApi, n: u16) -> Result<(), CmdError> {
    api.fw_set(
        "BootNext",
        &EFI_GLOBAL_VARIABLE,
        &n.to_le_bytes(),
        attr::NV_BS_RT,
    )?;
    Ok(())
}

pub fn parse_number(s: &str) -> Result<u16, CmdError> {
    let s = s
        .strip_prefix("Boot")
        .or_else(|| s.strip_prefix("boot"))
        .unwrap_or(s);
    if s.is_empty() || s.len() > 4 {
        return Err(CmdError::new(
            crate::out::Exit::Usage,
            format!("not a boot entry number: {s:?}"),
        ));
    }
    u16::from_str_radix(s, 16).map_err(|_| {
        CmdError::new(
            crate::out::Exit::Usage,
            format!("not a boot entry number: {s:?}"),
        )
    })
}
