//! `paguro status` — everything the tool can see, read-only. Each section
//! reports its own error instead of failing the whole command, so status
//! works on a half-installed or broken machine (which is when it is needed).

use paguro_core::guid::{EFI_GLOBAL_VARIABLE, PAGURO_VENDOR};
use serde_json::{Value, json};

use crate::bootent;
use crate::cfgfile::{self, OwnedEfi};
use crate::cmd::{disk, efi, mok, transition};
use crate::ctx::Ctx;
use crate::esp;
use crate::out::{At, CmdError, CmdResult, Report};

fn section<T: serde::Serialize>(r: Result<T, CmdError>) -> Value {
    match r {
        Ok(v) => serde_json::to_value(v).unwrap_or(Value::Null),
        Err(e) => json!({ "error": e.message }),
    }
}

fn wsl(ctx: &Ctx<'_>) -> Value {
    match ctx.api.run("wsl.exe", &["--status"], None) {
        Ok(o) => json!({ "present": o.ok() }),
        Err(e) => json!({ "present": false, "error": e.to_string() }),
    }
}

fn minifilter(ctx: &Ctx<'_>) -> Value {
    match ctx.api.run("fltmc.exe", &["filters"], None) {
        Ok(o) => {
            json!({ "loaded": o.ok() && o.stdout.lines().any(|l| l.trim_start().to_ascii_lowercase().starts_with("paguroflt")) })
        }
        Err(e) => json!({ "loaded": false, "error": e.to_string() }),
    }
}

pub fn status(ctx: &Ctx<'_>) -> CmdResult {
    let api = ctx.api;
    let uefi = api.firmware_is_uefi();
    let volumes = section(api.volumes().map_err(CmdError::from).map(|vs| {
        vs.into_iter()
            .map(|v| {
                let bl = v
                    .drive()
                    .map(|d| section(api.bitlocker(d).map_err(CmdError::from)));
                json!({ "volume": v, "esp": v.is_esp(), "bitlocker": bl })
            })
            .collect::<Vec<_>>()
    }));
    let firmware = if uefi {
        let sb = transition::secure_boot(ctx).ok();
        let setup_mode = api
            .fw_get("SetupMode", &EFI_GLOBAL_VARIABLE)
            .ok()
            .flatten()
            .map(|v| v.data == [1]);
        json!({
            "secure_boot": sb,
            "setup_mode": setup_mode,
            "paguro_variables": section(efi::vars_list(ctx).map(|r| r.data.at("variables").clone())),
            "boot_entries": section(bootent::list(api)),
            "boot_next": section(bootent::boot_next(api).map(|n| n.map(|n| format!("{n:04X}")))),
            "boot_order": section(bootent::boot_order(api).map(|o| o.iter().map(|n| format!("{n:04X}")).collect::<Vec<_>>())),
            "paguro_b": "not visible from an OS (boot-services only)",
        })
    } else {
        json!({ "uefi": false })
    };
    let esp_vol = ctx.esp();
    let (esp_json, config_json, images_json) = match &esp_vol {
        Err(e) => (json!({ "error": e.message }), Value::Null, Value::Null),
        Ok(e) => {
            let files = section(esp::verify(api, e));
            let seals = section(esp::seal_dirs(api, e));
            let found = cfgfile::read(api, e);
            let images = match &found {
                Ok(Some(f)) => match &f.parsed {
                    Ok(c) => {
                        let mut out = Vec::new();
                        for en in &c.entries {
                            let mut paths: Vec<&str> = en.root.iter().map(String::as_str).collect();
                            match &en.efi {
                                OwnedEfi::Disk { disk, .. } if Some(disk) != en.root.as_ref() => {
                                    paths.push(disk)
                                }
                                OwnedEfi::File { file } => paths.push(file),
                                OwnedEfi::Disk { .. } => {}
                            }
                            for p in paths {
                                let w = cfgfile::windows_path(api, &en.volume, p).ok().flatten();
                                let info = match &w {
                                    Some(w) => match disk::inspect_path(api, w) {
                                        Ok(i) => i.json,
                                        Err(err) => json!({ "error": err.message }),
                                    },
                                    None => json!({ "error": "volume not mounted" }),
                                };
                                out.push(json!({ "entry": en.name, "ntfs_path": p, "windows_path": w, "file": info }));
                            }
                        }
                        json!(out)
                    }
                    Err(_) => Value::Null,
                },
                _ => Value::Null,
            };
            let cfg = match found {
                Ok(Some(f)) => f.to_json(),
                Ok(None) => json!({ "present": false }),
                Err(err) => json!({ "error": err.message }),
            };
            (
                json!({ "volume": e.guid_path, "files": files, "volumes": seals }),
                cfg,
                images,
            )
        }
    };
    let mok = if uefi {
        section(mok::status(ctx, None).map(|r| r.data))
    } else {
        Value::Null
    };
    let tpm_broken = uefi
        && api
            .fw_get(transition::BROKEN_VAR, &PAGURO_VENDOR)
            .ok()
            .flatten()
            .is_some();
    let pf = transition::run_preflight(
        &Ctx {
            dry_run: true,
            ..Ctx::new(api)
        },
        false,
    );
    let preflight = section(
        pf.map(|p| json!({ "ready": p.action.is_some(), "action": p.action, "checks": p.checks })),
    );
    let data = json!({
        "elevated": api.is_elevated(),
        "uefi": uefi,
        "arch": api.arch(),
        "volumes": volumes,
        "firmware": firmware,
        "esp": esp_json,
        "config": config_json,
        "images": images_json,
        "mok": mok,
        "tpm": { "present": api.tpm_present(), "broken_flag": tpm_broken },
        "wsl": wsl(ctx),
        "minifilter": minifilter(ctx),
        "preflight": preflight,
    });
    let mut lines = vec![
        format!("firmware: {}", if uefi { "UEFI" } else { "legacy BIOS" }),
        format!("secure boot: {}", data.at("firmware").at("secure_boot")),
        format!(
            "ESP: {}",
            data.at("esp").at("volume").as_str().unwrap_or("not found")
        ),
        format!(
            "paguro.ini: {}",
            if data.at("config").at("valid") == true {
                "valid"
            } else {
                "absent or invalid"
            }
        ),
        format!(
            "WSL2: {}",
            if data.at("wsl").at("present") == true {
                "present"
            } else {
                "absent"
            }
        ),
        format!(
            "minifilter: {}",
            if data.at("minifilter").at("loaded") == true {
                "loaded"
            } else {
                "not loaded"
            }
        ),
    ];
    if let Some(checks) = data.at("preflight").at("checks").as_array() {
        lines.push("pre-flight:".into());
        for c in checks {
            lines.push(format!(
                "  {:<14} {:<12} {}",
                c.at("id").as_str().unwrap_or(""),
                c.at("state").as_str().unwrap_or(""),
                c.at("detail").as_str().unwrap_or("")
            ));
        }
    }
    Ok(Report::new(data).lines(lines))
}
