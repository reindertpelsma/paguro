//! `paguro preflight|restart-linux|stage-setup|repair` — the transition
//! app's logic (DESIGN.md §4.6, §6 "The PIN bypass", §7).
//!
//! The pre-flight checks what the next boot depends on, **repairs what it
//! can** (ESP files from the saved copies, the boot entry), and predicts a
//! TPM failure from PCR 0/2, the PCR 7 driver-config prefix of the event
//! log and the ESP hashes, against what Linux recorded. A predicted failure
//! stages `setupTPM` instead of letting the user meet it at the loader.

use paguro_core::guid::{Guid, PAGURO_VENDOR};
use paguro_core::recorded;
use paguro_core::seal::{self, Kind, Seal};
use serde::Serialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::api::{Volume, attr, join};
use crate::bootent;
use crate::cfgfile::{self, Found, OwnedEfi};
use crate::cmd::disk;
use crate::cmd::mok;
use crate::ctx::Ctx;
use crate::esp::{self, FileState};
use crate::keys;
use crate::out::{At, CmdError, CmdResult, Exit, Report, guid_text, to_hex};
use crate::preflight::{self, Action, Reason};
use crate::tpmwin;

pub const SETUP_VAR: &str = "PaguroSetup";
pub const BROKEN_VAR: &str = "PaguroTpmBroken";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Ok,
    /// Was wrong and has been put right.
    Repaired,
    /// Is wrong; a non-dry run puts it right.
    WouldRepair,
    Warn,
    Fail,
    Skipped,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Check {
    pub id: &'static str,
    pub state: State,
    pub detail: String,
}

fn check(id: &'static str, state: State, detail: impl Into<String>) -> Check {
    Check {
        id,
        state,
        detail: detail.into(),
    }
}

#[derive(Serialize)]
pub struct Preflight {
    pub checks: Vec<Check>,
    /// `None`: a check failed; restarting is refused.
    pub action: Option<Action>,
    #[serde(skip)]
    pub esp: Option<Volume>,
    #[serde(skip)]
    pub config: Option<Found>,
    #[serde(skip)]
    pub volume: Option<Volume>,
    pub entry: Option<String>,
    pub secure_boot: bool,
}

impl Preflight {
    pub fn failed(&self) -> Vec<&Check> {
        self.checks
            .iter()
            .filter(|c| c.state == State::Fail)
            .collect()
    }
    pub fn lines(&self) -> Vec<String> {
        self.checks
            .iter()
            .map(|c| {
                format!(
                    "{:<14} {:<12} {}",
                    c.id,
                    format!("{:?}", c.state).to_lowercase(),
                    c.detail
                )
            })
            .collect()
    }
}

pub fn secure_boot(ctx: &Ctx<'_>) -> Result<bool, CmdError> {
    Ok(ctx
        .api
        .fw_get("SecureBoot", &paguro_core::guid::EFI_GLOBAL_VARIABLE)?
        .is_some_and(|v| v.data == [1]))
}

/// The Windows volume holding the default entry.
pub fn entry_volume(ctx: &Ctx<'_>, volume: &Guid) -> Result<Volume, CmdError> {
    ctx.api
        .volumes()?
        .into_iter()
        .find(|v| v.partition_guid() == Some(*volume))
        .ok_or_else(|| {
            CmdError::not_found(format!(
                "volume {} is not present in Windows",
                guid_text(volume)
            ))
        })
}

/// What the machine looks like now, for [`preflight::decide`].
fn observe(ctx: &Ctx<'_>, esp_vol: &Volume) -> Result<preflight::Observed, String> {
    let pcrs = tpmwin::pcr_read(ctx.api, 1 << 0 | 1 << 2).map_err(|e| e.to_string())?;
    let log = ctx.api.tcg_log().map_err(|e| e.to_string())?;
    let sbc = preflight::secure_boot_config(&log).map_err(|e| format!("TCG log: {e:?}"))?;
    let hash = |name: &str| -> Result<[u8; 32], String> {
        let b = ctx
            .api
            .read_file(&esp::path(esp_vol, name), esp::MAX_ESP_FILE)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("{name} missing"))?;
        Ok(sha2::Digest::finalize(<sha2::Sha256 as sha2::Digest>::new_with_prefix(&b)).into())
    };
    Ok(preflight::Observed {
        pcr0: *pcrs.get(0).ok_or("PCR 0 not returned")?,
        pcr2: *pcrs.get(2).ok_or("PCR 2 not returned")?,
        secure_boot_config: sbc,
        shim_sha256: hash(&esp::shim_name(ctx.api.arch()))?,
        loader_sha256: hash(esp::LOADER)?,
    })
}

pub fn read_recorded(
    ctx: &Ctx<'_>,
    esp_vol: &Volume,
    volume: &Guid,
) -> Result<Option<recorded::Recorded>, CmdError> {
    let p = join(&esp::volume_dir(esp_vol, volume), recorded::FILE_NAME);
    match ctx.api.read_file(&p, recorded::LEN)? {
        None => Ok(None),
        Some(b) => recorded::parse(&b)
            .map(Some)
            .map_err(|e| CmdError::refused(format!("{p}: {e:?}"))),
    }
}

/// Run every check. `repair`: fix what is fixable (not in a dry run).
pub fn run_preflight(ctx: &Ctx<'_>, repair: bool) -> Result<Preflight, CmdError> {
    let mut pf = Preflight {
        checks: Vec::new(),
        action: None,
        esp: None,
        config: None,
        volume: None,
        entry: None,
        secure_boot: false,
    };
    let fix = repair && !ctx.dry_run;
    let c = &mut pf.checks;
    if !ctx.api.firmware_is_uefi() {
        c.push(check(
            "uefi",
            State::Fail,
            "legacy BIOS boot: paguro needs UEFI",
        ));
        return Ok(pf);
    }
    c.push(check("uefi", State::Ok, "UEFI firmware"));
    if ctx.api.is_elevated() {
        c.push(check("elevated", State::Ok, "administrator"));
    } else {
        c.push(check(
            "elevated",
            State::Fail,
            "needs an elevated prompt (firmware variables)",
        ));
    }
    pf.secure_boot = secure_boot(ctx)?;
    let esp_vol = match ctx.esp() {
        Ok(e) => e,
        Err(e) => {
            pf.checks.push(check("esp", State::Fail, e.message));
            return Ok(pf);
        }
    };
    let c = &mut pf.checks;
    // ESP files against the install manifest.
    match esp::verify(ctx.api, &esp_vol) {
        Err(e) => c.push(check("esp_files", State::Fail, e.message)),
        Ok(v) => {
            let bad: Vec<String> = v
                .iter()
                .filter(|f| f.state != FileState::Ok)
                .map(|f| f.name.clone())
                .collect();
            if bad.is_empty() {
                c.push(check(
                    "esp_files",
                    State::Ok,
                    "shim, MokManager and paguro.efi match the install",
                ));
            } else if repair {
                match esp::repair(ctx.api, &esp_vol, !fix) {
                    Ok(_) => c.push(check(
                        "esp_files",
                        if fix {
                            State::Repaired
                        } else {
                            State::WouldRepair
                        },
                        format!("restored from the saved copies: {}", bad.join(", ")),
                    )),
                    Err(e) => c.push(check("esp_files", State::Fail, e.message)),
                }
            } else {
                c.push(check(
                    "esp_files",
                    State::Fail,
                    format!("missing or modified: {}", bad.join(", ")),
                ));
            }
        }
    }
    // The standing boot entry: its creation is the normal operation (§4.6).
    match bootent::ensure_standing(ctx.api, &esp_vol, !fix) {
        Ok((n, changed)) => {
            pf.entry = Some(bootent::var_name(n));
            let state = match (changed, fix) {
                (false, _) => State::Ok,
                (true, true) => State::Repaired,
                (true, false) => State::WouldRepair,
            };
            pf.checks.push(check(
                "boot_entry",
                state,
                format!("{} → \\EFI\\paguro\\shim", bootent::var_name(n)),
            ));
        }
        Err(e) => pf.checks.push(check("boot_entry", State::Fail, e.message)),
    }
    // Configuration and its hash (§3.3).
    let found = cfgfile::read(ctx.api, &esp_vol)?;
    let c = &mut pf.checks;
    let default = match &found {
        None => {
            c.push(check(
                "config",
                State::Fail,
                "no paguro.ini (Linux has never finished its first boot?)",
            ));
            None
        }
        Some(f) => match &f.parsed {
            Err(e) => {
                c.push(check(
                    "config",
                    State::Fail,
                    format!("paguro.ini does not parse: {e}"),
                ));
                None
            }
            Ok(cfg) => {
                match (&f.var, f.hash_matches(), pf.secure_boot) {
                    (None, _, _) => c.push(check(
                        "config",
                        State::Fail,
                        "PaguroConfigHash is gone: the firmware NVRAM was cleared, and B with it. \
                         Run `paguro repair --bootstrap` (DESIGN.md §7)",
                    )),
                    (Some(_), true, _) => c.push(check("config", State::Ok, "paguro.ini matches PaguroConfigHash")),
                    (Some(_), false, true) => c.push(check(
                        "config",
                        State::Fail,
                        "paguro.ini does not match PaguroConfigHash: the loader will refuse it",
                    )),
                    (Some(_), false, false) => c.push(check(
                        "config",
                        State::Warn,
                        "paguro.ini does not match PaguroConfigHash (Secure Boot off: not enforced)",
                    )),
                }
                cfg.entries.iter().find(|e| e.name == cfg.default).cloned()
            }
        },
    };
    pf.config = found;
    // The default entry's files.
    if let Some(e) = &default {
        let files: Vec<&str> = e
            .root
            .iter()
            .map(String::as_str)
            .chain(match &e.efi {
                OwnedEfi::Disk { disk, .. } if Some(disk) != e.root.as_ref() => Some(disk.as_str()),
                OwnedEfi::File { file } => Some(file.as_str()),
                OwnedEfi::Disk { .. } => None,
            })
            .collect();
        match cfgfile::windows_path(ctx.api, &e.volume, "")? {
            None => pf.checks.push(check(
                "images",
                State::Fail,
                format!("volume {} is not mounted", guid_text(&e.volume)),
            )),
            Some(_) => {
                let mut problems = Vec::new();
                for f in &files {
                    let w = cfgfile::windows_path(ctx.api, &e.volume, f)?.unwrap_or_default();
                    match disk::inspect_path(ctx.api, &w) {
                        Ok(i) if i.problems.is_empty() => {}
                        Ok(i) => problems.push(format!("{w}: {}", i.problems.join(", "))),
                        Err(err) => problems.push(format!("{w}: {}", err.message)),
                    }
                }
                if problems.is_empty() {
                    pf.checks.push(check(
                        "images",
                        State::Ok,
                        format!(
                            "[Boot.{}]: {} file(s) present and contiguous-mappable",
                            e.name,
                            files.len()
                        ),
                    ));
                } else {
                    pf.checks
                        .push(check("images", State::Fail, problems.join("; ")));
                }
            }
        }
        pf.volume = entry_volume(ctx, &e.volume).ok();
    }
    // MOK (self-signed deployments).
    if pf.secure_boot {
        match mok::status(ctx, None) {
            Ok(r) => {
                let d = &r.data;
                let st = if d.at("machine_key").is_null() {
                    check("mok", State::Skipped, "no machine key recorded")
                } else if d.at("enrolled") == true {
                    check("mok", State::Ok, "machine key enrolled")
                } else if d.at("pending_request") == true {
                    check(
                        "mok",
                        State::Warn,
                        "enrolment pending: MokManager asks on this boot",
                    )
                } else {
                    check(
                        "mok",
                        State::Fail,
                        "the machine key is not enrolled: shim will refuse paguro.efi. Run `paguro mok enroll`",
                    )
                };
                pf.checks.push(st);
            }
            Err(e) => pf.checks.push(check("mok", State::Warn, e.message)),
        }
    } else {
        pf.checks
            .push(check("mok", State::Skipped, "Secure Boot off"));
    }
    // TPM prediction (§4.6), and the loader's own report.
    let broken = ctx
        .api
        .fw_get(BROKEN_VAR, &PAGURO_VENDOR)?
        .is_some_and(|v| v.data.len() == 1);
    let mut action = Action::Restart;
    if broken {
        action = Action::StageSetupTpm(Reason::LoaderReported);
        pf.checks
            .push(check("tpm", State::Warn, Reason::LoaderReported.explain()));
    } else if !ctx.api.tpm_present() {
        pf.checks
            .push(check("tpm", State::Skipped, "no TPM: nothing to predict"));
    } else if let Some(e) = &default {
        match read_recorded(ctx, &esp_vol, &e.volume)? {
            None => pf.checks.push(check(
                "tpm",
                State::Warn,
                "no record of the last Linux boot: the TPM result cannot be predicted",
            )),
            Some(rec) => match observe(ctx, &esp_vol) {
                Err(why) => pf.checks.push(check(
                    "tpm",
                    State::Warn,
                    format!("cannot observe this boot: {why}"),
                )),
                Ok(obs) => {
                    action = preflight::decide(&preflight::Recorded::from_record(&rec), &obs);
                    match action {
                        Action::Restart => pf.checks.push(check(
                            "tpm",
                            State::Ok,
                            "the TPM seal is predicted to unseal",
                        )),
                        Action::StageSetupTpm(r) => {
                            pf.checks.push(check("tpm", State::Warn, r.explain()))
                        }
                    }
                }
            },
        }
    }
    pf.esp = Some(esp_vol);
    if pf.failed().is_empty() {
        pf.action = Some(action);
    }
    Ok(pf)
}

pub fn preflight_cmd(ctx: &Ctx<'_>, repair: bool) -> CmdResult {
    let pf = run_preflight(ctx, repair)?;
    let data = serde_json::to_value(&pf).map_err(|e| CmdError::internal(e.to_string()))?;
    if pf.action.is_none() {
        let f: Vec<String> = pf.failed().iter().map(|c| c.id.to_string()).collect();
        return Err(CmdError::check_failed(
            format!("pre-flight failed: {}", f.join(", ")),
            data,
        ));
    }
    Ok(Report::new(data).lines(pf.lines()))
}

/// Stage a one-shot `setupTPM` (INTERFACES.md §11.2: `S` + `setuptpm_seal.bin`).
pub fn stage(
    ctx: &Ctx<'_>,
    pf_config: Option<&Found>,
    esp_vol: &Volume,
) -> Result<Value, CmdError> {
    let found = match pf_config {
        Some(f) => f,
        None => return Err(CmdError::not_found("no paguro.ini on the ESP")),
    };
    let cfg = found
        .parsed
        .as_ref()
        .map_err(|e| CmdError::refused(format!("paguro.ini does not parse: {e}")))?;
    if !cfg.setup_tpm {
        return Err(CmdError::refused("[SetupTPM] is disabled in paguro.ini"));
    }
    let e = cfg
        .entries
        .iter()
        .find(|e| e.name == cfg.default)
        .ok_or_else(|| CmdError::internal("default entry missing"))?;
    let vol = entry_volume(ctx, &e.volume)?;
    let keys = keys::from_windows(ctx.api, &vol)?.ok_or_else(|| {
        CmdError::refused("the volume is not BitLocker-encrypted: there is no key to stage (the loader unlocks nothing)")
    })?;
    let seal_path = join(
        &esp::volume_dir(esp_vol, &e.volume),
        Kind::SetupTpm.file_name(),
    );
    let plan = json!({
        "volume": guid_text(&e.volume),
        "seal": seal_path,
        "variable": SETUP_VAR,
        "vmk_source": keys.source,
    });
    if ctx.dry_run {
        return Ok(plan);
    }
    let pass = ctx.passphrase("Linux passphrase")?;
    let mut s = Zeroizing::new([0u8; 32]);
    let mut salt = [0u8; 16];
    ctx.api.random(&mut s[..])?;
    ctx.api.random(&mut salt)?;
    let ph = keys::pass_hash(&pass, &salt);
    let wrapped = keys::wrap_setup(&keys, &s, &found.bytes, &salt, &ph);
    let seal = Seal {
        kind: Kind::SetupTpm,
        deadline: None,
        pcrs: None,
        wrapped_vmk: &wrapped,
        salt: &salt,
        sealed: None,
    };
    let mut buf = Zeroizing::new(vec![0u8; seal::MAX_FILE]);
    let n = seal::write(&seal, &mut buf).map_err(|_| CmdError::internal("seal does not fit"))?;
    ctx.api
        .create_dir_all(&esp::volume_dir(esp_vol, &e.volume))?;
    esp::write_atomic(ctx.api, &seal_path, buf.get(..n).unwrap_or(&[]))?;
    // S last: a seal without S is inert, S without its seal is useless.
    ctx.api
        .fw_set(SETUP_VAR, &PAGURO_VENDOR, &s[..], attr::NV_BS_RT)?;
    // Whoever makes the seal match again clears the flag (INTERFACES.md §5).
    ctx.api.fw_delete(BROKEN_VAR, &PAGURO_VENDOR)?;
    Ok(plan)
}

pub fn stage_setup(ctx: &Ctx<'_>) -> CmdResult {
    ctx.need_uefi()?;
    if !ctx.dry_run {
        ctx.need_admin()?;
    }
    let esp_vol = ctx.esp()?;
    let found = cfgfile::read(ctx.api, &esp_vol)?;
    let plan = stage(ctx, found.as_ref(), &esp_vol)?;
    Ok(Report::new(plan).line(if ctx.dry_run {
        "would stage setupTPM for the next boot"
    } else {
        "setupTPM staged: the next Linux boot asks for the passphrase once and re-seals"
    }))
}

/// Write the PIN bypass; failures are reported, not fatal (the user is then
/// simply asked for the passphrase).
fn write_bypass(ctx: &Ctx<'_>, pf: &Preflight, esp_vol: &Volume) -> Result<Value, String> {
    let found = pf.config.as_ref().ok_or("no configuration")?;
    let cfg = found.parsed.as_ref().map_err(|e| e.clone())?;
    if !cfg.tpm {
        return Err("[TPM] is disabled".into());
    }
    let e = cfg
        .entries
        .iter()
        .find(|e| e.name == cfg.default)
        .ok_or("no default entry")?;
    let rec = read_recorded(ctx, esp_vol, &e.volume)
        .map_err(|e| e.message)?
        .ok_or("no record of the last Linux boot (PCR 4/7 unknown)")?;
    let vol = pf
        .volume
        .as_ref()
        .ok_or("the entry's volume is not mounted")?;
    let keys = keys::from_windows(ctx.api, vol)
        .map_err(|e| e.message)?
        .ok_or("unencrypted volume: nothing to bypass")?;
    let (file, deadline) = tpmwin::create_pin_bypass(
        ctx.api,
        &rec,
        &found.bytes,
        &keys.vmk,
        tpmwin::BYPASS_VALIDITY_MS,
    )
    .map_err(|e| e.to_string())?;
    let p = join(
        &esp::volume_dir(esp_vol, &e.volume),
        Kind::PinBypass.file_name(),
    );
    ctx.api
        .create_dir_all(&esp::volume_dir(esp_vol, &e.volume))
        .map_err(|e| e.to_string())?;
    esp::write_atomic(ctx.api, &p, &file).map_err(|e| e.message)?;
    Ok(json!({ "file": p, "deadline_clock_ms": deadline }))
}

pub fn restart_linux(ctx: &Ctx<'_>) -> CmdResult {
    let pf = run_preflight(ctx, true)?;
    let mut data = serde_json::to_value(&pf).map_err(|e| CmdError::internal(e.to_string()))?;
    let Some(action) = pf.action else {
        let f: Vec<String> = pf
            .failed()
            .iter()
            .map(|c| format!("{}: {}", c.id, c.detail))
            .collect();
        return Err(CmdError::check_failed(
            format!("not restarting: {}", f.join("; ")),
            data,
        ));
    };
    let esp_vol = pf
        .esp
        .clone()
        .ok_or_else(|| CmdError::internal("pre-flight passed without an ESP"))?;
    let mut r = Report::new(Value::Null).lines(pf.lines());
    let mut extra = serde_json::Map::new();
    match action {
        Action::StageSetupTpm(reason) => {
            r = r.line(format!(
                "the TPM seal will not unseal: {}",
                reason.explain()
            ));
            let plan = stage(ctx, pf.config.as_ref(), &esp_vol)?;
            extra.insert("staged".into(), plan);
            r = r.line(if ctx.dry_run {
                "would stage setupTPM"
            } else {
                "setupTPM staged"
            });
        }
        Action::Restart if ctx.dry_run => {
            r = r.line("would write the PIN bypass");
        }
        Action::Restart => match write_bypass(ctx, &pf, &esp_vol) {
            Ok(v) => {
                extra.insert("pin_bypass".into(), v);
                r = r.line("PIN bypass written: the next boot will not ask for the passphrase");
            }
            Err(why) => {
                extra.insert("pin_bypass".into(), json!({ "skipped": why }));
                r = r.warn(format!(
                    "no PIN bypass ({why}): the loader will ask for the passphrase"
                ));
            }
        },
    }
    let entry = pf
        .entry
        .clone()
        .ok_or_else(|| CmdError::internal("no boot entry"))?;
    let n = bootent::parse_number(&entry)?;
    if !ctx.dry_run {
        bootent::set_boot_next(ctx.api, n)?;
    }
    r = r.line(format!("BootNext = {n:04X}"));
    extra.insert("boot_next".into(), json!(format!("{n:04X}")));
    let restart = ctx.yes && !ctx.dry_run;
    extra.insert("restarting".into(), json!(restart));
    if let Some(o) = data.as_object_mut() {
        o.extend(extra);
    }
    r.data = data;
    if restart {
        ctx.api.restart()?;
        Ok(r.line("restarting"))
    } else {
        Ok(
            r.line(
                "ready: restart with `paguro restart-linux --yes` (or restart Windows normally)",
            ),
        )
    }
}

/// `paguro repair` (INTERFACES.md §11.2, DESIGN.md §7): ESP files and the
/// entry silently; the TPM path by staging (with `--stage`); a cleared NVRAM
/// by re-running the bootstrap (with `--bootstrap`).
pub fn repair(ctx: &Ctx<'_>, stage_now: bool, bootstrap: bool) -> CmdResult {
    ctx.need_uefi()?;
    if !ctx.dry_run {
        ctx.need_admin()?;
    }
    let pf = run_preflight(ctx, true)?;
    let mut data = serde_json::to_value(&pf).map_err(|e| CmdError::internal(e.to_string()))?;
    let mut r = Report::new(Value::Null).lines(pf.lines());
    let esp_vol = pf
        .esp
        .clone()
        .ok_or_else(|| CmdError::not_found("no ESP"))?;
    let nvram_cleared = pf.config.as_ref().is_some_and(|f| f.var.is_none());
    if bootstrap || nvram_cleared {
        if !bootstrap {
            return Err(CmdError::check_failed(
                "the firmware NVRAM was cleared (PaguroConfigHash and B are gone): run `paguro repair --bootstrap`",
                data,
            ));
        }
        let f = pf
            .config
            .as_ref()
            .ok_or_else(|| CmdError::not_found("no paguro.ini"))?;
        let cfg = f
            .parsed
            .as_ref()
            .map_err(|e| CmdError::refused(e.clone()))?;
        let e = cfg
            .entries
            .iter()
            .find(|e| e.name == cfg.default)
            .ok_or_else(|| CmdError::internal("no default"))?;
        let v = crate::cmd::install::write_bootstrap(ctx, &esp_vol, &e.volume)?;
        if let Some(o) = data.as_object_mut() {
            o.insert("bootstrap".into(), v);
        }
        r = r.line("bootstrap entry written and BootNext set: restart into Linux to re-seal");
        // The configuration check fails until that boot rewrites the hash;
        // the bootstrap is the repair for exactly that.
        r.data = data;
        return Ok(r);
    } else if matches!(pf.action, Some(Action::StageSetupTpm(_))) {
        if stage_now {
            let v = stage(ctx, pf.config.as_ref(), &esp_vol)?;
            if let Some(o) = data.as_object_mut() {
                o.insert("staged".into(), v);
            }
            r = r.line("setupTPM staged");
        } else {
            r = r.warn("the TPM seal is predicted to fail: `paguro repair --stage` (asks for the Linux passphrase)");
        }
    }
    r.data = data;
    if pf.action.is_none() {
        let f: Vec<String> = pf.failed().iter().map(|c| c.id.to_string()).collect();
        return Err(CmdError::check_failed(
            format!("still failing after repair: {}", f.join(", ")),
            r.data,
        ));
    }
    Ok(r)
}

/// For `status`: a summary line per volume directory's seals.
pub fn seal_summary(ctx: &Ctx<'_>, esp_vol: &Volume) -> Result<Value, CmdError> {
    Ok(serde_json::to_value(esp::seal_dirs(ctx.api, esp_vol)?).unwrap_or(Value::Null))
}

pub fn hex32(b: &[u8; 32]) -> String {
    to_hex(b)
}

pub fn exit_for(pf: &Preflight) -> Exit {
    if pf.action.is_some() {
        Exit::Ok
    } else {
        Exit::CheckFailed
    }
}
