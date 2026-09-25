//! `paguro protection options|set|check` — how Linux unlocks (DESIGN.md §8d
//! "The user chooses, once", §6; INTERFACES.md §11.8 "Unlocking", §13.5).
//!
//! | Choice | Offered when |
//! |---|---|
//! | `tpm_pin` (recommended) | Windows' BitLocker uses a TPM |
//! | `passphrase` | always |
//! | `tpm_only` | only when Windows itself is TPM-only: capped at Windows' level |
//! | `unprotected` | dedicated disk only (not built yet: never offered for images) |
//!
//! The question is asked only when the system volume uses BitLocker; without
//! it Linux is unprotected by paguro and there is nothing to choose.
//!
//! What `set` does today, for an image on NTFS: the rungs in `paguro.ini`
//! (`[TPM]`, `[Passphrase]`), the `[UI] keyboard` the secret is typed in,
//! and the PIN-bypass preference that `restart-linux` honours
//! (`%ProgramData%\paguro\protection.json`). **Mixing the PIN into the TPM
//! seal is a stub**: the TPM + PIN rung (`HMAC(D, stretch(PIN))`, DESIGN
//! §8d) has no seal format or loader support in INTERFACES §3–§4 yet, so the
//! PIN is checked against the keyboard layout and then reported as pending.

use paguro_boot::keymap;
use paguro_core::config::Keyboard;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::api::{BitLocker, join, protector};
use crate::cmd::config;
use crate::ctx::{Ctx, Secret};
use crate::out::{CmdError, CmdResult, Exit, Report};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Choice {
    TpmPin,
    Passphrase,
    TpmOnly,
    Unprotected,
}

impl Choice {
    pub const ALL: [Choice; 4] = [
        Choice::TpmPin,
        Choice::Passphrase,
        Choice::TpmOnly,
        Choice::Unprotected,
    ];
    pub const fn name(self) -> &'static str {
        match self {
            Choice::TpmPin => "tpm_pin",
            Choice::Passphrase => "passphrase",
            Choice::TpmOnly => "tpm_only",
            Choice::Unprotected => "unprotected",
        }
    }
    pub fn parse(s: &str) -> Option<Choice> {
        Self::ALL.iter().copied().find(|c| c.name() == s)
    }
    /// A secret is typed at boot for this choice.
    pub const fn needs_secret(self) -> bool {
        matches!(self, Choice::TpmPin | Choice::Passphrase)
    }
}

/// Where Linux lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    #[default]
    Image,
    /// DESIGN §8d: planned, not built (the choices are computed for it).
    Disk,
}

/// How Windows itself unlocks, from its BitLocker protectors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsLevel {
    /// BitLocker off (or no system volume information).
    Off,
    /// TPM with a PIN (or PIN and startup key).
    TpmPin,
    /// TPM with a startup key.
    TpmStartupKey,
    /// TPM alone: unlocks without input.
    TpmOnly,
    /// No TPM protector: a password or a USB key.
    NoTpm,
}

pub fn windows_level(b: Option<&BitLocker>) -> WindowsLevel {
    let Some(b) = b.filter(|b| b.is_encrypted()) else {
        return WindowsLevel::Off;
    };
    let has = |t| b.protector_types.contains(&t);
    if has(protector::TPM_PIN) || has(protector::TPM_PIN_STARTUP_KEY) {
        WindowsLevel::TpmPin
    } else if has(protector::TPM_STARTUP_KEY) {
        WindowsLevel::TpmStartupKey
    } else if has(protector::TPM) {
        WindowsLevel::TpmOnly
    } else {
        WindowsLevel::NoTpm
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Offer {
    pub id: Choice,
    pub offered: bool,
    pub recommended: bool,
    /// Why it is (not) offered, in words.
    pub reason: &'static str,
}

/// The protection screen's rows (DESIGN §8d's table), for `level`.
pub fn offers(level: WindowsLevel, target: Target, tpm_present: bool) -> Vec<Offer> {
    let tpm_windows = matches!(
        level,
        WindowsLevel::TpmPin | WindowsLevel::TpmStartupKey | WindowsLevel::TpmOnly
    );
    let tpm_pin = tpm_windows && tpm_present;
    Choice::ALL
        .iter()
        .map(|&id| {
            let (offered, reason) = match id {
                Choice::TpmPin if tpm_pin => (true, "matched to BitLocker: the TPM and a PIN typed at boot"),
                Choice::TpmPin => (false, "Windows' BitLocker does not use a TPM"),
                Choice::Passphrase => (true, "a passphrase typed at boot; no TPM involved"),
                Choice::TpmOnly if level == WindowsLevel::TpmOnly && tpm_present => {
                    (true, "Windows itself unlocks with the TPM alone, so Linux may too")
                }
                Choice::TpmOnly => (
                    false,
                    "only when Windows is TPM-only: Linux holds Windows' key, so it may never unlock with less than Windows does",
                ),
                Choice::Unprotected if target == Target::Disk => (
                    true,
                    "paguro sets up no encryption; the distribution's installer offers its own",
                ),
                Choice::Unprotected => (false, "an image inside Windows' BitLocker volume is always protected by it"),
            };
            Offer {
                id,
                offered,
                recommended: false,
                reason,
            }
        })
        .map(|mut o| {
            o.recommended = o.offered
                && match o.id {
                    Choice::TpmPin => true,
                    Choice::Passphrase => !tpm_pin,
                    _ => false,
                };
            o
        })
        .collect()
}

/// A character that cannot be typed at boot on `layout`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Refused {
    pub char: String,
    pub position: usize,
    pub reason: &'static str,
}

/// Every character of `secret` must be on a key of `layout` without a dead
/// key (INTERFACES.md §13.5): the loader does not compose.
pub fn check_secret(secret: &str, layout: Keyboard) -> Vec<Refused> {
    let t = keymap::table(layout);
    secret
        .chars()
        .enumerate()
        .filter(|&(_, c)| c != ' ' && !t.iter().any(|levels| levels.contains(&c)))
        .map(|(i, c)| Refused {
            char: c.to_string(),
            position: i,
            reason: if c.is_control() {
                "a control character"
            } else if c.is_ascii() {
                "needs a dead key on this layout"
            } else {
                "needs a dead key, or is not on this keyboard layout"
            },
        })
        .collect()
}

/// A Windows keyboard layout id (`KLID`, e.g. `00000407`) → the loader's
/// layout, when there is one.
pub fn from_klid(klid: &str) -> Option<Keyboard> {
    let id = u32::from_str_radix(klid.trim(), 16).ok()?;
    // The low word is the language; a few layouts are named by the whole id.
    Some(match id {
        0x0002_0409 => Keyboard::NlIntl, // United States-International
        0x0000_0813 | 0x0000_080c => Keyboard::Be,
        0x0000_0807 => Keyboard::ChDe,
        _ => match id & 0xffff {
            0x0409 => Keyboard::Us,
            0x0809 => Keyboard::Uk,
            0x0407 => Keyboard::De,
            0x040c => Keyboard::Fr,
            0x040a | 0x0c0a => Keyboard::Es,
            0x0413 => Keyboard::NlIntl,
            _ => return None,
        },
    })
}

/// `%ProgramData%\paguro\protection.json`: the choice and the PIN-bypass
/// preference (no secret).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Saved {
    pub choice: Choice,
    pub pin_bypass: bool,
    pub keyboard: String,
}

const MAX_SAVED: usize = 4096;

pub fn saved_path(ctx: &Ctx<'_>) -> String {
    join(&ctx.data_dir(), "protection.json")
}

pub fn load(ctx: &Ctx<'_>) -> Option<Saved> {
    let b = ctx.api.read_file(&saved_path(ctx), MAX_SAVED).ok()??;
    serde_json::from_slice(&b).ok()
}

/// The system volume's BitLocker state, when it has one.
fn system_bitlocker(ctx: &Ctx<'_>) -> Option<BitLocker> {
    ctx.api.bitlocker(&ctx.api.system_drive()).ok().flatten()
}

/// The layout's English name (the loader's `loader.layout_*` strings; the
/// GUI shows its own translation by `id`).
pub const fn layout_label(k: Keyboard) -> &'static str {
    match k {
        Keyboard::Us => "English (US)",
        Keyboard::Uk => "English (UK)",
        Keyboard::De => "German",
        Keyboard::Fr => "French",
        Keyboard::Es => "Spanish",
        Keyboard::Be => "Belgian (AZERTY)",
        Keyboard::ChDe => "Swiss German",
        Keyboard::NlIntl => "US International (Dutch)",
    }
}

fn keyboards() -> Value {
    Value::Array(
        Keyboard::ALL
            .iter()
            .map(|k| json!({ "id": k.name(), "name": layout_label(*k) }))
            .collect(),
    )
}

pub fn options(ctx: &Ctx<'_>, target: Target, klid: Option<&str>) -> CmdResult {
    let bl = system_bitlocker(ctx);
    let level = windows_level(bl.as_ref());
    let asked = level != WindowsLevel::Off;
    let tpm = ctx.api.tpm_present();
    let offers = if asked {
        offers(level, target, tpm)
    } else {
        Vec::new()
    };
    let saved = load(ctx);
    let suggested = klid.and_then(from_klid).unwrap_or(Keyboard::Us);
    let data = json!({
        "asked": asked,
        "target": target,
        "windows": level,
        "tpm_present": tpm,
        "choices": offers,
        "pin_bypass_default": true,
        "keyboards": keyboards(),
        "keyboard_suggested": suggested.name(),
        "current": saved,
    });
    let mut r = Report::new(data);
    if !asked {
        r = r.line("Windows does not use BitLocker: Linux is not protected by paguro, and there is nothing to choose.");
    } else {
        for o in &offers {
            r = r.line(format!(
                "{:<12} {:<13} {}",
                o.id.name(),
                if o.recommended {
                    "recommended"
                } else if o.offered {
                    "offered"
                } else {
                    "not offered"
                },
                o.reason
            ));
        }
    }
    Ok(r)
}

pub fn check(ctx: &Ctx<'_>, keyboard: &str) -> CmdResult {
    let k = config::keyboard(keyboard)?;
    let s = ctx.secret(Secret::Pin, "PIN or passphrase to check", false)?;
    let refused = check_secret(&s, k);
    let ok = refused.is_empty();
    let data =
        json!({ "ok": ok, "keyboard": k.name(), "length": s.chars().count(), "refused": refused });
    if ok {
        Ok(Report::new(data).line(format!(
            "every character can be typed at boot ({})",
            layout_label(k)
        )))
    } else {
        Err(CmdError::refused(format!(
            "{} character(s) cannot be typed at boot on the {} layout (dead keys are not supported)",
            refused.len(),
            layout_label(k)
        ))
        .with_data(data))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetArgs {
    pub choice: String,
    #[serde(default)]
    pub target: Target,
    #[serde(default = "default_keyboard")]
    pub keyboard: String,
    #[serde(default = "yes")]
    pub pin_bypass: bool,
}

fn default_keyboard() -> String {
    Keyboard::Us.name().into()
}
const fn yes() -> bool {
    true
}

pub fn set(ctx: &Ctx<'_>, a: &SetArgs) -> CmdResult {
    let choice = Choice::parse(&a.choice).ok_or_else(|| {
        CmdError::new(
            Exit::Usage,
            format!(
                "unknown choice {:?} (tpm_pin, passphrase, tpm_only, unprotected)",
                a.choice
            ),
        )
    })?;
    let k = config::keyboard(&a.keyboard)?;
    if a.target == Target::Disk {
        return Err(CmdError::refused(
            "STUB: a dedicated Linux disk (DESIGN §8d) is not built yet",
        )
        .with_data(json!({ "stub": true })));
    }
    let level = windows_level(system_bitlocker(ctx).as_ref());
    if level == WindowsLevel::Off {
        return Err(CmdError::refused(
            "Windows does not use BitLocker: there is no protection to choose (DESIGN §8d)",
        ));
    }
    let offer = offers(level, a.target, ctx.api.tpm_present())
        .into_iter()
        .find(|o| o.id == choice)
        .ok_or_else(|| CmdError::internal("choice without an offer"))?;
    if !offer.offered {
        return Err(CmdError::refused(format!(
            "{} is not offered here: {}",
            choice.name(),
            offer.reason
        )));
    }
    let what = if choice == Choice::TpmPin {
        "Linux PIN"
    } else {
        "Linux passphrase"
    };
    let mut refused = Vec::new();
    if choice.needs_secret() {
        let s = ctx.secret(Secret::Pin, what, true)?;
        refused = check_secret(&s, k);
    }
    if !refused.is_empty() {
        return Err(CmdError::refused(format!(
            "the {} has character(s) that cannot be typed at boot on the {} layout (dead keys are not supported)",
            what.to_lowercase(),
            layout_label(k)
        ))
        .with_data(json!({ "refused": refused, "keyboard": k.name() })));
    }
    let (tpm, pass) = match choice {
        Choice::TpmPin | Choice::TpmOnly => (true, false),
        Choice::Passphrase => (false, true),
        Choice::Unprotected => (false, false),
    };
    let edit = config::SetArgs {
        tpm: Some(tpm),
        passphrase: Some(pass),
        keyboard: Some(k.name().into()),
        ..config::SetArgs::default()
    };
    let cfg = config::edit(ctx, |c| config::apply(ctx, c, &edit))?;
    let saved = Saved {
        choice,
        pin_bypass: a.pin_bypass && choice == Choice::TpmPin,
        keyboard: k.name().into(),
    };
    if !ctx.dry_run {
        ctx.need_admin()?;
        ctx.api.create_dir_all(&ctx.data_dir())?;
        let body =
            serde_json::to_vec_pretty(&saved).map_err(|e| CmdError::internal(e.to_string()))?;
        ctx.api.write_file(&saved_path(ctx), &body)?;
    }
    let mut pending = Vec::new();
    if choice == Choice::TpmPin {
        pending.push("STUB: mixing the PIN into the TPM seal needs the TPM + PIN rung, which INTERFACES §3–§4 do not define yet; until then the TPM rung unlocks without the PIN");
    }
    let mut r = Report::new(json!({
        "choice": choice,
        "keyboard": k.name(),
        "pin_bypass": saved.pin_bypass,
        "config": cfg.data,
        "pending": pending,
    }))
    .lines(cfg.human)
    .line(format!(
        "protection: {} (keyboard {})",
        choice.name(),
        layout_label(k)
    ));
    for w in cfg.warnings {
        r = r.warn(w);
    }
    for p in pending {
        r = r.warn(p);
    }
    Ok(r)
}

#[cfg(test)]
pub mod tests_support {
    use crate::mock::MockApi;

    /// BitLocker with a TPM protector, a TPM, a paguro.ini.
    pub fn bitlocker_tpm(m: &MockApi) {
        let d = MockApi::demo();
        *m.bitlocker.borrow_mut() = d.bitlocker.borrow().clone();
        *m.files.borrow_mut() = d.files.borrow().clone();
        *m.dirs.borrow_mut() = d.dirs.borrow().clone();
        *m.vars.borrow_mut() = d.vars.borrow().clone();
        m.set_tpm(|_| Err(crate::api::ApiError::unsupported("t", "mock")));
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn bl(types: &[u32]) -> BitLocker {
        BitLocker {
            protection_status: 1,
            conversion_status: 1,
            encryption_percentage: 100,
            encryption_method: 6,
            protector_types: types.to_vec(),
            encryption_flags: Some(0),
        }
    }

    fn offered(level: WindowsLevel, target: Target) -> Vec<&'static str> {
        offers(level, target, true)
            .into_iter()
            .filter(|o| o.offered)
            .map(|o| o.id.name())
            .collect()
    }

    #[test]
    fn levels_from_protectors() {
        assert_eq!(windows_level(None), WindowsLevel::Off);
        assert_eq!(windows_level(Some(&bl(&[1, 3]))), WindowsLevel::TpmOnly);
        assert_eq!(windows_level(Some(&bl(&[4, 3]))), WindowsLevel::TpmPin);
        assert_eq!(windows_level(Some(&bl(&[6]))), WindowsLevel::TpmPin);
        assert_eq!(windows_level(Some(&bl(&[5]))), WindowsLevel::TpmStartupKey);
        assert_eq!(windows_level(Some(&bl(&[8, 3]))), WindowsLevel::NoTpm);
        let mut off = bl(&[1]);
        off.conversion_status = 0;
        assert_eq!(windows_level(Some(&off)), WindowsLevel::Off);
    }

    #[test]
    fn tpm_only_is_capped_at_windows_level() {
        assert_eq!(
            offered(WindowsLevel::TpmPin, Target::Image),
            ["tpm_pin", "passphrase"]
        );
        assert_eq!(
            offered(WindowsLevel::TpmOnly, Target::Image),
            ["tpm_pin", "passphrase", "tpm_only"]
        );
        assert_eq!(offered(WindowsLevel::NoTpm, Target::Image), ["passphrase"]);
        assert_eq!(
            offered(WindowsLevel::TpmPin, Target::Disk),
            ["tpm_pin", "passphrase", "unprotected"]
        );
        // No TPM on the machine: nothing TPM is offered.
        let o: Vec<_> = offers(WindowsLevel::TpmOnly, Target::Image, false)
            .into_iter()
            .filter(|o| o.offered)
            .map(|o| o.id)
            .collect();
        assert_eq!(o, [Choice::Passphrase]);
    }

    #[test]
    fn recommendation() {
        let r = |l| {
            offers(l, Target::Image, true)
                .into_iter()
                .filter(|o| o.recommended)
                .map(|o| o.id)
                .collect::<Vec<_>>()
        };
        assert_eq!(r(WindowsLevel::TpmPin), [Choice::TpmPin]);
        assert_eq!(r(WindowsLevel::NoTpm), [Choice::Passphrase]);
    }

    #[test]
    fn dead_keys_are_refused() {
        assert!(check_secret("hunter2 x", Keyboard::Us).is_empty());
        // é is on the French layout's number row, not on the US one.
        assert!(check_secret("é", Keyboard::Fr).is_empty());
        assert_eq!(check_secret("é", Keyboard::Us)[0].position, 0);
        // ^ and ¨ are dead keys on French; ê needs one.
        let r = check_secret("aê", Keyboard::Fr);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].char, "ê");
        assert_eq!(r[0].position, 1);
        assert!(!check_secret("a\u{7}", Keyboard::Us).is_empty());
    }

    #[test]
    fn klids() {
        assert_eq!(from_klid("00000407"), Some(Keyboard::De));
        assert_eq!(from_klid("0000040C"), Some(Keyboard::Fr));
        assert_eq!(from_klid("00000409"), Some(Keyboard::Us));
        assert_eq!(from_klid("00020409"), Some(Keyboard::NlIntl));
        assert_eq!(from_klid("00000813"), Some(Keyboard::Be));
        assert_eq!(from_klid("00000411"), None);
        assert_eq!(from_klid("zz"), None);
    }
}
