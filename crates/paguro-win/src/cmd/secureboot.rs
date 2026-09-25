//! `paguro secure-boot` — what the Secure Boot step will do, for the GUI's
//! explanation screen before it happens (INTERFACES.md §11.8 item 5, §11.6
//! "Enrolment, once", §2.1).

use paguro_core::efisig;
use paguro_core::guid::EFI_GLOBAL_VARIABLE;
use serde_json::json;

use crate::api::WinApi;
use crate::cmd::{mok, protection, transition};
use crate::ctx::Ctx;
use crate::out::{At, CmdError, CmdResult, Report};

/// Subjects of Microsoft's third-party UEFI CAs (the one that signs shim).
const MICROSOFT_UEFI_CAS: [&[u8]; 2] = [
    b"Microsoft Corporation UEFI CA 2011",
    b"Microsoft UEFI CA 2023",
];

/// Largest `db` read.
const MAX_DB: usize = efisig::MAX_VAR;

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// Whether `db` holds Microsoft's third-party UEFI CA; `None` when `db`
/// cannot be read or parsed.
pub fn microsoft_ca_in_db(api: &dyn WinApi) -> Option<bool> {
    let v = api.fw_get("db", &efisig::IMAGE_SECURITY_DATABASE).ok()??;
    if v.data.len() > MAX_DB {
        return None;
    }
    let mut found = false;
    efisig::for_each(&v.data, |s| {
        if s.kind == efisig::CERT_X509 && MICROSOFT_UEFI_CAS.iter().any(|n| contains(s.data, n)) {
            found = true;
        }
    })
    .ok()?;
    Some(found)
}

pub fn status(ctx: &Ctx<'_>) -> CmdResult {
    ctx.need_uefi()?;
    let sb = transition::secure_boot(ctx)?;
    let setup_mode = ctx
        .api
        .fw_get("SetupMode", &EFI_GLOBAL_VARIABLE)
        .ok()
        .flatten()
        .is_some_and(|v| v.data == [1]);
    let ms_ca = if sb {
        microsoft_ca_in_db(ctx.api)
    } else {
        None
    };
    let mok = mok::status(ctx, None).map(|r| r.data).unwrap_or_default();
    let pending = mok.at("pending_request").as_bool().unwrap_or(false);
    let enrolled = mok.at("enrolled").as_bool().unwrap_or(false);
    let bitlocker_on = protection::windows_level(
        ctx.api
            .bitlocker(&ctx.api.system_drive())
            .ok()
            .flatten()
            .as_ref(),
    ) != protection::WindowsLevel::Off;
    // db must change (§2.1) when the CA that signs shim is missing; under
    // BitLocker that change costs one suspended reboot.
    let db_change = sb && ms_ca == Some(false);
    let data = json!({
        "secure_boot": sb,
        "setup_mode": setup_mode,
        "microsoft_uefi_ca": ms_ca,
        "mok": mok,
        "mokmanager_next_boot": sb && pending,
        "machine_key_enrolled": enrolled,
        "enrolment_needed": sb && !enrolled,
        "db_change_needed": db_change,
        "bitlocker_suspend_needed": db_change && bitlocker_on,
    });
    let mut r = Report::new(data);
    r = r.line(if sb {
        "Secure Boot is on: paguro's machine key is enrolled once, through MokManager"
    } else {
        "Secure Boot is off: nothing is enrolled"
    });
    if sb && pending {
        r = r.line("MokManager will show on the next boot: choose Enroll MOK, Continue, Yes, then type the one-time password");
    }
    if db_change {
        r = r.warn(if bitlocker_on {
            "db lacks Microsoft's third-party UEFI CA: adding it suspends BitLocker for one reboot (§2.1)"
        } else {
            "db lacks Microsoft's third-party UEFI CA (§2.1)"
        });
    }
    Ok(r)
}

/// For `checks`: the error text of a failed read, or the state.
pub fn describe(ctx: &Ctx<'_>) -> Result<(bool, Option<bool>), CmdError> {
    let sb = transition::secure_boot(ctx)?;
    Ok((
        sb,
        if sb {
            microsoft_ca_in_db(ctx.api)
        } else {
            None
        },
    ))
}
