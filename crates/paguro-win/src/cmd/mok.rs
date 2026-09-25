//! `paguro mok enroll|status` — shim's enrolment request, written from
//! Windows (INTERFACES.md §11.6: WSL2 has no efivarfs, so `mokutil` cannot).
//!
//! What shim's MokManager checks, verified against its source
//! (rhboot/shim `MokManager.c` at 8947f069, `store_keys` →
//! `match_password` → `compute_pw_hash`, lines 697–848):
//!
//! ```text
//! MokNew   = EFI_SIGNATURE_LIST(s)            vendor SHIM_LOCK, NV|BS|RT
//! MokAuth  = SHA-256(MokNew ‖ password as UCS-2, no terminator)
//!            32 bytes = the SHA-256 form; MokManager also accepts the
//!            PASSWORD_CRYPT form mokutil writes today, and dispatches on
//!            the variable's size (auth_size == SHA256_DIGEST_SIZE)
//! password = 1..=256 UCS-2 characters (PASSWORD_MIN, PASSWORD_MAX)
//! ```
//!
//! The list layout is the one mokutil writes (lcp/mokutil `src/mokutil.c`
//! at cbf0b506, `issue_mok_request`), via `paguro_core::efisig`. The SHA-256
//! form binds the password to this exact request, and needs no crypt(3).

use paguro_core::efisig::{self, SHIM_LOCK};
use serde_json::json;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::api::{WinApi, attr, join};
use crate::ctx::Ctx;
use crate::out::{CmdError, CmdResult, Report, to_hex};

/// Largest certificate accepted.
pub const MAX_CERT: usize = 16 * 1024;
/// Letters that sit on the same key on US, UK, German and French layouts
/// (firmware consoles differ): no a/q/w/z/y/m, and nothing ambiguous.
const ALPHABET: &[u8] = b"bcdefghjknprstuvx";
pub const PASSWORD_LEN: usize = 10;
/// MokManager's password length range, in UTF-16 units (shim `MokAuth`).
const MOK_PASSWORD_UNITS: core::ops::RangeInclusive<usize> = 1..=256;
/// Most bytes read for `--password-stdin`.
const MAX_PASSWORD_STDIN: usize = 1024;
/// Values of one random byte (rejection sampling range).
const BYTE_VALUES: usize = 256;

// DER (X.690 §8.1.2–8.1.3): the SEQUENCE tag, and the length octet's
// long-form flag with its count of length bytes in the low bits.
const DER_SEQUENCE: u8 = 0x30;
const DER_LEN_LONG: u8 = 0x80;
const DER_LEN_COUNT_MASK: u8 = 0x7f;
/// Most length bytes accepted (certificates are far below 16 MiB).
const DER_MAX_LEN_BYTES: usize = 3;

/// `MokAuth` in its SHA-256 form.
pub fn mok_auth(mok_new: &[u8], password: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(mok_new);
    for u in password.encode_utf16() {
        h.update(u.to_le_bytes());
    }
    h.finalize().into()
}

/// A DER certificate is one SEQUENCE whose length covers the whole file.
pub fn check_der(der: &[u8]) -> Result<(), CmdError> {
    let bad = || {
        CmdError::refused(
            "the certificate is not a single DER SEQUENCE (convert PEM with `certutil -decode`)",
        )
    };
    let (&tag, rest) = der.split_first().ok_or_else(bad)?;
    let (&l0, rest) = rest.split_first().ok_or_else(bad)?;
    if tag != DER_SEQUENCE {
        return Err(bad());
    }
    let (len, body) = if l0 < DER_LEN_LONG {
        (usize::from(l0), rest)
    } else {
        let n = usize::from(l0 & DER_LEN_COUNT_MASK);
        if n == 0 || n > DER_MAX_LEN_BYTES {
            return Err(bad());
        }
        let (lb, body) = rest.split_at_checked(n).ok_or_else(bad)?;
        (
            lb.iter().fold(0usize, |a, &b| a << 8 | usize::from(b)),
            body,
        )
    };
    if len != body.len() {
        return Err(bad());
    }
    Ok(())
}

pub fn generate_password(api: &dyn WinApi) -> Result<Zeroizing<String>, CmdError> {
    let mut s = Zeroizing::new(String::with_capacity(PASSWORD_LEN));
    let mut b = [0u8; 1];
    while s.len() < PASSWORD_LEN {
        api.random(&mut b)?;
        // Rejection sampling keeps every letter equally likely.
        let lim = BYTE_VALUES - BYTE_VALUES % ALPHABET.len();
        if usize::from(b[0]) < lim {
            if let Some(&c) = ALPHABET.get(usize::from(b[0]) % ALPHABET.len()) {
                s.push(char::from(c));
            }
        }
    }
    Ok(s)
}

fn enrolled(api: &dyn WinApi, der: &[u8]) -> Result<(bool, usize), CmdError> {
    let Some(v) = api.fw_get("MokListRT", &SHIM_LOCK)? else {
        return Ok((false, 0));
    };
    let mut found = false;
    let n = efisig::for_each(&v.data, |s| {
        found |= s.kind == efisig::CERT_X509 && s.data == der
    })
    .map_err(|e| CmdError::refused(format!("MokListRT is malformed: {e:?}")))?;
    Ok((found, n))
}

/// Which shim request: enrol (`MokNew`/`MokAuth`) or delete
/// (`MokDel`/`MokDelAuth`, `MokManager.c` `delete_keys`, same hashing).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    Enroll,
    Delete,
}

impl Request {
    pub const fn vars(self) -> (&'static str, &'static str) {
        match self {
            Request::Enroll => ("MokNew", "MokAuth"),
            Request::Delete => ("MokDel", "MokDelAuth"),
        }
    }
}

/// Write a request for one certificate with `password`; the list first,
/// then its authorisation (mokutil's order), undoing the list if the
/// authorisation cannot be written.
pub fn queue(
    api: &dyn WinApi,
    req: Request,
    der: &[u8],
    password: &str,
) -> Result<usize, CmdError> {
    let mut list = vec![0u8; efisig::x509_list_len(der.len())];
    let n = efisig::write_x509(&SHIM_LOCK, der, &mut list)
        .map_err(|_| CmdError::internal("request does not fit"))?;
    list.truncate(n);
    let (data_var, auth_var) = req.vars();
    let auth = mok_auth(&list, password);
    api.fw_set(data_var, &SHIM_LOCK, &list, attr::NV_BS_RT)?;
    if let Err(e) = api.fw_set(auth_var, &SHIM_LOCK, &auth, attr::NV_BS_RT) {
        let _ = api.fw_delete(data_var, &SHIM_LOCK);
        return Err(e.into());
    }
    Ok(list.len())
}

/// Whether `der` is in `MokListRT`.
pub fn is_enrolled(api: &dyn WinApi, der: &[u8]) -> Result<bool, CmdError> {
    enrolled(api, der).map(|(f, _)| f)
}

pub fn cert_path(ctx: &Ctx<'_>) -> String {
    join(&ctx.data_dir(), "mok\\mok.der")
}

pub fn enroll(ctx: &Ctx<'_>, cert: &str, password_stdin: bool) -> CmdResult {
    ctx.need_uefi()?;
    let der = ctx
        .api
        .read_file(cert, MAX_CERT)?
        .ok_or_else(|| CmdError::not_found(format!("{cert}: no such file")))?;
    check_der(&der)?;
    let fp = to_hex(&Sha256::digest(&der));
    let sb = ctx
        .api
        .fw_get("SecureBoot", &paguro_core::guid::EFI_GLOBAL_VARIABLE)?
        .is_some_and(|v| v.data == [1]);
    if !sb {
        return Err(CmdError::refused(
            "Secure Boot is off: nothing needs enrolling (INTERFACES.md §11.6)",
        ));
    }
    let (already, _) = enrolled(ctx.api, &der)?;
    if already {
        return Ok(
            Report::new(json!({ "sha256": fp, "enrolled": true, "requested": false }))
                .line("this certificate is already enrolled (MokListRT)"),
        );
    }
    let (password, generated) = if password_stdin {
        let raw = ctx.api.read_stdin(MAX_PASSWORD_STDIN)?;
        let s = std::str::from_utf8(&raw)
            .map_err(|_| CmdError::refused("the password is not UTF-8"))?;
        (
            Zeroizing::new(s.trim_end_matches(['\r', '\n']).to_string()),
            false,
        )
    } else {
        (generate_password(ctx.api)?, true)
    };
    let units = password.encode_utf16().count();
    if !MOK_PASSWORD_UNITS.contains(&units) {
        return Err(CmdError::refused("MokManager accepts 1 to 256 characters"));
    }
    let mut data = json!({
        "sha256": fp,
        "enrolled": false,
        "requested": !ctx.dry_run,
    });
    let mut r = Report::new(json!({}));
    if !ctx.dry_run {
        ctx.need_admin()?;
        queue(ctx.api, Request::Enroll, &der, &password)?;
        ctx.api.create_dir_all(&join(&ctx.data_dir(), "mok"))?;
        ctx.api.write_file(&cert_path(ctx), &der)?;
        r = r.line("enrolment requested: on the next boot MokManager shows once.");
        r = r.line("choose \"Enroll MOK\", \"Continue\", \"Yes\", then type the password below.");
    }
    if generated {
        // Shown on purpose: the user must type it at MokManager, and it is
        // worthless once that boot has passed (see crate::out).
        if let Some(o) = data.as_object_mut() {
            o.insert("one_time_password".into(), json!(password.as_str()));
        }
        r = r.line(format!("one-time password: {}", password.as_str()));
    }
    r.data = data;
    Ok(r)
}

pub fn status(ctx: &Ctx<'_>, cert: Option<&str>) -> CmdResult {
    ctx.need_uefi()?;
    let der = match cert {
        Some(c) => ctx.api.read_file(c, MAX_CERT)?,
        None => ctx.api.read_file(&cert_path(ctx), MAX_CERT)?,
    };
    let pending = ctx.api.fw_get("MokNew", &SHIM_LOCK)?.is_some();
    let (is_enrolled, count) = match &der {
        Some(d) => enrolled(ctx.api, d)?,
        None => (false, enrolled(ctx.api, &[])?.1),
    };
    let data = json!({
        "machine_key": der.as_ref().map(|d| to_hex(&Sha256::digest(d))),
        "enrolled": is_enrolled,
        "pending_request": pending,
        "mok_list_entries": count,
    });
    let line = match (&der, is_enrolled, pending) {
        (None, _, _) => "no machine key recorded".to_string(),
        (Some(_), true, _) => "the machine key is enrolled".to_string(),
        (Some(_), false, true) => {
            "enrolment pending: MokManager will ask on the next boot".to_string()
        }
        (Some(_), false, false) => "the machine key is NOT enrolled".to_string(),
    };
    Ok(Report::new(data).line(line))
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn mok_auth_vector() {
        // Independent computation: python3 -c "import hashlib;
        //   print(hashlib.sha256(b'\x01\x02' + 'ab'.encode('utf-16-le')).hexdigest())"
        assert_eq!(
            to_hex(&mok_auth(&[1, 2], "ab")),
            "c2b1965bdace41dcc7b33de875162fb44672cf337a0efc095d134b6c39dfc848"
        );
    }

    #[test]
    fn der_shapes() {
        assert!(check_der(&[0x30, 0x03, 1, 2, 3]).is_ok());
        assert!(check_der(&[0x30, 0x81, 0x02, 1, 2]).is_ok());
        assert!(check_der(&[0x30, 0x82, 0x00, 0x01, 9]).is_ok());
        assert!(check_der(&[0x30, 0x04, 1, 2, 3]).is_err());
        assert!(check_der(&[0x31, 0x01, 1]).is_err());
        assert!(check_der(&[0x30, 0x80]).is_err());
        assert!(check_der(&[]).is_err());
    }
}
