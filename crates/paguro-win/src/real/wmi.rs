//! BitLocker through WMI's `Win32_EncryptableVolume`
//! (`root\CIMV2\Security\MicrosoftVolumeEncryption`), which exists on every
//! edition including Home (Device Encryption). Read-only: paguro never
//! changes BitLocker's configuration (DESIGN.md §6).
//!
//! The namespace requires packet-privacy authentication; the recovery
//! password (`GetKeyProtectorNumericalPassword`) requires an administrator.

use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
    CoInitializeSecurity, CoSetProxyBlanket, EOAC_NONE, RPC_C_AUTHN_LEVEL_DEFAULT,
    RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE,
};
use windows::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE};
use windows::Win32::System::Variant::{VARIANT, VariantGetElementCount, VariantGetStringElem};
use windows::Win32::System::Wmi::{
    IWbemClassObject, IWbemLocator, IWbemServices, WBEM_FLAG_FORWARD_ONLY,
    WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_GENERIC_FLAG_TYPE, WBEM_INFINITE, WbemLocator,
};
use windows::core::{BSTR, HSTRING, PCWSTR};
use zeroize::Zeroizing;

use super::win_err;
use crate::api::{ApiError, ApiResult, BitLocker, ErrorKind};

const NAMESPACE: &str = "ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption";
const CLASS: &str = "Win32_EncryptableVolume";
/// `GetKeyProtectors` type for numerical (recovery) passwords.
const NUMERICAL_PASSWORD: i32 = 3;
/// Most elements read from a WMI string array (protector IDs).
const MAX_ARRAY_ELEMENTS: u32 = 256;

fn connect() -> ApiResult<IWbemServices> {
    // SAFETY: COM initialisation for this thread; "already initialised in
    // another mode" and "security already set" are both fine to ignore.
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        let _ = CoInitializeSecurity(
            None,
            -1,
            None,
            None,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
            None,
        );
        let loc: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| win_err("CoCreateInstance", e))?;
        let svc = loc
            .ConnectServer(
                &BSTR::from(NAMESPACE),
                &BSTR::new(),
                &BSTR::new(),
                &BSTR::new(),
                0,
                &BSTR::new(),
                None,
            )
            .map_err(|e| win_err("IWbemLocator::ConnectServer", e))?;
        CoSetProxyBlanket(
            &svc,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            PCWSTR::null(),
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
        )
        .map_err(|e| win_err("CoSetProxyBlanket", e))?;
        Ok(svc)
    }
}

/// `C:` and nothing else: the value goes into a WQL string.
fn check_drive(drive: &str) -> ApiResult<()> {
    let b = drive.as_bytes();
    if matches!(b, [l, b':'] if l.is_ascii_alphabetic()) {
        Ok(())
    } else {
        Err(ApiError::new(
            ErrorKind::InvalidData,
            "Win32_EncryptableVolume",
            format!("not a drive letter: {drive:?}"),
        ))
    }
}

fn get(obj: &IWbemClassObject, name: &str) -> ApiResult<VARIANT> {
    let mut v = VARIANT::default();
    // SAFETY: `v` is a valid out-VARIANT.
    unsafe { obj.Get(&HSTRING::from(name), 0, &mut v, None, None) }
        .map_err(|e| win_err("IWbemClassObject::Get", e))?;
    Ok(v)
}

fn get_u32(obj: &IWbemClassObject, name: &str) -> ApiResult<u32> {
    let v = get(obj, name)?;
    u32::try_from(&v).map_err(|e| win_err("VariantToUInt32", e))
}

fn get_strings(obj: &IWbemClassObject, name: &str) -> ApiResult<Vec<String>> {
    let v = get(obj, name)?;
    if v.is_empty() {
        return Ok(Vec::new());
    }
    // SAFETY: `v` is a live VARIANT; elements are copied out and freed.
    unsafe {
        let n = VariantGetElementCount(&v);
        let mut out = Vec::with_capacity(n as usize);
        for i in 0..n.min(MAX_ARRAY_ELEMENTS) {
            let p = VariantGetStringElem(&v, i).map_err(|e| win_err("VariantGetStringElem", e))?;
            out.push(p.to_string().unwrap_or_default());
            windows::Win32::System::Com::CoTaskMemFree(Some(p.0 as *const _));
        }
        Ok(out)
    }
}

struct Volume {
    svc: IWbemServices,
    path: BSTR,
}

fn open(drive: &str) -> ApiResult<Option<Volume>> {
    check_drive(drive)?;
    let svc = connect()?;
    let q = format!("SELECT * FROM {CLASS} WHERE DriveLetter='{drive}'");
    // SAFETY: plain COM calls on a connected service.
    unsafe {
        let e = svc
            .ExecQuery(
                &BSTR::from("WQL"),
                &BSTR::from(q),
                WBEM_GENERIC_FLAG_TYPE(WBEM_FLAG_FORWARD_ONLY.0 | WBEM_FLAG_RETURN_IMMEDIATELY.0),
                None,
            )
            .map_err(|e| win_err("IWbemServices::ExecQuery", e))?;
        let mut row = [None];
        let mut n = 0u32;
        let _ = e.Next(WBEM_INFINITE, &mut row, &mut n);
        let Some(obj) = row[0].take().filter(|_| n == 1) else {
            return Ok(None);
        };
        let path =
            BSTR::try_from(&get(&obj, "__PATH")?).map_err(|e| win_err("VariantToBSTR", e))?;
        Ok(Some(Volume { svc, path }))
    }
}

impl Volume {
    /// Run `method` with `inputs`; the out-parameters, after checking
    /// `ReturnValue` is 0.
    fn call(&self, method: &str, inputs: &[(&str, VARIANT)]) -> ApiResult<IWbemClassObject> {
        let m = HSTRING::from(method);
        // SAFETY: plain COM calls; every out-pointer is a local.
        unsafe {
            let mut class = None;
            self.svc
                .GetObject(
                    &BSTR::from(CLASS),
                    WBEM_GENERIC_FLAG_TYPE(0),
                    None,
                    Some(&mut class),
                    None,
                )
                .map_err(|e| win_err("IWbemServices::GetObject", e))?;
            let class: IWbemClassObject =
                class.ok_or_else(|| ApiError::not_found("GetObject", CLASS))?;
            let mut in_sig = None;
            class
                .GetMethod(&m, 0, &mut in_sig, std::ptr::null_mut())
                .map_err(|e| win_err("GetMethod", e))?;
            let in_params = match (in_sig, inputs.is_empty()) {
                (Some(sig), false) => {
                    let inst = sig
                        .SpawnInstance(0)
                        .map_err(|e| win_err("SpawnInstance", e))?;
                    for (k, v) in inputs {
                        inst.Put(&HSTRING::from(*k), 0, v, 0)
                            .map_err(|e| win_err("IWbemClassObject::Put", e))?;
                    }
                    Some(inst)
                }
                _ => None,
            };
            let mut out = None;
            self.svc
                .ExecMethod(
                    &self.path,
                    &BSTR::from(method),
                    WBEM_GENERIC_FLAG_TYPE(0),
                    None,
                    in_params.as_ref(),
                    Some(&mut out),
                    None,
                )
                .map_err(|e| win_err("IWbemServices::ExecMethod", e))?;
            let out: IWbemClassObject =
                out.ok_or_else(|| ApiError::new(ErrorKind::Other, "ExecMethod", "no output"))?;
            let rv = get_u32(&out, "ReturnValue")?;
            if rv != 0 {
                return Err(ApiError::new(
                    ErrorKind::Other,
                    "Win32_EncryptableVolume",
                    format!("{method} returned 0x{rv:08x}"),
                )
                .with_code(i64::from(rv)));
            }
            Ok(out)
        }
    }
}

pub fn bitlocker(drive: &str) -> ApiResult<Option<BitLocker>> {
    let Some(v) = open(drive)? else {
        return Ok(None);
    };
    let prot = v.call("GetProtectionStatus", &[])?;
    let conv = v.call("GetConversionStatus", &[])?;
    let meth = v.call("GetEncryptionMethod", &[])?;
    let ids = get_strings(
        &v.call(
            "GetKeyProtectors",
            &[("KeyProtectorType", VARIANT::from(0i32))],
        )?,
        "VolumeKeyProtectorID",
    )?;
    let mut types = Vec::new();
    for id in ids {
        let o = v.call(
            "GetKeyProtectorType",
            &[("VolumeKeyProtectorID", VARIANT::from(id.as_str()))],
        )?;
        types.push(get_u32(&o, "KeyProtectorType")?);
    }
    Ok(Some(BitLocker {
        protection_status: get_u32(&prot, "ProtectionStatus")?,
        conversion_status: get_u32(&conv, "ConversionStatus")?,
        encryption_percentage: get_u32(&conv, "EncryptionPercentage")?,
        encryption_method: get_u32(&meth, "EncryptionMethod")?,
        protector_types: types,
    }))
}

pub fn recovery_passwords(drive: &str) -> ApiResult<Vec<Zeroizing<String>>> {
    let Some(v) = open(drive)? else {
        return Ok(Vec::new());
    };
    let ids = get_strings(
        &v.call(
            "GetKeyProtectors",
            &[("KeyProtectorType", VARIANT::from(NUMERICAL_PASSWORD))],
        )?,
        "VolumeKeyProtectorID",
    )?;
    let mut out = Vec::new();
    for id in ids {
        let o = v.call(
            "GetKeyProtectorNumericalPassword",
            &[("VolumeKeyProtectorID", VARIANT::from(id.as_str()))],
        )?;
        let pw = BSTR::try_from(&get(&o, "NumericalPassword")?)
            .map_err(|e| win_err("VariantToBSTR", e))?;
        out.push(Zeroizing::new(pw.to_string()));
    }
    Ok(out)
}
