//! Present PnP devices and their hardware/compatible IDs (SetupAPI), for the
//! host-hardware export. IDs go back as strings; `paguro_core::hwid` parses.

use windows::Win32::Devices::DeviceAndDriverInstallation::{
    DIGCF_ALLCLASSES, DIGCF_PRESENT, HDEVINFO, SETUP_DI_REGISTRY_PROPERTY, SP_DEVINFO_DATA,
    SPDRP_COMPATIBLEIDS, SPDRP_HARDWAREID, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo,
    SetupDiGetClassDevsW, SetupDiGetDeviceInstanceIdW, SetupDiGetDeviceRegistryPropertyW,
};
use windows::core::PCWSTR;

use super::win_err;
use crate::api::{ApiResult, PnpDevice};

/// Most devices enumerated (a desktop has a few hundred).
const MAX_DEVICES: u32 = 8192;
/// A REG_MULTI_SZ property buffer (hardware / compatible ID lists).
const MULTI_SZ_BUF: usize = 4096;
/// Device instance ID buffer (MAX_DEVICE_ID_LEN is 200; room to spare).
const INSTANCE_ID_BUF: usize = 512;

struct DevInfo(HDEVINFO);

impl Drop for DevInfo {
    fn drop(&mut self) {
        // SAFETY: destroys the set once.
        let _ = unsafe { SetupDiDestroyDeviceInfoList(self.0) };
    }
}

/// A REG_MULTI_SZ property as strings; empty when absent.
fn multi_sz(set: &DevInfo, d: &SP_DEVINFO_DATA, prop: SETUP_DI_REGISTRY_PROPERTY) -> Vec<String> {
    let mut buf = vec![0u8; MULTI_SZ_BUF];
    let mut need = 0u32;
    // SAFETY: `buf` is writable for its length; `d` came from this set.
    if unsafe {
        SetupDiGetDeviceRegistryPropertyW(set.0, d, prop, None, Some(&mut buf), Some(&mut need))
    }
    .is_err()
    {
        return Vec::new();
    }
    let n = (need as usize).min(buf.len());
    let w: Vec<u16> = buf
        .get(..n)
        .unwrap_or(&[])
        .chunks_exact(2)
        .map(|c| {
            u16::from_le_bytes([
                c.first().copied().unwrap_or(0),
                c.get(1).copied().unwrap_or(0),
            ])
        })
        .collect();
    w.split(|&c| c == 0)
        .filter(|s| !s.is_empty())
        .map(String::from_utf16_lossy)
        .collect()
}

pub fn pnp_devices() -> ApiResult<Vec<PnpDevice>> {
    // SAFETY: all classes, present devices only; no parent window.
    let set = unsafe {
        SetupDiGetClassDevsW(None, PCWSTR::null(), None, DIGCF_PRESENT | DIGCF_ALLCLASSES)
    }
    .map_err(|e| win_err("SetupDiGetClassDevsW", e))?;
    let set = DevInfo(set);
    let mut out = Vec::new();
    for i in 0..MAX_DEVICES {
        let mut d = SP_DEVINFO_DATA {
            cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
            ..Default::default()
        };
        // SAFETY: `d` has its size set, as the API requires.
        if unsafe { SetupDiEnumDeviceInfo(set.0, i, &mut d) }.is_err() {
            break;
        }
        let mut id = [0u16; INSTANCE_ID_BUF];
        // SAFETY: `id` is writable for its length.
        let instance = match unsafe { SetupDiGetDeviceInstanceIdW(set.0, &d, Some(&mut id), None) }
        {
            Ok(()) => super::from_wide(&id),
            Err(_) => String::new(),
        };
        out.push(PnpDevice {
            instance_id: instance,
            hardware_ids: multi_sz(&set, &d, SPDRP_HARDWAREID),
            compatible_ids: multi_sz(&set, &d, SPDRP_COMPATIBLEIDS),
        });
    }
    Ok(out)
}
