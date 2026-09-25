//! `host-hardware.json` (INTERFACES.md §11.5): the real machine as the
//! distribution installer inside WSL2 should see it.
//!
//! Collection ([`collect`]) is a handful of OS calls; conversion
//! ([`convert`]) is pure and tested. SMBIOS parsing and PnP-ID parsing are
//! `paguro_core::smbios` and `paguro_core::hwid`, so the Linux side's
//! synthetic sysfs can reuse the same modalias writers ([`modaliases`]).
//!
//! Only models, never identities: no serial numbers, UUIDs, MAC addresses or
//! disk serials are read.

use paguro_core::{hwid, smbios};
use serde::{Deserialize, Serialize};

use crate::api::{DiskDevice, PnpDevice, WinApi};
use crate::out::CmdError;

pub const VERSION: u32 = 1;

/// CPUID leaves read: 0 (vendor string, highest leaf), 1 (family/model/stepping).
const CPUID_VENDOR: u32 = 0;
const CPUID_SIGNATURE: u32 = 1;

// CPUID leaf 1 EAX fields (Intel SDM Vol. 2A, CPUID, Figure 3-6).
const EAX_STEPPING_SHIFT: u32 = 0;
const EAX_MODEL_SHIFT: u32 = 4;
const EAX_FAMILY_SHIFT: u32 = 8;
const EAX_EXT_MODEL_SHIFT: u32 = 16;
const EAX_EXT_FAMILY_SHIFT: u32 = 20;
const EAX_NIBBLE: u32 = 0xf;
const EAX_EXT_FAMILY_MASK: u32 = 0xff;
/// Family 0xF adds the extended family.
const FAMILY_USES_EXT: u32 = 0xf;
/// Family 6 and up add the extended model (Linux `x86_model`).
const FAMILY_EXT_MODEL_MIN: u32 = 6;
/// The vendor string: EBX, EDX, ECX of leaf 0, 12 ASCII bytes.
const VENDOR_LEN: usize = 12;
/// Longest modalias built (hwid's hardware-ID length cap).
const MODALIAS_BUF: usize = paguro_core::hwid::MAX_ID;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cpu {
    pub vendor: String,
    pub family: u32,
    pub model: u32,
    pub stepping: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dmi {
    pub sys_vendor: String,
    pub product_name: String,
    pub board_vendor: String,
    pub board_name: String,
    pub bios_vendor: String,
    pub bios_version: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pci {
    pub vendor: String,
    pub device: String,
    pub subvendor: String,
    pub subdevice: String,
    pub class: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usb {
    pub vendor: String,
    pub product: String,
    pub class: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Storage {
    pub bus: String,
    pub model: String,
    pub size: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostHardware {
    pub version: u32,
    pub cpu: Cpu,
    pub dmi: Dmi,
    pub pci: Vec<Pci>,
    pub usb: Vec<Usb>,
    pub acpi: Vec<String>,
    pub storage: Vec<Storage>,
}

/// Everything the export is computed from.
#[derive(Clone, Debug, Default)]
pub struct Collected {
    pub cpuid0: Option<[u32; 4]>,
    pub cpuid1: Option<[u32; 4]>,
    pub smbios: Option<Vec<u8>>,
    pub devices: Vec<PnpDevice>,
    pub disks: Vec<DiskDevice>,
}

pub fn collect(api: &dyn WinApi) -> Result<Collected, CmdError> {
    Ok(Collected {
        cpuid0: api.cpuid(CPUID_VENDOR, 0),
        cpuid1: api.cpuid(CPUID_SIGNATURE, 0),
        // A machine without SMBIOS still exports its devices.
        smbios: api.smbios().ok(),
        devices: api.pnp_devices()?,
        disks: api.disks()?,
    })
}

/// CPUID leaf 1 EAX → (family, model, stepping) as Linux reports them in
/// `/proc/cpuinfo` (`x86_family`, `x86_model` in arch/x86/lib/cpu.c).
pub fn fms(eax: u32) -> (u32, u32, u32) {
    let mut family = (eax >> EAX_FAMILY_SHIFT) & EAX_NIBBLE;
    if family == FAMILY_USES_EXT {
        family += (eax >> EAX_EXT_FAMILY_SHIFT) & EAX_EXT_FAMILY_MASK;
    }
    let mut model = (eax >> EAX_MODEL_SHIFT) & EAX_NIBBLE;
    if family >= FAMILY_EXT_MODEL_MIN {
        model += ((eax >> EAX_EXT_MODEL_SHIFT) & EAX_NIBBLE) << EAX_MODEL_SHIFT;
    }
    (family, model, (eax >> EAX_STEPPING_SHIFT) & EAX_NIBBLE)
}

fn vendor_string(leaf0: [u32; 4]) -> String {
    let [_, b, c, d] = leaf0;
    let mut v = Vec::with_capacity(VENDOR_LEN);
    for r in [b, d, c] {
        v.extend_from_slice(&r.to_le_bytes());
    }
    String::from_utf8_lossy(&v)
        .trim_end_matches('\0')
        .to_string()
}

fn text(b: Option<&[u8]>) -> String {
    b.map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default()
}

pub fn convert(c: &Collected) -> HostHardware {
    let cpu = match (c.cpuid0, c.cpuid1) {
        (Some(l0), Some(l1)) => {
            let (family, model, stepping) = fms(l1[0]);
            Cpu {
                vendor: vendor_string(l0),
                family,
                model,
                stepping,
            }
        }
        _ => Cpu::default(),
    };
    let dmi = c
        .smbios
        .as_deref()
        .and_then(|b| smbios::parse(b).ok())
        .map(|d| Dmi {
            sys_vendor: text(d.sys_vendor),
            product_name: text(d.product_name),
            board_vendor: text(d.board_vendor),
            board_name: text(d.board_name),
            bios_vendor: text(d.bios_vendor),
            bios_version: text(d.bios_version),
        })
        .unwrap_or_default();
    let mut out = HostHardware {
        version: VERSION,
        cpu,
        dmi,
        ..HostHardware::default()
    };
    for d in &c.devices {
        let ids = || {
            d.hardware_ids
                .iter()
                .chain(&d.compatible_ids)
                .map(String::as_str)
        };
        if let Some(p) = hwid::pci(ids()) {
            let e = Pci {
                vendor: format!("{:04x}", p.vendor),
                device: format!("{:04x}", p.device),
                subvendor: format!("{:04x}", p.subvendor.unwrap_or(0)),
                subdevice: format!("{:04x}", p.subdevice.unwrap_or(0)),
                class: format!("{:06x}", p.class.unwrap_or(0)),
            };
            if !out.pci.contains(&e) {
                out.pci.push(e);
            }
        } else if let Some(u) = hwid::usb(ids()) {
            // Interfaces of a composite device are listed once, as the device.
            if u.interface.is_none() {
                let e = Usb {
                    vendor: format!("{:04x}", u.vendor),
                    product: format!("{:04x}", u.product),
                    class: format!("{:02x}", u.class.unwrap_or(0)),
                };
                if !out.usb.contains(&e) {
                    out.usb.push(e);
                }
            }
        } else {
            let mut buf = [0u8; 8];
            if let Some(a) = ids().find_map(|id| hwid::acpi(id, &mut buf).map(str::to_string)) {
                if !out.acpi.contains(&a) {
                    out.acpi.push(a);
                }
            }
        }
    }
    out.storage = c
        .disks
        .iter()
        .map(|d| Storage {
            bus: d.bus.clone(),
            model: d.model.clone(),
            size: d.size,
        })
        .collect();
    out
}

fn h16(s: &str) -> u16 {
    u16::from_str_radix(s, 16).unwrap_or(0)
}

/// The modalias of every exported device and of the DMI identity, for the
/// synthetic sysfs (INTERFACES.md §11.5). Unknown USB fields are zero: the
/// export carries only vendor, product and class.
pub fn modaliases(h: &HostHardware) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = [0u8; MODALIAS_BUF];
    let mut push = |r: Result<usize, paguro_core::bytes::Full>, buf: &[u8]| {
        if let Ok(n) = r {
            out.push(String::from_utf8_lossy(buf.get(..n).unwrap_or(&[])).into_owned());
        }
    };
    for p in &h.pci {
        let id = hwid::Pci {
            vendor: h16(&p.vendor),
            device: h16(&p.device),
            subvendor: Some(h16(&p.subvendor)),
            subdevice: Some(h16(&p.subdevice)),
            class: u32::from_str_radix(&p.class, 16).ok(),
        };
        let r = hwid::pci_modalias(&id, &mut buf);
        push(r, &buf);
    }
    for u in &h.usb {
        let id = hwid::Usb {
            vendor: h16(&u.vendor),
            product: h16(&u.product),
            class: u8::from_str_radix(&u.class, 16).ok(),
            ..hwid::Usb::default()
        };
        let r = hwid::usb_modalias(&id, &mut buf);
        push(r, &buf);
    }
    for a in &h.acpi {
        let r = hwid::acpi_modalias(a, &mut buf);
        push(r, &buf);
    }
    let d = hwid::DmiFields {
        bios_vendor: h.dmi.bios_vendor.as_bytes(),
        bios_version: h.dmi.bios_version.as_bytes(),
        sys_vendor: h.dmi.sys_vendor.as_bytes(),
        product_name: h.dmi.product_name.as_bytes(),
        board_vendor: h.dmi.board_vendor.as_bytes(),
        board_name: h.dmi.board_name.as_bytes(),
    };
    let r = hwid::dmi_modalias(&d, &mut buf);
    push(r, &buf);
    out
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn family_model_stepping() {
        // Intel Meteor Lake, family 6 model 170 stepping 4 (§11.5's example).
        assert_eq!(fms(0x000A_06A4), (6, 170, 4));
        // AMD Zen 4: family 0x19, model 0x61.
        assert_eq!(fms(0x00A6_0F12), (25, 97, 2));
        assert_eq!(fms(0), (0, 0, 0));
    }

    #[test]
    fn vendor() {
        // "GenuineIntel" = ebx "Genu", edx "ineI", ecx "ntel"
        let l0 = [0x20, 0x756e_6547, 0x6c65_746e, 0x4965_6e69];
        assert_eq!(vendor_string(l0), "GenuineIntel");
    }
}
