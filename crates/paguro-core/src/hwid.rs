//! Device identities for the host-hardware export (INTERFACES.md §11.5):
//! Windows PnP hardware/compatible IDs in, the export's PCI/USB/ACPI
//! identities out, and the Linux `modalias` strings the synthetic sysfs
//! presents for them.
//!
//! Windows forms read (case-insensitive, as SetupAPI returns them):
//!
//! ```text
//! PCI\VEN_10DE&DEV_28A0&SUBSYS_1F3A1043&REV_A1   SUBSYS = subdevice ‖ subvendor
//! PCI\VEN_10DE&DEV_28A0&CC_030000                CC = base ‖ sub ‖ prog-if
//! USB\VID_8087&PID_0033&REV_0000  [&MI_00]
//! USB\Class_E0&SubClass_01&Prot_01
//! ACPI\PNP0C50   ACPI\VEN_INT&DEV_33D2   *PNP0C50
//! ```
//!
//! Linux forms written (`scripts/mod/file2alias.c`, upper-case hex):
//!
//! ```text
//! pci:v%08Xd%08Xsv%08Xsd%08Xbc%02Xsc%02Xi%02X
//! usb:v%04Xp%04Xd%04Xdc%02Xdsc%02Xdp%02Xic%02Xisc%02Xip%02Xin%02X
//! acpi:%s:
//! dmi:bvn%s:bvr%s:bd%s:br%s:efr%s:svn%s:pn%s:pvr%s:rvn%s:rn%s:rvr%s:cvn%s:ct%s:cvr%s:sku%s:
//! ```
//!
//! No allocation: parsers borrow, writers fill a caller's buffer. Every
//! input is a short string from the OS; anything malformed is skipped
//! (`None`), never guessed.

use crate::bytes::{Full, Writer};

/// Longest hardware ID considered (Windows caps device IDs at 200 chars).
pub const MAX_ID: usize = 256;

/// Hex digits of each field in a Windows PnP hardware ID ("Identifiers for
/// PCI Devices", "Identifiers for USB Devices", Windows Driver Kit docs).
const VEN_DEV_DIGITS: usize = 4;
const SUBSYS_DIGITS: usize = 8;
const CC_DIGITS: usize = 6;
const BYTE_DIGITS: usize = 2;
/// `SUBSYS_`: subdevice in the high 16 bits, subvendor in the low 16.
const SUBSYS_DEVICE_SHIFT: u32 = 16;

/// An ACPI/PNP ID (ACPI 6.5 §6.1.5 `_HID`): a 3-character PNP or
/// 4-character ACPI vendor prefix, then 4 hex digits.
const PNP_ID_LEN: usize = 7;
const ACPI_ID_LEN: usize = 8;
const PNP_VENDOR_LEN: usize = 3;
const ACPI_VENDOR_LEN: usize = 4;

/// Hex digits of each `modalias` field (`scripts/mod/file2alias.c`).
const PCI_ID_DIGITS: u32 = 8;
const USB_ID_DIGITS: u32 = 4;
const CLASS_BYTE_DIGITS: u32 = 2;
/// PCI class code: base ‖ sub ‖ prog-if, one byte each.
const CLASS_BASE_SHIFT: u32 = 16;
const CLASS_SUB_SHIFT: u32 = 8;
const BYTE_MASK: u32 = 0xff;
const NIBBLE_BITS: u32 = 4;
const NIBBLE_MASK: u32 = 0xf;
/// ASCII DEL: the first byte past printable ASCII.
const ASCII_DEL: u8 = 0x7f;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pci {
    pub vendor: u16,
    pub device: u16,
    pub subvendor: Option<u16>,
    pub subdevice: Option<u16>,
    /// 24-bit class code: base ‖ sub ‖ prog-if.
    pub class: Option<u32>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usb {
    pub vendor: u16,
    pub product: u16,
    /// `bcdDevice`, from `REV_`.
    pub rev: Option<u16>,
    /// Class ‖ subclass ‖ protocol, from `Class_`/`SubClass_`/`Prot_`.
    pub class: Option<u8>,
    pub subclass: Option<u8>,
    pub protocol: Option<u8>,
    /// `MI_`: this devnode is one interface of a composite device.
    pub interface: Option<u8>,
}

fn hex<const N: usize>(s: &str) -> Option<u32> {
    if s.len() != N || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(s, 16).ok()
}

/// `(bus, fields)`: `PCI\A&B&C` → `("PCI", "A&B&C")`.
fn split(id: &str) -> Option<(&str, &str)> {
    if id.len() > MAX_ID || !id.is_ascii() {
        return None;
    }
    id.split_once('\\')
}

/// The value after `key` among `&`-separated fields, case-insensitively.
fn field<'a>(fields: &'a str, key: &str) -> Option<&'a str> {
    fields.split('&').find_map(|f| {
        let (k, v) = f.split_at_checked(key.len())?;
        k.eq_ignore_ascii_case(key).then_some(v)
    })
}

/// Merge every PCI ID of one devnode (hardware IDs then compatible IDs).
pub fn pci<'a>(ids: impl IntoIterator<Item = &'a str>) -> Option<Pci> {
    let mut out: Option<Pci> = None;
    let mut class = None;
    for id in ids {
        let Some((bus, f)) = split(id) else { continue };
        if !bus.eq_ignore_ascii_case("PCI") {
            continue;
        }
        if class.is_none() {
            class = field(f, "CC_").and_then(hex::<CC_DIGITS>);
        }
        let (Some(v), Some(d)) = (
            field(f, "VEN_").and_then(hex::<VEN_DEV_DIGITS>),
            field(f, "DEV_").and_then(hex::<VEN_DEV_DIGITS>),
        ) else {
            continue;
        };
        let sub = field(f, "SUBSYS_").and_then(hex::<SUBSYS_DIGITS>);
        let p = out.get_or_insert(Pci {
            vendor: v as u16,
            device: d as u16,
            ..Pci::default()
        });
        if p.vendor == v as u16 && p.device == d as u16 && p.subvendor.is_none() {
            if let Some(s) = sub {
                p.subdevice = Some((s >> SUBSYS_DEVICE_SHIFT) as u16);
                p.subvendor = Some(s as u16);
            }
        }
    }
    out.map(|mut p| {
        p.class = class;
        p
    })
}

/// Merge every USB ID of one devnode.
pub fn usb<'a>(ids: impl IntoIterator<Item = &'a str>) -> Option<Usb> {
    let mut out: Option<Usb> = None;
    let (mut class, mut subclass, mut protocol) = (None, None, None);
    for id in ids {
        let Some((bus, f)) = split(id) else { continue };
        if !bus.eq_ignore_ascii_case("USB") {
            continue;
        }
        if class.is_none() {
            class = field(f, "Class_")
                .and_then(hex::<BYTE_DIGITS>)
                .map(|c| c as u8);
            subclass = field(f, "SubClass_")
                .and_then(hex::<BYTE_DIGITS>)
                .map(|c| c as u8);
            protocol = field(f, "Prot_")
                .and_then(hex::<BYTE_DIGITS>)
                .map(|c| c as u8);
        }
        let (Some(v), Some(p)) = (
            field(f, "VID_").and_then(hex::<VEN_DEV_DIGITS>),
            field(f, "PID_").and_then(hex::<VEN_DEV_DIGITS>),
        ) else {
            continue;
        };
        let u = out.get_or_insert(Usb {
            vendor: v as u16,
            product: p as u16,
            ..Usb::default()
        });
        if u.rev.is_none() {
            u.rev = field(f, "REV_")
                .and_then(hex::<VEN_DEV_DIGITS>)
                .map(|r| r as u16);
        }
        if u.interface.is_none() {
            u.interface = field(f, "MI_")
                .and_then(hex::<BYTE_DIGITS>)
                .map(|i| i as u8);
        }
    }
    out.map(|mut u| {
        (u.class, u.subclass, u.protocol) = (class, subclass, protocol);
        u
    })
}

/// An ACPI/PNP ID: 3 upper-case letters + 4 hex digits (`PNP0C50`) or
/// 4 upper-case alphanumerics + 4 hex digits (`INT33D2`, `MSFT0101`).
fn acpi_id_ok(s: &str) -> bool {
    let b = s.as_bytes();
    let (vendor, product) = match b.len() {
        PNP_ID_LEN => b.split_at(PNP_VENDOR_LEN),
        ACPI_ID_LEN => b.split_at(ACPI_VENDOR_LEN),
        _ => return false,
    };
    vendor
        .iter()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
        && product.iter().all(|c| c.is_ascii_hexdigit())
}

/// The ACPI ID in one hardware ID, written into `out` (at most 8 bytes).
pub fn acpi<'o>(id: &str, out: &'o mut [u8; ACPI_ID_LEN]) -> Option<&'o str> {
    let body = if let Some(rest) = id.strip_prefix('*') {
        rest
    } else {
        let (bus, f) = split(id)?;
        if !bus.eq_ignore_ascii_case("ACPI") {
            return None;
        }
        f
    };
    let n = if let (Some(v), Some(d)) = (field(body, "VEN_"), field(body, "DEV_")) {
        let (v, d) = (v.as_bytes(), d.as_bytes());
        if v.len() + d.len() > ACPI_ID_LEN {
            return None;
        }
        out.get_mut(..v.len())?.copy_from_slice(v);
        out.get_mut(v.len()..v.len() + d.len())?.copy_from_slice(d);
        v.len() + d.len()
    } else {
        let b = body.as_bytes();
        if b.len() > ACPI_ID_LEN {
            return None;
        }
        out.get_mut(..b.len())?.copy_from_slice(b);
        b.len()
    };
    for c in out.iter_mut().take(n) {
        c.make_ascii_uppercase();
    }
    let s = core::str::from_utf8(out.get(..n)?).ok()?;
    acpi_id_ok(s).then_some(s)
}

const HEX: &[u8; 16] = b"0123456789ABCDEF";

fn put_hex(w: &mut Writer<'_>, v: u32, digits: u32) -> Result<(), Full> {
    for i in (0..digits).rev() {
        let nib = ((v >> (i * NIBBLE_BITS)) & NIBBLE_MASK) as usize;
        w.u8(*HEX.get(nib).unwrap_or(&b'0'))?;
    }
    Ok(())
}

/// `pci:v…d…sv…sd…bc…sc…i…`. An absent subsystem or class is written as
/// zero, which is what a device without one reports in real sysfs.
pub fn pci_modalias(p: &Pci, out: &mut [u8]) -> Result<usize, Full> {
    let mut w = Writer::new(out);
    let class = p.class.unwrap_or(0);
    w.put(b"pci:v")?;
    put_hex(&mut w, u32::from(p.vendor), PCI_ID_DIGITS)?;
    w.put(b"d")?;
    put_hex(&mut w, u32::from(p.device), PCI_ID_DIGITS)?;
    w.put(b"sv")?;
    put_hex(&mut w, u32::from(p.subvendor.unwrap_or(0)), PCI_ID_DIGITS)?;
    w.put(b"sd")?;
    put_hex(&mut w, u32::from(p.subdevice.unwrap_or(0)), PCI_ID_DIGITS)?;
    w.put(b"bc")?;
    put_hex(&mut w, class >> CLASS_BASE_SHIFT, CLASS_BYTE_DIGITS)?;
    w.put(b"sc")?;
    put_hex(
        &mut w,
        (class >> CLASS_SUB_SHIFT) & BYTE_MASK,
        CLASS_BYTE_DIGITS,
    )?;
    w.put(b"i")?;
    put_hex(&mut w, class & BYTE_MASK, CLASS_BYTE_DIGITS)?;
    Ok(w.len())
}

/// `usb:v…p…d…dc…dsc…dp…ic…isc…ip…in…`. For an interface devnode (`MI_`)
/// the class triple is the interface's and goes in `ic/isc/ip`; for a
/// device devnode it is the device's and goes in `dc/dsc/dp`.
pub fn usb_modalias(u: &Usb, out: &mut [u8]) -> Result<usize, Full> {
    let mut w = Writer::new(out);
    let c = |x: Option<u8>| u32::from(x.unwrap_or(0));
    let (dev, intf) = if u.interface.is_some() {
        ((0, 0, 0), (c(u.class), c(u.subclass), c(u.protocol)))
    } else {
        ((c(u.class), c(u.subclass), c(u.protocol)), (0, 0, 0))
    };
    w.put(b"usb:v")?;
    put_hex(&mut w, u32::from(u.vendor), USB_ID_DIGITS)?;
    w.put(b"p")?;
    put_hex(&mut w, u32::from(u.product), USB_ID_DIGITS)?;
    w.put(b"d")?;
    put_hex(&mut w, u32::from(u.rev.unwrap_or(0)), USB_ID_DIGITS)?;
    for (tag, v) in [
        (&b"dc"[..], dev.0),
        (b"dsc", dev.1),
        (b"dp", dev.2),
        (b"ic", intf.0),
        (b"isc", intf.1),
        (b"ip", intf.2),
        (b"in", c(u.interface)),
    ] {
        w.put(tag)?;
        put_hex(&mut w, v, CLASS_BYTE_DIGITS)?;
    }
    Ok(w.len())
}

/// `acpi:<ID>:`.
pub fn acpi_modalias(id: &str, out: &mut [u8]) -> Result<usize, Full> {
    let mut w = Writer::new(out);
    w.put(b"acpi:")?;
    w.put(id.as_bytes())?;
    w.put(b":")?;
    Ok(w.len())
}

/// DMI identity fields for [`dmi_modalias`]; absent ones are written empty.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DmiFields<'a> {
    pub bios_vendor: &'a [u8],
    pub bios_version: &'a [u8],
    pub sys_vendor: &'a [u8],
    pub product_name: &'a [u8],
    pub board_vendor: &'a [u8],
    pub board_name: &'a [u8],
}

/// The kernel's `ascii_filter` (drivers/firmware/dmi-id.c): printable
/// characters except space and `:`.
fn put_filtered(w: &mut Writer<'_>, s: &[u8]) -> Result<(), Full> {
    for &c in s {
        if c > b' ' && c < ASCII_DEL && c != b':' {
            w.u8(c)?;
        }
    }
    Ok(())
}

/// `/sys/class/dmi/id/modalias`, in the kernel's field order.
pub fn dmi_modalias(d: &DmiFields<'_>, out: &mut [u8]) -> Result<usize, Full> {
    let mut w = Writer::new(out);
    w.put(b"dmi")?;
    for (tag, v) in [
        (&b"bvn"[..], d.bios_vendor),
        (b"bvr", d.bios_version),
        (b"bd", b""),
        (b"br", b""),
        (b"efr", b""),
        (b"svn", d.sys_vendor),
        (b"pn", d.product_name),
        (b"pvr", b""),
        (b"rvn", d.board_vendor),
        (b"rn", d.board_name),
        (b"rvr", b""),
        (b"cvn", b""),
        (b"ct", b""),
        (b"cvr", b""),
        (b"sku", b""),
    ] {
        w.put(b":")?;
        w.put(tag)?;
        put_filtered(&mut w, v)?;
    }
    w.put(b":")?;
    Ok(w.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(b: &[u8], n: usize) -> &str {
        core::str::from_utf8(&b[..n]).unwrap()
    }

    #[test]
    fn pci_ids_merge() {
        let p = pci([
            "PCI\\VEN_10DE&DEV_28A0&SUBSYS_1F3A1043&REV_A1",
            "PCI\\VEN_10DE&DEV_28A0&SUBSYS_1F3A1043",
            "PCI\\VEN_10DE&DEV_28A0&REV_A1",
            "PCI\\VEN_10DE&DEV_28A0&CC_030000",
            "PCI\\CC_0300",
        ])
        .unwrap();
        assert_eq!(
            p,
            Pci {
                vendor: 0x10de,
                device: 0x28a0,
                subvendor: Some(0x1043),
                subdevice: Some(0x1f3a),
                class: Some(0x030000),
            }
        );
        let mut b = [0u8; 64];
        let n = pci_modalias(&p, &mut b).unwrap();
        assert_eq!(
            s(&b, n),
            "pci:v000010DEd000028A0sv00001043sd00001F3Abc03sc00i00"
        );
        assert_eq!(pci(["USB\\VID_1&PID_2", "PCI\\VEN_XYZW&DEV_0001"]), None);
    }

    #[test]
    fn usb_device_and_interface() {
        let u = usb([
            "USB\\VID_8087&PID_0033&REV_0000",
            "USB\\VID_8087&PID_0033",
            "USB\\Class_e0&SubClass_01&Prot_01",
            "USB\\Class_e0",
        ])
        .unwrap();
        assert_eq!(
            (u.vendor, u.product, u.class, u.interface),
            (0x8087, 0x33, Some(0xe0), None)
        );
        let mut b = [0u8; 80];
        let n = usb_modalias(&u, &mut b).unwrap();
        assert_eq!(
            s(&b, n),
            "usb:v8087p0033d0000dcE0dsc01dp01ic00isc00ip00in00"
        );
        let i = usb([
            "USB\\VID_046D&PID_C52B&REV_2400&MI_02",
            "USB\\Class_03&SubClass_00&Prot_00",
        ])
        .unwrap();
        assert_eq!(i.interface, Some(2));
        let n = usb_modalias(&i, &mut b).unwrap();
        assert_eq!(
            s(&b, n),
            "usb:v046DpC52Bd2400dc00dsc00dp00ic03isc00ip00in02"
        );
    }

    #[test]
    fn acpi_forms() {
        let mut o = [0u8; 8];
        assert_eq!(acpi("ACPI\\PNP0C50", &mut o), Some("PNP0C50"));
        assert_eq!(acpi("ACPI\\VEN_INT&DEV_33D2", &mut o), Some("INT33D2"));
        assert_eq!(acpi("*pnp0c0a", &mut o), Some("PNP0C0A"));
        assert_eq!(acpi("ACPI\\MSFT0101", &mut o), Some("MSFT0101"));
        assert_eq!(acpi("ACPI\\GenuineIntel_-_Intel64", &mut o), None);
        assert_eq!(acpi("ACPI_HAL\\PNP0C08", &mut o), None);
        let mut b = [0u8; 32];
        let n = acpi_modalias("PNP0C50", &mut b).unwrap();
        assert_eq!(s(&b, n), "acpi:PNP0C50:");
    }

    #[test]
    fn dmi_filtering() {
        let mut b = [0u8; 256];
        let n = dmi_modalias(
            &DmiFields {
                bios_vendor: b"LENOVO",
                bios_version: b"N3HET80W (1.52 )",
                sys_vendor: b"LENOVO",
                product_name: b"20QD:CTO 1WW",
                ..DmiFields::default()
            },
            &mut b,
        )
        .unwrap();
        assert_eq!(
            s(&b, n),
            "dmi:bvnLENOVO:bvrN3HET80W(1.52):bd:br:efr:svnLENOVO:pn20QDCTO1WW:pvr:rvn:rn:rvr:cvn:ct:cvr:sku:"
        );
    }

    #[test]
    fn nothing_panics_on_junk() {
        let mut o = [0u8; 8];
        for id in [
            "",
            "\\",
            "PCI\\",
            "PCI\\VEN_&DEV_",
            "ACPI\\VEN_ABCDEFG&DEV_12345",
            "é\\x",
        ] {
            let _ = pci([id]);
            let _ = usb([id]);
            let _ = acpi(id, &mut o);
        }
    }
}
