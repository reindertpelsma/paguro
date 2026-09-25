//! Host identity passthrough (DESIGN.md §4.5, §11 Q32): the VM carries the
//! machine's own identity, so an OEM or digital licence sees the machine it
//! was activated on.
//!
//! - the host's **whole SMBIOS table** (`/sys/firmware/dmi/tables/DMI`)
//!   passed as QEMU `-smbios file=`, with paguro's type 11 marker
//!   `paguro-vm/1` appended (the minifilter's "this is the VM" signal,
//!   §4.4) and the end-of-table structure left to QEMU;
//! - QEMU's `-uuid` set to the type 1 UUID in that table;
//! - the firmware licence tables MSDM and SLIC as `-acpitable file=`;
//! - the system disk's serial number and the host NIC's MAC address.
//!
//! Parsing is bounded like every other parser here: structure lengths are
//! checked against the table, strings end inside it, at most
//! [`MAX_STRUCTURES`] are walked.

use std::fs;
use std::path::{Path, PathBuf};

/// The marker the minifilter looks for (windows/minifilter/pg_smbios.c).
pub const MARKER: &str = "paguro-vm/1";
pub const MAX_TABLE: usize = 1 << 20;
pub const MAX_STRUCTURES: usize = 4096;
const TYPE_SYSTEM: u8 = 1;
const TYPE_OEM_STRINGS: u8 = 11;
const TYPE_END: u8 = 127;
const HEADER: usize = 4;
/// Type 1: UUID at formatted offset 8, 16 bytes (SMBIOS 2.1+).
const SYSTEM_UUID_AT: usize = 8;
const SYSTEM_UUID_END: usize = SYSTEM_UUID_AT + 16;
/// Type 11's formatted part: header and the string count.
const OEM_STRINGS_LEN: u8 = 5;
/// QEMU caps a disk's serial at 20 characters (ATA, NVMe, virtio-blk).
pub const SERIAL_MAX: usize = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmbiosError {
    TooLarge,
    Truncated,
    BadLength,
    TooMany,
}

impl core::fmt::Display for SmbiosError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SMBIOS table: {self:?}")
    }
}

/// One structure's span in the table: `[start, end)`, and its type and
/// handle.
struct Structure {
    ty: u8,
    handle: u16,
    start: usize,
    formatted_end: usize,
    end: usize,
}

fn walk(t: &[u8]) -> Result<Vec<Structure>, SmbiosError> {
    if t.len() > MAX_TABLE {
        return Err(SmbiosError::TooLarge);
    }
    let mut out = Vec::new();
    let mut at = 0;
    while at < t.len() {
        if out.len() >= MAX_STRUCTURES {
            return Err(SmbiosError::TooMany);
        }
        let Some(&[ty, len, h0, h1]) = t.get(at..at + HEADER) else {
            return Err(SmbiosError::Truncated);
        };
        let len = usize::from(len);
        let handle = u16::from_le_bytes([h0, h1]);
        if len < HEADER {
            return Err(SmbiosError::BadLength);
        }
        let formatted_end = at + len;
        if formatted_end > t.len() {
            return Err(SmbiosError::Truncated);
        }
        // Strings: NUL-terminated, the set ends with a second NUL (an
        // empty set is two NULs).
        let rest = t.get(formatted_end..).ok_or(SmbiosError::Truncated)?;
        let end = rest
            .windows(2)
            .position(|w| w == [0, 0])
            .map(|p| formatted_end + p + 2)
            .ok_or(SmbiosError::Truncated)?;
        out.push(Structure {
            ty,
            handle,
            start: at,
            formatted_end,
            end,
        });
        if ty == TYPE_END {
            break;
        }
        at = end;
    }
    Ok(out)
}

/// The table QEMU is given: every structure of the host's but the
/// end-of-table, then a type 11 carrying `marker`. And the type 1 UUID.
pub fn smbios_blob(table: &[u8], marker: &str) -> Result<(Vec<u8>, Option<[u8; 16]>), SmbiosError> {
    let s = walk(table)?;
    let mut out = Vec::with_capacity(table.len() + 32);
    let mut uuid = None;
    let mut max_handle = 0u16;
    for x in &s {
        if x.ty == TYPE_END {
            continue;
        }
        max_handle = max_handle.max(x.handle);
        out.extend_from_slice(table.get(x.start..x.end).ok_or(SmbiosError::Truncated)?);
        if x.ty == TYPE_SYSTEM && x.formatted_end - x.start >= SYSTEM_UUID_END {
            let u: [u8; 16] = table
                .get(x.start + SYSTEM_UUID_AT..x.start + SYSTEM_UUID_END)
                .and_then(|b| b.try_into().ok())
                .ok_or(SmbiosError::Truncated)?;
            // All zeros: not present; all ones: not set (DSP0134 7.2.1).
            if u != [0; 16] && u != [0xFF; 16] {
                uuid = Some(u);
            }
        }
    }
    let handle = max_handle.checked_add(1).ok_or(SmbiosError::TooMany)?;
    out.extend_from_slice(&[TYPE_OEM_STRINGS, OEM_STRINGS_LEN]);
    out.extend_from_slice(&handle.to_le_bytes());
    out.push(1);
    out.extend_from_slice(marker.as_bytes());
    out.extend_from_slice(&[0, 0]);
    Ok((out, uuid))
}

/// SMBIOS 2.6+ UUID bytes as text: the first three fields little-endian,
/// the order Windows (and `dmidecode`) prints.
pub fn uuid_text(u: &[u8; 16]) -> String {
    let t = paguro_core::guid::Guid(*u).to_text();
    String::from_utf8_lossy(&t).into_owned()
}

/// What the host gives the VM, read from sysfs (`root` is `/` outside
/// tests).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostIdentity {
    /// The `-smbios file=` blob (marker included).
    pub smbios: Vec<u8>,
    /// The host's entry point is SMBIOS 3 (`_SM3_`): use the 64-bit one.
    pub smbios3: bool,
    pub uuid: Option<String>,
    /// MSDM and SLIC, when the firmware has them.
    pub acpi_tables: Vec<PathBuf>,
    pub mac: Option<String>,
    pub disk_serial: Option<String>,
    /// What could not be read, for the log.
    pub missing: Vec<String>,
}

/// The interface of the default IPv4 route (`/proc/net/route`).
fn default_iface(route: &str) -> Option<String> {
    route.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        (f.get(1) == Some(&"00000000") && f.get(7) == Some(&"00000000"))
            .then(|| f.first().map(|s| s.to_string()))?
    })
}

fn valid_mac(m: &str) -> bool {
    let parts: Vec<&str> = m.split(':').collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
        && m != "00:00:00:00:00:00"
}

/// The serial of the disk holding `partition` (a block device name such as
/// `nvme0n1p3`, `sda3` or `vda3`), from sysfs.
fn disk_serial(root: &Path, partition: &str) -> Option<String> {
    let class = root.join("sys/class/block").join(partition);
    let real = fs::canonicalize(&class).ok()?;
    // A partition's directory sits inside its disk's.
    let disk = if real.join("partition").exists() {
        real.parent()?.to_path_buf()
    } else {
        real
    };
    for f in ["device/serial", "serial", "device/vpd_pg80"] {
        if let Ok(b) = fs::read(disk.join(f)) {
            let s: String = if f.ends_with("vpd_pg80") {
                // VPD page 0x80: 4-byte header, then the serial.
                b.get(4..)
                    .unwrap_or(&[])
                    .iter()
                    .map(|&c| char::from(c))
                    .collect()
            } else {
                String::from_utf8_lossy(&b).into_owned()
            };
            let s = s.trim().trim_matches(char::from(0)).to_string();
            if !s.is_empty() && s.is_ascii() {
                return Some(s.chars().take(SERIAL_MAX).collect());
            }
        }
    }
    None
}

pub fn read_host(root: &Path, system_partition: Option<&str>, marker: &str) -> HostIdentity {
    let mut id = HostIdentity::default();
    let dmi = root.join("sys/firmware/dmi/tables/DMI");
    match fs::read(&dmi)
        .map_err(|e| e.to_string())
        .and_then(|t| smbios_blob(&t, marker).map_err(|e| e.to_string()))
    {
        Ok((blob, uuid)) => {
            id.smbios = blob;
            id.uuid = uuid.as_ref().map(uuid_text);
        }
        Err(e) => {
            id.missing.push(format!("SMBIOS ({}): {e}", dmi.display()));
            // The marker alone.
            id.smbios = smbios_blob(&[], marker).map(|(b, _)| b).unwrap_or_default();
        }
    }
    id.smbios3 = fs::read(root.join("sys/firmware/dmi/tables/smbios_entry_point"))
        .is_ok_and(|e| e.starts_with(b"_SM3_"));
    for t in ["MSDM", "SLIC"] {
        let p = root.join("sys/firmware/acpi/tables").join(t);
        if p.is_file() {
            id.acpi_tables.push(p);
        } else {
            id.missing.push(format!("ACPI {t}"));
        }
    }
    let iface = fs::read_to_string(root.join("proc/net/route"))
        .ok()
        .and_then(|r| default_iface(&r));
    id.mac = iface.and_then(|i| {
        fs::read_to_string(root.join("sys/class/net").join(i).join("address"))
            .ok()
            .map(|m| m.trim().to_ascii_lowercase())
            .filter(|m| valid_mac(m))
    });
    if id.mac.is_none() {
        id.missing.push("MAC of the default-route interface".into());
    }
    id.disk_serial = system_partition.and_then(|p| disk_serial(root, p));
    if id.disk_serial.is_none() {
        id.missing.push("system disk serial".into());
    }
    id
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn st(ty: u8, handle: u16, formatted: &[u8], strings: &[&str]) -> Vec<u8> {
        let mut v = vec![ty, (HEADER + formatted.len()) as u8];
        v.extend(handle.to_le_bytes());
        v.extend(formatted);
        if strings.is_empty() {
            v.extend([0, 0]);
        } else {
            for s in strings {
                v.extend(s.as_bytes());
                v.push(0);
            }
            v.push(0);
        }
        v
    }

    fn table() -> Vec<u8> {
        let mut t = st(0, 0, &[1, 2, 0, 0xf0, 3, 0], &["LENOVO", "N3HET"]);
        let mut sys = vec![1, 2, 3, 4];
        sys.extend([
            0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]);
        sys.extend([6, 5, 6]);
        t.extend(st(
            1,
            1,
            &sys,
            &["LENOVO", "20XW", "1.0", "PF2ABCDE", "SKU", "ThinkPad"],
        ));
        t.extend(st(11, 7, &[1], &["vendor"]));
        t.extend(st(127, 0x20, &[], &[]));
        t
    }

    #[test]
    fn blob_keeps_everything_adds_the_marker() {
        let t = table();
        let (b, uuid) = smbios_blob(&t, MARKER).unwrap();
        let s = walk(&b).unwrap();
        let types: Vec<u8> = s.iter().map(|x| x.ty).collect();
        assert_eq!(types, [0, 1, 11, 11]);
        let last = s.last().unwrap();
        assert_eq!(last.handle, 8);
        assert_eq!(&b[last.formatted_end..last.end], b"paguro-vm/1\0\0");
        // everything before is the host's, byte for byte
        let end_at = t.len() - 6;
        assert_eq!(&b[..end_at], &t[..end_at]);
        assert_eq!(
            uuid_text(&uuid.unwrap()),
            "00112233-4455-6677-8899-aabbccddeeff"
        );
    }

    #[test]
    fn no_uuid_when_unset() {
        let mut t = table();
        // zero the UUID
        let at = t.iter().position(|&x| x == 0x33).unwrap();
        t[at..at + 16].fill(0xff);
        assert_eq!(smbios_blob(&t, MARKER).unwrap().1, None);
        // an empty table still gets the marker
        let (b, u) = smbios_blob(&[], MARKER).unwrap();
        assert_eq!(u, None);
        assert_eq!(b[0], 11);
    }

    #[test]
    fn hostile_tables() {
        assert_eq!(
            smbios_blob(&[1, 2, 0, 0], MARKER).unwrap_err(),
            SmbiosError::BadLength
        );
        assert_eq!(
            smbios_blob(&[1, 30, 0, 0, 0, 0], MARKER).unwrap_err(),
            SmbiosError::Truncated
        );
        assert_eq!(
            smbios_blob(&[1, 4, 0, 0, b'x'], MARKER).unwrap_err(),
            SmbiosError::Truncated
        );
        let mut many = Vec::new();
        for _ in 0..=MAX_STRUCTURES {
            many.extend([2u8, 4, 0, 0, 0, 0]);
        }
        assert_eq!(
            smbios_blob(&many, MARKER).unwrap_err(),
            SmbiosError::TooMany
        );
        // arbitrary bytes never panic
        let mut x = 0x1234_5678u32;
        for _ in 0..2000 {
            let n = (x % 64) as usize;
            let v: Vec<u8> = (0..n)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    x as u8
                })
                .collect();
            let _ = smbios_blob(&v, MARKER);
        }
    }

    #[test]
    fn host_from_a_fake_sysfs() {
        let r = std::env::temp_dir().join(format!("paguro-vm-id-{}", std::process::id()));
        let mk = |p: &str, d: &[u8]| {
            let p = r.join(p);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, d).unwrap();
        };
        mk("sys/firmware/dmi/tables/DMI", &table());
        mk("sys/firmware/dmi/tables/smbios_entry_point", b"_SM3_xxxx");
        mk("sys/firmware/acpi/tables/MSDM", b"MSDM....");
        mk(
            "proc/net/route",
            b"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
              wlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\n\
              wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\n",
        );
        mk("sys/class/net/wlan0/address", b"A4:B1:C1:00:11:22\n");
        mk(
            "sys/devices/pci0/nvme/nvme0/nvme0n1/serial",
            b"S4EWNX0R123456789012345\n",
        );
        mk(
            "sys/devices/pci0/nvme/nvme0/nvme0n1/nvme0n1p3/partition",
            b"3",
        );
        fs::create_dir_all(r.join("sys/class/block")).unwrap();
        std::os::unix::fs::symlink(
            r.join("sys/devices/pci0/nvme/nvme0/nvme0n1/nvme0n1p3"),
            r.join("sys/class/block/nvme0n1p3"),
        )
        .unwrap();
        let id = read_host(&r, Some("nvme0n1p3"), MARKER);
        let _ = fs::remove_dir_all(&r);
        assert!(id.smbios3);
        assert_eq!(
            id.uuid.as_deref(),
            Some("00112233-4455-6677-8899-aabbccddeeff")
        );
        assert_eq!(id.acpi_tables.len(), 1);
        assert_eq!(id.mac.as_deref(), Some("a4:b1:c1:00:11:22"));
        assert_eq!(id.disk_serial.as_deref(), Some("S4EWNX0R123456789012"));
        assert_eq!(id.missing, ["ACPI SLIC"]);
    }
}
