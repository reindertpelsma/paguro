//! Pure planning: device-mapper tables as text, testable without root.

use core::fmt::Write;

/// Sectors reserved for the primary GPT plus 1 MiB alignment, and for the
/// backup GPT (DESIGN.md §4.3, the dm-linear sandwich).
pub const GPT_HEAD_SECTORS: u64 = 2048;
pub const GPT_TAIL_SECTORS: u64 = 33;

pub struct VmDisk<'a> {
    pub gpt_head: &'a str,
    pub esp: &'a str,
    pub msr: &'a str,
    /// The module's protected view B.
    pub volume: &'a str,
    pub gpt_tail: &'a str,
    pub esp_sectors: u64,
    pub msr_sectors: u64,
    pub volume_sectors: u64,
}

/// The synthetic disk handed to QEMU: stock `dm-linear`, built in userspace,
/// untrusted by construction — enforcement lives beneath it, in view B.
pub fn vm_disk_table(d: &VmDisk<'_>) -> String {
    let segs = [
        (GPT_HEAD_SECTORS, d.gpt_head),
        (d.esp_sectors, d.esp),
        (d.msr_sectors, d.msr),
        (d.volume_sectors, d.volume),
        (GPT_TAIL_SECTORS, d.gpt_tail),
    ];
    let mut out = String::new();
    let mut start = 0u64;
    for (len, dev) in segs {
        let _ = writeln!(out, "{start} {len} linear {dev} 0");
        start = start.saturating_add(len);
    }
    out
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn sandwich_is_contiguous() {
        let t = vm_disk_table(&VmDisk {
            gpt_head: "h",
            esp: "e",
            msr: "m",
            volume: "v",
            gpt_tail: "t",
            esp_sectors: 10,
            msr_sectors: 20,
            volume_sectors: 30,
        });
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(lines[0], "0 2048 linear h 0");
        assert_eq!(lines[3], "2078 30 linear v 0");
        assert_eq!(lines[4], "2108 33 linear t 0");
    }
}
