//! `paguro-initrd` — runs in the initrd inside the UKI.
//!
//! Responsibilities (DESIGN.md §4.3, §6):
//! - consume the loader's handoff (VMK, FVEK + layout, B, PCR values, verified
//!   `paguro.ini` bytes) from the module's one-shot interface, then wipe it;
//! - build the decrypted volume (`dm-crypt`, BitLocker's own segment layout);
//! - ask the module to export the views; run the `ntfs3` FIEMAP cross-check,
//!   which can only cause a refusal;
//! - assert the nested ESP's FAT signature before anything mounts;
//! - on a provisioning boot, write `paguro.ini`, `tpm_seal.bin` and the config
//!   hash; delete `tpm_pin_bypass_seal.bin` after use.
//!
//! Everything that is pure — table generation, layouts — lives in `plan` and is
//! unit-tested; the device-mapper ioctls and file writes are thin.

mod plan;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("plan-vmdisk") => {
            let t = plan::vm_disk_table(&plan::VmDisk {
                gpt_head: "/dev/loop0",
                esp: "/dev/loop1",
                msr: "/dev/loop2",
                volume: "/dev/mapper/paguro-b",
                gpt_tail: "/dev/loop3",
                esp_sectors: 409_600,
                msr_sectors: 32_768,
                volume_sectors: 1_000_000_000,
            });
            print!("{t}");
        }
        _ => {
            eprintln!("paguro-initrd: nothing implemented yet; try `plan-vmdisk`");
            std::process::exit(2);
        }
    }
}
