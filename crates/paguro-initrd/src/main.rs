//! `paguro-initrd` — runs in the initramfs, before the root is mounted.
//!
//! ```text
//! paguro-initrd systab             the EFI system table's address, for
//!                                  `modprobe paguro-handoff systab=`
//! paguro-initrd setup [--env F] [--handoff DEV] [--wait S] [--no-esp]
//!                                  the boot path (below); writes F
//!                                  (default /run/paguro/root.env)
//! paguro-initrd status             /dev/paguro's volumes and claims
//! paguro-initrd plan-vmdisk        the VM disk sandwich (example)
//! ```
//!
//! `setup` (DESIGN.md §4.3, §6; INTERFACES.md §5, §8, §10): reads the
//! loader's handoff once from `/dev/paguro-handoff` (kernel/paguro-handoff)
//! and wipes it; builds the decrypted volume with BitLocker's own segment
//! table (`dm-crypt` keyed through a kernel `logon` key, never a table
//! string), or passes an unencrypted volume through; registers it with
//! `dm-paguro` (`PG_VOLUME_ADD` with the FVE regions reserved); probes the
//! chosen entry's disks on a read-only `ntfs3` (identity by MFT record and
//! sequence, VHD footer, FIEMAP), claims them (`PG_CLAIM`) and
//! cross-checks (`PG_CROSSCHECK`, which can only refuse); loads view A,
//! where the module asserts the payload's structure before anything can
//! mount it; exposes a GPT's partitions (dm-linear) or a bare file system,
//! read-only when the volume is dirty or hibernated; and records the
//! loader's PCR values on the ESP (`recorded.bin`), writing `paguro.ini`,
//! `PaguroConfigHash` and `tpm_seal.bin` on a provisioning boot.
//!
//! Everything that is pure — tables, layouts, root choice — lives in
//! `plan` and is unit-tested; the rest is thin system-call glue.

mod dm;
mod esp;
mod pg;
mod plan;
mod setup;
mod sys;

use std::path::PathBuf;
use std::time::Duration;

fn usage() -> ! {
    eprintln!(
        "usage: paguro-initrd systab | setup [--env FILE] [--handoff DEV] [--wait SECS] [--no-esp] | status | plan-vmdisk"
    );
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let r = match args.get(1).map(String::as_str) {
        Some("systab") => setup::systab().map(|a| println!("{a:#x}")),
        Some("status") => setup::status().map(|s| print!("{s}")),
        Some("setup") => {
            let mut o = setup::Opts {
                handoff: PathBuf::from(setup::HANDOFF_DEV),
                env: PathBuf::from("/run/paguro/root.env"),
                wait: Duration::from_secs(30),
                root_hint: setup::cmdline_arg("paguro.root"),
                esp: true,
            };
            let mut it = args.iter().skip(2);
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--env" => o.env = it.next().map(PathBuf::from).unwrap_or_else(|| usage()),
                    "--handoff" => {
                        o.handoff = it.next().map(PathBuf::from).unwrap_or_else(|| usage())
                    }
                    "--wait" => {
                        o.wait = Duration::from_secs(
                            it.next()
                                .and_then(|s| s.parse().ok())
                                .unwrap_or_else(|| usage()),
                        )
                    }
                    "--no-esp" => o.esp = false,
                    _ => usage(),
                }
            }
            setup::run(&o)
        }
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
            Ok(())
        }
        _ => usage(),
    };
    if let Err(e) = r {
        setup::log(&format!("error: {e}"));
        std::process::exit(1);
    }
}
