//! Pure logic for paguro, with no dependencies and no allocation.
//!
//! Everything here is `no_std` so the same code runs in three places: the UEFI
//! loader (`paguro-efi`) and Linux/Windows userspace, and [`range`] is the
//! specification the C kernel module is differential-tested against. That is the point of
//! the crate: the parts that decide whether a disk survives are ordinary
//! functions over byte slices, testable on every push (DESIGN.md §5.5).
//!
//! Modules map onto the design:
//!
//! | module      | design section                                   |
//! |-------------|--------------------------------------------------|
//! | [`range`]   | §4.3 — the runtime range test, the whole enforcement path |
//! | [`runlist`] | §4.3 — the one NTFS parse at module load         |
//! | [`vhd`]     | §2 — fixed-VHD image files                       |
//! | [`disk`]    | §2 — disk format detection, finding the FAT32    |
//! | [`edid`]    | §13.2a — a display's preferred resolution        |
//! | [`fat`]     | §4.2 — read-only FAT32 directories (recovery browser, tier 2) |
//! | [`ini`]     | §6 — the frozen `paguro.ini` grammar             |
//! | [`seal`]    | §6 — the `*_seal.bin` file layouts               |
//! | [`fve`]     | §6 — bounded walk over BitLocker FVE metadata    |
//! | [`bde`]     | §6 — BitLocker volume header, metadata cross-check, protectors, sector map |
//! | [`efisig`]  | §11.6 — `EFI_SIGNATURE_LIST` (`MokNew`, `db`, `MokListRT`) |
//! | [`smbios`]  | §11.5 — the DMI strings of the host-hardware export |
//! | [`hwid`]    | §11.5 — Windows hardware IDs → PCI/USB/ACPI identities and Linux modaliases |
//! | [`recorded`] | §4.6 — what Linux recorded for the pre-flight (PROPOSED) |
//! | [`tcglog`]  | §4.6 — the TCG event log's PCR 7 driver-config prefix (pre-flight) |
#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::indexing_slicing))]

pub mod bde;
pub mod bootstrap;
pub mod bytes;
pub mod config;
pub mod disk;
pub mod edid;
pub mod efisig;
pub mod fat;
pub mod fve;
pub mod gpt;
pub mod guid;
pub mod handoff;
pub mod hwid;
pub mod ini;
pub mod ntfs;
pub mod range;
pub mod recorded;
pub mod runlist;
pub mod seal;
pub mod smbios;
pub mod tcglog;
pub mod tpm;
pub mod vhd;
