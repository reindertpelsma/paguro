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
//! | [`ini`]     | §6 — the frozen `paguro.ini` grammar             |
//! | [`seal`]    | §6 — the `*_seal.bin` file layouts               |
//! | [`fve`]     | §6 — bounded walk over BitLocker FVE metadata    |
#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::indexing_slicing))]

pub mod bootstrap;
pub mod bytes;
pub mod config;
pub mod fve;
pub mod gpt;
pub mod guid;
pub mod handoff;
pub mod ini;
pub mod ntfs;
pub mod range;
pub mod runlist;
pub mod seal;
pub mod tpm;
pub mod vhd;
