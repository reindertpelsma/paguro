//! `paguro-vm` — the Windows VM launcher (DESIGN.md §4.3 "View B is a
//! synthesised disk", §4.5, §5b, §5c, §6 "The VM boot"; INTERFACES.md §10,
//! §11.9).
//!
//! The pure parts — what the guest's disk looks like, the substituted
//! BitLocker metadata, the ESP, QEMU's command line — are planning code
//! with unit tests; the rest (loop devices, device-mapper, QEMU, QMP) is
//! thin glue in [`session`].

pub mod fat;
pub mod fve;
pub mod regf;
