//! `paguro-vm` — the Windows VM launcher (DESIGN.md §4.3 "View B is a
//! synthesised disk", §4.5, §4.7, §5b, §5c, §6 "The VM boot";
//! INTERFACES.md §10, §11.9).
//!
//! The pure parts — what the guest's disk looks like, the substituted
//! BitLocker metadata, the ESP and its BCD, the host's identity, QEMU's
//! command line, the private link's configuration — are planning code with
//! unit tests; the rest (loop devices, device-mapper, QEMU, QMP) is thin
//! glue in [`session`].

pub mod disk;
pub mod esp;
pub mod fat;
pub mod fve;
pub mod gpu;
pub mod identity;
pub mod loopdev;
pub mod mem;
pub mod net;
pub mod qemu;
pub mod qmp;
pub mod rdp;
pub mod regf;
pub mod session;
