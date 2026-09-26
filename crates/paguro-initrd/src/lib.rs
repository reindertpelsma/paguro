//! The initrd's modules as a library: `paguro-initrd` (the binary) runs the
//! boot path, and `paguro-vm` (the VM launcher, DESIGN.md §4.5) reuses the
//! device-mapper, `/dev/paguro` and BitLocker segment-table code.

pub mod dm;
pub mod esp;
pub mod pg;
pub mod plan;
pub mod reseal;
pub mod setup;
pub mod sys;
