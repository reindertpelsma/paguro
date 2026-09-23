// SPDX-License-Identifier: GPL-2.0

//! paguro — the single enforcement point (DESIGN.md §4.3).
//!
//! The only component we write that can corrupt a disk. Its whole runtime job:
//!
//!   read  intersecting a protected range -> EIO
//!   write intersecting a protected range -> EIO
//!   everything else                      -> pass through
//!
//! No cipher, no key, no NTFS parsing in the request path. One NTFS parse at
//! load (and one per growth event), done over the decrypted volume userspace
//! built; `ntfs3`'s FIEMAP is a cross-check that can only cause refusal.
//!
//! The range logic is shared with userspace and unit-tested there: it is
//! included by path because out-of-tree Rust modules cannot depend on crates.

use kernel::prelude::*;

#[path = "../../crates/paguro-core/src/range.rs"]
#[allow(dead_code)]
mod range;

module! {
    type: Paguro,
    name: "paguro",
    authors: ["paguro contributors"],
    description: "paguro: protected block views over an NTFS volume",
    license: "GPL",
}

struct Paguro;

impl kernel::Module for Paguro {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        // Not implemented: exporting views needs a way to forward bios to the
        // underlying device, which upstream Rust block abstractions do not yet
        // provide (see README.md). Until then this only proves the build.
        let mut set: range::RangeSet<4> = range::RangeSet::new();
        if let Some(e) = range::Extent::new(100, 10) {
            let _ = set.insert(e);
        }
        pr_info!("paguro: loaded (skeleton); self-test blocks={}\n", set.blocks(105, 1));
        Ok(Paguro)
    }
}
