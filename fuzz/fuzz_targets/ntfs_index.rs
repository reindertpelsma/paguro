//! The loader's NTFS index-node parser (`ntfs::dir::node_entries`) and the
//! file-name collation over arbitrary node bytes: no panic, every entry
//! inside the node, names within 255 units, the walk ends.
#![no_main]

use libfuzzer_sys::fuzz_target;
use paguro_core::ntfs::dir::{self, UPCASE_LEN};
use std::sync::OnceLock;

fn upcase() -> &'static [u16; UPCASE_LEN] {
    static U: OnceLock<Box<[u16; UPCASE_LEN]>> = OnceLock::new();
    U.get_or_init(|| {
        let mut t = Box::new([0u16; UPCASE_LEN]);
        for (i, u) in t.iter_mut().enumerate() {
            let c = i as u16;
            *u = if (u16::from(b'a')..=u16::from(b'z')).contains(&c) { c - 32 } else { c };
        }
        t
    })
}

fuzz_target!(|data: &[u8]| {
    let (key, node) = data.split_at(data.len().min(16));
    let key: Vec<u16> = key.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let mut n = 0usize;
    let _ = dir::node_entries(node, |e| {
        n += 1;
        assert!(n <= node.len() / 16 + 1);
        if let Some(k) = e.key {
            assert!(!k.name.is_empty() && k.name.len() <= dir::MAX_NAME);
            let a = dir::collate(upcase(), &key, k.name);
            let b = dir::collate(upcase(), k.name, &key);
            assert_eq!(a, b.reverse());
        }
        Ok(true)
    });
});
