//! Differential: the kernel module's C core against the Rust specification
//! on the same sparse volume — same result, same error, same sector reads —
//! plus the runlist decoder, payload check and claim checks on raw bytes.
#![no_main]

#[path = "../../crates/paguro-harness/src/cntfs.rs"]
#[allow(dead_code)]
mod cntfs;

use libfuzzer_sys::fuzz_target;
use paguro_core::ntfs;
use paguro_core::range::Extent;

fuzz_target!(|data: &[u8]| {
    let Some((rec, seq, _)) = cntfs::SparseDisk::parse(data) else {
        return;
    };
    let disk = || {
        cntfs::SparseDisk::parse(data)
            .map(|p| p.2)
            .unwrap_or(cntfs::SparseDisk { entries: vec![] })
    };
    let mut d = disk();
    let mut t = cntfs::Trace {
        inner: &mut d,
        reads: vec![],
    };
    let r = cntfs::rust_file(&mut t, rec, seq);
    let rr = t.reads;
    let mut d = disk();
    let mut t = cntfs::Trace {
        inner: &mut d,
        reads: vec![],
    };
    let c = cntfs::c_file(&mut t, rec, seq);
    assert_eq!(r, c, "file result");
    assert_eq!(rr, t.reads, "sector reads");
    assert_eq!(
        cntfs::rust_flags(&mut disk()),
        cntfs::c_flags(&mut disk()),
        "volume flags"
    );

    let body = data.get(8..).unwrap_or(&[]);
    assert_eq!(
        cntfs::rust_runlist(body, 64),
        cntfs::c_runlist(body, 64),
        "runlist"
    );

    // Claim checks on extents read straight from the input.
    let ext: Vec<Extent> = body
        .chunks_exact(4)
        .take(16)
        .map(|c| {
            let s = u64::from(u16::from_le_bytes([c[0], c[1]]));
            Extent {
                start: s,
                end: s + u64::from(c[2] % 16),
            }
        })
        .collect();
    let (a, b) = ext.split_at(ext.len() / 2);
    let mut out = vec![Extent { start: 0, end: 0 }; a.len()];
    let rn = ntfs::normalise(a, &mut out)
        .map(|n| out[..n].to_vec())
        .map_err(|e| e.code());
    assert_eq!(rn, cntfs::c_normalise(a, a.len()), "normalise");
    let (na, nb) = (cntfs::c_range_normalise(a), cntfs::c_range_normalise(b));
    assert_eq!(
        ntfs::intersects(&na, &nb),
        cntfs::c_intersects(&na, &nb),
        "intersects"
    );
    assert_eq!(ntfs::grows(a, b), cntfs::c_grows(a, b), "grows");
    let mut c2 = a.to_vec();
    assert_eq!(
        ntfs::coalesce(&mut c2).map(|n| c2[..n].to_vec()),
        cntfs::c_coalesce(a),
        "coalesce"
    );
    let l = u64::from(data[6]);
    assert_eq!(ntfs::gather(a, l), cntfs::c_gather(a, l), "gather");
});
