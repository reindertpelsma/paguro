//! Differential test: the kernel module's C range logic against the Rust spec.

use paguro_core::range::{Extent, RangeSet};

#[repr(C)]
#[derive(Clone, Copy)]
struct PgExtent {
    start: u64,
    end: u64,
}

unsafe extern "C" {
    fn pg_range_normalise(e: *mut PgExtent, n: usize) -> usize;
    fn pg_range_blocks(e: *const PgExtent, n: usize, sector: u64, count: u64) -> i32;
}

struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

pub fn check(rounds: u64, seed: u64) -> Result<(), String> {
    let mut rng = XorShift(seed | 1);
    for round in 0..rounds {
        let mut spec: RangeSet<64> = RangeSet::new();
        let mut c: Vec<PgExtent> = Vec::new();
        for _ in 0..1 + rng.below(8) {
            let (s, l) = (rng.below(1000), 1 + rng.below(50));
            if let Some(e) = Extent::new(s, l) {
                spec.insert(e).map_err(|e| format!("insert: {e:?}"))?;
                c.push(PgExtent {
                    start: s,
                    end: s + l,
                });
            }
        }
        // SAFETY: `c` is a valid, initialised buffer of `c.len()` extents.
        let n = unsafe { pg_range_normalise(c.as_mut_ptr(), c.len()) };
        let norm = c.get(..n).ok_or("normalise returned too many")?;
        let as_spec: Vec<Extent> = norm
            .iter()
            .map(|e| Extent {
                start: e.start,
                end: e.end,
            })
            .collect();
        if as_spec != spec.as_slice() {
            return Err(format!("round {round}: normalise differs"));
        }
        for _ in 0..16 {
            let (s, l) = match rng.below(20) {
                0 => (u64::MAX - rng.below(4), 1 + rng.below(8)), // overflow edge
                _ => (rng.below(1100), rng.below(60)),
            };
            // SAFETY: `norm` is a valid normalised slice.
            let got = unsafe { pg_range_blocks(norm.as_ptr(), norm.len(), s, l) } != 0;
            if got != spec.blocks(s, l) {
                return Err(format!("round {round}: request ({s}, {l}): C={got}"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn c_matches_rust_spec() {
        super::check(50_000, 7).unwrap();
    }
}
