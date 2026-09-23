//! Model check: `RangeSet::blocks` against a brute-force oracle.

use paguro_core::range::{Extent, RangeSet};

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
        let mut set: RangeSet<64> = RangeSet::new();
        let mut raw: Vec<(u64, u64)> = Vec::new();
        for _ in 0..rng.below(8) {
            let (s, l) = (rng.below(1000), 1 + rng.below(50));
            if let Some(e) = Extent::new(s, l) {
                set.insert(e).map_err(|e| format!("insert: {e:?}"))?;
                raw.push((s, s + l));
            }
        }
        for _ in 0..16 {
            let (s, l) = (rng.below(1100), rng.below(60));
            let oracle = l == 0 || raw.iter().any(|&(a, b)| s < b && a < s + l);
            if set.blocks(s, l) != oracle {
                return Err(format!("round {round}: request ({s}, {l}) vs {raw:?}"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    #[test]
    fn range_test_matches_oracle() {
        super::check(20_000, 42).unwrap();
    }
}
