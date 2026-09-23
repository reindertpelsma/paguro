//! The runtime enforcement path: a range test (DESIGN.md §4.3).
//!
//! Any read or write whose sector span intersects a protected range fails with
//! `EIO`; everything else passes through. There is deliberately nothing else in
//! the request path — no NTFS parsing, no `$Bitmap` tracking, no cryptography.
//!
//! This file is **self-contained** (no `use` of other crate modules, no
//! dependencies) because the kernel module includes it by `#[path]`: out-of-tree
//! Rust kernel modules cannot depend on crates.

/// A half-open sector range `[start, end)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extent {
    pub start: u64,
    pub end: u64,
}

impl Extent {
    /// `None` if `len` is zero or the range would overflow.
    pub const fn new(start: u64, len: u64) -> Option<Extent> {
        if len == 0 {
            return None;
        }
        match start.checked_add(len) {
            Some(end) => Some(Extent { start, end }),
            None => None,
        }
    }

    pub const fn len(&self) -> u64 {
        self.end - self.start
    }

    pub const fn is_empty(&self) -> bool {
        self.start == self.end
    }

    pub const fn intersects(&self, other: &Extent) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// Why a range set could not be built or extended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeError {
    /// More extents than the fixed capacity allows.
    Full,
    /// Growth must only append: an existing extent changed or moved (§5.6).
    NotAppendOnly,
}

/// A fixed-capacity set of protected extents, kept sorted and merged.
///
/// Fixed capacity is intentional: no allocation derived from on-disk content.
pub struct RangeSet<const N: usize> {
    extents: [Extent; N],
    count: usize,
}

impl<const N: usize> Default for RangeSet<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> RangeSet<N> {
    pub const fn new() -> Self {
        RangeSet {
            extents: [Extent { start: 0, end: 0 }; N],
            count: 0,
        }
    }

    pub fn as_slice(&self) -> &[Extent] {
        self.extents.get(..self.count).unwrap_or(&[])
    }

    /// Insert an extent, merging with neighbours that touch or overlap.
    pub fn insert(&mut self, e: Extent) -> Result<(), RangeError> {
        let mut merged = e;
        let mut out = [Extent { start: 0, end: 0 }; N];
        let mut n = 0usize;
        let mut placed = false;
        for cur in self.as_slice() {
            if cur.end < merged.start {
                *out.get_mut(n).ok_or(RangeError::Full)? = *cur;
                n += 1;
            } else if merged.end < cur.start {
                if !placed {
                    *out.get_mut(n).ok_or(RangeError::Full)? = merged;
                    n += 1;
                    placed = true;
                }
                *out.get_mut(n).ok_or(RangeError::Full)? = *cur;
                n += 1;
            } else {
                merged = Extent {
                    start: merged.start.min(cur.start),
                    end: merged.end.max(cur.end),
                };
            }
        }
        if !placed {
            *out.get_mut(n).ok_or(RangeError::Full)? = merged;
            n += 1;
        }
        self.extents = out;
        self.count = n;
        Ok(())
    }

    /// The whole enforcement decision: does `[sector, sector + count)` touch a
    /// protected extent? Zero-length and overflowing requests are refused
    /// (treated as intersecting) rather than waved through.
    pub fn blocks(&self, sector: u64, count: u64) -> bool {
        let Some(req) = Extent::new(sector, count) else {
            return true;
        };
        // Sorted and disjoint: binary search for the first extent ending after
        // the request starts.
        let s = self.as_slice();
        let idx = s.partition_point(|e| e.end <= req.start);
        s.get(idx).is_some_and(|e| e.intersects(&req))
    }
}

/// Growth check (§5.6): `next` must equal `prev` with runs appended at the end.
/// Existing extents may not change, move or reorder.
pub fn is_append_only(prev: &[Extent], next: &[Extent]) -> bool {
    next.len() >= prev.len() && next.get(..prev.len()) == Some(prev)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(ranges: &[(u64, u64)]) -> RangeSet<16> {
        let mut s = RangeSet::new();
        for &(a, l) in ranges {
            s.insert(Extent::new(a, l).unwrap()).unwrap();
        }
        s
    }

    #[test]
    fn boundaries_are_exact() {
        let s = set(&[(100, 10)]); // [100, 110)
        assert!(!s.blocks(90, 10)); // [90, 100) touches, does not overlap
        assert!(s.blocks(91, 10)); // [91, 101)
        assert!(s.blocks(109, 1));
        assert!(!s.blocks(110, 5));
        assert!(s.blocks(0, 1000)); // straddles
    }

    #[test]
    fn zero_length_and_overflow_are_refused() {
        let s = set(&[(100, 10)]);
        assert!(s.blocks(5, 0));
        assert!(s.blocks(u64::MAX, 2));
    }

    #[test]
    fn inserts_merge_and_stay_sorted() {
        let s = set(&[(50, 10), (10, 10), (20, 5), (58, 10)]);
        assert_eq!(
            s.as_slice(),
            &[Extent { start: 10, end: 25 }, Extent { start: 50, end: 68 }]
        );
    }

    #[test]
    fn capacity_is_enforced() {
        let mut s: RangeSet<2> = RangeSet::new();
        s.insert(Extent::new(0, 1).unwrap()).unwrap();
        s.insert(Extent::new(10, 1).unwrap()).unwrap();
        assert_eq!(s.insert(Extent::new(20, 1).unwrap()), Err(RangeError::Full));
    }

    #[test]
    fn append_only_growth() {
        let a = [Extent { start: 0, end: 10 }];
        let b = [Extent { start: 0, end: 10 }, Extent { start: 50, end: 60 }];
        let moved = [Extent { start: 5, end: 15 }, Extent { start: 50, end: 60 }];
        assert!(is_append_only(&a, &b));
        assert!(!is_append_only(&a, &moved));
        assert!(!is_append_only(&b, &a));
    }
}
