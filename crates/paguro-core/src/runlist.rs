//! NTFS mapping-pairs ("runlist") decoding — the one NTFS parse the kernel
//! module performs, once, at load (DESIGN.md §4.3).
//!
//! The input is attacker-authorable (an untrusted guest may have written it), so
//! the decoder is strict: fixed output capacity, every read bounds-checked,
//! sparse runs and arithmetic overflow rejected rather than tolerated.

/// One run in clusters: `count` clusters starting at logical cluster `lcn`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Run {
    pub lcn: u64,
    pub count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunlistError {
    Truncated,
    /// A length or offset field wider than 8 bytes.
    FieldTooWide,
    /// Offset field of zero width: a sparse run. Images must be fully allocated.
    Sparse,
    ZeroLength,
    NegativeLcn,
    Overflow,
    TooManyRuns,
    /// No terminating zero header before the end of the attribute.
    Unterminated,
}

fn read_le(bytes: &[u8], signed: bool) -> Option<i128> {
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    let mut v: u64 = 0;
    for (i, b) in bytes.iter().enumerate() {
        v |= u64::from(*b) << (8 * i);
    }
    let bits = 8 * bytes.len() as u32;
    if signed && bits < 64 && (v >> (bits - 1)) & 1 == 1 {
        // sign-extend
        v |= u64::MAX << bits;
        return Some(i128::from(v as i64));
    }
    Some(if signed {
        i128::from(v as i64)
    } else {
        i128::from(v)
    })
}

/// Decode a mapping-pairs array into `out`, returning the number of runs.
pub fn decode(input: &[u8], out: &mut [Run]) -> Result<usize, RunlistError> {
    let mut pos = 0usize;
    let mut lcn: i128 = 0;
    let mut n = 0usize;
    loop {
        let header = *input.get(pos).ok_or(RunlistError::Unterminated)?;
        if header == 0 {
            return Ok(n);
        }
        pos += 1;
        let len_sz = usize::from(header & 0x0f);
        let off_sz = usize::from(header >> 4);
        if len_sz == 0 || len_sz > 8 || off_sz > 8 {
            return Err(RunlistError::FieldTooWide);
        }
        if off_sz == 0 {
            return Err(RunlistError::Sparse);
        }
        let len_end = pos.checked_add(len_sz).ok_or(RunlistError::Overflow)?;
        let len_bytes = input.get(pos..len_end).ok_or(RunlistError::Truncated)?;
        pos = len_end;
        let off_end = pos.checked_add(off_sz).ok_or(RunlistError::Overflow)?;
        let off_bytes = input.get(pos..off_end).ok_or(RunlistError::Truncated)?;
        pos = off_end;

        let count = read_le(len_bytes, false).ok_or(RunlistError::Truncated)?;
        if count <= 0 {
            return Err(RunlistError::ZeroLength);
        }
        let delta = read_le(off_bytes, true).ok_or(RunlistError::Truncated)?;
        lcn = lcn.checked_add(delta).ok_or(RunlistError::Overflow)?;
        if lcn < 0 {
            return Err(RunlistError::NegativeLcn);
        }
        let run = Run {
            lcn: u64::try_from(lcn).map_err(|_| RunlistError::Overflow)?,
            count: u64::try_from(count).map_err(|_| RunlistError::Overflow)?,
        };
        run.lcn
            .checked_add(run.count)
            .ok_or(RunlistError::Overflow)?;
        *out.get_mut(n).ok_or(RunlistError::TooManyRuns)? = run;
        n += 1;
    }
}

/// Total clusters across runs — must equal the allocated size recorded in the
/// MFT record, or the map is refused (§4.3, "allocated == sum(extents)").
pub fn total_clusters(runs: &[Run]) -> Option<u64> {
    runs.iter()
        .try_fold(0u64, |acc, r| acc.checked_add(r.count))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_delta_encoded_runs() {
        // run 1: len 0x18 @ LCN 0x5634; run 2: len 0x10 @ +0x100 (0x5734);
        // run 3: len 0x08 @ -0x1000 (0x4734).
        let data = [
            0x21, 0x18, 0x34, 0x56, //
            0x21, 0x10, 0x00, 0x01, //
            0x21, 0x08, 0x00, 0xf0, //
            0x00,
        ];
        let mut out = [Run { lcn: 0, count: 0 }; 8];
        let n = decode(&data, &mut out).unwrap();
        assert_eq!(n, 3);
        assert_eq!(
            out[0],
            Run {
                lcn: 0x5634,
                count: 0x18
            }
        );
        assert_eq!(
            out[1],
            Run {
                lcn: 0x5734,
                count: 0x10
            }
        );
        assert_eq!(
            out[2],
            Run {
                lcn: 0x4734,
                count: 0x08
            }
        );
        assert_eq!(total_clusters(&out[..n]), Some(0x30));
    }

    #[test]
    fn rejects_sparse_truncated_and_unterminated() {
        let mut out = [Run { lcn: 0, count: 0 }; 4];
        assert_eq!(
            decode(&[0x01, 0x10, 0x00], &mut out),
            Err(RunlistError::Sparse)
        );
        assert_eq!(
            decode(&[0x21, 0x10], &mut out),
            Err(RunlistError::Truncated)
        );
        assert_eq!(
            decode(&[0x11, 0x10, 0x05], &mut out),
            Err(RunlistError::Unterminated)
        );
        assert_eq!(
            decode(&[0x11, 0x00, 0x05, 0], &mut out),
            Err(RunlistError::ZeroLength)
        );
    }

    #[test]
    fn rejects_negative_lcn_and_capacity() {
        let mut out = [Run { lcn: 0, count: 0 }; 1];
        assert_eq!(
            decode(&[0x11, 0x01, 0xff, 0], &mut out),
            Err(RunlistError::NegativeLcn)
        );
        let two = [0x11, 0x01, 0x05, 0x11, 0x01, 0x05, 0x00];
        assert_eq!(decode(&two, &mut out), Err(RunlistError::TooManyRuns));
    }
}
