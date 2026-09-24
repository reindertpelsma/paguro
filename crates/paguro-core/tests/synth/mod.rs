//! Synthetic NTFS volumes: just the structures `paguro_core::ntfs` and
//! `pg_ntfs.c` read (boot sector, FILE records with update sequences,
//! attributes, runlists, attribute lists), laid out byte by byte so every
//! field can be broken on purpose. Shared by the core's unit tests, the
//! harness's differential tests and the fuzz seed generator.
#![allow(dead_code, clippy::indexing_slicing)]

use std::collections::BTreeMap;

use paguro_core::ntfs::{Disk, IoError};

/// A volume image in memory; reads past the end fail.
#[derive(Clone)]
pub struct Mem(pub Vec<u8>);

impl Disk for Mem {
    fn read(&mut self, sector: u64, buf: &mut [u8; 512]) -> Result<(), IoError> {
        let at = usize::try_from(sector).map_err(|_| IoError)?;
        let src = at
            .checked_mul(512)
            .and_then(|o| self.0.get(o..o + 512))
            .ok_or(IoError)?;
        buf.copy_from_slice(src);
        Ok(())
    }
}

pub fn put(b: &mut [u8], at: usize, v: u64, n: usize) {
    b[at..at + n].copy_from_slice(&v.to_le_bytes()[..n]);
}

fn align8(n: usize) -> usize {
    (n + 7) & !7
}

/// Mapping pairs for `(lcn, count)` runs, delta-encoded, zero-terminated.
pub fn runs(list: &[(u64, u64)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut prev: i64 = 0;
    for &(lcn, count) in list {
        let len = unsigned_bytes(count);
        let off = signed_bytes(lcn as i64 - prev);
        prev = lcn as i64;
        out.push((off.len() as u8) << 4 | len.len() as u8);
        out.extend(len);
        out.extend(off);
    }
    out.push(0);
    out
}

fn unsigned_bytes(v: u64) -> Vec<u8> {
    let b = v.to_le_bytes();
    let n = (8 - v.leading_zeros() as usize / 8).max(1);
    b[..n].to_vec()
}

fn signed_bytes(v: i64) -> Vec<u8> {
    let b = v.to_le_bytes();
    for n in 1..8 {
        let shift = 64 - 8 * n;
        if (v << shift) >> shift == v {
            return b[..n].to_vec();
        }
    }
    b.to_vec()
}

/// A resident attribute.
pub fn resident(ty: u32, value: &[u8], instance: u16) -> Vec<u8> {
    let voff = 0x18;
    let len = align8(voff + value.len());
    let mut a = vec![0u8; len];
    put(&mut a, 0, ty.into(), 4);
    put(&mut a, 4, len as u64, 4);
    put(&mut a, 0x0a, 0x18, 2);
    put(&mut a, 0x0e, instance.into(), 2);
    put(&mut a, 0x10, value.len() as u64, 4);
    put(&mut a, 0x14, voff as u64, 2);
    a[voff..voff + value.len()].copy_from_slice(value);
    a
}

/// A non-resident attribute. Fields are public so tests can break them.
#[derive(Clone)]
pub struct NonRes {
    pub ty: u32,
    pub name: &'static str,
    pub flags: u16,
    pub instance: u16,
    pub lowest: u64,
    pub highest: u64,
    pub cu: u8,
    pub alloc: u64,
    pub size: u64,
    pub init: u64,
    pub pairs: Vec<u8>,
}

impl NonRes {
    /// The whole unnamed `$DATA` of a file in one segment.
    pub fn data(list: &[(u64, u64)], cluster: u64) -> NonRes {
        let total: u64 = list.iter().map(|r| r.1).sum();
        NonRes {
            ty: 0x80,
            name: "",
            flags: 0,
            instance: 1,
            lowest: 0,
            highest: total.wrapping_sub(1),
            cu: 0,
            alloc: total * cluster,
            size: total * cluster,
            init: total * cluster,
            pairs: runs(list),
        }
    }

    /// A later segment (sizes are only meaningful at VCN 0).
    pub fn segment(lowest: u64, list: &[(u64, u64)], instance: u16) -> NonRes {
        let total: u64 = list.iter().map(|r| r.1).sum();
        NonRes {
            lowest,
            highest: lowest + total - 1,
            alloc: 0,
            size: 0,
            init: 0,
            instance,
            ..NonRes::data(list, 0)
        }
    }

    pub fn bytes(&self) -> Vec<u8> {
        let name: Vec<u16> = self.name.encode_utf16().collect();
        let mp = align8(0x40 + 2 * name.len());
        let len = align8(mp + self.pairs.len());
        let mut a = vec![0u8; len];
        put(&mut a, 0, self.ty.into(), 4);
        put(&mut a, 4, len as u64, 4);
        a[8] = 1;
        a[9] = name.len() as u8;
        put(&mut a, 0x0a, 0x40, 2);
        put(&mut a, 0x0c, self.flags.into(), 2);
        put(&mut a, 0x0e, self.instance.into(), 2);
        put(&mut a, 0x10, self.lowest, 8);
        put(&mut a, 0x18, self.highest, 8);
        put(&mut a, 0x20, mp as u64, 2);
        a[0x22] = self.cu;
        put(&mut a, 0x28, self.alloc, 8);
        put(&mut a, 0x30, self.size, 8);
        put(&mut a, 0x38, self.init, 8);
        for (i, c) in name.iter().enumerate() {
            put(&mut a, 0x40 + 2 * i, (*c).into(), 2);
        }
        a[mp..mp + self.pairs.len()].copy_from_slice(&self.pairs);
        a
    }
}

/// One `$ATTRIBUTE_LIST` entry (unnamed).
pub fn alist_entry(ty: u32, lowest: u64, rec: u64, seq: u16, instance: u16) -> Vec<u8> {
    let mut e = vec![0u8; 0x20];
    put(&mut e, 0, ty.into(), 4);
    put(&mut e, 4, 0x20, 2);
    e[7] = 0x1a;
    put(&mut e, 8, lowest, 8);
    put(&mut e, 0x10, rec | u64::from(seq) << 48, 8);
    put(&mut e, 0x18, instance.into(), 2);
    e
}

/// A FILE record before serialisation.
#[derive(Clone)]
pub struct Record {
    pub recno: u64,
    pub seq: u16,
    pub flags: u16,
    pub base: u64,
    pub attrs: Vec<Vec<u8>>,
}

impl Record {
    pub fn file(recno: u64, seq: u16, attrs: Vec<Vec<u8>>) -> Record {
        Record {
            recno,
            seq,
            flags: 1,
            base: 0,
            attrs,
        }
    }

    /// An extension record of `base` (record number, sequence).
    pub fn extension(recno: u64, base: (u64, u16), attrs: Vec<Vec<u8>>) -> Record {
        Record {
            recno,
            seq: 1,
            flags: 1,
            base: base.0 | u64::from(base.1) << 48,
            attrs,
        }
    }

    /// Serialised, with the update sequence applied as on disk.
    pub fn bytes(&self, size: usize) -> Vec<u8> {
        let mut r = vec![0u8; size];
        let count = size / 512 + 1;
        let attrs = align8(0x30 + 2 * count);
        r[..4].copy_from_slice(b"FILE");
        put(&mut r, 4, 0x30, 2);
        put(&mut r, 6, count as u64, 2);
        put(&mut r, 0x10, self.seq.into(), 2);
        put(&mut r, 0x12, 1, 2);
        put(&mut r, 0x14, attrs as u64, 2);
        put(&mut r, 0x16, self.flags.into(), 2);
        put(&mut r, 0x1c, size as u64, 4);
        put(&mut r, 0x20, self.base, 8);
        put(&mut r, 0x2c, self.recno & 0xffff_ffff, 4);
        let mut pos = attrs;
        for a in &self.attrs {
            r[pos..pos + a.len()].copy_from_slice(a);
            pos += a.len();
        }
        put(&mut r, pos, 0xffff_ffff, 4);
        put(&mut r, 0x18, (pos + 8) as u64, 4);
        let usn = 0x4b4a_u64;
        put(&mut r, 0x30, usn, 2);
        for i in 1..count {
            let at = i * 512 - 2;
            let orig = u64::from(r[at]) | u64::from(r[at + 1]) << 8;
            put(&mut r, 0x30 + 2 * i, orig, 2);
            put(&mut r, at, usn, 2);
        }
        r
    }
}

/// A whole volume: geometry, `$MFT` layout and records.
#[derive(Clone)]
pub struct Vol {
    pub bps: u64,
    pub spc: u64,
    pub record: usize,
    pub clusters: u64,
    pub mft_runs: Vec<(u64, u64)>,
    pub records: BTreeMap<u64, Record>,
    /// Raw bytes placed at a cluster (non-resident attribute lists).
    pub raw: Vec<(u64, Vec<u8>)>,
    pub dirty: bool,
}

pub const USER: u64 = 30;

impl Vol {
    /// 512-byte clusters, 1 KiB records, 8192 clusters, `$MFT` at LCN 16
    /// with room for 256 records.
    pub fn new() -> Vol {
        Vol::with(512, 1, 1024, 8192, vec![(16, 512)])
    }

    pub fn with(bps: u64, spc: u64, record: usize, clusters: u64, mft: Vec<(u64, u64)>) -> Vol {
        Vol {
            bps,
            spc,
            record,
            clusters,
            mft_runs: mft,
            records: BTreeMap::new(),
            raw: Vec::new(),
            dirty: false,
        }
    }

    pub fn cluster(&self) -> u64 {
        self.bps * self.spc
    }

    /// Add a file whose unnamed $DATA is `list`; returns its record number.
    pub fn add_file(&mut self, recno: u64, list: &[(u64, u64)]) -> u64 {
        let d = NonRes::data(list, self.cluster()).bytes();
        let si = resident(0x10, &[0u8; 0x48], 0);
        self.records
            .insert(recno, Record::file(recno, 7, vec![si, d]));
        recno
    }

    pub fn boot(&self) -> [u8; 512] {
        let mut b = [0u8; 512];
        b[0..3].copy_from_slice(&[0xeb, 0x52, 0x90]);
        b[3..11].copy_from_slice(b"NTFS    ");
        put(&mut b, 0x0b, self.bps, 2);
        b[0x0d] = if self.spc <= 128 {
            self.spc as u8
        } else {
            (256 - u64::from(self.spc.trailing_zeros())) as u8
        };
        b[0x15] = 0xf8;
        put(&mut b, 0x28, self.clusters * self.spc, 8);
        put(&mut b, 0x30, self.mft_runs[0].0, 8);
        put(&mut b, 0x38, 2, 8);
        b[0x40] = (256 - self.record.trailing_zeros()) as u8;
        b[0x44] = 1;
        b[510] = 0x55;
        b[511] = 0xaa;
        b
    }

    fn mft_bytes(&self) -> u64 {
        self.mft_runs.iter().map(|r| r.1).sum::<u64>() * self.cluster()
    }

    fn mft_record(&self) -> Record {
        let d = NonRes::data(&self.mft_runs, self.cluster());
        Record::file(0, 1, vec![resident(0x10, &[0u8; 0x48], 0), d.bytes()])
    }

    fn volume_record(&self) -> Record {
        let mut info = [0u8; 12];
        info[8] = 3;
        info[9] = 1;
        put(&mut info, 0x0a, u64::from(self.dirty), 2);
        Record::file(3, 3, vec![resident(0x70, &info, 1)])
    }

    /// Byte offset on the volume of byte `off` of `$MFT`.
    fn mft_offset(&self, mut off: u64) -> u64 {
        let c = self.cluster();
        for &(lcn, count) in &self.mft_runs {
            if off < count * c {
                return lcn * c + off;
            }
            off -= count * c;
        }
        panic!("record outside the synthetic $MFT");
    }

    pub fn image(&self) -> Vec<u8> {
        let mut img = vec![0u8; (self.clusters * self.cluster()) as usize];
        img[..512].copy_from_slice(&self.boot());
        let mut all = self.records.clone();
        all.entry(0).or_insert_with(|| self.mft_record());
        all.entry(3).or_insert_with(|| self.volume_record());
        for (recno, r) in &all {
            let bytes = r.bytes(self.record);
            // Place 512 bytes at a time: records may straddle $MFT runs.
            for (i, chunk) in bytes.chunks(512).enumerate() {
                let off = recno * self.record as u64 + 512 * i as u64;
                assert!(off < self.mft_bytes());
                let at = self.mft_offset(off) as usize;
                img[at..at + 512].copy_from_slice(chunk);
            }
        }
        for (lcn, bytes) in &self.raw {
            let at = (lcn * self.cluster()) as usize;
            img[at..at + bytes.len()].copy_from_slice(bytes);
        }
        img
    }
}

impl Default for Vol {
    fn default() -> Self {
        Vol::new()
    }
}

/// Offset of record `recno` in `image` (for byte-level mutation), assuming a
/// contiguous $MFT at the boot sector's LCN.
pub fn record_offset(v: &Vol, recno: u64) -> usize {
    v.mft_offset(recno * v.record as u64) as usize
}
