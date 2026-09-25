//! Just enough of the Windows registry hive format (`regf`) to author the
//! synthetic ESP's BCD offline (DESIGN.md §12: "the VM's BCD is authored
//! offline into the synthetic ESP, never set with `bcdedit` on a running
//! machine").
//!
//! Reading follows the format as libregf and hivex document it: a 4 KiB
//! base block, then hive bins of cells; a key (`nk`) points at a subkey
//! index (`lf`, `lh`, `li`, or `ri` of those) and a value list of `vk`
//! cells. Every offset read is bounds-checked against the hive, every walk
//! bounded. Writing never moves a cell: a changed value is rewritten in
//! place when its size is unchanged, and anything new — a key, its value,
//! a grown subkey index — goes into a fresh hive bin appended at the end;
//! the replaced index cell is freed. The base block's sequence numbers are
//! then made equal (a clean hive: no transaction log is replayed over it)
//! and its checksum recomputed.
//!
//! A hive whose sequence numbers differ has unflushed changes in its log
//! files; that is refused rather than guessed at ([`RegError::Dirty`]).

pub const BASE_BLOCK: usize = 4096;
const HBIN_ALIGN: usize = 4096;
const HBIN_HEADER: usize = 32;
const CELL_ALIGN: usize = 8;
const NONE: u32 = 0xFFFF_FFFF;

// Base block fields.
const B_SEQ1: usize = 4;
const B_SEQ2: usize = 8;
const B_TIME: usize = 12;
const B_ROOT: usize = 36;
const B_BINS_SIZE: usize = 40;
const B_CHECKSUM: usize = 508;

// nk fields (from the cell's content).
const NK_FLAGS: usize = 2;
const NK_TIME: usize = 4;
const NK_PARENT: usize = 16;
const NK_SUBKEYS: usize = 20;
const NK_VOLATILE_SUBKEYS: usize = 24;
const NK_SUBKEY_LIST: usize = 28;
const NK_VOLATILE_LIST: usize = 32;
const NK_VALUES: usize = 36;
const NK_VALUE_LIST: usize = 40;
const NK_SK: usize = 44;
const NK_CLASS: usize = 48;
const NK_MAX_SUBKEY_NAME: usize = 52;
const NK_MAX_VALUE_NAME: usize = 60;
const NK_MAX_VALUE_DATA: usize = 64;
const NK_NAME_LEN: usize = 72;
const NK_CLASS_LEN: usize = 74;
const NK_NAME: usize = 76;
const KEY_COMP_NAME: u16 = 0x0020;

// vk fields.
const VK_NAME_LEN: usize = 2;
const VK_DATA_SIZE: usize = 4;
const VK_DATA: usize = 8;
const VK_TYPE: usize = 12;
const VK_FLAGS: usize = 16;
const VK_NAME: usize = 20;
const VALUE_COMP_NAME: u16 = 0x0001;
/// Data size's top bit: the data (≤ 4 bytes) sits in the offset field.
const DATA_INLINE: u32 = 0x8000_0000;
const INLINE_MAX: usize = 4;

// sk fields.
const SK_REFS: usize = 12;

/// `REG_SZ` and `REG_BINARY`.
pub const REG_SZ: u32 = 1;
pub const REG_BINARY: u32 = 3;

/// Bounds on walks: subkeys of one key, values of one key, path depth.
const MAX_LIST: usize = 1 << 16;
const MAX_DEPTH: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegError {
    NotAHive,
    /// Sequence numbers differ: the log files hold changes.
    Dirty,
    Corrupt(&'static str),
    NotFound(String),
    Unsupported(&'static str),
}

impl core::fmt::Display for RegError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RegError::NotAHive => write!(f, "not a registry hive"),
            RegError::Dirty => write!(
                f,
                "hive has unflushed log entries (sequence numbers differ)"
            ),
            RegError::Corrupt(w) => write!(f, "corrupt hive: {w}"),
            RegError::NotFound(p) => write!(f, "not in the hive: {p}"),
            RegError::Unsupported(w) => write!(f, "unsupported hive structure: {w}"),
        }
    }
}

type R<T> = Result<T, RegError>;

fn rd16(b: &[u8], at: usize) -> R<u16> {
    Ok(u16::from_le_bytes(
        b.get(at..at + 2)
            .ok_or(RegError::Corrupt("short read"))?
            .try_into()
            .map_err(|_| RegError::Corrupt("short read"))?,
    ))
}
fn rd32(b: &[u8], at: usize) -> R<u32> {
    Ok(u32::from_le_bytes(
        b.get(at..at + 4)
            .ok_or(RegError::Corrupt("short read"))?
            .try_into()
            .map_err(|_| RegError::Corrupt("short read"))?,
    ))
}
fn wr(b: &mut [u8], at: usize, v: &[u8]) -> R<()> {
    b.get_mut(at..at + v.len())
        .ok_or(RegError::Corrupt("write outside the hive"))?
        .copy_from_slice(v);
    Ok(())
}

/// A hive in memory.
pub struct Hive {
    pub data: Vec<u8>,
    /// Cells added in this session, in a bin appended by [`Hive::finish`].
    new_cells: Vec<Vec<u8>>,
    /// Where the next new cell will land (offset from the first bin).
    next_new: u32,
    /// Where the appended bin starts.
    new_bin: u32,
}

/// Name comparison as the registry does it: case-insensitive.
fn upper(s: &str) -> String {
    s.to_uppercase()
}

/// `lh` hash: h = h * 37 + upper(c), over UTF-16 units.
fn lh_hash(name: &str) -> u32 {
    upper(name)
        .encode_utf16()
        .fold(0u32, |h, c| h.wrapping_mul(37).wrapping_add(u32::from(c)))
}

impl Hive {
    pub fn parse(data: Vec<u8>) -> R<Hive> {
        if data.len() < BASE_BLOCK + HBIN_ALIGN || data.get(..4) != Some(b"regf") {
            return Err(RegError::NotAHive);
        }
        if rd32(&data, B_SEQ1)? != rd32(&data, B_SEQ2)? {
            return Err(RegError::Dirty);
        }
        let bins = rd32(&data, B_BINS_SIZE)? as usize;
        if bins % HBIN_ALIGN != 0
            || BASE_BLOCK + bins > data.len()
            || data.get(BASE_BLOCK..BASE_BLOCK + 4) != Some(b"hbin")
        {
            return Err(RegError::Corrupt("hive bins"));
        }
        let mut data = data;
        data.truncate(BASE_BLOCK + bins);
        Ok(Hive {
            new_bin: bins as u32,
            next_new: (bins + HBIN_HEADER) as u32,
            new_cells: Vec::new(),
            data,
        })
    }

    fn bins_len(&self) -> usize {
        self.data.len() - BASE_BLOCK
    }

    /// The content of the allocated cell at `off` (offset from the first
    /// bin), bounded by its size.
    fn cell(&self, off: u32) -> R<&[u8]> {
        if let Some(i) = self.new_index(off) {
            return self
                .new_cells
                .get(i)
                .map(|c| c.as_slice())
                .ok_or(RegError::Corrupt("cell"));
        }
        let at = BASE_BLOCK + off as usize;
        if off as usize >= self.bins_len() || off % CELL_ALIGN as u32 != 0 {
            return Err(RegError::Corrupt("cell offset"));
        }
        let size = rd32(&self.data, at)? as i32;
        if size >= 0 {
            return Err(RegError::Corrupt("free cell referenced"));
        }
        let len = size.unsigned_abs() as usize;
        if len < 8 || at + len > self.data.len() {
            return Err(RegError::Corrupt("cell size"));
        }
        self.data
            .get(at + 4..at + len)
            .ok_or(RegError::Corrupt("cell"))
    }

    fn cell_mut(&mut self, off: u32) -> R<&mut [u8]> {
        if let Some(i) = self.new_index(off) {
            return self
                .new_cells
                .get_mut(i)
                .map(|c| c.as_mut_slice())
                .ok_or(RegError::Corrupt("cell"));
        }
        let len = self.cell(off)?.len();
        let at = BASE_BLOCK + off as usize + 4;
        self.data
            .get_mut(at..at + len)
            .ok_or(RegError::Corrupt("cell"))
    }

    /// Index of a cell added this session, from its offset.
    fn new_index(&self, off: u32) -> Option<usize> {
        if off < self.new_bin {
            return None;
        }
        let mut at = self.new_bin + HBIN_HEADER as u32;
        for (i, c) in self.new_cells.iter().enumerate() {
            if at == off {
                return Some(i);
            }
            at += cell_len(c.len()) as u32;
        }
        None
    }

    /// Add a cell; its offset.
    fn alloc(&mut self, content: Vec<u8>) -> u32 {
        let off = self.next_new;
        self.next_new += cell_len(content.len()) as u32;
        self.new_cells.push(content);
        off
    }

    pub fn root(&self) -> R<u32> {
        rd32(&self.data, B_ROOT)
    }

    fn nk(&self, off: u32) -> R<&[u8]> {
        let c = self.cell(off)?;
        if c.get(..2) != Some(b"nk") || c.len() < NK_NAME {
            return Err(RegError::Corrupt("nk"));
        }
        Ok(c)
    }

    fn name_of(
        cell: &[u8],
        len_at: usize,
        flags_at: usize,
        comp_flag: u16,
        name_at: usize,
    ) -> R<String> {
        let n = usize::from(rd16(cell, len_at)?);
        let raw = cell
            .get(name_at..name_at + n)
            .ok_or(RegError::Corrupt("name"))?;
        if rd16(cell, flags_at)? & comp_flag != 0 {
            Ok(raw.iter().map(|&b| char::from(b)).collect())
        } else {
            let u: Vec<u16> = raw
                .chunks_exact(2)
                .map(|c| {
                    u16::from_le_bytes([
                        c.first().copied().unwrap_or(0),
                        c.get(1).copied().unwrap_or(0),
                    ])
                })
                .collect();
            Ok(String::from_utf16_lossy(&u))
        }
    }

    pub fn key_name(&self, nk: u32) -> R<String> {
        Hive::name_of(self.nk(nk)?, NK_NAME_LEN, NK_FLAGS, KEY_COMP_NAME, NK_NAME)
    }

    /// Offsets of `nk`'s subkeys, as listed.
    pub fn subkeys(&self, nk: u32) -> R<Vec<u32>> {
        let k = self.nk(nk)?;
        let n = rd32(k, NK_SUBKEYS)? as usize;
        let list = rd32(k, NK_SUBKEY_LIST)?;
        if n == 0 || list == NONE {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        self.index(list, &mut out, 0)?;
        if out.len() != n {
            return Err(RegError::Corrupt("subkey count"));
        }
        Ok(out)
    }

    fn index(&self, list: u32, out: &mut Vec<u32>, depth: usize) -> R<()> {
        if depth > 1 {
            return Err(RegError::Corrupt("nested index"));
        }
        let c = self.cell(list)?;
        let n = usize::from(rd16(c, 2)?);
        if n > MAX_LIST || out.len() + n > MAX_LIST {
            return Err(RegError::Corrupt("index size"));
        }
        match c.get(..2) {
            Some(b"lf") | Some(b"lh") => {
                for i in 0..n {
                    out.push(rd32(c, 4 + 8 * i)?);
                }
            }
            Some(b"li") => {
                for i in 0..n {
                    out.push(rd32(c, 4 + 4 * i)?);
                }
            }
            Some(b"ri") => {
                for i in 0..n {
                    self.index(rd32(c, 4 + 4 * i)?, out, depth + 1)?;
                }
            }
            _ => return Err(RegError::Corrupt("subkey index")),
        }
        Ok(())
    }

    pub fn subkey(&self, nk: u32, name: &str) -> R<Option<u32>> {
        let want = upper(name);
        for s in self.subkeys(nk)? {
            if upper(&self.key_name(s)?) == want {
                return Ok(Some(s));
            }
        }
        Ok(None)
    }

    /// The key at `path` (`\`-separated, from the root).
    pub fn key(&self, path: &str) -> R<u32> {
        let mut k = self.root()?;
        for (depth, comp) in path.split('\\').filter(|c| !c.is_empty()).enumerate() {
            if depth >= MAX_DEPTH {
                return Err(RegError::Corrupt("depth"));
            }
            k = self
                .subkey(k, comp)?
                .ok_or_else(|| RegError::NotFound(path.to_string()))?;
        }
        Ok(k)
    }

    fn values(&self, nk: u32) -> R<Vec<u32>> {
        let k = self.nk(nk)?;
        let n = rd32(k, NK_VALUES)? as usize;
        if n == 0 {
            return Ok(Vec::new());
        }
        if n > MAX_LIST {
            return Err(RegError::Corrupt("value count"));
        }
        let list = self.cell(rd32(k, NK_VALUE_LIST)?)?;
        (0..n).map(|i| rd32(list, 4 * i)).collect()
    }

    fn vk(&self, off: u32) -> R<&[u8]> {
        let c = self.cell(off)?;
        if c.get(..2) != Some(b"vk") || c.len() < VK_NAME {
            return Err(RegError::Corrupt("vk"));
        }
        Ok(c)
    }

    fn find_value(&self, nk: u32, name: &str) -> R<Option<u32>> {
        let want = upper(name);
        for v in self.values(nk)? {
            let c = self.vk(v)?;
            if upper(&Hive::name_of(
                c,
                VK_NAME_LEN,
                VK_FLAGS,
                VALUE_COMP_NAME,
                VK_NAME,
            )?) == want
            {
                return Ok(Some(v));
            }
        }
        Ok(None)
    }

    /// A value's type and data.
    pub fn value(&self, nk: u32, name: &str) -> R<Option<(u32, Vec<u8>)>> {
        let Some(v) = self.find_value(nk, name)? else {
            return Ok(None);
        };
        let c = self.vk(v)?;
        let size = rd32(c, VK_DATA_SIZE)?;
        let ty = rd32(c, VK_TYPE)?;
        let data = if size & DATA_INLINE != 0 {
            let n = (size & !DATA_INLINE) as usize;
            if n > INLINE_MAX {
                return Err(RegError::Corrupt("inline size"));
            }
            c.get(VK_DATA..VK_DATA + n)
                .ok_or(RegError::Corrupt("inline"))?
                .to_vec()
        } else {
            let d = self.cell(rd32(c, VK_DATA)?)?;
            if d.get(..2) == Some(b"db") {
                return Err(RegError::Unsupported("big data value"));
            }
            d.get(..size as usize)
                .ok_or(RegError::Corrupt("value data"))?
                .to_vec()
        };
        Ok(Some((ty, data)))
    }

    /// Set `name` under `nk` to `(ty, data)` (≤ 4 bytes: stored inline).
    /// An existing value is rewritten in place; a new one is added.
    pub fn set_small_value(&mut self, nk: u32, name: &str, ty: u32, data: &[u8]) -> R<()> {
        if data.len() > INLINE_MAX || !name.is_ascii() {
            return Err(RegError::Unsupported(
                "value larger than 4 bytes or non-ASCII name",
            ));
        }
        let mut inline = [0u8; 4];
        wr(&mut inline, 0, data)?;
        if let Some(v) = self.find_value(nk, name)? {
            let c = self.cell_mut(v)?;
            wr(
                c,
                VK_DATA_SIZE,
                &(DATA_INLINE | data.len() as u32).to_le_bytes(),
            )?;
            wr(c, VK_DATA, &inline)?;
            wr(c, VK_TYPE, &ty.to_le_bytes())?;
            return Ok(());
        }
        let mut vk = vec![0u8; VK_NAME];
        wr(&mut vk, 0, b"vk")?;
        wr(&mut vk, VK_NAME_LEN, &(name.len() as u16).to_le_bytes())?;
        wr(
            &mut vk,
            VK_DATA_SIZE,
            &(DATA_INLINE | data.len() as u32).to_le_bytes(),
        )?;
        wr(&mut vk, VK_DATA, &inline)?;
        wr(&mut vk, VK_TYPE, &ty.to_le_bytes())?;
        wr(&mut vk, VK_FLAGS, &VALUE_COMP_NAME.to_le_bytes())?;
        vk.extend_from_slice(name.as_bytes());
        let voff = self.alloc(vk);
        let mut list: Vec<u8> = Vec::new();
        for v in self.values(nk)? {
            list.extend_from_slice(&v.to_le_bytes());
        }
        list.extend_from_slice(&voff.to_le_bytes());
        let old_list = rd32(self.nk(nk)?, NK_VALUE_LIST)?;
        let n = self.values(nk)?.len() as u32 + 1;
        let loff = self.alloc(list);
        let k = self.cell_mut(nk)?;
        wr(k, NK_VALUES, &n.to_le_bytes())?;
        wr(k, NK_VALUE_LIST, &loff.to_le_bytes())?;
        let max_name = rd32(k, NK_MAX_VALUE_NAME)?.max(2 * name.len() as u32);
        wr(k, NK_MAX_VALUE_NAME, &max_name.to_le_bytes())?;
        let max_data = rd32(k, NK_MAX_VALUE_DATA)?.max(data.len() as u32);
        wr(k, NK_MAX_VALUE_DATA, &max_data.to_le_bytes())?;
        if n > 1 {
            self.free(old_list)?;
        }
        Ok(())
    }

    /// Add subkey `name` under `parent` (which must not have it); its offset.
    pub fn add_key(&mut self, parent: u32, name: &str) -> R<u32> {
        if !name.is_ascii() || name.is_empty() || name.len() > 255 || name.contains('\\') {
            return Err(RegError::Unsupported("key name"));
        }
        if self.subkey(parent, name)?.is_some() {
            return Err(RegError::Unsupported("key exists"));
        }
        let p = self.nk(parent)?;
        let sk = rd32(p, NK_SK)?;
        let old_list = rd32(p, NK_SUBKEY_LIST)?;
        let kind: [u8; 2] = match rd32(p, NK_SUBKEYS)? {
            0 => *b"lh",
            _ => {
                let l = self.cell(old_list)?;
                match l.get(..2) {
                    Some(b"lf") => *b"lf",
                    Some(b"lh") => *b"lh",
                    Some(b"li") => *b"li",
                    _ => return Err(RegError::Unsupported("ri subkey index")),
                }
            }
        };
        let mut nk = vec![0u8; NK_NAME];
        wr(&mut nk, 0, b"nk")?;
        wr(&mut nk, NK_FLAGS, &KEY_COMP_NAME.to_le_bytes())?;
        let time = rd32(&self.data, B_TIME)?.to_le_bytes();
        let time_hi = rd32(&self.data, B_TIME + 4)?.to_le_bytes();
        wr(&mut nk, NK_TIME, &time)?;
        wr(&mut nk, NK_TIME + 4, &time_hi)?;
        wr(&mut nk, NK_PARENT, &parent.to_le_bytes())?;
        for f in [NK_SUBKEY_LIST, NK_VOLATILE_LIST, NK_VALUE_LIST, NK_CLASS] {
            wr(&mut nk, f, &NONE.to_le_bytes())?;
        }
        wr(&mut nk, NK_SUBKEYS, &0u32.to_le_bytes())?;
        wr(&mut nk, NK_VOLATILE_SUBKEYS, &0u32.to_le_bytes())?;
        wr(&mut nk, NK_SK, &sk.to_le_bytes())?;
        wr(&mut nk, NK_NAME_LEN, &(name.len() as u16).to_le_bytes())?;
        wr(&mut nk, NK_CLASS_LEN, &0u16.to_le_bytes())?;
        nk.extend_from_slice(name.as_bytes());
        let off = self.alloc(nk);

        // The parent's index, rebuilt sorted with the new key in it.
        let mut entries: Vec<(String, u32)> = Vec::new();
        for s in self.subkeys(parent)? {
            entries.push((upper(&self.key_name(s)?), s));
        }
        entries.push((upper(name), off));
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let mut list = kind.to_vec();
        list.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        for (n, o) in &entries {
            list.extend_from_slice(&o.to_le_bytes());
            match &kind {
                b"lf" => {
                    let mut hint = [0u8; 4];
                    let orig = if *o == off {
                        name.to_string()
                    } else {
                        self.key_name(*o)?
                    };
                    let first: Vec<u8> = orig.bytes().take(4).collect();
                    wr(&mut hint, 0, &first)?;
                    list.extend_from_slice(&hint);
                }
                b"lh" => list.extend_from_slice(&lh_hash(n).to_le_bytes()),
                _ => {}
            }
        }
        let loff = self.alloc(list);
        let count = entries.len() as u32;
        let k = self.cell_mut(parent)?;
        wr(k, NK_SUBKEYS, &count.to_le_bytes())?;
        wr(k, NK_SUBKEY_LIST, &loff.to_le_bytes())?;
        // The low 16 bits: longest subkey name, in bytes of UTF-16.
        let m = rd32(k, NK_MAX_SUBKEY_NAME)?;
        let want = (2 * name.len() as u32).max(m & 0xFFFF);
        wr(
            k,
            NK_MAX_SUBKEY_NAME,
            &((m & 0xFFFF_0000) | want).to_le_bytes(),
        )?;
        if count > 1 {
            self.free(old_list)?;
        }
        // One more key uses the parent's security descriptor.
        let s = self.cell_mut(sk)?;
        if s.get(..2) != Some(b"sk") {
            return Err(RegError::Corrupt("sk"));
        }
        let refs = rd32(s, SK_REFS)?.saturating_add(1);
        wr(s, SK_REFS, &refs.to_le_bytes())?;
        Ok(off)
    }

    /// Mark an original cell free (cells added this session are never
    /// freed: they are about to be written).
    fn free(&mut self, off: u32) -> R<()> {
        if self.new_index(off).is_some() || off == NONE {
            return Ok(());
        }
        let at = BASE_BLOCK + off as usize;
        let size = rd32(&self.data, at)? as i32;
        if size < 0 {
            wr(&mut self.data, at, &size.unsigned_abs().to_le_bytes())?;
        }
        Ok(())
    }

    /// The hive file: the new cells in an appended bin, the base block
    /// clean (sequence numbers equal, advanced) and checksummed.
    pub fn finish(mut self) -> R<Vec<u8>> {
        if !self.new_cells.is_empty() {
            let used: usize = HBIN_HEADER
                + self
                    .new_cells
                    .iter()
                    .map(|c| cell_len(c.len()))
                    .sum::<usize>();
            let size = used.div_ceil(HBIN_ALIGN) * HBIN_ALIGN;
            let mut bin = vec![0u8; size];
            wr(&mut bin, 0, b"hbin")?;
            wr(&mut bin, 4, &self.new_bin.to_le_bytes())?;
            wr(&mut bin, 8, &(size as u32).to_le_bytes())?;
            let mut at = HBIN_HEADER;
            for c in &self.new_cells {
                let len = cell_len(c.len());
                wr(&mut bin, at, &(-(len as i32)).to_le_bytes())?;
                wr(&mut bin, at + 4, c)?;
                at += len;
            }
            if at < size {
                // The rest of the bin: one free cell.
                wr(&mut bin, at, &((size - at) as u32).to_le_bytes())?;
            }
            self.data.extend_from_slice(&bin);
            let bins = (self.data.len() - BASE_BLOCK) as u32;
            wr(&mut self.data, B_BINS_SIZE, &bins.to_le_bytes())?;
        }
        let seq = rd32(&self.data, B_SEQ1)?.wrapping_add(1);
        wr(&mut self.data, B_SEQ1, &seq.to_le_bytes())?;
        wr(&mut self.data, B_SEQ2, &seq.to_le_bytes())?;
        let sum = checksum(&self.data)?;
        wr(&mut self.data, B_CHECKSUM, &sum.to_le_bytes())?;
        Ok(self.data)
    }
}

fn cell_len(content: usize) -> usize {
    (content + 4).div_ceil(CELL_ALIGN) * CELL_ALIGN
}

/// The base block checksum: XOR of its first 127 dwords, never 0 or ~0.
pub fn checksum(b: &[u8]) -> R<u32> {
    let mut x = 0u32;
    for i in 0..B_CHECKSUM / 4 {
        x ^= rd32(b, 4 * i)?;
    }
    Ok(match x {
        0xFFFF_FFFF => 0xFFFF_FFFE,
        0 => 1,
        x => x,
    })
}

/// BCD: the `{bootmgr}` object and the elements used here.
pub mod bcd {
    use super::*;

    /// `{bootmgr}`, the Windows Boot Manager object.
    pub const BOOTMGR: &str = "{9dea862c-5cdd-4e70-acc1-f32b344d4795}";
    /// `BcdBootMgrObject_DefaultObject` (a GUID string).
    pub const DEFAULT_OBJECT: &str = "23000003";
    /// `BcdLibraryBoolean_AllowPrereleaseSignatures`: `testsigning`.
    pub const TESTSIGNING: &str = "16000049";
    const ELEMENT: &str = "Element";

    fn utf16z_to_string(d: &[u8]) -> String {
        let u: Vec<u16> = d
            .chunks_exact(2)
            .map(|c| {
                u16::from_le_bytes([
                    c.first().copied().unwrap_or(0),
                    c.get(1).copied().unwrap_or(0),
                ])
            })
            .take_while(|&c| c != 0)
            .collect();
        String::from_utf16_lossy(&u)
    }

    /// The object `{bootmgr}` starts by default.
    pub fn default_loader(h: &Hive) -> R<String> {
        let path = format!("Objects\\{BOOTMGR}\\Elements\\{DEFAULT_OBJECT}");
        let k = h.key(&path)?;
        match h.value(k, ELEMENT)? {
            Some((REG_SZ, d)) => Ok(utf16z_to_string(&d)),
            _ => Err(RegError::NotFound(format!("{path}\\{ELEMENT}"))),
        }
    }

    /// A boolean element on `object`, created if absent (REG_BINARY, one
    /// byte, as `bcdedit` writes booleans).
    pub fn set_bool(h: &mut Hive, object: &str, element: &str, on: bool) -> R<()> {
        let elements = h.key(&format!("Objects\\{object}\\Elements"))?;
        let k = match h.subkey(elements, element)? {
            Some(k) => k,
            None => h.add_key(elements, element)?,
        };
        h.set_small_value(k, ELEMENT, REG_BINARY, &[u8::from(on)])
    }

    pub fn get_bool(h: &Hive, object: &str, element: &str) -> R<Option<bool>> {
        let elements = h.key(&format!("Objects\\{object}\\Elements"))?;
        let Some(k) = h.subkey(elements, element)? else {
            return Ok(None);
        };
        Ok(match h.value(k, ELEMENT)? {
            Some((REG_BINARY, d)) => d.first().map(|&b| b != 0),
            _ => None,
        })
    }

    /// `testsigning on` for the default boot entry, in this BCD only.
    /// Returns the object it was set on.
    pub fn enable_testsigning(bcd: Vec<u8>) -> R<(Vec<u8>, String)> {
        let mut h = Hive::parse(bcd)?;
        let obj = default_loader(&h)?;
        set_bool(&mut h, &obj, TESTSIGNING, true)?;
        Ok((h.finish()?, obj))
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
pub(crate) mod tests {
    use super::bcd::*;
    use super::*;

    /// A small BCD-shaped hive, written independently of the editor:
    /// every cell in one bin, keys with `lf` or `lh` indexes.
    pub(crate) struct Build {
        cells: Vec<u8>,
    }

    impl Build {
        fn cell(&mut self, content: &[u8]) -> u32 {
            let off = (HBIN_HEADER + self.cells.len()) as u32;
            let len = cell_len(content.len());
            self.cells.extend_from_slice(&(-(len as i32)).to_le_bytes());
            self.cells.extend_from_slice(content);
            self.cells
                .resize(self.cells.len() + len - 4 - content.len(), 0);
            off
        }
        fn nk(
            &mut self,
            name: &str,
            parent: u32,
            subkeys: &[u32],
            list_kind: &[u8; 2],
            values: &[u32],
            sk: u32,
        ) -> u32 {
            let list = if subkeys.is_empty() {
                NONE
            } else {
                let mut l = list_kind.to_vec();
                l.extend((subkeys.len() as u16).to_le_bytes());
                for &s in subkeys {
                    l.extend(s.to_le_bytes());
                    if list_kind != b"li" {
                        l.extend([0u8; 4]); // hints/hashes are not read back
                    }
                }
                self.cell(&l)
            };
            let vlist = if values.is_empty() {
                NONE
            } else {
                let l: Vec<u8> = values.iter().flat_map(|v| v.to_le_bytes()).collect();
                self.cell(&l)
            };
            let mut c = vec![0u8; NK_NAME];
            c[..2].copy_from_slice(b"nk");
            c[NK_FLAGS..NK_FLAGS + 2].copy_from_slice(&KEY_COMP_NAME.to_le_bytes());
            c[NK_PARENT..NK_PARENT + 4].copy_from_slice(&parent.to_le_bytes());
            c[NK_SUBKEYS..NK_SUBKEYS + 4].copy_from_slice(&(subkeys.len() as u32).to_le_bytes());
            c[NK_SUBKEY_LIST..NK_SUBKEY_LIST + 4].copy_from_slice(&list.to_le_bytes());
            c[NK_VOLATILE_LIST..NK_VOLATILE_LIST + 4].copy_from_slice(&NONE.to_le_bytes());
            c[NK_VALUES..NK_VALUES + 4].copy_from_slice(&(values.len() as u32).to_le_bytes());
            c[NK_VALUE_LIST..NK_VALUE_LIST + 4].copy_from_slice(&vlist.to_le_bytes());
            c[NK_SK..NK_SK + 4].copy_from_slice(&sk.to_le_bytes());
            c[NK_CLASS..NK_CLASS + 4].copy_from_slice(&NONE.to_le_bytes());
            c[NK_NAME_LEN..NK_NAME_LEN + 2].copy_from_slice(&(name.len() as u16).to_le_bytes());
            c.extend(name.as_bytes());
            let off = self.cell(&c);
            for &k in subkeys {
                let at = k as usize - HBIN_HEADER + 4 + NK_PARENT;
                self.cells[at..at + 4].copy_from_slice(&off.to_le_bytes());
            }
            off
        }
        fn vk(&mut self, name: &str, ty: u32, data: &[u8]) -> u32 {
            let (size, off) = if data.len() <= 4 {
                let mut b = [0u8; 4];
                b[..data.len()].copy_from_slice(data);
                (DATA_INLINE | data.len() as u32, u32::from_le_bytes(b))
            } else {
                (data.len() as u32, self.cell(data))
            };
            let mut c = vec![0u8; VK_NAME];
            c[..2].copy_from_slice(b"vk");
            c[VK_NAME_LEN..VK_NAME_LEN + 2].copy_from_slice(&(name.len() as u16).to_le_bytes());
            c[VK_DATA_SIZE..VK_DATA_SIZE + 4].copy_from_slice(&size.to_le_bytes());
            c[VK_DATA..VK_DATA + 4].copy_from_slice(&off.to_le_bytes());
            c[VK_TYPE..VK_TYPE + 4].copy_from_slice(&ty.to_le_bytes());
            c[VK_FLAGS..VK_FLAGS + 2].copy_from_slice(&VALUE_COMP_NAME.to_le_bytes());
            c.extend(name.as_bytes());
            self.cell(&c)
        }
    }

    fn utf16z(s: &str) -> Vec<u8> {
        s.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    /// `testsigning`: None = no element, Some(b) = the element with b.
    pub(crate) fn bcd_hive(testsigning: Option<bool>, list_kind: &[u8; 2]) -> Vec<u8> {
        const LOADER: &str = "{9d37057e-b92b-11f1-94f8-aa07fdcbec39}";
        let mut b = Build { cells: Vec::new() };
        // Parents are patched after the fact only where the reader cares
        // (it does not): keep them 0.
        let mut sd = b"sk".to_vec();
        sd.extend([0u8; 2]);
        sd.extend(((HBIN_HEADER) as u32).to_le_bytes());
        sd.extend(((HBIN_HEADER) as u32).to_le_bytes());
        sd.extend(1u32.to_le_bytes());
        sd.extend(0u32.to_le_bytes());
        let sk = b.cell(&sd);
        let v = b.vk("Element", REG_SZ, &utf16z(LOADER));
        let e_default = b.nk(DEFAULT_OBJECT, 0, &[], list_kind, &[v], sk);
        let v2 = b.vk(
            "Element",
            REG_SZ,
            &utf16z("\\EFI\\Microsoft\\Boot\\bootmgfw.efi"),
        );
        let e_path = b.nk("12000002", 0, &[], list_kind, &[v2], sk);
        let bm_el = b.nk("Elements", 0, &[e_path, e_default], list_kind, &[], sk);
        let bm = b.nk(BOOTMGR, 0, &[bm_el], list_kind, &[], sk);
        let v3 = b.vk(
            "Element",
            REG_SZ,
            &utf16z("\\WINDOWS\\system32\\winload.efi"),
        );
        let l_path = b.nk("12000002", 0, &[], list_kind, &[v3], sk);
        let mut lsub = vec![l_path];
        if let Some(on) = testsigning {
            let v4 = b.vk("Element", REG_BINARY, &[u8::from(on)]);
            lsub.push(b.nk(TESTSIGNING, 0, &[], list_kind, &[v4], sk));
        }
        let v5 = b.vk("Element", REG_BINARY, &[0]);
        lsub.push(b.nk("26000010", 0, &[], list_kind, &[v5], sk));
        let l_el = b.nk("Elements", 0, &lsub, list_kind, &[], sk);
        let loader = b.nk(LOADER, 0, &[l_el], list_kind, &[], sk);
        let objects = b.nk("Objects", 0, &[bm, loader], list_kind, &[], sk);
        let desc = b.nk("Description", 0, &[], list_kind, &[], sk);
        let root = b.nk("NewStoreRoot", 0, &[desc, objects], list_kind, &[], sk);
        // The root: KEY_HIVE_ENTRY | KEY_NO_DELETE | KEY_COMP_NAME.
        let at = root as usize - HBIN_HEADER + 4 + NK_FLAGS;
        b.cells[at..at + 2].copy_from_slice(&0x2cu16.to_le_bytes());
        let mut bin = b"hbin".to_vec();
        bin.extend(0u32.to_le_bytes());
        let size = (HBIN_HEADER + b.cells.len()).div_ceil(4096) * 4096;
        bin.extend((size as u32).to_le_bytes());
        bin.resize(HBIN_HEADER, 0);
        bin.extend(&b.cells);
        let free = size - bin.len();
        bin.extend((free as u32).to_le_bytes());
        bin.resize(size, 0);
        let mut base = vec![0u8; BASE_BLOCK];
        base[..4].copy_from_slice(b"regf");
        base[B_SEQ1..B_SEQ1 + 4].copy_from_slice(&7u32.to_le_bytes());
        base[B_SEQ2..B_SEQ2 + 4].copy_from_slice(&7u32.to_le_bytes());
        base[20..24].copy_from_slice(&1u32.to_le_bytes());
        base[24..28].copy_from_slice(&3u32.to_le_bytes());
        base[32..36].copy_from_slice(&1u32.to_le_bytes());
        base[B_ROOT..B_ROOT + 4].copy_from_slice(&root.to_le_bytes());
        base[B_BINS_SIZE..B_BINS_SIZE + 4].copy_from_slice(&(size as u32).to_le_bytes());
        base[44..48].copy_from_slice(&1u32.to_le_bytes());
        let sum = checksum(&base).unwrap();
        base[B_CHECKSUM..B_CHECKSUM + 4].copy_from_slice(&sum.to_le_bytes());
        base.extend(bin);
        base
    }

    const LOADER: &str = "{9d37057e-b92b-11f1-94f8-aa07fdcbec39}";

    #[test]
    fn testsigning_every_starting_point() {
        for kind in [b"lf", b"lh", b"li"] {
            for start in [None, Some(false), Some(true)] {
                let hive = bcd_hive(start, kind);
                let before = Hive::parse(hive.clone()).unwrap();
                assert_eq!(default_loader(&before).unwrap(), LOADER);
                assert_eq!(get_bool(&before, LOADER, TESTSIGNING).unwrap(), start);
                let (out, obj) = enable_testsigning(hive.clone()).unwrap();
                assert_eq!(obj, LOADER);
                let h = Hive::parse(out.clone()).unwrap();
                assert_eq!(get_bool(&h, LOADER, TESTSIGNING).unwrap(), Some(true));
                // everything else still there, subkeys sorted
                let el = h.key(&format!("Objects\\{LOADER}\\Elements")).unwrap();
                let names: Vec<String> = h
                    .subkeys(el)
                    .unwrap()
                    .iter()
                    .map(|&k| h.key_name(k).unwrap())
                    .collect();
                let mut sorted = names.clone();
                sorted.sort();
                assert_eq!(names, sorted);
                assert!(
                    names.contains(&"12000002".to_string())
                        && names.contains(&"26000010".to_string())
                );
                assert_eq!(get_bool(&h, LOADER, "26000010").unwrap(), Some(false));
                // clean base block
                assert_eq!(rd32(&out, B_SEQ1).unwrap(), 8);
                assert_eq!(rd32(&out, B_SEQ2).unwrap(), 8);
                assert_eq!(rd32(&out, B_CHECKSUM).unwrap(), checksum(&out).unwrap());
                assert_eq!(out.len() % 4096, 0);
                assert_eq!(
                    rd32(&out, B_BINS_SIZE).unwrap() as usize + BASE_BLOCK,
                    out.len()
                );
                // an existing element is changed in place: same length
                if start.is_some() {
                    assert_eq!(out.len(), hive.len());
                } else {
                    // the new key shares its parent's security descriptor
                    let sk = rd32(h.nk(el).unwrap(), NK_SK).unwrap();
                    assert_eq!(rd32(h.cell(sk).unwrap(), SK_REFS).unwrap(), 2);
                }
                // and is idempotent
                let (again, _) = enable_testsigning(out.clone()).unwrap();
                assert_eq!(again.len(), out.len());
            }
        }
    }

    #[test]
    fn refusals() {
        let mut h = bcd_hive(None, b"lh");
        h[B_SEQ2] ^= 1;
        assert_eq!(Hive::parse(h).err(), Some(RegError::Dirty));
        assert_eq!(Hive::parse(vec![0; 8192]).err(), Some(RegError::NotAHive));
        let h = bcd_hive(None, b"lh");
        let hive = Hive::parse(h).unwrap();
        assert!(matches!(
            hive.key("Objects\\{nope}"),
            Err(RegError::NotFound(_))
        ));
    }

    #[test]
    fn lh_hash_known() {
        // "Objects": h = h*37 + c over upper case
        let mut h = 0u32;
        for c in "OBJECTS".bytes() {
            h = h.wrapping_mul(37).wrapping_add(u32::from(c));
        }
        assert_eq!(lh_hash("Objects"), h);
    }

    /// A real BCD, when one is at hand (never committed): `PAGURO_VM_REF`
    /// holds `bcd-real` (testsigning element present) and `bcd-nots` (the
    /// element deleted with hivexregedit).
    #[test]
    fn windows_bcd() {
        let Ok(dir) = std::env::var("PAGURO_VM_REF") else {
            return;
        };
        for f in ["bcd-real", "bcd-nots"] {
            let b = std::fs::read(format!("{dir}/{f}")).unwrap();
            let (out, obj) = enable_testsigning(b).unwrap();
            let h = Hive::parse(out.clone()).unwrap();
            assert_eq!(get_bool(&h, &obj, TESTSIGNING).unwrap(), Some(true), "{f}");
            std::fs::write(format!("{dir}/{f}.out"), out).unwrap();
        }
    }

    /// hivex reads what the editor writes, when installed.
    #[test]
    fn hivex_agrees() {
        if std::process::Command::new("hivexregedit")
            .arg("--help")
            .output()
            .is_err()
        {
            return;
        }
        let (out, _) = enable_testsigning(bcd_hive(None, b"lh")).unwrap();
        let dir = std::env::temp_dir().join(format!("paguro-vm-regf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("BCD");
        std::fs::write(&p, &out).unwrap();
        let r = std::process::Command::new("hivexregedit")
            .arg("--export")
            .arg(&p)
            .arg("\\")
            .output()
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let text = String::from_utf8_lossy(&r.stdout);
        assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));
        assert!(
            text.contains(&format!(
                "[\\Objects\\{LOADER}\\Elements\\16000049]\n\"Element\"=hex(3):01"
            )),
            "{text}"
        );
    }
}
