//! Bounded cursor primitives shared by every parser and encoder in this crate.
//!
//! [`Reader`] never indexes: every read is a checked split, and running out of
//! input is a value ([`Short`]), never a panic. [`Writer`] fills a caller-owned
//! buffer and reports [`Full`] instead of growing, so no length taken from input
//! can size an allocation (INTERFACES.md §0).

/// The input ended before the read completed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Short;

/// The output buffer is too small.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Full;

#[derive(Clone, Debug)]
pub struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub const fn new(b: &'a [u8]) -> Self {
        Reader { rest: b }
    }
    pub const fn remaining(&self) -> usize {
        self.rest.len()
    }
    pub const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }
    /// Everything not yet consumed.
    pub const fn rest(&self) -> &'a [u8] {
        self.rest
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Short> {
        let (head, tail) = self.rest.split_at_checked(n).ok_or(Short)?;
        self.rest = tail;
        Ok(head)
    }
    pub fn array<const N: usize>(&mut self) -> Result<&'a [u8; N], Short> {
        self.take(N)?.try_into().map_err(|_| Short)
    }
    pub fn u8(&mut self) -> Result<u8, Short> {
        Ok(self.array::<1>()?[0])
    }
    pub fn u16_le(&mut self) -> Result<u16, Short> {
        Ok(u16::from_le_bytes(*self.array()?))
    }
    pub fn u32_le(&mut self) -> Result<u32, Short> {
        Ok(u32::from_le_bytes(*self.array()?))
    }
    pub fn u64_le(&mut self) -> Result<u64, Short> {
        Ok(u64::from_le_bytes(*self.array()?))
    }
    pub fn u16_be(&mut self) -> Result<u16, Short> {
        Ok(u16::from_be_bytes(*self.array()?))
    }
    pub fn u32_be(&mut self) -> Result<u32, Short> {
        Ok(u32::from_be_bytes(*self.array()?))
    }
    pub fn u64_be(&mut self) -> Result<u64, Short> {
        Ok(u64::from_be_bytes(*self.array()?))
    }
}

#[derive(Debug)]
pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Writer { buf, pos: 0 }
    }
    pub const fn len(&self) -> usize {
        self.pos
    }
    pub const fn is_empty(&self) -> bool {
        self.pos == 0
    }
    /// The bytes written so far.
    pub fn written(&self) -> &[u8] {
        self.buf.get(..self.pos).unwrap_or(&[])
    }
    pub fn into_written(self) -> &'a [u8] {
        let pos = self.pos;
        let buf: &'a [u8] = self.buf;
        buf.get(..pos).unwrap_or(&[])
    }
    pub fn put(&mut self, b: &[u8]) -> Result<(), Full> {
        let end = self.pos.checked_add(b.len()).ok_or(Full)?;
        self.buf
            .get_mut(self.pos..end)
            .ok_or(Full)?
            .copy_from_slice(b);
        self.pos = end;
        Ok(())
    }
    pub fn u8(&mut self, v: u8) -> Result<(), Full> {
        self.put(&[v])
    }
    pub fn u16_le(&mut self, v: u16) -> Result<(), Full> {
        self.put(&v.to_le_bytes())
    }
    pub fn u32_le(&mut self, v: u32) -> Result<(), Full> {
        self.put(&v.to_le_bytes())
    }
    pub fn u64_le(&mut self, v: u64) -> Result<(), Full> {
        self.put(&v.to_le_bytes())
    }
    pub fn u16_be(&mut self, v: u16) -> Result<(), Full> {
        self.put(&v.to_be_bytes())
    }
    pub fn u32_be(&mut self, v: u32) -> Result<(), Full> {
        self.put(&v.to_be_bytes())
    }
    pub fn u64_be(&mut self, v: u64) -> Result<(), Full> {
        self.put(&v.to_be_bytes())
    }
    /// Overwrite already-written bytes at `at` (for length fields patched after
    /// the body is known).
    pub fn patch(&mut self, at: usize, b: &[u8]) -> Result<(), Full> {
        let end = at.checked_add(b.len()).ok_or(Full)?;
        if end > self.pos {
            return Err(Full);
        }
        self.buf.get_mut(at..end).ok_or(Full)?.copy_from_slice(b);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_is_bounded() {
        let mut r = Reader::new(&[1, 2, 3, 4, 5]);
        assert_eq!(r.u16_le(), Ok(0x0201));
        assert_eq!(r.u16_be(), Ok(0x0304));
        assert_eq!(r.u32_le(), Err(Short));
        assert_eq!(r.remaining(), 1, "a failed read consumes nothing");
        assert_eq!(r.u8(), Ok(5));
        assert!(r.is_empty());
        assert_eq!(r.take(1), Err(Short));
        assert_eq!(r.take(usize::MAX), Err(Short));
    }

    #[test]
    fn writer_refuses_overflow_and_patches() {
        let mut buf = [0u8; 6];
        let mut w = Writer::new(&mut buf);
        assert!(w.is_empty());
        w.u32_be(0x0102_0304).unwrap();
        assert_eq!(w.u32_le(1), Err(Full));
        assert_eq!(w.len(), 4);
        w.patch(0, &[9]).unwrap();
        assert_eq!(w.patch(3, &[0, 0]), Err(Full), "patch beyond written");
        assert_eq!(w.patch(usize::MAX, &[0]), Err(Full));
        w.u16_le(0x0605).unwrap();
        assert_eq!(w.u8(0), Err(Full));
        assert_eq!(w.into_written(), &[9, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn all_widths() {
        let mut buf = [0u8; 28];
        let mut w = Writer::new(&mut buf);
        w.u64_le(1).unwrap();
        w.u64_be(2).unwrap();
        w.u32_be(3).unwrap();
        w.u16_be(4).unwrap();
        w.u8(5).unwrap();
        w.u8(6).unwrap();
        assert_eq!(w.written().len(), 24);
        let mut r = Reader::new(&buf);
        assert_eq!(r.u64_le(), Ok(1));
        assert_eq!(r.u64_be(), Ok(2));
        assert_eq!(r.u32_be(), Ok(3));
        assert_eq!(r.u16_be(), Ok(4));
        assert_eq!(r.array::<2>(), Ok(&[5, 6]));
        assert_eq!(r.rest(), &[0; 4]);
    }
}
