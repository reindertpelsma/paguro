//! Helpers for the layout-only structs that document on-disk and wire
//! formats.
//!
//! Fixed-layout structures are declared as `#[repr(C, packed)]` structs that
//! mirror their specification. They are never instantiated or cast onto a
//! buffer: `core::mem::offset_of!` and [`field_size`] turn them into the
//! offsets and widths that feed the bounds-checked readers in
//! [`crate::bytes`], and const assertions pin them to the documented values.

/// The size of one field of a layout struct: `field_size(|h: Hdr| h.crc)`.
/// The closure is never called; it only names the field's type.
pub const fn field_size<S, T>(_: fn(S) -> T) -> usize {
    core::mem::size_of::<T>()
}
