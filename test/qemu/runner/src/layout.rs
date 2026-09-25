//! Offsets into fixed-layout firmware structures, derived from layout-only
//! `#[repr(C, packed)]` mirrors of the spec. The mirrors are never
//! instantiated or cast onto buffers: [`field!`] only turns a field into the
//! byte range the bounds-checked slice accessors use.

/// The byte range of field `$f` in the layout-only struct `$t`.
macro_rules! field {
    ($t:ty, $f:ident) => {{
        let start = core::mem::offset_of!($t, $f);
        start..start + paguro_core::layout::field_size(|s: $t| s.$f)
    }};
}
pub(crate) use field;
