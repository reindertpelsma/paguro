//! `paguro-ui` — the loader's graphical front end (INTERFACES.md §13).
//!
//! ```text
//! (Screen, View, Theme, width×height) --layout--> DrawList --paint--> Canvas (BGRA)
//! ```
//!
//! - [`builtin`]: the theme compiled in by `build.rs` from `themes/<name>/`
//!   (`PAGURO_THEME`, `PAGURO_LANG`) — statics only; no PNG, TOML or font
//!   parser exists in this crate.
//! - [`layout`]: pure layout into a fixed-capacity [`draw::DrawList`].
//! - [`canvas`]: the software rasteriser, clipped on every write.
//! - [`driver`]: the prompt loop over a [`driver::Display`] (the GOP in
//!   `paguro-efi`, a memory buffer in tests) and the text-console fallback.
//!
//! `no_std`, no allocation, no `unsafe`, integer arithmetic only.
#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::indexing_slicing))]

pub mod canvas;
pub mod display;
pub mod draw;
pub mod driver;
pub mod fixtures;
pub mod layout;
pub mod pointer;
pub mod text;
pub mod textui;
pub mod theme;

/// The string catalogue ([`strings::Str`]), generated from
/// `paguro_theme::spec::STRINGS`.
pub mod strings {
    include!(concat!(env!("OUT_DIR"), "/strings.rs"));
}

/// The compiled-in theme and its variants: [`builtin::THEMES`].
pub mod builtin {
    #![allow(clippy::unreadable_literal, clippy::large_const_arrays)]
    use crate::strings::STR_COUNT;
    use crate::theme::*;
    include!(concat!(env!("OUT_DIR"), "/theme.rs"));
}

pub use canvas::{Canvas, Rect};
pub use draw::{DrawList, paint};
pub use layout::{Toast, View, layout, supported};

/// Lay out and paint `screen` into `canvas`. `false` (and nothing drawn)
/// when the canvas is below the supported size: use the text console.
pub fn render(
    screen: &paguro_boot::Screen,
    view: &View<'_>,
    theme: &theme::Theme,
    canvas: &mut Canvas<'_>,
) -> bool {
    let (w, h) = (canvas.width(), canvas.height());
    if !supported(w, h) {
        return false;
    }
    let mut list = DrawList::new();
    layout(screen, view, theme, w, h, &mut list);
    paint(&list, canvas);
    true
}
