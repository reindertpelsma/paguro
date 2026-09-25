//! The pointer (INTERFACES.md §13.2b), as a pure state machine the prompt
//! loop drives: protocol reports in, cursor rectangles to redraw and clicks
//! out. The firmware adapter only reads `EFI_SIMPLE_POINTER_PROTOCOL` /
//! `EFI_ABSOLUTE_POINTER_PROTOCOL` and blits.
//!
//! - The cursor is hidden until the pointer first moves, and hidden again by
//!   the next key press.
//! - It lives on one display: frame 0's first display, in its pixels.
//! - Moving it redraws only the rectangles under the old and the new
//!   position ([`Update::dirty`]); the cursor is composited at blit time
//!   ([`composite`]) and never drawn into the frame, so other displays
//!   showing the same frame never see it.
//! - A click is the left button going down; what it hits comes from the
//!   layout's element rectangles ([`crate::draw::Hits`]).
//! - Reports are external data (a USB device's): relative motion is
//!   clamped, an absolute report with an empty range is ignored, and
//!   nothing here can panic or leave the screen.

use crate::canvas::{BYTES_PER_PIXEL, Rect, over};
use crate::theme::Image;

/// Relative motion is scaled to this many pixels per millimetre when the
/// device reports its resolution.
pub const PX_PER_MM: i64 = 4;
/// The largest motion one report can cause, in pixels per axis.
pub const MAX_STEP: i32 = 4096;
/// The most wheel notches one report can scroll.
pub const MAX_WHEEL: i32 = 16;

/// One pointer report, as the adapter read it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Report {
    /// `EFI_SIMPLE_POINTER_STATE`: counts moved since the last report, the
    /// device's counts per millimetre (0: unknown), the left button.
    Relative {
        dx: i32,
        dy: i32,
        /// The wheel (`RelativeMovementZ`): positive is towards the user
        /// (down the list).
        dz: i32,
        resolution: u64,
        left: bool,
    },
    /// `EFI_ABSOLUTE_POINTER_STATE` with the mode's range: a position
    /// anywhere in `[min, max]` maps onto the whole display. `touch`: the
    /// touch-active or primary button bit.
    Absolute {
        x: u64,
        y: u64,
        min: (u64, u64),
        max: (u64, u64),
        touch: bool,
    },
}

/// What a report changed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Update {
    /// Redraw these (the old and the new cursor rectangles), and nothing
    /// else, for the move.
    pub dirty: [Option<Rect>; 2],
    /// The left button went down at this position.
    pub click: Option<(i32, i32)>,
    /// Wheel notches: positive scrolls down.
    pub wheel: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pointer {
    x: i32,
    y: i32,
    visible: bool,
    down: bool,
    /// The display the cursor lives on.
    bounds: (u32, u32),
    /// The cursor image's size.
    size: (i32, i32),
}

impl Default for Pointer {
    fn default() -> Self {
        Self::new()
    }
}

impl Pointer {
    pub const fn new() -> Pointer {
        Pointer {
            x: 0,
            y: 0,
            visible: false,
            down: false,
            bounds: (0, 0),
            size: (0, 0),
        }
    }

    /// The display the cursor lives on changed size (or is first known);
    /// the position is kept inside it, starting in the middle.
    pub fn set_bounds(&mut self, w: u32, h: u32) {
        if self.bounds == (0, 0) {
            self.x = i32::try_from(w / 2).unwrap_or(0);
            self.y = i32::try_from(h / 2).unwrap_or(0);
        }
        self.bounds = (w, h);
        self.clamp();
    }

    /// The cursor image in use (its size bounds the dirty rectangles).
    pub fn set_image(&mut self, img: &Image) {
        self.size = (
            i32::try_from(img.w).unwrap_or(0),
            i32::try_from(img.h).unwrap_or(0),
        );
    }

    pub const fn visible(&self) -> bool {
        self.visible
    }

    pub const fn position(&self) -> (i32, i32) {
        (self.x, self.y)
    }

    /// The cursor's rectangle when it is shown.
    pub fn rect(&self) -> Option<Rect> {
        self.visible
            .then(|| Rect::new(self.x, self.y, self.size.0, self.size.1))
    }

    fn clamp(&mut self) {
        let w = i32::try_from(self.bounds.0).unwrap_or(i32::MAX).max(1);
        let h = i32::try_from(self.bounds.1).unwrap_or(i32::MAX).max(1);
        self.x = self.x.clamp(0, w - 1);
        self.y = self.y.clamp(0, h - 1);
    }

    /// A key was pressed: hide the cursor. The rectangle to redraw, if it
    /// was shown.
    pub fn hide(&mut self) -> Option<Rect> {
        let r = self.rect();
        self.visible = false;
        r
    }

    /// Apply one report.
    pub fn report(&mut self, r: Report) -> Update {
        let before = self.rect();
        let old = (self.x, self.y);
        let mut wheel = 0;
        let (moved, pressed) = match r {
            Report::Relative {
                dx,
                dy,
                dz,
                resolution,
                left,
            } => {
                wheel = dz.clamp(-MAX_WHEEL, MAX_WHEEL);
                let scale = |d: i32| -> i32 {
                    let d = i64::from(d);
                    let px = if resolution == 0 {
                        d
                    } else {
                        let r = i64::try_from(resolution).unwrap_or(i64::MAX);
                        d.saturating_mul(PX_PER_MM) / r
                    };
                    px.clamp(-i64::from(MAX_STEP), i64::from(MAX_STEP)) as i32
                };
                self.x = self.x.saturating_add(scale(dx));
                self.y = self.y.saturating_add(scale(dy));
                (dx != 0 || dy != 0, left)
            }
            Report::Absolute {
                x,
                y,
                min,
                max,
                touch,
            } => {
                if max.0 <= min.0 || max.1 <= min.1 {
                    // A device without a range: nothing to map.
                    return Update::default();
                }
                let map = |v: u64, lo: u64, hi: u64, px: u32| -> i32 {
                    let v = v.clamp(lo, hi) - lo;
                    let span = u128::from(hi - lo);
                    let p = u128::from(v) * u128::from(px.saturating_sub(1)) / span;
                    i32::try_from(p).unwrap_or(i32::MAX)
                };
                self.x = map(x, min.0, max.0, self.bounds.0);
                self.y = map(y, min.1, max.1, self.bounds.1);
                ((self.x, self.y) != old || !self.visible, touch)
            }
        };
        self.clamp();
        let click = (pressed && !self.down).then_some((self.x, self.y));
        self.down = pressed;
        let mut u = Update {
            dirty: [None, None],
            click,
            wheel,
        };
        if moved && ((self.x, self.y) != old || !self.visible) {
            self.visible = true;
            u.dirty = [before, self.rect()];
        } else if click.is_some() && !self.visible {
            // A tap without motion still shows where it landed.
            self.visible = true;
            u.dirty = [None, self.rect()];
        }
        u
    }
}

/// The cursor as drawn: an image with its top-left pixel at (`x`, `y`).
#[derive(Clone, Copy, Debug)]
pub struct Cursor {
    pub img: &'static Image,
    pub x: i32,
    pub y: i32,
}

impl Cursor {
    pub fn rect(&self) -> Rect {
        Rect::new(
            self.x,
            self.y,
            i32::try_from(self.img.w).unwrap_or(0),
            i32::try_from(self.img.h).unwrap_or(0),
        )
    }
}

/// Copy `r` of a packed `fw`×`fh` BGRA frame into `out` (packed, `r.w`
/// pixels per row), with `cursor` composited where it overlaps. `r` is
/// clipped to the frame; returns the rectangle written (empty when `out`
/// is too small or nothing is left).
pub fn composite(
    frame: &[u8],
    fw: u32,
    fh: u32,
    r: Rect,
    cursor: Option<&Cursor>,
    out: &mut [u8],
) -> Rect {
    let fwi = i32::try_from(fw).unwrap_or(0);
    let fhi = i32::try_from(fh).unwrap_or(0);
    let r = r.intersect(&Rect::new(0, 0, fwi, fhi));
    if r.is_empty() {
        return Rect::default();
    }
    let (w, h) = (r.w as usize, r.h as usize);
    const BPP: usize = BYTES_PER_PIXEL;
    if out.len() < w * h * BPP || frame.len() < (fw as usize) * (fh as usize) * BPP {
        return Rect::default();
    }
    for row in 0..h {
        let src = ((r.y as usize + row) * fw as usize + r.x as usize) * BPP;
        if let (Some(d), Some(s)) = (
            out.get_mut(row * w * BPP..(row + 1) * w * BPP),
            frame.get(src..src + w * BPP),
        ) {
            d.copy_from_slice(s);
        }
    }
    let Some(c) = cursor else {
        return r;
    };
    let cr = c.rect().intersect(&r);
    for yy in cr.y..cr.bottom() {
        for xx in cr.x..cr.right() {
            let si = (((yy - c.y) as usize) * c.img.w as usize + (xx - c.x) as usize) * BPP;
            let di = (((yy - r.y) as usize) * w + (xx - r.x) as usize) * BPP;
            let (Some(s), Some(d)) = (c.img.px.get(si..si + BPP), out.get_mut(di..di + BPP)) else {
                continue;
            };
            over(d, s);
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    static IMG: Image = Image {
        w: 2,
        h: 2,
        px: &[
            255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 128, 128, 128, 128,
        ],
    };

    fn ptr() -> Pointer {
        let mut p = Pointer::new();
        p.set_bounds(100, 50);
        p.set_image(&IMG);
        p
    }

    fn rel(dx: i32, dy: i32, left: bool) -> Report {
        Report::Relative {
            dx,
            dy,
            dz: 0,
            resolution: 0,
            left,
        }
    }

    #[test]
    fn shown_on_first_motion_hidden_by_a_key() {
        let mut p = ptr();
        assert!(!p.visible());
        assert_eq!(p.position(), (50, 25), "starts in the middle");
        assert_eq!(p.hide(), None, "nothing to redraw while hidden");
        let u = p.report(rel(0, 0, false));
        assert_eq!(u, Update::default(), "no motion: still hidden");
        let u = p.report(rel(3, -2, false));
        assert!(p.visible());
        assert_eq!(u.dirty, [None, Some(Rect::new(53, 23, 2, 2))]);
        let u = p.report(rel(1, 1, false));
        assert_eq!(
            u.dirty,
            [Some(Rect::new(53, 23, 2, 2)), Some(Rect::new(54, 24, 2, 2))],
            "only the old and new rectangles"
        );
        assert_eq!(p.hide(), Some(Rect::new(54, 24, 2, 2)));
        assert!(!p.visible());
    }

    #[test]
    fn clicks_are_button_down_edges() {
        let mut p = ptr();
        let u = p.report(rel(0, 0, true));
        assert_eq!(u.click, Some((50, 25)));
        assert!(p.visible(), "a click shows where it landed");
        assert_eq!(p.report(rel(0, 0, true)).click, None, "held");
        assert_eq!(p.report(rel(5, 0, true)).click, None, "dragged");
        assert_eq!(p.report(rel(0, 0, false)).click, None, "released");
        assert_eq!(p.report(rel(0, 0, true)).click, Some((55, 25)));
    }

    #[test]
    fn bounds_and_scaling() {
        let mut p = ptr();
        p.report(rel(-10_000, 10_000, false));
        assert_eq!(p.position(), (0, 49));
        p.report(rel(i32::MAX, i32::MIN, false));
        assert_eq!(p.position(), (99, 0));
        // 8 counts per mm: 16 counts is 2 mm, 8 px.
        p.report(Report::Relative {
            dx: -16,
            dy: 16,
            dz: 0,
            resolution: 8,
            left: false,
        });
        assert_eq!(p.position(), (91, 8));
        p.report(Report::Relative {
            dx: i32::MIN,
            dy: 1,
            dz: 0,
            resolution: u64::MAX,
            left: false,
        });
        assert_eq!(p.position(), (91, 8), "huge resolution: sub-pixel motion");
        // The display shrinks: the cursor stays on it.
        p.set_bounds(20, 5);
        assert_eq!(p.position(), (19, 4));
    }

    #[test]
    fn the_wheel_scrolls_without_moving_the_cursor() {
        let mut p = ptr();
        let u = p.report(Report::Relative {
            dx: 0,
            dy: 0,
            dz: 2,
            resolution: 0,
            left: false,
        });
        assert_eq!(u.wheel, 2);
        assert_eq!(u.dirty, [None, None]);
        assert!(!p.visible());
        let u = p.report(Report::Relative {
            dx: 0,
            dy: 0,
            dz: i32::MIN,
            resolution: 0,
            left: false,
        });
        assert_eq!(u.wheel, -16, "clamped");
    }

    #[test]
    fn absolute_reports_map_the_range() {
        let mut p = ptr();
        let abs = |x, y, touch| Report::Absolute {
            x,
            y,
            min: (0, 0),
            max: (0x7fff, 0x7fff),
            touch,
        };
        p.report(abs(0x7fff, 0, false));
        assert_eq!(p.position(), (99, 0));
        assert!(p.visible());
        let u = p.report(abs(0x4000, 0x4000, true));
        assert_eq!(u.click, Some((49, 24)));
        p.report(abs(u64::MAX, u64::MAX, false));
        assert_eq!(p.position(), (99, 49), "clamped into the range");
        // Offset ranges.
        let u = p.report(Report::Absolute {
            x: 150,
            y: 100,
            min: (100, 100),
            max: (200, 200),
            touch: true,
        });
        assert_eq!(u.click, Some((49, 0)));
        // A device without a range (a protocol error): ignored.
        for (min, max) in [((0, 0), (0, 0)), ((5, 0), (4, 10)), ((0, 9), (10, 9))] {
            let before = p;
            let u = p.report(Report::Absolute {
                x: 3,
                y: 3,
                min,
                max,
                touch: true,
            });
            assert_eq!(u, Update::default());
            assert_eq!(p, before);
        }
    }

    #[test]
    fn composite_blends_only_where_the_cursor_is() {
        // A 4×3 frame of grey 10.
        let frame = [10u8; 4 * 3 * 4];
        let c = Cursor {
            img: &IMG,
            x: 2,
            y: 1,
        };
        let mut out = [0u8; 4 * 3 * 4];
        let r = composite(&frame, 4, 3, Rect::new(1, 0, 3, 3), Some(&c), &mut out);
        assert_eq!(r, Rect::new(1, 0, 3, 3));
        let px = |x: usize, y: usize| &out[(y * 3 + x) * 4..(y * 3 + x) * 4 + 3];
        assert_eq!(px(0, 0), [10, 10, 10]);
        assert_eq!(px(1, 1), [255, 255, 255], "opaque white");
        assert_eq!(px(2, 1), [10, 10, 10], "transparent");
        assert_eq!(px(2, 2), [133, 133, 133], "half: 128 + 10 × 127/255");
        // Clipped to the frame; too small an output writes nothing.
        let r = composite(&frame, 4, 3, Rect::new(-5, -5, 7, 6), None, &mut out);
        assert_eq!(r, Rect::new(0, 0, 2, 1));
        assert!(composite(&frame, 4, 3, Rect::new(0, 0, 4, 3), None, &mut [0; 8]).is_empty());
        assert!(composite(&frame, 9, 9, Rect::new(0, 0, 1, 1), None, &mut out).is_empty());
    }
}
