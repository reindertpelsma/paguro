//! A BGRA byte buffer (the layout of `EFI_GRAPHICS_OUTPUT_BLT_PIXEL`) and the
//! software rasteriser's primitives. Every write is clipped to the canvas
//! and to the caller's clip rectangle, so no draw call can touch memory
//! outside the buffer, whatever its arguments. Integer arithmetic only (the
//! UEFI targets are soft-float).

use crate::theme::{Color, Font, Image, SUBPX, SUBPX_SHIFT};

/// Bytes per pixel: blue, green, red, reserved (alpha in images).
pub const BYTES_PER_PIXEL: usize = 4;
/// The colour channels of a pixel, and where an image keeps its alpha.
pub const COLOR_CHANNELS: usize = 3;
pub const ALPHA: usize = 3;
/// Full coverage / opacity.
pub const OPAQUE: u32 = 255;

/// `dst` under the premultiplied `src` pixel (`src` over `dst`, rounded).
pub(crate) fn over(dst: &mut [u8], src: &[u8]) {
    let inv = OPAQUE - u32::from(src.get(ALPHA).copied().unwrap_or(0));
    for (dc, sc) in dst.iter_mut().zip(src.iter()).take(COLOR_CHANNELS) {
        *dc = (u32::from(*sc) + (u32::from(*dc) * inv + OPAQUE / 2) / OPAQUE).min(OPAQUE) as u8;
    }
}

/// Anti-aliasing of rounded corners: SAMPLES × SAMPLES samples per pixel,
/// at the centres of a grid of 1/(2 × SAMPLES) px cells.
const SAMPLES: i64 = 4;
const SAMPLE_GRID: i64 = 2 * SAMPLES;

/// A rectangle in pixels; `w` or `h` ≤ 0 is empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

impl Rect {
    pub const fn new(x: i32, y: i32, w: i32, h: i32) -> Rect {
        Rect { x, y, w, h }
    }
    pub const fn right(&self) -> i32 {
        self.x.saturating_add(self.w)
    }
    pub const fn bottom(&self) -> i32 {
        self.y.saturating_add(self.h)
    }
    pub const fn is_empty(&self) -> bool {
        self.w <= 0 || self.h <= 0
    }
    pub fn intersect(&self, o: &Rect) -> Rect {
        let x0 = self.x.max(o.x);
        let y0 = self.y.max(o.y);
        let x1 = self.right().min(o.right());
        let y1 = self.bottom().min(o.bottom());
        Rect::new(
            x0,
            y0,
            x1.saturating_sub(x0).max(0),
            y1.saturating_sub(y0).max(0),
        )
    }
    pub fn intersects(&self, o: &Rect) -> bool {
        !self.intersect(o).is_empty()
    }
    pub fn contains(&self, o: &Rect) -> bool {
        o.is_empty()
            || (o.x >= self.x
                && o.y >= self.y
                && o.right() <= self.right()
                && o.bottom() <= self.bottom())
    }
    /// Shrink by `d` on every side.
    pub fn inset(&self, d: i32) -> Rect {
        Rect::new(
            self.x.saturating_add(d),
            self.y.saturating_add(d),
            self.w.saturating_sub(d.saturating_mul(2)),
            self.h.saturating_sub(d.saturating_mul(2)),
        )
    }
}

/// A frame to draw into: `stride` pixels per row, 4 bytes per pixel
/// (blue, green, red, reserved).
pub struct Canvas<'a> {
    buf: &'a mut [u8],
    width: u32,
    height: u32,
    stride: u32,
}

impl<'a> Canvas<'a> {
    /// `None` when the buffer is too small for the geometry.
    pub fn new(buf: &'a mut [u8], width: u32, height: u32, stride: u32) -> Option<Canvas<'a>> {
        let need = (stride as usize)
            .checked_mul(height as usize)?
            .checked_mul(BYTES_PER_PIXEL)?;
        if stride < width
            || buf.len() < need
            || width > i32::MAX as u32 / 2
            || height > i32::MAX as u32 / 2
        {
            return None;
        }
        Some(Canvas {
            buf,
            width,
            height,
            stride,
        })
    }

    pub fn width(&self) -> u32 {
        self.width
    }
    pub fn height(&self) -> u32 {
        self.height
    }
    pub fn stride(&self) -> u32 {
        self.stride
    }
    pub fn bytes(&self) -> &[u8] {
        self.buf
    }
    pub fn bounds(&self) -> Rect {
        Rect::new(0, 0, self.width as i32, self.height as i32)
    }

    /// The BGRA bytes of pixel (`x`, `y`), if on the canvas.
    pub fn pixel(&self, x: i32, y: i32) -> Option<[u8; BYTES_PER_PIXEL]> {
        let (x, y) = (u32::try_from(x).ok()?, u32::try_from(y).ok()?);
        if x >= self.width || y >= self.height {
            return None;
        }
        let i = ((y as usize) * (self.stride as usize) + x as usize) * BYTES_PER_PIXEL;
        <[u8; BYTES_PER_PIXEL]>::try_from(self.buf.get(i..i + BYTES_PER_PIXEL)?).ok()
    }

    /// Row `y`, pixels `x0..x1` (already clipped by the caller).
    fn span(&mut self, y: i32, x0: i32, x1: i32) -> &mut [u8] {
        let (Ok(y), Ok(x0), Ok(x1)) =
            (usize::try_from(y), usize::try_from(x0), usize::try_from(x1))
        else {
            return &mut [];
        };
        let row = y * self.stride as usize;
        self.buf
            .get_mut((row + x0) * BYTES_PER_PIXEL..(row + x1.max(x0)) * BYTES_PER_PIXEL)
            .unwrap_or(&mut [])
    }

    /// Wipe the whole buffer (all zero).
    pub fn clear(&mut self) {
        self.buf.fill(0);
    }

    /// Fill the whole canvas with `c`.
    pub fn fill(&mut self, c: Color) {
        let r = self.bounds();
        self.fill_rect(r, c, r);
    }

    fn fill_rect(&mut self, r: Rect, c: Color, clip: Rect) {
        let r = r.intersect(&clip).intersect(&self.bounds());
        if r.is_empty() {
            return;
        }
        let px = [c.b, c.g, c.r, 0];
        for y in r.y..r.bottom() {
            for p in self
                .span(y, r.x, r.right())
                .chunks_exact_mut(BYTES_PER_PIXEL)
            {
                p.copy_from_slice(&px);
            }
        }
    }

    fn blend_px(&mut self, x: i32, y: i32, c: Color, a: u8) {
        if a == 0 || x < 0 || y < 0 || x >= self.width as i32 || y >= self.height as i32 {
            return;
        }
        if let Some(p) = self.span(y, x, x + 1).get_mut(..BYTES_PER_PIXEL) {
            blend(p, c, a);
        }
    }

    /// A filled rectangle with anti-aliased corners of radius `radius`.
    pub fn round_rect(&mut self, r: Rect, radius: i32, c: Color, clip: Rect) {
        let area = r.intersect(&clip).intersect(&self.bounds());
        if area.is_empty() {
            return;
        }
        let rad = radius.clamp(0, r.w.min(r.h) / 2);
        if rad == 0 {
            self.fill_rect(area, c, area);
            return;
        }
        for y in area.y..area.bottom() {
            let in_corner_rows = y < r.y + rad || y >= r.bottom() - rad;
            if !in_corner_rows {
                self.fill_rect(Rect::new(area.x, y, area.w, 1), c, area);
                continue;
            }
            let solid0 = (r.x + rad).max(area.x);
            let solid1 = (r.right() - rad).min(area.right());
            for x in area.x..solid0.min(area.right()) {
                self.blend_px(x, y, c, coverage(&r, rad, x, y));
            }
            if solid1 > solid0 {
                self.fill_rect(Rect::new(solid0, y, solid1 - solid0, 1), c, area);
            }
            for x in solid1.max(area.x).max(solid0)..area.right() {
                self.blend_px(x, y, c, coverage(&r, rad, x, y));
            }
        }
    }

    /// The outline of a rounded rectangle, `width` pixels thick, inside `r`.
    pub fn round_stroke(&mut self, r: Rect, radius: i32, width: i32, c: Color, clip: Rect) {
        let area = r.intersect(&clip).intersect(&self.bounds());
        if area.is_empty() || width <= 0 {
            return;
        }
        let rad = radius.clamp(0, r.w.min(r.h) / 2);
        let inner = r.inset(width);
        let irad = (rad - width).max(0);
        let band = width.max(rad);
        for y in area.y..area.bottom() {
            let edge_row = y < r.y + band || y >= r.bottom() - band;
            let mut x = area.x;
            while x < area.right() {
                if !edge_row && x >= r.x + band && x < r.right() - band {
                    x = r.right() - band;
                    continue;
                }
                let outer = coverage(&r, rad, x, y);
                let inn = if inner.is_empty() {
                    0
                } else {
                    coverage(&inner, irad, x, y)
                };
                self.blend_px(x, y, c, outer.saturating_sub(inn));
                x += 1;
            }
        }
    }

    /// Composite a premultiplied BGRA image with its top-left at (`x`, `y`).
    pub fn blit(&mut self, img: &Image, x: i32, y: i32, clip: Rect) {
        let r = Rect::new(x, y, img.w as i32, img.h as i32);
        let area = r.intersect(&clip).intersect(&self.bounds());
        if area.is_empty() {
            return;
        }
        for yy in area.y..area.bottom() {
            let sy = (yy - y) as usize;
            let sx0 = (area.x - x) as usize;
            let src0 = (sy * img.w as usize + sx0) * BYTES_PER_PIXEL;
            let src = img
                .px
                .get(src0..src0 + (area.w as usize) * BYTES_PER_PIXEL)
                .unwrap_or(&[]);
            let dst = self.span(yy, area.x, area.right());
            for (d, s) in dst
                .chunks_exact_mut(BYTES_PER_PIXEL)
                .zip(src.chunks_exact(BYTES_PER_PIXEL))
            {
                over(d, s);
            }
        }
    }

    /// Draw `text` with the pen starting at (`x`, `baseline`); returns the
    /// pen position after it (px). Characters without a glyph draw the
    /// fallback.
    pub fn text(
        &mut self,
        font: &Font,
        x: i32,
        baseline: i32,
        text: impl Iterator<Item = char>,
        c: Color,
        clip: Rect,
    ) -> i32 {
        let clip = clip.intersect(&self.bounds());
        let mut pen = i64::from(x) * SUBPX;
        for ch in text {
            let Some(g) = font.glyph_or_fallback(ch) else {
                continue;
            };
            let gx = i32::try_from((pen + SUBPX / 2) >> SUBPX_SHIFT)
                .unwrap_or(i32::MAX)
                .saturating_add(i32::from(g.x));
            let gy = baseline.saturating_add(i32::from(g.y));
            let gr = Rect::new(gx, gy, i32::from(g.w), i32::from(g.h)).intersect(&clip);
            if !gr.is_empty() {
                font.pixels(g, |px, py, a| {
                    let (xx, yy) = (gx.saturating_add(px as i32), gy.saturating_add(py as i32));
                    if xx >= gr.x && xx < gr.right() && yy >= gr.y && yy < gr.bottom() {
                        self.blend_px(xx, yy, c, a);
                    }
                });
            }
            pen += i64::from(g.adv);
        }
        i32::try_from((pen + SUBPX - 1) >> SUBPX_SHIFT).unwrap_or(i32::MAX)
    }
}

fn blend(p: &mut [u8], c: Color, a: u8) {
    let a = u32::from(a);
    let mix = |d: u8, s: u8| -> u8 {
        let (d, s) = (u32::from(d), u32::from(s));
        ((d * (OPAQUE - a) + s * a + OPAQUE / 2) / OPAQUE) as u8
    };
    if let [b, g, r, ..] = p {
        *b = mix(*b, c.b);
        *g = mix(*g, c.g);
        *r = mix(*r, c.r);
    }
}

/// Coverage 0..=255 of pixel (`x`, `y`) by the rounded rectangle `r` with
/// corner radius `rad`, from a 4×4 grid of samples.
fn coverage(r: &Rect, rad: i32, x: i32, y: i32) -> u8 {
    if x < r.x || y < r.y || x >= r.right() || y >= r.bottom() {
        return 0;
    }
    let (cx0, cx1) = (r.x + rad, r.right() - rad);
    let (cy0, cy1) = (r.y + rad, r.bottom() - rad);
    let in_x = x >= cx0 && x < cx1;
    let in_y = y >= cy0 && y < cy1;
    if rad == 0 || in_x || in_y {
        return OPAQUE as u8;
    }
    // Corner centre, in sample-grid cells.
    let ccx = i64::from(if x < cx0 { cx0 } else { cx1 }) * SAMPLE_GRID;
    let ccy = i64::from(if y < cy0 { cy0 } else { cy1 }) * SAMPLE_GRID;
    let rr = i64::from(rad) * SAMPLE_GRID;
    let mut n = 0u32;
    for j in 0..SAMPLES {
        for i in 0..SAMPLES {
            let sx = i64::from(x) * SAMPLE_GRID + 2 * i + 1;
            let sy = i64::from(y) * SAMPLE_GRID + 2 * j + 1;
            let (dx, dy) = (sx - ccx, sy - ccy);
            if dx * dx + dy * dy <= rr * rr {
                n += 1;
            }
        }
    }
    (n * OPAQUE / (SAMPLES * SAMPLES) as u32) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec;

    #[test]
    fn geometry_checks() {
        let mut b = vec![0u8; 16];
        assert!(Canvas::new(&mut b, 2, 2, 2).is_some());
        assert!(Canvas::new(&mut b, 3, 2, 2).is_none(), "stride < width");
        assert!(Canvas::new(&mut b, 2, 3, 2).is_none(), "buffer too small");
        assert!(Canvas::new(&mut b, u32::MAX, 1, u32::MAX).is_none());
    }

    #[test]
    fn drawing_is_clipped_everywhere() {
        let mut b = vec![0u8; 10 * 10 * 4 + 7];
        let sentinel = b.len() - 7;
        b[sentinel..].fill(0xee);
        let mut c = Canvas::new(&mut b, 10, 10, 10).unwrap();
        let red = Color::rgb(255, 0, 0);
        let all = Rect::new(-100, -100, 1000, 1000);
        for r in [
            Rect::new(-5, -5, 30, 30),
            Rect::new(8, 8, 50, 50),
            Rect::new(i32::MAX - 3, 0, 10, 10),
            Rect::new(i32::MIN, i32::MIN, i32::MAX, i32::MAX),
            Rect::new(3, 3, -4, 5),
        ] {
            c.round_rect(r, 4, red, all);
            c.round_stroke(r, 7, 2, red, all);
        }
        assert_eq!(c.pixel(9, 9), Some([0, 0, 255, 0]));
        assert_eq!(c.pixel(10, 0), None);
        assert!(
            b[sentinel..].iter().all(|&x| x == 0xee),
            "nothing past the frame"
        );
    }

    #[test]
    fn corners_are_anti_aliased() {
        let mut b = vec![0u8; 20 * 20 * 4];
        let mut c = Canvas::new(&mut b, 20, 20, 20).unwrap();
        let r = Rect::new(0, 0, 20, 20);
        c.round_rect(r, 8, Color::rgb(0, 0, 255), r);
        assert_eq!(c.pixel(0, 0).unwrap()[0], 0, "outside the corner");
        assert_eq!(c.pixel(10, 10).unwrap()[0], 255);
        let edge = c.pixel(1, 3).unwrap()[0];
        assert!(edge > 0 && edge < 255, "partial coverage {edge}");
    }
}
