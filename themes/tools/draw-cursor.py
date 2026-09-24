#!/usr/bin/env python3
"""Draw the pointer cursors of the default theme: a classic arrow, light with
a dark outline for the dark variants and dark with a light outline for the
light ones (INTERFACES.md §13.2b).

Pure Python (standard library only) and deterministic:

    python3 themes/tools/draw-cursor.py [OUT_DIR]

writes cursor-on-dark.png and cursor-on-light.png (default OUT_DIR
themes/default/images). The arrow's tip is the image's top-left pixel: the
loader draws the image with that pixel at the pointer's position.

The arrow is a polygon on a 24×36 grid, drawn 4× larger with 4×4
supersampling; build.rs premultiplies and scales it per scale step.
"""

import struct
import sys
import zlib

SCALE = 4
W, H = 18 * SCALE, 27 * SCALE
# The classic arrow, tip at (0, 0), in units of the 18×27 design grid.
ARROW = [(0.6, 0.6), (0.6, 21.5), (5.5, 16.8), (9.0, 25.0), (12.2, 23.6),
         (8.8, 15.6), (15.4, 15.6)]
OUTLINE = 1.35  # design units

VARIANTS = {
    # fill, outline
    "cursor-on-dark.png": ((0xFF, 0xFF, 0xFF), (0x10, 0x12, 0x16)),
    "cursor-on-light.png": ((0x16, 0x19, 0x1F), (0xFF, 0xFF, 0xFF)),
}


def inside(poly, x, y):
    c = False
    n = len(poly)
    for i in range(n):
        (x0, y0), (x1, y1) = poly[i], poly[(i + 1) % n]
        if (y0 > y) != (y1 > y) and x < (x1 - x0) * (y - y0) / (y1 - y0) + x0:
            c = not c
    return c


def edge_dist(poly, x, y):
    best = 1e9
    n = len(poly)
    for i in range(n):
        (ax, ay), (bx, by) = poly[i], poly[(i + 1) % n]
        dx, dy = bx - ax, by - ay
        ll = dx * dx + dy * dy
        t = max(0.0, min(1.0, ((x - ax) * dx + (y - ay) * dy) / ll)) if ll else 0.0
        px, py = ax + t * dx - x, ay + t * dy - y
        best = min(best, (px * px + py * py) ** 0.5)
    return best


def render(fill, line):
    rgba = bytearray(W * H * 4)
    ss = 4
    for y in range(H):
        for x in range(W):
            f = o = 0
            for sy in range(ss):
                for sx in range(ss):
                    gx = (x + (sx + 0.5) / ss) / SCALE
                    gy = (y + (sy + 0.5) / ss) / SCALE
                    if inside(ARROW, gx, gy):
                        if edge_dist(ARROW, gx, gy) < OUTLINE:
                            o += 1
                        else:
                            f += 1
                    elif edge_dist(ARROW, gx, gy) < 0.35:
                        o += 1
            n = ss * ss
            a = (f + o) / n
            if a == 0:
                continue
            i = (y * W + x) * 4
            for c in range(3):
                rgba[i + c] = round((fill[c] * f + line[c] * o) / (f + o))
            rgba[i + 3] = round(a * 255)
    return rgba


def png(rgba):
    raw = b"".join(b"\0" + bytes(rgba[y * W * 4:(y + 1) * W * 4]) for y in range(H))

    def chunk(t, data):
        c = struct.pack(">I", len(data)) + t + data
        return c + struct.pack(">I", zlib.crc32(t + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", W, H, 8, 6, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "themes/default/images"
    for name, (fill, line) in VARIANTS.items():
        with open(f"{out}/{name}", "wb") as f:
            f.write(png(render(fill, line)))


if __name__ == "__main__":
    main()
