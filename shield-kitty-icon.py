#!/usr/bin/env python3
# Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# Copyright (c) 2026 Living Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# Licensed under Living Sin Proprietary License (LSPL-1.0)
# See LICENSE file for details.
"""
shield-kitty-icon.py — render the Shield Kitty nyan cat to a PNG.

Pure stdlib (zlib + struct), so the notification icon works even when Qt is not
importable. Same art module as the fullscreen view, so the notification icon and
the fullscreen kitty are the same cat.

Writes to $XDG_CACHE_HOME/shield-kitty/nyan-<variant>.png and prints the path.
"""

import os
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
try:
    from shield_kitty_art import CAT, TART, TRAIL, FLAME
except ImportError:  # art module missing: render a plain red block, never crash
    CAT = ["..BBBBBBBB..", ".BBBBBBBBBB.", "BBBBBBBBBBBB", "BBBBBBBBBBBB",
           "BBBBBBBBBBBB", "BBBBBBBBBBBB", "BBBBBBBBBBBB", "BBBBBBBBBBBB",
           ".BBBBBBBBBB.", "..BBBBBBBB.."]
    TART = TRAIL = FLAME = []

RAINBOW = {
    "r": (255, 45, 45),
    "o": (255, 140, 0),
    "y": (255, 215, 0),
    "g": (60, 220, 90),
    "c": (60, 200, 230),
    "b": (70, 110, 255),
    "v": (170, 90, 240),
    "p": (255, 120, 190),
}

# Critical = cat on blood red. Warning = same cat, amber field.
VARIANTS = {
    "critical": {
        "bg": (18, 0, 0),
        "body": (255, 45, 45),
        "ink": (26, 0, 0),
        "tart": (214, 140, 60),
        "icing": (255, 220, 240),
    },
    "warning": {
        "bg": (26, 20, 0),
        "body": (255, 176, 0),
        "ink": (26, 18, 0),
        "tart": (200, 140, 60),
        "icing": (255, 245, 220),
    },
}

CELL = 10          # pixels per art cell
MARGIN = 5         # padding around the art


def render(variant="critical", cell=CELL):
    """Return (width, height, rows) with rows a list of (r,g,b) tuples."""
    style = VARIANTS.get(variant, VARIANTS["critical"])
    bg = style["bg"]

    art_rows = [CAT, TART, FLAME] if TART else [CAT, FLAME]
    n_rows = sum(len(g) for g in art_rows)
    n_cols = max(len(r) for g in art_rows for r in g)
    trail_w = len(TRAIL[0]) if TRAIL else 0

    w = (n_cols + trail_w) * cell + MARGIN * 2
    h = n_rows * cell + MARGIN * 2

    px = [[bg for _ in range(w)] for _ in range(h)]

    def put(x, y, color, alpha=1.0):
        if 0 <= x < w and 0 <= y < h:
            px[y][x] = color if alpha >= 1.0 else tuple(
                int(bg[i] + (color[i] - bg[i]) * alpha) for i in range(3)
            )

    def draw(grid, top, left, palette):
        for r, line in enumerate(grid):
            for c, ch in enumerate(line):
                if ch == ".":
                    continue
                color = palette.get(ch)
                if color is None:
                    continue
                for dy in range(cell):
                    for dx in range(cell):
                        put(left + c * cell + dx, top + r * cell + dy, color)

    pal = {
        "B": style["body"],
        "K": style["ink"],
        "W": (255, 255, 255),
        "T": style["icing"],
        "F": style["tart"],
        "Y": (255, 208, 0),
        "O": (255, 90, 0),
    }
    pal.update(RAINBOW)

    # Rainbow trail: the tart rows only, so the trail lines up with the body.
    if TRAIL:
        cat_h = len(CAT)
        tart_h = len(TART) if TART else 0
        top = MARGIN + cat_h * cell
        # Rainbow stripes: TART maps 1:1 onto the trail rows.
        for r, line in enumerate(TRAIL):
            ty = top + (r * tart_h // len(TRAIL)) * cell
            draw([line], ty, MARGIN, pal)

    top = MARGIN
    for grid in art_rows:
        draw(grid, top, MARGIN + (len(TRAIL[0]) * cell if TRAIL else 0), pal)
        top += len(grid) * cell

    return w, h, px


def write_png(path, w, h, rows):
    raw = bytearray()
    for row in rows:
        raw.append(0)  # filter type 0
        for r, g, b in row:
            raw += bytes((r, g, b))

    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(bytes(raw), 9))
    png += chunk(b"IEND", b"")
    path.write_bytes(png)


def icon_path(variant="critical"):
    """Path to the icon, rendering it if missing. None on failure."""
    cache = Path(os.environ.get("XDG_CACHE_HOME",
                                Path.home() / ".cache")) / "shield-kitty"
    try:
        cache.mkdir(parents=True, exist_ok=True)
        out = cache / "nyan-{}.png".format(variant)
        if out.exists() and out.stat().st_size > 0:
            return out
        w, h, px = render(variant)
        write_png(out, w, h, px)
        return out
    except Exception:
        return None


def main():
    variant = sys.argv[1] if len(sys.argv) > 1 else "critical"
    p = icon_path(variant)
    if p is None:
        print("icon render failed", file=sys.stderr)
        return 1
    print(p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
