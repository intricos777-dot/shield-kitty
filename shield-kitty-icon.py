#!/usr/bin/env python3
"""
shield-kitty-icon.py — render the Shield Kitty nyan cat to a PNG.

Pure stdlib (zlib + struct), so the notification icon works even if Qt is not
importable. The pixel art is the same CAT/FLAME grid the fullscreen view uses,
so the icon and the fullscreen kitty are the same cat.

Writes to $XDG_CACHE_HOME/shield-kitty/nyan-<variant>.png and prints the path.
"""

import os
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
try:
    from shield_kitty_art import CAT, FLAME
except ImportError:
    # Fallback copy so this file works even if the art module is missing.
    CAT = [
        "..BBBBB...",
        ".BBBBBBB..",
        "BBBBBBBBBB",
        "BBKBBBBKBB",
        "BBBBBBBBBB",
        "BBBBBBBBBB",
        "BBKKKKKBBB",
        "BBBBBBWBBB",
        "BBBBBBBBBB",
        "BBBBBBBBBB",
        "BBKBBBBKBB",
        ".BBBBBBB..",
        "..BBBBB...",
    ]
    FLAME = [
        "..Y.......",
        ".YY.Y.Y...",
        "..Y...Y...",
        ".Y.Y.Y.Y..",
        "..Y...Y...",
        ".Y.Y.Y...",
        ".OYO.YO...",
        "..O...O...",
    ]

# Critical = the cat on a dark blood-red field. Warning = same cat, amber field.
VARIANTS = {
    "critical": {
        "bg": (18, 0, 0),
        "palette": {"B": (255, 45, 45), "K": (26, 0, 0), "W": (255, 255, 255),
                    "Y": (255, 208, 0), "O": (255, 60, 0)},
    },
    "warning": {
        "bg": (26, 20, 0),
        "palette": {"B": (255, 176, 0), "K": (26, 20, 0), "W": (255, 255, 255),
                    "Y": (255, 208, 0), "O": (255, 60, 0)},
    },
}

CELL = 12          # pixels per art cell
MARGIN = 6         # padding around the art
TRAIL = 3          # comet-trail cells drawn behind the cat


def render(variant="critical", cell=CELL):
    """Return raw RGB rows for the icon."""
    style = VARIANTS.get(variant, VARIANTS["critical"])
    pal = style["palette"]
    bg = style["bg"]

    rows = len(CAT) + len(FLAME)
    cols = len(CAT[0]) + TRAIL
    w = cols * cell + MARGIN * 2
    h = rows * cell + MARGIN * 2

    px = [[bg for _ in range(w)] for _ in range(h)]

    def put(x, y, color, alpha=1.0):
        if 0 <= x < w and 0 <= y < h:
            px[y][x] = color if alpha >= 1.0 else tuple(
                int(bg[i] + (color[i] - bg[i]) * alpha) for i in range(3)
            )

    ox = MARGIN + TRAIL * cell
    oy = MARGIN

    # comet trail behind the cat, fading left
    for i, t in enumerate((0.25, 0.15)):
        for r in range(len(CAT)):
            for c in range(TRAIL - i):
                x = ox - (TRAIL - i - c) * cell
                y = oy + r * cell
                for dy in range(cell):
                    for dx in range(cell):
                        put(x + dx, y + dy, pal["O"], t)

    def draw(grid, top, palette):
        for r, line in enumerate(grid):
            for c, ch in enumerate(line):
                if ch == ".":
                    continue
                color = palette.get(ch)
                if color is None:
                    continue
                for dy in range(cell):
                    for dx in range(cell):
                        put(ox + c * cell + dx, top + r * cell + dy, color)

    draw(CAT, oy, pal)
    draw(FLAME, oy + len(CAT) * cell, pal)
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
    """Path to the icon, rendering it if missing or stale. None on failure."""
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
