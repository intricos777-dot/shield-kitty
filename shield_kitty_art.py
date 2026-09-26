#!/usr/bin/env python3
"""
shield_kitty_art.py — the pixel art, in one place.

Shared by the notification icon renderer and the opt-in fullscreen view, so the
cat in your notification popup is the same cat as the fullscreen kitty.

B = body, K = outline/eye, W = white, Y = flame yellow, O = flame orange, . = transparent
"""

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
