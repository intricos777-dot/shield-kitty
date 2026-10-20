#!/usr/bin/env python3
# Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# Copyright (c) 2026 Living Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# Licensed under Living Sin Proprietary License (LSPL-1.0)
# See LICENSE file for details.
"""
shield_kitty_art.py — the pixel art, in one place.

Shared by the notification icon renderer and the opt-in fullscreen view, so the
cat in your notification popup is the same cat as the fullscreen kitty.

Grid legend
-----------
  B  body (cat + pop-tart)
  K  outline / eye / mouth
  W  white (eye glint, icing highlight)
  T  pop-tart crust / icing
  r  rainbow red      o  rainbow orange    y  rainbow yellow
  g  rainbow green    c  rainbow cyan      b  rainbow blue
  v  rainbow violet   p  rainbow pink
  Y  flame yellow     O  flame orange      .  transparent

CAT is 16 wide, TRAIL is 16 wide and sits immediately to its left, so the
composite is 32 cells. FLAME hangs below the cat.
"""

CAT = [
    "....BBBBBBBB....",
    "...BBBBBBBBBB...",
    "..BBBBBBBBBBBB..",
    "..BBKBBBBBBKBB..",
    "..BBKBBBBBBKBB..",
    "..BBBBBBBBBBBB..",
    "..BBBBKBBKBBBB..",
    "..BBBBBBBBBBBB..",
    "..BBWBBBBBBWBB..",
    "..BBBBBBBBBBBB..",
    "..BBKBBBBBBKBB..",
    "..BBBBBBBBBBBB..",
    "...BBBBBBBBBB...",
    "....BBBBBBBB....",
]

# Pop-tart body below the head: F = crust, T = icing, W = icing highlight.
TART = [
    ".FFFFFFFFFFFFFF.",
    "FFTTTTTTTTTTTTFF",
    "FTTWTTTTTTTTWTTF",
    "FTTTTTTTTTTTTTTF",
    "FFTTTTTTTTTTTTFF",
    ".FFFFFFFFFFFFFF.",
]

# Rainbow trail, 16 wide, ordered from the cat outward.
TRAIL = [
    "rroyyggccbbvpppp",
    "rroyyggccbbvpppp",
    "rroyyggccbbvpppp",
    "rroyyggccbbvpppp",
    "rroyyggccbbvpppp",
]

FLAME = [
    "....Y...Y.......",
    "...YY.Y.YY..Y...",
    "..Y..Y...Y.Y.Y..",
    ".Y.Y.Y..Y...Y.Y.",
    "..Y...Y.Y.Y..Y..",
    "..OY.Y.....Y.O..",
    ".O...Y...Y...O..",
    "..O..Y.Y...O.O..",
]

ART_W = 16
TRAIL_W = 16
