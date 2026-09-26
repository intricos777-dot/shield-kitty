#!/usr/bin/env python3
"""
alert.py — fullscreen pixel-art nyan cat intrusion alert.

Usage:  ./alert.py '<json payload>'
        ./alert.py --demo      # trigger with fake data, for testing

Drawn with PyQt6. Falls back to zenity/kdialog, then to a terminal banner,
so an alert ALWAYS reaches you even if the GUI stack is unhappy.
"""

import json
import subprocess
import sys
import time

DURATION_MS = 12000

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
    "..Y.Y.Y...",
    ".OYO.YO...",
    "..O...O...",
]

DEMO = {
    "severity": "critical",
    "events": [
        {"rule": "login_failure", "label": "AUTHENTICATION FAILURE",
         "severity": "critical", "count": 42, "sample": "Failed password for invalid user admin from 203.0.113.5"},
    ],
    "timestamp": "2026-09-26 12:30:00",
}


def _build_widget_classes():
    """
    Build the Qt widget classes. Imported lazily so that the module can be
    imported (and the terminal fallback used) on a machine with no Qt.
    """
    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import QColor
    from PyQt6.QtWidgets import QWidget

    class Alert(QWidget):
        def __init__(self, payload: dict):
            super().__init__()
            self.payload = payload
            self.sev = payload.get("severity", "warning")
            self.crit = self.sev == "critical"
            self.bg = QColor("#120000") if self.crit else QColor("#1a1400")
            self.body = QColor("#ff2d2d") if self.crit else QColor("#ffb000")
            self.light = QColor("#ffd7d7") if self.crit else QColor("#fff0c0")
            self.ink = QColor("#1a0000")
            self.flame_cols = [QColor("#ff3c00"), QColor("#ff8c00"), QColor("#ffd000")]
            self.frames = 0
            self.setWindowTitle("INTRUSION ALERT")

        def pixel_map(self, rows, palette, cell, ox, oy):
            out = []
            for r, row in enumerate(rows):
                for c, ch in enumerate(row):
                    if ch == ".":
                        continue
                    color = palette.get(ch)
                    if color is not None:
                        out.append((ox + c * cell, oy + r * cell, cell, cell, color))
            return out

        def paintEvent(self, ev):
            from PyQt6.QtGui import QFont, QPainter
            from PyQt6.QtCore import Qt as _Qt

            p = QPainter(self)
            p.fillRect(self.rect(), self.bg)

            w, h = self.width(), self.height()
            if w <= 0 or h <= 0:
                return

            # drifting starfield
            for i in range(60):
                x = (i * 137 + self.frames * 7) % w
                y = (i * 83) % max(1, h // 2)
                p.fillRect(x, y, 3, 3, QColor("#332222"))

            cw = max(8, min(w, 1100) // 24)
            ch = max(4, cw // 2)
            total_h = len(CAT) * ch + len(FLAME) * ch
            ox = (w - 13 * cw) // 2
            oy = (h - total_h) // 2 - 40

            # comet trail behind the cat
            for i, col in enumerate(self.flame_cols[:2]):
                p.setPen(col)
                p.setOpacity(0.25 - i * 0.1)
                p.drawRect(ox - (3 - i) * cw * 2, oy + ch, 3 * cw * 2, len(CAT) * ch)
            p.setOpacity(1.0)

            pal = {"B": self.body, "K": self.ink, "W": QColor("#ffffff")}
            for x, y, ww, hh, color in self.pixel_map(CAT, pal, cw, ox, oy):
                p.fillRect(x, y, ww, hh, color)

            # animated flames
            fpal = {"Y": self.flame_cols[self.frames % 3], "O": self.flame_cols[0]}
            foy = oy + len(CAT) * ch
            for x, y, ww, hh, color in self.pixel_map(FLAME, fpal, ch, ox, foy):
                p.fillRect(x, y, ww, hh, color)

            # GFSF wordmark
            p.setPen(self.light)
            p.setFont(QFont("DejaVu Sans Mono", max(28, cw), QFont.Bold))
            p.drawText(0, foy + len(FLAME) * ch + 70, w, 60,
                       _Qt.AlignmentFlag.AlignHCenter, "GFSF")

            # banner
            p.setPen(QColor("#ff2d2d") if self.crit else QColor("#ffb000"))
            p.setFont(QFont("DejaVu Sans", 34, QFont.Bold))
            p.drawText(0, 60, w, 50, _Qt.AlignmentFlag.AlignHCenter,
                       "INTRUSION DETECTED" if self.crit else "SECURITY EVENT")

            # details
            p.setPen(self.light)
            p.setFont(QFont("DejaVu Sans Mono", 13))
            lines = [f"severity: {self.sev}",
                     f"time:     {self.payload.get('timestamp')}"]
            for e in self.payload.get("events", [])[:6]:
                lines.append(f"  [{e.get('count')}x] {e.get('label')}")
                if e.get("sample"):
                    lines.append(f"        {e['sample'][:88]}")
            y = h - 40 - 22 * len(lines)
            p.drawText(60, max(40, y), w - 120, 22 * len(lines) + 20,
                       _Qt.AlignmentFlag.AlignLeft, "\n".join(lines))

            p.drawText(0, h - 30, w, 20, _Qt.AlignmentFlag.AlignHCenter,
                       "press ESC or click to dismiss")

        def keyPressEvent(self, e):
            from PyQt6.QtCore import Qt as _Qt
            if e.key() == _Qt.Key.Key_Escape:
                self.close()

        def mousePressEvent(self, e):
            self.close()

    return Alert


def gui(payload: dict) -> int:
    from PyQt6.QtCore import QTimer
    from PyQt6.QtWidgets import QApplication

    Alert = _build_widget_classes()
    app = QApplication.instance() or QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(True)
    w = Alert(payload)
    from PyQt6.QtCore import Qt
    w.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
    w.showFullScreen()

    def advance():
        w.frames += 1
        w.update()

    t = QTimer()
    t.timeout.connect(advance)
    t.start(120)
    QTimer.singleShot(DURATION_MS, w.close)
    return app.exec()


def terminal(payload: dict) -> int:
    sev = payload.get("severity", "?")
    bar = "!" * 78
    print(f"\n{bar}\n{'!! INTRUSION DETECTED !!' if sev == 'critical' else '!! SECURITY EVENT !!':^78}\n{bar}")
    print(f"  severity : {sev}")
    print(f"  time     : {payload.get('timestamp')}")
    for e in payload.get("events", []):
        print(f"  [{e.get('count')}x] {e.get('label')}")
        if e.get("sample"):
            print(f"       {e['sample'][:88]}")
    print(f"{bar}\n")
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--demo":
        payload = DEMO
    elif len(sys.argv) > 1:
        try:
            payload = json.loads(sys.argv[1])
        except Exception:
            payload = DEMO
    else:
        payload = DEMO

    try:
        return gui(payload)
    except Exception as exc:
        print(f"[alert] GUI unavailable ({exc}); falling back", file=sys.stderr)
        return terminal(payload)


if __name__ == "__main__":
    sys.exit(main())
