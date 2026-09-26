#!/usr/bin/env python3
"""
shield-kitty-alert.py — intrusion notification for Shield Kitty.

Default behaviour is a DESKTOP NOTIFICATION (notify-send). It never takes over
the screen, never blocks input, and never opens a window on its own. A fullscreen
pixel kitty only appears if you explicitly ask for one with --fullscreen.

Rationale: an alert that hijacks the display is indistinguishable from an alert
triggered by your own activity, and it gets in the way of the thing you are
trying to do about it. Notify, then investigate.

Usage:
  shield-kitty-alert.py '<json payload>'       # desktop notification (default)
  shield-kitty-alert.py --demo                 # test with fake data
  shield-kitty-alert.py --test-notify          # verify the notification path
  shield-kitty-alert.py --fullscreen '<json>'  # opt-in fullscreen pixel kitty

Falls back to a terminal banner if no notification daemon answers, so an alert
is never silently lost.
"""

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
try:
    from shield_kitty_art import CAT, FLAME
    from shield_kitty_icon import icon_path
except ImportError:  # art/icon module missing: notifications still work
    CAT = FLAME = []
    icon_path = lambda variant="critical": None

SEVERITY = {
    "critical": {"urgency": "critical", "icon": "dialog-warning", "timeout": 15000},
    "warning": {"urgency": "normal", "icon": "dialog-information", "timeout": 8000},
}

# Used only by --fullscreen.
DURATION_MS = 12000

DEMO = {
    "severity": "critical",
    "events": [
        {"rule": "login_failure", "label": "AUTHENTICATION FAILURE",
         "severity": "critical", "count": 42, "sample": "Failed password for invalid user admin from 203.0.113.5"},
    ],
    "timestamp": "2026-09-26 12:30:00",
}


def summarize(payload):
    """One-line body sized for a notification popup."""
    events = payload.get("events", [])
    sev = payload.get("severity", "warning")
    head = "SHIELD KITTY" if sev == "critical" else "SHIELD KITTY (warning)"
    if not events:
        return head, ""
    top = events[0]
    body = "{} x{}".format(top.get("label", "SECURITY EVENT"), top.get("count", 1))
    extra = events[1:4]
    if extra:
        body += "  ·  " + ", ".join(
            "{} x{}".format(e.get("label", ""), e.get("count", 1)) for e in extra
        )
    if len(events) > 4:
        body += "  ·  +{} more".format(len(events) - 4)
    return head, body


def notify(payload):
    """Desktop notification via notify-send. Returns 0 on success."""
    sev = payload.get("severity", "warning")
    style = SEVERITY.get(sev, SEVERITY["warning"])
    head, body = summarize(payload)
    stamp = payload.get("timestamp") or time.strftime("%Y-%m-%d %H:%M:%S")
    full = "{}\n{}".format(body, stamp) if body else stamp

    if not shutil.which("notify-send"):
        print("[shield-kitty] notify-send not found; falling back to terminal",
              file=sys.stderr)
        return terminal(payload)

    # The nyan cat, rendered to PNG. Falls back to a stock icon if the
    # renderer is unavailable.
    icon = icon_path(sev) or style["icon"]

    cmd = [
        "notify-send",
        "--app-name=shield-kitty",
        "--urgency={}".format(style["urgency"]),
        "--icon={}".format(icon),
        "--expire-time={}".format(style["timeout"]),
        head,
        full,
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if r.returncode != 0:
            print("[shield-kitty] notify-send failed: {}".format(r.stderr.strip()),
                  file=sys.stderr)
            return terminal(payload)
        return 0
    except Exception as exc:
        print("[shield-kitty] notification error: {}".format(exc), file=sys.stderr)
        return terminal(payload)


def test_notify():
    """Verify the notification path end to end without touching the detector."""
    payload = dict(DEMO, timestamp=time.strftime("%Y-%m-%d %H:%M:%S"))
    print("[shield-kitty] sending a test notification...")
    rc = notify(payload)
    print("[shield-kitty] notify returned {}".format(rc))
    if rc != 0:
        print("[shield-kitty] FAILED — alerts would not reach you.")
        return 1
    print("[shield-kitty] ok — check your notification area.")
    return 0


def _build_widget_classes():
    """
    Fullscreen pixel kitty. Imported lazily so the module stays importable (and
    the notification path usable) on a machine with no Qt.
    """
    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import QColor
    from PyQt6.QtWidgets import QWidget

    class Alert(QWidget):
        def __init__(self, payload):
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
            self.setWindowTitle("SHIELD KITTY - INTRUSION ALERT")

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

            for i in range(60):
                x = (i * 137 + self.frames * 7) % w
                y = (i * 83) % max(1, h // 2)
                p.fillRect(x, y, 3, 3, QColor("#332222"))

            cw = max(8, min(w, 1100) // 24)
            ch = max(4, cw // 2)
            total_h = len(CAT) * ch + len(FLAME) * ch
            ox = (w - 13 * cw) // 2
            oy = (h - total_h) // 2 - 40

            for i, col in enumerate(self.flame_cols[:2]):
                p.setPen(col)
                p.setOpacity(0.25 - i * 0.1)
                p.drawRect(ox - (3 - i) * cw * 2, oy + ch, 3 * cw * 2, len(CAT) * ch)
            p.setOpacity(1.0)

            pal = {"B": self.body, "K": self.ink, "W": QColor("#ffffff")}
            for x, y, ww, hh, color in self.pixel_map(CAT, pal, cw, ox, oy):
                p.fillRect(x, y, ww, hh, color)

            fpal = {"Y": self.flame_cols[self.frames % 3], "O": self.flame_cols[0]}
            foy = oy + len(CAT) * ch
            for x, y, ww, hh, color in self.pixel_map(FLAME, fpal, ch, ox, foy):
                p.fillRect(x, y, ww, hh, color)

            p.setPen(self.light)
            p.setFont(QFont("DejaVu Sans Mono", max(28, cw), QFont.Weight.Bold))
            p.drawText(0, foy + len(FLAME) * ch + 70, w, 60,
                       _Qt.AlignmentFlag.AlignHCenter, "SHIELD KITTY")

            p.setPen(QColor("#ff2d2d") if self.crit else QColor("#ffb000"))
            p.setFont(QFont("DejaVu Sans", 34, QFont.Weight.Bold))
            p.drawText(0, 60, w, 50, _Qt.AlignmentFlag.AlignHCenter,
                       "INTRUSION DETECTED" if self.crit else "SECURITY EVENT")

            p.setPen(self.light)
            p.setFont(QFont("DejaVu Sans Mono", 13))
            lines = ["severity: {}".format(self.sev),
                     "time:     {}".format(self.payload.get("timestamp"))]
            for e in self.payload.get("events", [])[:6]:
                lines.append("  [{}x] {}".format(e.get("count"), e.get("label")))
                if e.get("sample"):
                    lines.append("        {}".format(e["sample"][:88]))
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


def fullscreen(payload):
    """Opt-in fullscreen display. Only reached via --fullscreen."""
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


def terminal(payload):
    sev = payload.get("severity", "?")
    bar = "!" * 78
    head = "!! INTRUSION DETECTED !!" if sev == "critical" else "!! SECURITY EVENT !!"
    print("\n{}\n{:^78}\n{}".format(bar, head, bar))
    print("  severity : {}".format(sev))
    print("  time     : {}".format(payload.get("timestamp")))
    for e in payload.get("events", []):
        print("  [{}x] {}".format(e.get("count"), e.get("label")))
        if e.get("sample"):
            print("       {}".format(e["sample"][:88]))
    print("{}\n".format(bar))
    return 0


def main():
    want_fullscreen = "--fullscreen" in sys.argv
    args = [a for a in sys.argv[1:] if a != "--fullscreen"]

    if "--test-notify" in args:
        return test_notify()

    if "--demo" in args:
        payload = DEMO
    elif args:
        try:
            payload = json.loads(args[0])
        except Exception:
            payload = DEMO
    else:
        payload = DEMO

    if want_fullscreen:
        try:
            return fullscreen(payload)
        except Exception as exc:
            print("[shield-kitty] fullscreen unavailable ({}); "
                  "using notification".format(exc), file=sys.stderr)

    return notify(payload)


if __name__ == "__main__":
    sys.exit(main())
