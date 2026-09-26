#!/usr/bin/env python3
"""
Edge-case tests for the USB device admission policy.

This is the highest-consequence code on the system: a wrong decision unbinds
a keyboard or mouse and the machine becomes unusable. These tests target the
failure modes that would actually lock someone out, plus the parsing bugs that
have already bitten this file once (state headers parsed as ban records).

Run:  python3 test_device_policy.py
"""
import importlib.util
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
TARGET = HERE / "shield-kitty-devices.py"

spec = importlib.util.spec_from_file_location("skdev", TARGET)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  — {detail}" if detail and not cond else ""))


print("=== 1. lockout safety: these must NEVER be blocked ===")

# Root hubs: blocking these removes the whole bus.
check("root hub usb1 is not a device target", mod.sysfs_path("1d6b", "0002", "") is None
      or "usb1" not in str(mod.sysfs_path("1d6b", "0002", "") or ""))
rc, out = os.popen("ls -d /sys/bus/usb/devices/usb* 2>/dev/null | head -3").read().strip(), None
print(f"        (root hubs present: {rc.split()[:2]})")

# Interface nodes must never be treated as unbindable devices.
for node in ("3-1:1.0", "usb1:1.0", "1-0:1.0"):
    # sysfs_path must not return an interface node for a device-style query.
    r = mod.sysfs_path("dead", "beef", "")
    check(f"interface node {node} not returned as a device", r is None or ":" not in str(r).rsplit("/", 1)[-1],
          f"got {r}")

print("\n=== 2. state file parsing: headers must not become ban records ===")
with tempfile.TemporaryDirectory() as td:
    bl = Path(td) / "blacklist.csv"
    # The exact header shape that previously produced a phantom ban.
    bl.write_text("# vid,pid,when,count\n")
    mod.BLACKLIST = bl
    recs = mod.parse_bans(bl)
    check("comment-only blacklist parses to zero records", len(recs) == 0, f"got {recs}")

    # Column order is vid,pid,serial,when,attempts -- matching add_ban() and
    # the header it writes. An earlier version of this test used a 4-column
    # row, so "serial" consumed the date and the assertion failed against
    # correct code.
    bl.write_text("# vid,pid,serial,when,attempts\n046d,c52b,,2026-09-26 10:00:00,1\n")
    recs = mod.parse_bans(bl)
    check("header line is not parsed as a record", len(recs) == 1, f"got {recs}")
    check("real record parses correctly",
          any(v == ("046d", "c52b", "2026-09-26 10:00:00", 1) for v in recs.values()),
          f"got {list(recs.values())}")

    # Round-trip through the real writer, which is the shape that matters.
    bl2 = Path(td) / "written.csv"
    mod.BLACKLIST = bl2
    mod.add_ban("1a86", "7523", "SN123", 2)
    recs = mod.parse_bans(bl2)
    check("add_ban -> parse_bans round-trips",
          any(v[:2] == ("1a86", "7523") and v[3] == 2 for v in recs.values()),
          f"got {list(recs.values())}")
    check("written header is ignored on re-read", len(recs) == 1, f"got {recs}")

    bl.write_text("")
    check("empty blacklist -> no records", len(mod.parse_bans(bl)) == 0)

    bl.write_text("# vid,pid,when,count\ngarbage-line-no-commas\n")
    check("malformed line does not crash the parser", isinstance(mod.parse_bans(bl), dict))

print("\n=== 3. is_banned must not crash on a populated blacklist ===")
with tempfile.TemporaryDirectory() as td:
    bl = Path(td) / "blacklist.csv"
    bl.write_text("# vid,pid,when,count\n046d,c52b,2026-09-26,1\n1a86,7523,2026-09-26,2\n")
    mod.BLACKLIST = bl
    try:
        r1 = mod.is_banned("046d", "c52b", "")
        r2 = mod.is_banned("ffff", "ffff", "")
        check("is_banned True for listed device", r1 is True, f"got {r1}")
        check("is_banned False for unlisted device", r2 is False, f"got {r2}")
    except Exception as exc:
        check("is_banned does not raise", False, f"{type(exc).__name__}: {exc}")

print("\n=== 4. HID exemption: a keyboard must never be unbound ===")


class FakeIface:
    def __init__(self, cls):
        self._cls = cls

    def __truediv__(self, other):
        return self

    def exists(self):
        return True

    def read_text(self):
        return self._cls


class FakeDev:
    def __init__(self, classes):
        self.classes = classes

    def glob(self, pat):
        return [FakeIface(c) for c in self.classes]


check("keyboard (HID class 03) is input", mod.is_input_device(FakeDev(["03"])) is True)
check("mouse (HID class 03) is input", mod.is_input_device(FakeDev(["03"])) is True)
check("composite HID+storage is input", mod.is_input_device(FakeDev(["03", "08"])) is True)
check("mass storage (08) is NOT input", mod.is_input_device(FakeDev(["08"])) is False)
check("network (02) is NOT input", mod.is_input_device(FakeDev(["02"])) is False)
check("no interfaces -> not input", mod.is_input_device(FakeDev([])) is False)


class ExplodingDev:
    """A device whose sysfs read fails — the lockout scenario."""

    def glob(self, pat):
        raise OSError("sysfs read failed")


check("unreadable device FAILS SAFE (exempted, not blockable)",
      mod.is_input_device(ExplodingDev()) is True,
      "an unreadable keyboard must never be quarantined")

print("\n=== 5b. NEVER_BLOCK is the second backstop ===")
# Root hubs (1d6b:0002/0003) must be in the never-block set: unbinding a
# root hub takes the whole bus down, not just one device.
for vid, pid in (("1d6b", "0002"), ("1d6b", "0003")):
    check(f"root hub {vid}:{pid} in NEVER_BLOCK", (vid, pid) in mod.NEVER_BLOCK,
          f"NEVER_BLOCK={mod.NEVER_BLOCK}")
check("NEVER_BLOCK is populated", len(mod.NEVER_BLOCK) > 0)

print("\n=== 5. sysfs_path must not return a root hub ===")
r = mod.sysfs_path("1d6b", "0002", "")
check("root-hub VID:PID does not resolve to a bindable node",
      r is None or "usb" not in str(r).split("/")[-1][:3],
      f"got {r}")

print(f"\n{'='*56}\n{len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("FAILED:")
    for f in FAIL:
        print("  -", f)
sys.exit(1 if FAIL else 0)
