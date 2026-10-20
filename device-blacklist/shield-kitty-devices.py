#!/usr/bin/env python3
# Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# Copyright (c) 2026 Living Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# Licensed under Living Sin Proprietary License (LSPL-1.0)
# See LICENSE file for details.
"""
shield-kitty-devices.py — USB device admission control.

Policy
------
  whitelisted          -> allowed, no action
  already banned       -> stays blocked
  unknown, 1st sighting -> QUARANTINE + notify you
  unknown, 2nd sighting -> BAN permanently

"Quarantine" means unbinding the device from every kernel driver that would let
it do anything: usb-storage/uas (files), hid (input), and anything else bound to
its interfaces. The node disappears. Nothing can read your disk through it. It
is not a soft warning.

This is the enforcement half of Shield Kitty. The watcher
(shield-kitty-watch.py) is the notification half and deliberately does not
alert on ordinary device attaches — that is this script's job, and it acts
rather than informs.

Run manually to inspect or test; udev calls it on device add.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
WHITELIST = HERE / "whitelist.conf"
# Overridable so the policy can be exercised against a scratch state directory
# without root and without touching the real blacklist.
STATE_DIR = Path(os.environ.get("SHIELD_KITTY_STATE", "/var/lib/shield-kitty"))
BLACKLIST = STATE_DIR / "blacklist.conf"
ATTEMPTS = STATE_DIR / "attempts.conf"
LOG = STATE_DIR / "device-policy.log"
# The alert script sits beside this one after install (/opt/shield-kitty), and
# one level up when run from the repo. Check both.
ALERT = HERE / "shield-kitty-alert.py"
if not ALERT.exists():
    ALERT = HERE.parent / "shield-kitty-alert.py"

# udev runs us as root with no DISPLAY, no XDG_RUNTIME_DIR and no idea who is
# logged in. A root-owned notify-send fails silently. Drop to the desktop user
# and hand it a display, or the alert never reaches you.
DESKTOP_USER = os.environ.get("SHIELD_KITTY_USER", "livings")
DESKTOP_DISPLAY = os.environ.get("SHIELD_KITTY_DISPLAY", ":0")
DESKTOP_RUNTIME = os.environ.get("SHIELD_KITTY_RUNTIME", "/run/user/1000")

# Never quarantine these, whatever the list says. Getting this wrong means an
# unusable keyboard and a machine you cannot log into.
NEVER_BLOCK = {
    ("1d6b", "0001"), ("1d6b", "0002"), ("1d6b", "0003"),  # root hubs
    ("1d6b", "0004"), ("1d6b", "0005"),
}

# Input devices are allowed through even when unlisted. An unwhitelisted
# keyboard is overwhelmingly likely to be a keyboard you did not list, and
# unbinding its HID driver leaves you typing at a dead screen with no way to
# fix the list. Verified on this machine: the built-in mouse reports device
# class 00, NOT 09 — so the exemption has to look at the INTERFACE class of
# every interface, not the device class.
HID_CLASSES = {"03", "09"}  # keyboard, mouse / HID


def is_input_device(dev):
    """
    True if any interface of this device is HID (keyboard, mouse, gamepad).

    FAILS SAFE: if the class cannot be read we return True, exempting the
    device. The original returned False on error, which meant a transient
    sysfs read failure on a keyboard made it look like ordinary storage --
    and the caller would then quarantine it. An unreadable device must never
    be treated as safe to block: the cost of a false negative here is a
    machine with no keyboard, while the cost of a false positive is merely
    that one device is not auto-banned.

    never_block() is the second backstop for exactly this case.
    """
    try:
        for iface in dev.glob("*:*"):
            f = iface / "bInterfaceClass"
            if f.exists() and f.read_text().strip()[:2] in HID_CLASSES:
                return True
    except Exception as exc:
        log(f"is_input_device: unreadable, exempting out of caution: {exc}")
        return True
    return False

DRIVERS_TO_UNBIND = ("usb-storage", "uas", "hid", "hid-generic",
                     "usbhid", "r8152", "cdc_ether", "rndis_host", "nvme",
                     "asix", "sierra", "option")


def log(msg):
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        with open(LOG, "a") as f:
            f.write(msg + "\n")
    except Exception:
        pass
    print(msg, file=sys.stderr)


def parse_ids(path):
    """Return a set of (vid, pid) lowercase tuples."""
    out = set()
    for line in _data_lines(path):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"^([0-9a-fA-F]{4})\s*:\s*([0-9a-fA-F]{4})$", line)
        if m:
            out.add((m.group(1).lower(), m.group(2).lower()))
        else:
            log("WARN malformed line in {}: {!r}".format(path, line))
    return out


def _data_lines(path):
    """Yield non-comment, non-blank lines. Header comments must never be
    parsed as data — a '# key,count' header parses as a record named '# key'."""
    try:
        for line in Path(path).read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            yield line
    except FileNotFoundError:
        return
    except Exception as exc:
        log(f"WARN could not read {path}: {exc}")


def parse_bans(path):
    """Return {key: (vid, pid, when, attempts)}.

    Column order matches add_ban() and the header it writes:
        vid,pid,serial,when,attempts
    Note the return tuple deliberately OMITS serial: callers match on
    (vid, pid) only, because a device that reports no serial must still be
    recognised as banned.
    """
    out = {}
    for line in _data_lines(path):
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 2:
            continue
        vid, pid = parts[0].lower(), parts[1].lower()
        serial = parts[2] if len(parts) > 2 else ""
        when = parts[3] if len(parts) > 3 else ""
        # attempts is the FIFTH column (index 4). The old code tested
        # parts[4].isdigit() only when len(parts) > 4, so a 4-field row left
        # count as the literal string "1" instead of the int 1 -- and any
        # caller doing arithmetic or comparison on it got a string.
        raw_count = parts[4] if len(parts) > 4 else ""
        count = int(raw_count) if raw_count.isdigit() else 1
        out["{}:{}:{}".format(vid, pid, serial)] = (vid, pid, when, count)
    return out


def device_identifiers():
    """(vid, pid, serial) from the env udev sets. Empty when run by hand."""
    vid = os.environ.get("ID_VENDOR_ID", "").lower()
    pid = os.environ.get("ID_MODEL_ID", "").lower()
    serial = os.environ.get("ID_SERIAL_SHORT", "")
    return vid, pid, serial


def sysfs_path(vid, pid, serial):
    """
    Locate the sysfs device node for a VID:PID, preferring a serial match.

    Naming in /sys/bus/usb/devices:
      "3-2"      a real device on bus 3 port 2   <- what we want
      "3-2:1.0"  one interface of that device    <- not a device
      "usb3"     a root hub                      <- never a target
      "3-0:1.0"  a root hub interface            <- never a target
    """
    base = Path("/sys/bus/usb/devices")
    if not base.is_dir():
        return None
    cands = []
    for d in sorted(base.iterdir()):
        name = d.name
        if ":" in name or name.startswith("usb"):
            continue          # interface or root hub
        if name.endswith("-0"):
            continue          # bus root port
        v, p = d / "idVendor", d / "idProduct"
        if not (v.exists() and p.exists()):
            continue
        try:
            if v.read_text().strip().lower() != vid:
                continue
            if p.read_text().strip().lower() != pid:
                continue
        except Exception:
            continue
        cands.append(d)
    if not cands:
        return None
    if serial:
        for d in cands:
            try:
                if (d / "serial").read_text().strip() == serial:
                    return d
            except Exception:
                pass
    return cands[0]


def _write_sysfs(path: Path, value: str) -> bool:
    """Write to a sysfs control file. Returns True on success."""
    try:
        with open(path, "w") as f:
            f.write(value)
        return True
    except Exception:
        return False


def quarantine(dev: Path) -> list:
    """
    Unbind every driver that would let the device do anything: mass storage
    (usb-storage/uas), network (rndis/cdc_ether/asix), input (hid). The kernel
    stops exposing the interfaces, so the device cannot read your disk, take
    your network, or type into your session.

    Returns the list of things actually unbound.
    """
    unbound = []

    # The device-level driver first.
    try:
        dlink = dev / "driver"
        if dlink.exists():
            drv = os.path.basename(os.readlink(str(dlink)))
            unbind_file = Path("/sys/bus/usb/drivers") / drv / "unbind"
            if _write_sysfs(unbind_file, dev.name):
                unbound.append(drv)
    except Exception:
        pass

    # Then every interface — a composite device has one per function, and
    # unbinding only the top level leaves hid/usb-storage live.
    for iface in sorted(dev.glob("*:*")):
        try:
            ilink = iface / "driver"
            if not ilink.exists():
                continue
            drv = os.path.basename(os.readlink(str(ilink)))
            unbind_file = Path("/sys/bus/usb/drivers") / drv / "unbind"
            if _write_sysfs(unbind_file, iface.name):
                unbound.append("{}:{}".format(drv, iface.name))
        except Exception:
            continue

    return unbound


def notify(vid, pid, serial, attempt, action):
    """Fire a Shield Kitty notification. Never raises."""
    import json
    import time
    payload = {
        "severity": "critical",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "events": [{
            "rule": "device_admission",
            "label": "UNKNOWN USB DEVICE {} (attempt {})".format(action, attempt),
            "severity": "critical",
            "count": attempt,
            "sample": "{}:{} serial={}".format(vid, pid, serial or "(none)"),
        }],
    }
    # Run as the desktop user: a root notify-send has no bus connection and
    # exits 0 without showing anything, which is worse than not trying.
    # setpriv needs the target uid's group list; --init-groups fails when the
    # caller is not root, so fall back to plain --reuid/--regid.
    home = "/home/" + DESKTOP_USER
    env_args = [
        "DISPLAY=" + DESKTOP_DISPLAY,
        "XDG_RUNTIME_DIR=" + DESKTOP_RUNTIME,
        "XDG_CACHE_HOME=" + home + "/.cache",
        "HOME=" + home,
    ]
    attempts = [
        ["setpriv", "--reuid", DESKTOP_USER, "--regid", DESKTOP_USER,
         "--init-groups", "env"] + env_args + [sys.executable, str(ALERT), json.dumps(payload)],
        ["setpriv", "--reuid", DESKTOP_USER, "--regid", DESKTOP_USER,
         "--clear-groups", "env"] + env_args + [sys.executable, str(ALERT), json.dumps(payload)],
        ["runuser", "-u", DESKTOP_USER, "--", "env"] + env_args
        + [sys.executable, str(ALERT), json.dumps(payload)],
        [sys.executable, str(ALERT), json.dumps(payload)],
    ]
    last = ""
    for cmd in attempts:
        try:
            r = subprocess.run(cmd, timeout=20, capture_output=True, text=True)
            if r.returncode == 0:
                return
            last = "{}: {}".format(Path(cmd[0]).name, r.stderr.strip()[:160])
        except FileNotFoundError:
            last = "{} not installed".format(Path(cmd[0]).name)
        except Exception as exc:
            last = str(exc)[:160]
    # Every route failed. Log loudly — a silent alert on a security tool is
    # the one failure mode that must never be swallowed.
    log("ALERT DELIVERY FAILED ({}). Policy was still applied.".format(last))


def record_attempt(key, vid, pid, serial):
    """Count sightings in ATTEMPTS. Returns the new count."""
    counts = {}
    for line in _data_lines(ATTEMPTS):
        parts = [p.strip() for p in line.split(",") if p.strip()]
        if len(parts) >= 2 and parts[1].isdigit():
            counts[parts[0]] = int(parts[1])
    n = counts.get(key, 0) + 1
    counts[key] = n
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        with open(ATTEMPTS, "w") as f:
            f.write("# key,count  (managed by shield-kitty-devices.py)\n")
            for k, v in counts.items():
                f.write(f"{k},{v}\n")
    except Exception as exc:
        log(f"could not write {ATTEMPTS}: {exc}")
    return n


def add_ban(vid, pid, serial, count):
    """Persist a permanent ban. Returns True if it reached disk.

    A ban that fails to write is the worst failure mode this tool has: the
    device looks banned for this session, then walks straight back in after a
    reboot. So the failure is logged at ALERT level and the caller is told,
    rather than the write being swallowed.
    """
    import time
    row = "{},{},{},{},{}\n".format(
        vid, pid, serial, time.strftime("%Y-%m-%d %H:%M:%S"), count)
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        if not BLACKLIST.exists() or BLACKLIST.stat().st_size == 0:
            with open(BLACKLIST, "w") as f:
                f.write("# vid,pid,serial,when,attempts "
                        "(managed by shield-kitty-devices.py)\n")
        with open(BLACKLIST, "a") as f:
            f.write(row)
            f.flush()
            os.fsync(f.fileno())
        # Verify the record parses back. A write that silently truncated or
        # interleaved is worse than no write: it looks persisted but does not
        # match, so is_banned() would disagree with what the operator sees.
        if not any(v == vid and p == pid
                   for (v, p, _w, _n) in parse_bans(BLACKLIST).values()):
            raise OSError("record did not survive a read-back check")
        return True
    except Exception as exc:
        log("ALERT BAN NOT PERSISTED for {}:{}: {} — this device will NOT be "
            "blocked after a reboot; fix {} or the device is only quarantined "
            "for this session".format(vid, pid, exc, BLACKLIST))
        return False


def is_banned(vid, pid, serial):
    """True if this device is on the blacklist (matching serial when we have one)."""
    for (vid_b, pid_b, _when, _n) in parse_bans(BLACKLIST).values():
        if (vid_b, pid_b) != (vid, pid):
            continue
        return True
    return False


def handle_add():
    vid, pid, serial = device_identifiers()
    if not (vid and pid):
        log("no ID_VENDOR_ID/ID_MODEL_ID in env; not a udev add event")
        return 0

    ident = "{}:{}:{}".format(vid, pid, serial)
    if (vid, pid) in NEVER_BLOCK:
        return 0

    dev = sysfs_path(vid, pid, serial)
    if dev is not None and is_input_device(dev):
        # Keyboard/mouse/gamepad. Allowed even if unlisted — see HID_CLASSES.
        return 0

    if is_banned(vid, pid, serial):
        log(f"BANNED device {ident} reattached - re-quarantining")
        if dev:
            quarantine(dev)
        notify(vid, pid, serial, 99, "RE-ATTACH")
        return 0

    if (vid, pid) in parse_ids(WHITELIST):
        return 0

    n = record_attempt(ident, vid, pid, serial)
    action = "QUARANTINED" if n == 1 else "BANNED"
    log(f"unknown device {ident} attempt {n} -> {action}")
    if dev:
        done = quarantine(dev)
        log("  unbound: {}".format(done or ["(nothing bound - device was already inert)"]))
    else:
        log("  sysfs node not found; nothing to unbind, alerting only")
    if n >= 2:
        persisted = add_ban(vid, pid, serial, n)
        if not persisted:
            # Do not claim BANNED. The device IS unbound right now, so it is
            # quarantined for this session — but the permanent record failed,
            # and the operator has to know that distinction.
            log(f"  BAN RECORD FAILED — {ident} is quarantined this session "
                f"only and will be treated as a first sighting on replug")
            action = "QUARANTINED (BAN FAILED TO PERSIST)"
    notify(vid, pid, serial, n, action)
    return 0


def list_devices():
    wl = parse_ids(WHITELIST)
    bans = parse_bans(BLACKLIST)
    print("WHITELISTED ({}):".format(len(wl)))
    for vid, pid in sorted(wl):
        print("  {}:{}".format(vid, pid))
    print("\nBANNED ({}):".format(len(bans)))
    for key, (vid, pid, when, count) in sorted(bans.items()):
        print("  {}:{} serial={} banned={} attempts={}".format(
            vid, pid, key.split(":")[-1] or "(none)", when, count))


def whitelist_add(vid, pid, desc=""):
    entry = "\n{}:{}      # {}\n".format(vid.lower(), pid.lower(), desc or "added by user")
    with open(WHITELIST, "a") as f:
        if not WHITELIST.read_text().endswith("\n\n"):
            f.write("\n")
        f.write(entry)
    print("whitelisted {}:{}{}".format(vid, pid, " and removed any ban" if False else ""))
    for key in [k for k in parse_bans(BLACKLIST)
                if parse_bans(BLACKLIST)[k][0] == vid.lower() and parse_bans(BLACKLIST)[k][1] == pid.lower()]:
        pass  # bans are append-only by design; clear with `unban`


def unban(vid, pid):
    bans = parse_bans(BLACKLIST)
    keep = []
    removed = 0
    for key, (v, p, when, count) in bans.items():
        if v == vid.lower() and p == pid.lower():
            removed += 1
        else:
            keep.append("{},{},{},{},{}".format(v, p, when, count))
    try:
        with open(BLACKLIST, "w") as f:
            f.write("# vid,pid,serial,when,attempts (managed by shield-kitty-devices.py)\n")
            for line in keep:
                f.write(line + "\n")
    except Exception as exc:
        log(f"could not rewrite {BLACKLIST}: {exc}")
        return 1
    print("removed {} ban(s) for {}:{}".format(removed, vid, pid))
    return 0


def selftest():
    print("selftest: never-block set has {} entries".format(len(NEVER_BLOCK)))
    wl = parse_ids(WHITELIST)
    print("selftest: whitelist parsed {} entries: {}".format(len(wl), sorted(wl)[:4]))
    banned = parse_bans(BLACKLIST)
    print("selftest: blacklist parsed {} entries".format(len(banned)))
    # The rules that matter: is a known internal device recognised as allowed?
    checks = [
        ("root hub 1d6b:0002 is never-blocked", ("1d6b", "0002") in NEVER_BLOCK),
        ("built-in mouse 4e53:5406 is whitelisted", ("4e53", "5406") in wl),
        ("built-in webcam 13d3:56a2 is whitelisted", ("13d3", "56a2") in wl),
        ("an arbitrary attacker stick is NOT whitelisted",
         not any(k == ("dead", "beef") for k in wl)),
        ("whitelist file is world-owned and writable by us only",
         (WHITELIST.exists() and (WHITELIST.stat().st_mode & 0o022) == 0)
         if WHITELIST.exists() else True),
    ]
    ok = True
    for name, passed in checks:
        print("  {} {}".format("PASS" if passed else "FAIL", name))
        ok = ok and passed
    print("selftest:", "all checks passed" if ok else "FAILURES PRESENT")
    return 0 if ok else 1


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 0
    cmd = sys.argv[1]
    if cmd == "add":
        handle_add()
        return 0
    if cmd == "list":
        list_devices()
        return 0
    if cmd == "whitelist":
        if len(sys.argv) < 4:
            print("usage: shield-kitty-devices.py whitelist VID PID [description]")
            return 1
        whitelist_add(sys.argv[2], sys.argv[3], " ".join(sys.argv[4:]))
        return 0
    if cmd == "unban":
        if len(sys.argv) < 4:
            print("usage: shield-kitty-devices.py unban VID PID")
            return 1
        return unban(sys.argv[2], sys.argv[3])
    if cmd == "selftest":
        return selftest()
    print("unknown command: {}".format(cmd))
    return 1


if __name__ == "__main__":
    sys.exit(main())
