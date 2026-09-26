#!/usr/bin/env python3
"""
shield-kitty — intrusion event detector.

Tails the systemd journal for signals that something outside the machine
tried to get in, and fires a fullscreen pixel nyan cat alert on the local
display.

This is a DETECTION and NOTIFICATION tool. It blocks nothing on its own.
Blocking is the job of pam_faillock (already enabled) and the firewall
(enable with: sudo systemctl enable --now firewalld).

Design notes:
  - Runs as a per-user service, not root. Least privilege: it only reads
    the journal, which the user is already allowed to do.
  - Uses a cursor file so a restart does not replay old events.
  - Debounces: a burst of failed SSH attempts is one alert, not fifty.
  - Never blocks. If the display cannot be opened, it logs and continues.

Usage:
  shield-kitty-watch            run in foreground (for testing)
  shield-kitty-watch --selftest run detector once against the last 10 minutes
"""

import argparse
import getpass
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

XDG_RUNTIME = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"))
STATE_DIR = XDG_RUNTIME / "shield-kitty"
CURSOR = STATE_DIR / "cursor"
ALERT_SCRIPT = Path(__file__).parent / "shield-kitty-alert.py"
# Tamper-evident evidence store. Optional: if this repo is not present the
# watcher still fires alerts, it just does not build a court-defensible record.
EVIDENCE = Path.home() / "Projects/shield-kitty-forensics/evidence.py"
LOCK = STATE_DIR / "watch.lock"

# Seconds to suppress further alerts after one fires.
#
# This used to be 45s, which meant a password-spraying run of 50 attempts in a
# minute produced exactly one notification — the exact case where you want to
# know it is still happening. Now short enough that a sustained attack keeps
# notifying, long enough that a single burst does not become a wall of popups.
# Escalates: repeated critical alerts inside the window shorten it further.
DEBOUNCE = 10
DEBOUNCE_MIN = 3

# --- Detection rules -------------------------------------------------------
# Each rule: (name, compiled regex, human label, severity)
# Severity: "critical" = credential attack on a login surface
#           "warning"  = privilege escalation attempt or physical attach
RULES = [
    (
        "login_failure",
        re.compile(
            r"(Failed password for (invalid user )?"
            r"|Invalid user \S+ from"
            r"|FAILED LOGIN \d+ FROM"
            r"|pam_unix\([^)]*:auth\): authentication failure)",
            re.I,
        ),
        "AUTHENTICATION FAILURE",
        "critical",
    ),
    (
        # Match pam_faillock's ACTUAL denial output, not the bare word
        # "faillock" — otherwise this fires on the admin's own
        # `sudo cp /etc/security/faillock.conf` commands.
        "faillock_denial",
        re.compile(
            r"(tries to authenticate but locked out"
            r"|pam_faillock\(authfail\)"
            r"|pam_faillock\(preauth\).*(fail|denied)"
            r"|Unlocking account \S+)"
        ),
        "ACCOUNT LOCKOUT TRIGGERED",
        "critical",
    ),
    (
        # sudo: the actor name is the field right after "sudo:". "a password
        # is required" fires on every non-interactive sudo attempt, including
        # the admin's own — so only flag it when the actor is NOT the local
        # user. "incorrect password" is always a real failure.
        "sudo_failure",
        re.compile(r"sudo:.*incorrect password", re.I),
        "UNAUTHORIZED PRIVILEGE ESCALATION",
        "critical",
    ),
    (
        # Non-interactive sudo attempt from someone other than us.
        "sudo_unattended",
        re.compile(r"sudo:\s*(?P<actor>\w+)\s*:.*a password is required", re.I),
        "UNAUTHORIZED PRIVILEGE ESCALATION",
        "critical",
    ),
    (
        "sddm_failure",
        re.compile(r"(sddm|lightdm|gdm).*(failed|auth|login).*fail", re.I),
        "LOGIN SCREEN AUTH FAILURE",
        "critical",
    ),
]

# Deliberately NOT alerting on:
#   - USB / Thunderbolt attach. A device appearing is not an intrusion — it is
#     the ordinary case of plugging in a phone or a keyboard, and root-hub
#     attach lines fire on every boot. Physical-device policy is handled by
#     blocking (see device-blacklist/ in this repo), not by notification.
#   - The local admin's own sudo activity. See is_local_admin_actor().
#   - Anything that is not an authentication or privilege boundary being
#     crossed by someone else. If it is not someone trying in, it is noise.


def log(msg: str) -> None:
    print(f"[shield-kitty] {msg}", flush=True)


def have_journal_access() -> bool:
    """Can we actually read the auth log? If not, the detector is useless."""
    try:
        r = subprocess.run(
            ["journalctl", "-n", "1", "--no-pager", "-q"],
            capture_output=True, timeout=10,
        )
        return r.returncode == 0
    except Exception:
        return False


def read_cursor() -> str:
    try:
        return CURSOR.read_text().strip()
    except Exception:
        return ""


def write_cursor(value: str) -> None:
    try:
        CURSOR.write_text(value)
    except Exception:
        pass


def fetch_since(since: str, limit: int = 400) -> list[str]:
    """Journal lines since cursor. Falls back to a time window on first run."""
    cmd = ["journalctl", "--no-pager", "-q", "-n", str(limit), "-o", "short-iso"]
    if since:
        cmd += ["--after-cursor", since]
    else:
        cmd += ["--since", "-10min"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        return r.stdout.splitlines() if r.returncode == 0 else []
    except Exception:
        return []


def latest_cursor() -> str:
    """Ask journald for the current end-of-stream position."""
    try:
        r = subprocess.run(
            ["journalctl", "--no-pager", "-n", "1", "-o", "export"],
            capture_output=True, text=True, timeout=10,
        )
        for line in r.stdout.splitlines():
            if line.startswith("__CURSOR="):
                return line.split("=", 1)[1].strip()
    except Exception:
        pass
    return ""


LOCAL_USER = os.environ.get("USER") or getpass.getuser()


def is_local_admin_actor(match: re.Match) -> bool:
    """
    True if the sudo actor is the logged-in user doing their own thing.
    Guards the rules that would otherwise fire on normal admin activity.
    """
    actor = (match.groupdict().get("actor") or "").strip().lower()
    return bool(actor) and actor == LOCAL_USER.lower()


def classify(lines: list[str]) -> list[dict]:
    """Run every rule over every line, collect unique hits."""
    found: dict[str, dict] = {}
    for line in lines:
        for name, pattern, label, severity in RULES:
            m = pattern.search(line)
            if not m:
                continue
            # Skip our own sudo attempts — not an intrusion.
            if name == "sudo_unattended" and is_local_admin_actor(m):
                continue
            key = f"{name}:{label}"
            if key in found:
                found[key]["count"] += 1
            else:
                found[key] = {
                    "rule": name, "label": label,
                    "severity": severity, "count": 1,
                    "sample": line.strip()[:200],
                }
    return list(found.values())


def most_severe(events: list[dict]) -> str:
    if any(e["severity"] == "critical" for e in events):
        return "critical"
    return "warning"


def fire_alert(events: list[dict]) -> None:
    payload = {
        "severity": most_severe(events),
        "events": events,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    log(f"ALERT: {len(events)} event(s), severity={payload['severity']}")
    for e in events:
        log(f"        {e['label']} x{e['count']}")

    # Append to the tamper-evident evidence chain BEFORE displaying. If the
    # log write fails we still alert: losing evidence is bad, but staying
    # silent about an intrusion is worse.
    #
    # The return code IS checked. It was previously discarded, so a failed
    # record looked identical to a successful one from the journal — a broken
    # evidence chain would have been invisible until you needed the proof.
    if EVIDENCE.exists():
        try:
            r = subprocess.run(
                [sys.executable, str(EVIDENCE), "record", "--event", json.dumps(payload)],
                capture_output=True, text=True, timeout=20,
            )
            if r.returncode != 0:
                log("EVIDENCE WRITE FAILED (rc={}): {}".format(
                    r.returncode, (r.stderr or r.stdout).strip()[:200]))
        except Exception as exc:
            log(f"evidence logging failed: {exc}")
    else:
        log(f"evidence store missing at {EVIDENCE}; alert only, no proof")

    # Detach the display so a slow/fullscreen window never stalls detection.
    try:
        subprocess.Popen(
            [sys.executable, str(ALERT_SCRIPT), json.dumps(payload)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception as exc:
        log(f"could not launch alert display: {exc}")


def selftest() -> int:
    log(f"selftest: journal access = {have_journal_access()}")
    lines = fetch_since("", limit=2000)
    log(f"selftest: scanned {len(lines)} journal lines from last 10min")
    events = classify(lines)
    if not events:
        print("  result: no matching events in window (detector logic OK, nothing firing)")
        # Prove the rules actually match something.
        probe = "Sep 26 12:00:00 host sshd[99]: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2"
        if classify([probe]):
            print("  result: rules DO match a known attack string — logic verified")
            return 0
        print("  result: FAILED — rules match nothing, detector is broken")
        return 1
    for e in events:
        print(f"  detected: {e['label']} x{e['count']}")
    return 0


def acquire_lock() -> bool:
    """Single-instance guard so a second service start cannot double-fire."""
    try:
        import fcntl
        f = open(LOCK, "w")
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        f.write(str(os.getpid()))
        f.flush()
        return True
    except Exception:
        return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    if not have_journal_access():
        log("FATAL: cannot read the journal.")
        log("Add yourself to the systemd-journal group:")
        log("  sudo usermod -aG systemd-journal $USER")
        log("Then log out and back in. Refusing to run blind.")
        return 1

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if not acquire_lock():
        log("another watcher is already running; exiting")
        return 0

    cursor = read_cursor() or latest_cursor()
    write_cursor(cursor)
    log(f"watching journal from cursor {cursor[:16] or '(fresh start)'}")

    last_fire = 0.0
    cooldown = DEBOUNCE
    while True:
        lines = fetch_since(cursor)
        if lines:
            cursor = latest_cursor() or cursor
            write_cursor(cursor)
            events = classify(lines)
            if events:
                crit = most_severe(events) == "critical"
                if (time.time() - last_fire) > cooldown:
                    fire_alert(events)
                    last_fire = time.time()
                    # Sustained attack: keep talking, but back off a little so
                    # a spray does not turn into hundreds of popups.
                    cooldown = DEBOUNCE_MIN if crit else DEBOUNCE
        time.sleep(3)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
