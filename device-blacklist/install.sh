#!/bin/bash
# Shield Kitty device admission control — installer.
#
# Needs root: it writes a udev rule and a sysfs-writing helper. Nothing is
# enabled until the final `udevadm control --reload`, and there is an UNINSTALL
# that removes exactly what this added.
#
#   sudo ./install.sh            install
#   sudo ./install.sh --uninstall remove

set -e

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$REPO_DIR/device-blacklist"
DEST="/opt/shield-kitty"
RULE="/etc/udev/rules.d/99-shield-kitty-devices.rules"
STATE="/var/lib/shield-kitty"

if [ "$(id -u)" -ne 0 ]; then
    echo "needs root: sudo $0" >&2
    exit 1
fi

if [ "$1" = "--uninstall" ]; then
    echo "Removing Shield Kitty device policy..."
    rm -f "$RULE"
    udevadm control --reload-rules 2>/dev/null || true
    udevadm trigger 2>/dev/null || true
    echo "  removed $RULE"
    echo "  state kept for the record: $STATE (delete it by hand if you want it gone)"
    exit 0
fi

# The alert script has to be reachable from the udev context (root, no PATH
# guarantees, no DISPLAY), so it lives in DEST too.
echo "Installing Shield Kitty device policy..."

# Warn if a device attached right now is not in the whitelist — it would be
# quarantined on the next boot. Root hubs are exempt by NEVER_BLOCK.
# lsusb prints "Bus 001 Device 002: ID 1234:5678 Name", so pull the ID field
# with a regex rather than field splitting (splitting on ': ' yields "ID 1234").
MISSING=0
while read -r vidpid; do
    [ -z "$vidpid" ] && continue
    case "$vidpid" in
        1d6b:*) continue ;;
    esac
    if ! grep -qi "^[[:space:]]*$vidpid" "$SRC/whitelist.conf"; then
        echo "  WARNING: attached device $vidpid is not in the whitelist."
        echo "           Add it now or it will be quarantined on next boot."
        MISSING=$((MISSING+1))
    fi
done < <(lsusb 2>/dev/null | grep -oE 'ID [0-9a-fA-F]{4}:[0-9a-fA-F]{4}' | awk '{print tolower($2)}')
[ "$MISSING" -gt 0 ] && echo "  $MISSING attached device(s) missing from the whitelist."

mkdir -p "$DEST" "$STATE"

install -m 0755 "$SRC/shield-kitty-devices.py" "$DEST/shield-kitty-devices.py"
install -m 0644 "$SRC/whitelist.conf" "$DEST/whitelist.conf"
install -m 0755 "$REPO_DIR/shield-kitty-alert.py" "$DEST/shield-kitty-alert.py"
install -m 0644 "$REPO_DIR/shield_kitty_art.py" "$DEST/shield_kitty_art.py"
install -m 0755 "$REPO_DIR/shield-kitty-icon.py" "$DEST/shield-kitty-icon.py"

# The script resolves ALERT as ../shield-kitty-alert.py, which is correct when
# it lives beside them in DEST.
install -m 0644 "$SRC/99-shield-kitty-devices.rules" "$RULE"

# uid=0 gid=0 mode=0600: the whitelist is the whole security policy, and a
# writable whitelist is a disabled whitelist.
chown root:root "$DEST/whitelist.conf" "$STATE" 2>/dev/null || true
chmod 0755 "$DEST"
chmod 0600 "$DEST/whitelist.conf"
touch "$STATE/blacklist.conf" "$STATE/attempts.conf"
chmod 0600 "$STATE/blacklist.conf" "$STATE/attempts.conf"

# Never let this fire before the policy is in place: a cold boot with a broken
# whitelist would quarantine your own keyboard.
python3 "$DEST/shield-kitty-devices.py" selftest

udevadm control --reload-rules
udevadm trigger --subsystem-match=usb --action=add >/dev/null 2>&1 || true

echo ""
echo "Installed. Policy:"
echo "  whitelist : $DEST/whitelist.conf (root-only, 0600)"
echo "  blacklist : $STATE/blacklist.conf"
echo "  log       : $STATE/device-policy.log"
echo "  manage    : python3 $DEST/shield-kitty-devices.py list|whitelist VID PID|unban VID PID"
echo ""
echo "NOTHING on this machine is blocked right now. The first unrecognised"
echo "device is quarantined and you get a Shield Kitty notification; the second"
echo "attempt bans it permanently."
