# Shield Kitty — device admission control

Unknown USB devices get one chance. The first time one is plugged in it is
**quarantined** and you get a Shield Kitty notification; the second attempt
**bans it permanently**.

This is the enforcement half of Shield Kitty. `../shield-kitty-watch.py` is the
notification half and deliberately does *not* alert on ordinary device attaches
— a phone being plugged in is not an intrusion, and it fires on every boot for
the machine's own root hubs. This directory acts instead of informing.

## Install

```bash
sudo ./install.sh            # install
sudo ./install.sh --uninstall
```

Writes `/opt/shield-kitty/`, `/etc/udev/rules.d/99-shield-kitty-devices.rules`,
and `/var/lib/shield-kitty/`. The installer warns about any currently-attached
device that is missing from the whitelist before it enables anything.

## Policy

| Device | Result |
|---|---|
| In `whitelist.conf` | allowed, no action |
| Root hub (`1d6b:*`) | always allowed |
| HID — keyboard, mouse, gamepad | always allowed, even if unlisted |
| Unknown, 1st sighting | **quarantined** + notification |
| Unknown, 2nd sighting | **permanently banned** + notification |
| Banned, reattached | re-quarantined + notification |

HID is exempt on purpose. An unwhitelisted keyboard is far more likely to be a
keyboard you forgot to list than an attack, and unbinding its HID driver leaves
you typing at a dead screen with no way to fix the list. Storage, network and
mass-storage devices get no such exemption.

### What "quarantine" actually does

Unbinds the device from every kernel driver bound to it or to its interfaces —
`usb-storage`/`uas` (disk access), `rndis`/`cdc_ether`/`asix` (network),
`usbhid` (input). The kernel stops exposing the interfaces. The device cannot
read your disk, take your network, or type into your session. This is a real
block, not a warning.

Note the driver check is on the **interface** class, not the device class: the
built-in mouse on this machine reports device class `00`, not `09`, so a
device-class check would have missed it.

## Managing

```bash
python3 /opt/shield-kitty/shield-kitty-devices.py list
python3 /opt/shield-kitty/shield-kitty-devices.py whitelist 046d c52b "logitech receiver"
python3 /opt/shield-kitty/shield-kitty-devices.py unban dead beef
python3 /opt/shield-kitty/shield-kitty-devices.py selftest
```

| Path | Contents |
|---|---|
| `/opt/shield-kitty/whitelist.conf` | the policy, root-owned mode 0600 |
| `/var/lib/shield-kitty/blacklist.conf` | permanent bans |
| `/var/lib/shield-kitty/attempts.conf` | sighting counts |
| `/var/lib/shield-kitty/device-policy.log` | every decision, and any alert-delivery failure |

## Failure modes worth knowing

- **A writable whitelist is a disabled whitelist.** It is installed root-owned
  0600; the selftest checks this.
- **Alert delivery is not assumed.** udev runs as root with no display, so the
  script drops to the desktop user and tries four routes. If all four fail it
  writes `ALERT DELIVERY FAILED` to the log — the policy is still applied, but
  you will not have been told. Grep the log.
- **Uninstall is `sudo ./install.sh --uninstall`.** State files are kept for the
  record; delete `/var/lib/shield-kitty` by hand if you want them gone.
