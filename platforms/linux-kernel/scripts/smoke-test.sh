#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# smoke-test.sh — safe insmod → observe → rmmod cycle for aivpn.ko.
#
# Loads the freshly-built module WITHOUT wiring any socket/TUN (so no packet
# ever traverses the data path), confirms /proc/aivpn/stats appears, then
# unloads it. Prints any kernel oops/warning that appeared during the window so
# a C bug shows up immediately instead of silently wedging the live kernel.
#
# Usage:  sudo ./scripts/smoke-test.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
KO="$HERE/aivpn.ko"

if [[ $EUID -ne 0 ]]; then
	echo "must run as root (insmod/rmmod)" >&2
	exit 1
fi
if [[ ! -f "$KO" ]]; then
	echo "module not built: $KO — run 'make' first" >&2
	exit 1
fi
if lsmod | grep -q '^aivpn'; then
	echo "aivpn already loaded — rmmod first" >&2
	exit 1
fi

MARK="aivpn-smoke-$$"
echo "$MARK begin" > /dev/kmsg || true

echo "== insmod =="
insmod "$KO"

echo "== /proc/aivpn/stats =="
cat /proc/aivpn/stats

echo "== lsmod =="
lsmod | grep '^aivpn' || true

echo "== rmmod =="
rmmod aivpn

echo "$MARK end" > /dev/kmsg || true

echo "== kernel messages during window =="
dmesg | sed -n "/$MARK begin/,/$MARK end/p" | grep -iE 'aivpn|oops|warn|bug|panic|call trace' || echo "(clean — no oops/warn)"

echo "OK: load/observe/unload cycle completed cleanly"
