#!/bin/sh
set -eu

START=0
DISABLE_SMARTD=0
for argument in "$@"; do
    case "$argument" in
        --start) START=1 ;;
        --disable-smartd) DISABLE_SMARTD=1 ;;
        *) echo "Unknown argument: $argument" >&2; exit 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo 'Launcher installation requires root.' >&2
    exit 1
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHONPATH=/opt/cnserverops/current PYTHONDONTWRITEBYTECODE=1 \
    /usr/bin/python3 -c 'import cnserverops.operator_console, cnserverops.production'

/usr/bin/install -d -m 0700 /etc/cnserverops /var/lib/cnserverops/production
/usr/bin/install -m 0755 "$SCRIPT_DIR/cnserverops-console" /usr/local/sbin/cnserverops-console
/usr/bin/install -m 0755 "$SCRIPT_DIR/cnserverops-launcher-rollback" /usr/local/sbin/cnserverops-launcher-rollback
/usr/bin/install -m 0644 "$SCRIPT_DIR/cnserverops-console.service" /etc/systemd/system/cnserverops-console.service
/usr/bin/install -m 0644 "$SCRIPT_DIR/cnserverops-firmware-resume.service" /etc/systemd/system/cnserverops-firmware-resume.service
/usr/bin/install -m 0644 "$SCRIPT_DIR/cnserverops-firmware-resume-retry.service" /etc/systemd/system/cnserverops-firmware-resume-retry.service
/usr/bin/install -m 0644 "$SCRIPT_DIR/cnserverops-firmware-resume-retry.timer" /etc/systemd/system/cnserverops-firmware-resume-retry.timer
/usr/bin/install -m 0644 "$SCRIPT_DIR/cnserverops-clone-firstboot.service" /etc/systemd/system/cnserverops-clone-firstboot.service
/usr/bin/install -m 0644 "$SCRIPT_DIR/cnserverops-sync-retry.service" /etc/systemd/system/cnserverops-sync-retry.service
/usr/bin/install -m 0644 "$SCRIPT_DIR/cnserverops-sync-retry.timer" /etc/systemd/system/cnserverops-sync-retry.timer

if [ ! -e /etc/cnserverops/production.json ]; then
    /usr/bin/install -m 0600 "$SCRIPT_DIR/cnserverops-production.example.json" /etc/cnserverops/production.json
fi
if [ ! -e /etc/cnserverops/central.json ]; then
    /usr/bin/install -m 0600 "$SCRIPT_DIR/cnserverops-central.example.json" /etc/cnserverops/central.json
fi

# Verify immutable release bytes and the configured factory-default BMC secret
# *without ever reading the secret*.  This must happen before tty ownership or
# unit enablement changes, so a missing deployment prerequisite cannot leave a
# partially activated console.
PYTHONPATH=/opt/cnserverops/current PYTHONDONTWRITEBYTECODE=1 \
    /usr/bin/python3 -m cnserverops.runtime_preflight \
    --release-root /opt/cnserverops/current \
    --config /etc/cnserverops/production.json

STATE=/var/lib/cnserverops/launcher-install-state.json
if [ ! -e "$STATE" ]; then
    GETTY_STATE=$(/usr/bin/systemctl is-enabled getty@tty1.service 2>/dev/null || true)
    DELL_STATE=$(/usr/bin/systemctl is-enabled cngpu-countdown-menu.service 2>/dev/null || true)
    SMARTD_STATE=$(/usr/bin/systemctl is-enabled smartmontools.service 2>/dev/null || true)
    /usr/bin/python3 - "$STATE" "$GETTY_STATE" "$DELL_STATE" "$SMARTD_STATE" <<'PY'
import json, os, sys, tempfile
from datetime import datetime, timezone
path, getty, dell, smartd = sys.argv[1:]
payload = {
    "schema_version": 1,
    "captured_at_utc": datetime.now(timezone.utc).isoformat(),
    "getty_tty1_enable_state": getty,
    "legacy_dell_menu_enable_state": dell,
    "smartmontools_enable_state": smartd,
    "legacy_dell_files_deleted": False,
}
directory = os.path.dirname(path)
fd, temporary = tempfile.mkstemp(prefix="launcher-state.", suffix=".tmp", dir=directory)
with os.fdopen(fd, "w", encoding="utf-8") as stream:
    json.dump(payload, stream, indent=2, sort_keys=True)
    stream.write("\n")
    stream.flush()
    os.fsync(stream.fileno())
os.chmod(temporary, 0o600)
os.replace(temporary, path)
PY
fi

# The new launcher owns tty1.  The legacy Dell unit remains present but must
# remain disabled; this command changes enablement only and never deletes files.
/usr/bin/systemctl disable --now getty@tty1.service >/dev/null 2>&1 || true
/usr/bin/systemctl disable --now cngpu-countdown-menu.service >/dev/null 2>&1 || true

if [ "$DISABLE_SMARTD" -eq 1 ]; then
    # smartctl remains installed and is invoked on demand.  smartd is not useful
    # on this USB image when it exits 17 because no monitorable device exists.
    /usr/bin/systemctl disable --now smartmontools.service >/dev/null 2>&1 || true
    /usr/bin/systemctl reset-failed smartmontools.service >/dev/null 2>&1 || true
fi

/usr/bin/systemctl daemon-reload
/usr/bin/systemctl enable cnserverops-console.service >/dev/null
/usr/bin/systemctl enable cnserverops-firmware-resume.service >/dev/null
/usr/bin/systemctl enable --now cnserverops-firmware-resume-retry.timer >/dev/null
/usr/bin/systemctl enable cnserverops-clone-firstboot.service >/dev/null
/usr/bin/systemctl enable --now cnserverops-sync-retry.timer >/dev/null
# The copied systemd units must exactly match the active immutable release.
# This is intentionally a byte comparison, not merely a service-name check.
PYTHONPATH=/opt/cnserverops/current PYTHONDONTWRITEBYTECODE=1 \
    /usr/bin/python3 -m cnserverops.runtime_preflight \
    --release-root /opt/cnserverops/current \
    --config /etc/cnserverops/production.json \
    --systemd-root /etc/systemd/system
if [ "$START" -eq 1 ]; then
    /usr/bin/systemctl restart cnserverops-console.service
fi

echo 'CNServerOps launcher installed.'
echo "started=$START"
echo 'No production workflow was started by this installer.'
