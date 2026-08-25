#!/bin/sh
set -eu

# Keep the entry point tiny and auditable.  All disk discovery, confirmation,
# destructive-operation guards and validation live in the Python core.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec /usr/bin/python3 "$SCRIPT_DIR/cnserverops_ssd_installer.py" "$@"
