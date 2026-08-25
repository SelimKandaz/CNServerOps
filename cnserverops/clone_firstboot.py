"""CLI for explicit golden-image preparation and marker-gated first boot."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Mapping

from .personalization import personalize_clone, prepare_clone_template


def storage_fingerprint_from_properties(properties: Mapping[str, str]) -> str:
    anchors = {
        key: str(properties.get(key) or "").strip()
        for key in ("ID_SERIAL", "ID_SERIAL_SHORT", "ID_WWN", "ID_WWN_WITH_EXTENSION")
        if str(properties.get(key) or "").strip()
    }
    if not anchors:
        raise RuntimeError("ROOT_STORAGE_HARDWARE_ID_UNAVAILABLE")
    canonical = "|".join(f"{key}={anchors[key]}" for key in sorted(anchors))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def discover_root_storage_fingerprint() -> str:
    source = _run(("findmnt", "-n", "-o", "SOURCE", "/")).strip()
    if not source.startswith("/dev/"):
        raise RuntimeError("ROOT_STORAGE_DEVICE_UNAVAILABLE")
    device = source
    visited: set[str] = set()
    while device not in visited:
        visited.add(device)
        parent = _run(("lsblk", "-ndo", "PKNAME", device)).strip()
        if not parent:
            break
        device = "/dev/" + parent
    properties: dict[str, str] = {}
    for line in _run(("udevadm", "info", "--query=property", f"--name={device}")).splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            properties[key] = value
    return storage_fingerprint_from_properties(properties)


def _run(command: tuple[str, ...]) -> str:
    completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=30)
    if completed.returncode != 0:
        raise RuntimeError(f"ALLOWLISTED_DISCOVERY_COMMAND_FAILED:{command[0]}")
    return completed.stdout


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CNServerOps cloned SSD personalization")
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare-template")
    prepare.add_argument("--root", type=Path, default=Path("/"))
    prepare.add_argument("--template-id", required=True)
    prepare.add_argument("--i-understand-this-is-the-golden-image", action="store_true")
    firstboot = commands.add_parser("personalize")
    firstboot.add_argument("--root", type=Path, default=Path("/"))
    firstboot.add_argument("--runtime-version", default="")
    firstboot.add_argument(
        "--runtime-version-file",
        type=Path,
        help="immutable release-manifest.json used by the systemd clone-firstboot unit",
    )
    firstboot.add_argument("--storage-fingerprint-sha256", default="")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "prepare-template":
        result = prepare_clone_template(
            args.root,
            template_id=args.template_id,
            authorized=args.i_understand_this_is_the_golden_image,
        )
    else:
        runtime_version = str(args.runtime_version or "").strip()
        if not runtime_version and args.runtime_version_file:
            try:
                payload = json.loads(args.runtime_version_file.read_text(encoding="utf-8"))
                runtime_version = str(payload.get("version") or "").strip() if isinstance(payload, dict) else ""
            except (OSError, ValueError, json.JSONDecodeError):
                raise RuntimeError("IMMUTABLE_RUNTIME_VERSION_UNAVAILABLE")
        if not runtime_version:
            raise RuntimeError("RUNTIME_VERSION_REQUIRED")
        storage = args.storage_fingerprint_sha256 or discover_root_storage_fingerprint()
        result = personalize_clone(args.root, runtime_version=runtime_version, storage_fingerprint=storage)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
