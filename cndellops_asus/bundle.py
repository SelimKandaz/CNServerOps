"""Local evidence bundle generation for read-only ASUS discovery."""

from __future__ import annotations

import json
import os
import re
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cnserverops.secrets import sanitize_evidence


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_") or "unknown"


def write_discovery(output_dir: Path, discovery: dict[str, Any]) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    serial = _safe_name(str(discovery.get("identity", {}).get("system_serial") or "unknown"))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = output_dir / f"asus_discovery_{serial}_{stamp}.json"
    _atomic_json(path, sanitize_evidence(discovery))
    return path


def build_support_bundle(output_dir: Path, discovery_path: Path, discovery: dict[str, Any]) -> Path:
    """Package collected JSON and a technician-friendly manifest; never include credentials."""
    serial = _safe_name(str(discovery.get("identity", {}).get("system_serial") or "unknown"))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    bundle_path = output_dir / f"asus_support_bundle_{serial}_{stamp}.zip"
    manifest = {
        "schema_version": 1,
        "bundle_type": "asus_read_only_support_bundle",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "identity": discovery.get("identity", {}),
        "included": [discovery_path.name],
        "excluded": ["BMC password", "authorization header", "firmware updates", "power actions", "event-log clearing"],
        "collection_errors": discovery.get("collection_errors", []),
    }
    descriptor, temporary_name = tempfile.mkstemp(prefix=bundle_path.name + ".", suffix=".tmp", dir=output_dir)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(discovery_path, arcname=discovery_path.name)
            archive.writestr("manifest.json", json.dumps(sanitize_evidence(manifest), indent=2, sort_keys=True) + "\n")
        temporary.replace(bundle_path)
    finally:
        if temporary.exists():
            temporary.unlink()
    return bundle_path


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        Path(temporary_name).replace(path)
    finally:
        temporary = Path(temporary_name)
        if temporary.exists():
            temporary.unlink()
