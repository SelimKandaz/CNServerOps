"""Safe transition when one SSD is moved to a different physical server."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping


_STALE_CURRENT_STATE = (
    "current-server.json",
    "current-run.json",
    "workflow-state.json",
    "resume-state.json",
    "active-workflow.json",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_json(path: Path) -> Mapping[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, ValueError):
        return None
    return payload if isinstance(payload, Mapping) else None


def _server_from_run(path: Path) -> dict[str, str]:
    context = _read_json(path)
    if not context:
        return {}
    server = context.get("server") if isinstance(context.get("server"), Mapping) else {}
    run = context.get("run") if isinstance(context.get("run"), Mapping) else {}
    return {
        "server_id": str(server.get("server_id") or ""),
        "fingerprint_sha256": str(server.get("fingerprint_sha256") or run.get("server_fingerprint_sha256") or ""),
        "vendor": str(server.get("vendor") or run.get("vendor") or ""),
        "model": str(server.get("model") or run.get("model") or ""),
        "system_serial": str(server.get("system_serial") or run.get("system_serial") or ""),
        "run_id": str(run.get("run_id") or ""),
        "started_at_utc": str(run.get("started_at_utc") or ""),
    }


def _latest_server(primary_root: Path) -> dict[str, str]:
    runs = primary_root / "runs"
    candidates: list[dict[str, str]] = []
    if not runs.is_dir():
        return {}
    for path in runs.glob("RUN-*/run.json"):
        item = _server_from_run(path)
        if item.get("fingerprint_sha256"):
            candidates.append(item)
    return max(candidates, key=lambda item: (item.get("started_at_utc", ""), item.get("run_id", "")), default={})


def _atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
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


def reconcile_server_enrollment(
    primary_root: Path,
    identity: Mapping[str, Any],
    *,
    runner_id: str = "",
    server_specific_paths: Iterable[Path | str] = (),
) -> dict[str, Any]:
    """Adopt a trusted new server without transferring old resumable state.

    Historical run directories are never moved or deleted.  Only explicitly
    named root-level current/resume files are moved into a dated quarantine.
    A new run is always created by the caller with a new SERVER_ID/RUN_ID while
    the caller-provided RUNNER_ID remains unchanged.
    """
    current_fp = str(identity.get("fingerprint_sha256") or "")
    current = {
        "server_id": str(identity.get("server_id") or ""),
        "fingerprint_sha256": current_fp,
        "vendor": str(identity.get("vendor") or ""),
        "model": str(identity.get("model") or ""),
        "system_serial": str(identity.get("primary_serial") or ""),
        "boot_id": str(identity.get("boot_id") or ""),
    }
    if not current_fp or str(identity.get("identity_state") or "") != "TRUSTED_CURRENT":
        return {
            "schema_version": 1,
            "status": "UNTRUSTED_IDENTITY",
            "current": current,
            "previous": _latest_server(primary_root),
            "runner_id_preserved": str(runner_id or ""),
            "quarantined_paths": [],
            "reason": str(identity.get("resume_block_reason") or "trusted current identity is not available"),
        }

    previous = _latest_server(primary_root)
    if not previous:
        status = "FIRST_SERVER_ENROLLED"
    elif previous.get("fingerprint_sha256") == current_fp:
        status = "EXISTING_SERVER"
    else:
        status = "NEW_SERVER_ENROLLED"

    quarantined: list[str] = []
    quarantine_dir = primary_root / "enrollment-quarantine" / (
        f"ENR-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{current_fp[:12].upper()}"
    )
    # Operational BMC credentials are deliberately outside ``primary_root``.
    # When a technician SSD is moved to a new (or first) physical server, move
    # those files into the same reversible quarantine before any auth discovery
    # can see them.  Their contents are never opened.  A same-server reboot
    # keeps them intact so an interrupted run can resume normally.
    external_quarantined: list[str] = []
    if status in {"NEW_SERVER_ENROLLED", "FIRST_SERVER_ENROLLED"}:
        for raw_path in server_specific_paths:
            source = Path(raw_path)
            if not source.exists() and not source.is_symlink():
                continue
            label = f"external-state/{source.name}"
            destination = quarantine_dir / label
            suffix = 1
            while destination.exists() or destination.is_symlink():
                destination = quarantine_dir / "external-state" / f"{source.name}.{suffix}"
                suffix += 1
            destination.parent.mkdir(parents=True, exist_ok=True)
            source.replace(destination)
            external_quarantined.append(label)
    if status == "NEW_SERVER_ENROLLED":
        for name in _STALE_CURRENT_STATE:
            source = primary_root / name
            if not source.exists() and not source.is_symlink():
                continue
            destination = quarantine_dir / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists() or destination.is_symlink():
                continue
            source.replace(destination)
            quarantined.append(name)

    record = {
        "schema_version": 1,
        "status": status,
        "enrolled_at_utc": _utc_now(),
        "current": current,
        "previous": previous,
        "runner_id_preserved": str(runner_id or ""),
        "historical_state_preserved": True,
        "previous_run_resumed": False,
        "old_mutation_gate_transferred": False,
        "prior_firmware_target_transferred": False,
        "quarantine_directory": str(quarantine_dir) if (quarantined or external_quarantined) else "",
        "quarantined_paths": quarantined + external_quarantined,
        "new_server_id": current.get("server_id", ""),
        "new_run_required": True,
    }
    _atomic_json(primary_root / "enrollment" / "latest.json", record)
    return record
