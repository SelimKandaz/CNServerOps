"""Atomic, identity-bound universal workflow state."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


class StateMismatchError(RuntimeError):
    """State belongs to a different server or vendor."""


class UnsafeIdentityError(RuntimeError):
    """Current identity is insufficient for a safe reboot/resume workflow."""


class FirmwareTaskContinuityError(RuntimeError):
    """A rebooted firmware workflow cannot prove continuity with its task/job."""


def load_state(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise StateMismatchError("Persisted state is not a JSON object.")
    return payload


def assert_resume_allowed(existing: Mapping[str, Any] | None, identity: Mapping[str, Any]) -> None:
    if not identity.get("resumable") or not identity.get("fingerprint_sha256"):
        raise UnsafeIdentityError(str(identity.get("resume_block_reason") or "machine identity is not resumable"))
    if not existing:
        return
    recorded_fingerprint = str(existing.get("machine_fingerprint_sha256") or "")
    recorded_vendor = str(existing.get("vendor") or "").upper()
    recorded_platform = str(existing.get("platform_id") or "").upper()
    if (
        not recorded_fingerprint
        or recorded_fingerprint != identity.get("fingerprint_sha256")
        or recorded_vendor != str(identity.get("vendor") or "").upper()
        or recorded_platform != str(identity.get("platform_id") or "").upper()
    ):
        raise StateMismatchError(
            "Persisted workflow state belongs to another server/vendor/platform; refusing resume."
        )


def assert_workflow_resume_allowed(
    existing: Mapping[str, Any] | None,
    identity: Mapping[str, Any],
    *,
    run_id: str | None = None,
    runner_id: str | None = None,
) -> None:
    """Apply machine binding plus optional run/runner continuity checks."""
    assert_resume_allowed(existing, identity)
    if not existing:
        return
    if run_id is not None and str(existing.get("run_id") or "") != run_id:
        raise StateMismatchError("Persisted workflow state has a different RUN_ID; refusing resume.")
    if runner_id is not None and str(existing.get("runner_id") or "").upper() != runner_id.upper():
        raise StateMismatchError("Persisted workflow state belongs to a different RUNNER_ID; refusing resume.")


def assert_firmware_task_continuity(
    existing: Mapping[str, Any],
    *,
    observed_task_identity: str,
    observed_task_state: str,
) -> None:
    expected = str(existing.get("firmware_task_identity") or "")
    if not expected:
        raise FirmwareTaskContinuityError("Persisted reboot state has no firmware task identity.")
    if not observed_task_identity or observed_task_identity != expected:
        raise FirmwareTaskContinuityError("Observed firmware task does not match persisted reboot state.")
    if observed_task_state.upper() not in {"COMPLETED", "REBOOT_REQUIRED", "RUNNING"}:
        raise FirmwareTaskContinuityError(
            f"Firmware task is not in an expected resumable state: {observed_task_state or 'missing'}"
        )


def write_state(
    path: Path,
    identity: Mapping[str, Any],
    phase: str,
    details: Mapping[str, Any] | None = None,
    *,
    run_id: str = "",
    runner_id: str = "",
    runtime_version: str = "",
    expected_next_stage: str = "",
    firmware_task_identity: str = "",
) -> None:
    assert_resume_allowed(None, identity)
    payload = {
        "schema_version": 3,
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
        "vendor": identity["vendor"],
        "platform_id": identity["platform_id"],
        "machine_fingerprint_sha256": identity["fingerprint_sha256"],
        "server_id": identity.get("server_id", ""),
        "boot_id": identity.get("boot_id", ""),
        "primary_serial": identity.get("primary_serial", ""),
        "model": identity.get("model", ""),
        "run_id": run_id,
        "runner_id": runner_id,
        "runtime_version": runtime_version,
        "phase": phase,
        "current_workflow_stage": phase,
        "expected_next_stage": expected_next_stage,
        "firmware_task_identity": firmware_task_identity,
        "details": dict(details or {}),
    }
    _atomic_json(path, payload)


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
