"""Durable, identity-bound firmware reboot/resume checkpoints.

The production console is deliberately the only place that starts a new
firmware workflow.  Once an explicitly authorised update needs a host reboot,
this module owns the *continuation* record: it is written and fsynced before
the reboot request, carries no credential material, and can only be consumed
by the same SSD and the same physical server after a new Linux boot.

It is intentionally vendor-neutral.  ASUS transport code reports that a
component requires a reboot; the production workflow decides which post-reboot
pipeline (firmware-only, production, or production+diagnostics) must resume.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol


class FirmwareLifecycleError(RuntimeError):
    """Safe lifecycle failure; messages never include secrets or HTTP bodies."""


class RebootCommandExecutor(Protocol):
    def run(self, tool: str, arguments: tuple[str, ...], *, timeout_seconds: int) -> dict[str, Any]: ...


_RUN_ID = re.compile(r"^RUN-[A-Z0-9-]{8,96}$")
_WORKFLOWS = frozenset({"PRODUCTION", "PRODUCTION_EXTENDED", "FIRMWARE_ONLY"})


def pending_path(primary_root: Path) -> Path:
    return Path(primary_root) / "firmware-pending.json"


def build_pending(
    *,
    run_id: str,
    run_directory: Path,
    identity: Mapping[str, Any],
    runner_id: str,
    workflow_mode: str,
    profile_id: str = "STANDARD",
    profile_total_seconds: int = 0,
    extended_diagnostics: bool = False,
    plan: Mapping[str, Any],
    execution: Mapping[str, Any],
    bmc_auth_changed: bool,
) -> dict[str, Any]:
    """Create a public, durable checkpoint from an exact firmware plan."""
    normalized_run_id = str(run_id or "").upper()
    if not _RUN_ID.fullmatch(normalized_run_id):
        raise FirmwareLifecycleError("PENDING_FIRMWARE_RUN_ID_INVALID")
    normalized_mode = str(workflow_mode or "").upper()
    if normalized_mode not in _WORKFLOWS:
        raise FirmwareLifecycleError("PENDING_FIRMWARE_WORKFLOW_INVALID")
    resolved_dir = Path(run_directory)
    if not str(identity.get("fingerprint_sha256") or "") or not str(identity.get("server_id") or ""):
        raise FirmwareLifecycleError("PENDING_FIRMWARE_IDENTITY_INCOMPLETE")
    if not str(runner_id or ""):
        raise FirmwareLifecycleError("PENDING_FIRMWARE_RUNNER_ID_MISSING")

    components: list[dict[str, str]] = []
    for item in plan.get("components") or []:
        if not isinstance(item, Mapping):
            continue
        status = str(item.get("status") or "").upper()
        component = str(item.get("component") or "").upper()
        target = str(item.get("target") or "")
        if component and target and status in {
            "UPDATE_REQUIRED",
            "CURRENT_VERIFIED",
            "UPDATED_VERIFIED",
            "REBOOT_REQUIRED",
        }:
            components.append(
                {
                    "component": component,
                    "before": str(item.get("before") or ""),
                    "target": target,
                    # Preserve whether this component was already attested
                    # before a later component requested another reboot.  A
                    # refreshed plan can legitimately describe a BMC that
                    # this same RUN just updated as CURRENT_VERIFIED while a
                    # later BIOS activation is still REBOOT_REQUIRED.  Keep
                    # that exact target in the checkpoint so resume can
                    # independently re-attest both components.  A second
                    # checkpoint must never re-queue a component that the
                    # same RUN already verified.
                    "plan_status": status,
                }
            )
    if not components:
        raise FirmwareLifecycleError("PENDING_FIRMWARE_COMPONENTS_MISSING")
    executed: dict[str, str] = {}
    activation_pending: list[str] = []
    for item in execution.get("components") or []:
        if not isinstance(item, Mapping):
            continue
        component = str(item.get("component") or "").upper()
        status = str(item.get("status") or "").upper()
        if not component:
            continue
        executed[component] = status
        if status == "REBOOT_REQUIRED":
            activation_pending.append(component)
    if not activation_pending:
        pending_component = str(execution.get("pending_component") or "").upper()
        if pending_component:
            activation_pending.append(pending_component)
    if not activation_pending:
        # A checkpoint must correspond to an actual activation boundary; a
        # generic plan alone is never enough to restart a run automatically.
        raise FirmwareLifecycleError("PENDING_FIRMWARE_ACTIVATION_COMPONENT_MISSING")
    # Components which completed before this activation boundary still need a
    # current-boot AFTER attestation.  For example, a BMC update can complete
    # and verify before a later BIOS update requests the host reboot.  Without
    # retaining this set, the resume path could report the old plan state even
    # though the BMC was successfully updated, or (worse) skip the independent
    # post-reboot BMC verification.
    completed_pre_reboot = sorted(
        {
            component
            for component, status in executed.items()
            if status in {"SUCCESS", "SUCCESS_WITH_WARNING", "UPDATED_VERIFIED"}
        }
    )
    remaining = [
        item["component"]
        for item in components
        if item.get("plan_status") in {"UPDATE_REQUIRED", "REBOOT_REQUIRED"}
        and item["component"] not in set(activation_pending)
        and executed.get(item["component"]) not in {"SUCCESS", "SUCCESS_WITH_WARNING", "UPDATED_VERIFIED"}
    ]
    return {
        "schema_version": 2,
        "created_at_utc": _utc_now(),
        "updated_at_utc": _utc_now(),
        "state": "REBOOT_PENDING",
        "run_id": normalized_run_id,
        "run_directory": str(resolved_dir),
        "workflow_mode": normalized_mode,
        "profile_id": str(profile_id or "STANDARD").upper(),
        "profile_total_seconds": max(0, int(profile_total_seconds or 0)),
        "extended_diagnostics": bool(extended_diagnostics),
        "server_id": str(identity.get("server_id") or ""),
        "system_serial": str(identity.get("primary_serial") or ""),
        "fingerprint_sha256": str(identity.get("fingerprint_sha256") or ""),
        "runner_id": str(runner_id),
        "boot_id_before": str(identity.get("boot_id") or ""),
        "components": components,
        "activation_pending_components": sorted(set(activation_pending)),
        "completed_pre_reboot_components": completed_pre_reboot,
        "remaining_components": remaining,
        "execution_status": str(execution.get("status") or "REBOOT_REQUIRED"),
        "firmware_task_identity": str(execution.get("task_id") or execution.get("firmware_task_identity") or ""),
        "mutation_started": bool(execution.get("mutation_started")),
        "bmc_auth_changed": bool(bmc_auth_changed),
        "reboot": {"requested": False, "requested_at_utc": "", "status": "NOT_REQUESTED"},
        "sensitive_material_exposed": False,
    }


def save_pending(primary_root: Path, payload: Mapping[str, Any]) -> Path:
    """Atomically publish a checkpoint before any reboot is requested."""
    target = pending_path(primary_root)
    _atomic_json(target, payload)
    return target


def load_pending(primary_root: Path) -> dict[str, Any] | None:
    path = pending_path(primary_root)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, Mapping):
        return None
    result = dict(payload)
    if not _RUN_ID.fullmatch(str(result.get("run_id") or "").upper()):
        return None
    if str(result.get("workflow_mode") or "").upper() not in _WORKFLOWS:
        return None
    return result


def validate_pending_for_resume(
    pending: Mapping[str, Any],
    *,
    identity: Mapping[str, Any],
    runner_id: str,
    require_new_boot: bool = True,
) -> None:
    """Reject cross-server/cross-runner continuations and (normally) no reboot.

    ``require_new_boot`` is false only for the boot-service recovery path.  A
    process can be restarted on the same Linux boot after ``systemctl reboot``
    was denied or a BMC-only restart interrupted the request.  That path may
    re-issue the already-authorized reboot checkpoint, but it must never run a
    firmware adapter again on the same boot.
    """
    if not bool(identity.get("resumable")):
        raise FirmwareLifecycleError("PENDING_FIRMWARE_CURRENT_IDENTITY_NOT_RESUMABLE")
    bindings = {
        "server_id": (str(pending.get("server_id") or ""), str(identity.get("server_id") or "")),
        "fingerprint": (
            str(pending.get("fingerprint_sha256") or ""),
            str(identity.get("fingerprint_sha256") or ""),
        ),
        "runner_id": (str(pending.get("runner_id") or "").upper(), str(runner_id or "").upper()),
    }
    for label, (expected, observed) in bindings.items():
        if not expected or expected != observed:
            raise FirmwareLifecycleError(f"PENDING_FIRMWARE_{label.upper()}_MISMATCH")
    before = str(pending.get("boot_id_before") or "")
    after = str(identity.get("boot_id") or "")
    if require_new_boot and before and after and before == after:
        raise FirmwareLifecycleError("PENDING_FIRMWARE_BOOT_ID_UNCHANGED")


def request_controlled_reboot(
    *,
    executor: RebootCommandExecutor,
    primary_root: Path,
    pending: Mapping[str, Any],
) -> dict[str, Any]:
    """Record and request the one controlled host reboot needed by firmware.

    The record is updated before executing ``systemctl reboot``.  If the
    command fails, the durable checkpoint remains recoverable and the caller
    can safely report a failed reboot request without discarding the staged
    firmware evidence.
    """
    payload = dict(pending)
    run_id = str(payload.get("run_id") or "")
    if not _RUN_ID.fullmatch(run_id):
        raise FirmwareLifecycleError("PENDING_FIRMWARE_RUN_ID_INVALID")
    reboot = dict(payload.get("reboot") or {})
    retry_count = int(reboot.get("retry_count") or 0)
    if retry_count >= 3:
        return {
            "status": "REBOOT_REQUEST_FAILED",
            "pending": payload,
            "reason": "PENDING_FIRMWARE_REBOOT_RETRY_LIMIT_EXCEEDED",
            "sensitive_material_exposed": False,
        }
    retry_count += 1
    reboot.update({"requested": True, "requested_at_utc": _utc_now(), "status": "REQUESTED"})
    reboot["retry_count"] = retry_count
    payload["reboot"] = reboot
    payload["updated_at_utc"] = _utc_now()
    save_pending(primary_root, payload)
    result = executor.run(
        "systemctl",
        ("reboot", "--message", f"CNServerOps firmware resume {run_id}"),
        timeout_seconds=60,
    )
    passed = str(result.get("status") or "").upper() in {"PASS", "OK", "COMPLETED"} or result.get("exit_code") == 0
    reboot["status"] = "REQUESTED" if passed else "FAILED"
    reboot["result"] = {
        "tool": "systemctl",
        "status": str(result.get("status") or "UNKNOWN"),
        "exit_code": result.get("exit_code"),
    }
    payload["reboot"] = reboot
    payload["updated_at_utc"] = _utc_now()
    save_pending(primary_root, payload)
    return {
        "status": "REBOOT_REQUESTED" if passed else "REBOOT_REQUEST_FAILED",
        "pending": payload,
        "sensitive_material_exposed": False,
    }


def clear_pending(primary_root: Path, run_directory: Path | None = None) -> None:
    for path in (pending_path(primary_root), (Path(run_directory) / "firmware-pending.json") if run_directory else None):
        if path is None:
            continue
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(dict(payload), stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_name, 0o600)
        Path(temporary_name).replace(path)
    finally:
        temporary = Path(temporary_name)
        if temporary.exists():
            temporary.unlink()
