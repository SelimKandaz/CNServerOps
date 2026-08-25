"""Gated, vendor-neutral firmware lifecycle orchestration.

ASUS transport selection lives in :mod:`cnserverops.asus_firmware`; this
module owns the immutable package gate, task lifecycle and post-version proof.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .firmware import ApplicabilityDecision, FirmwarePackageMetadata, FirmwareRepository
from .safety import MutationGate


class FirmwareExecutionError(RuntimeError):
    pass


def _version_matches(installed: str, target: str, evidence: Mapping[str, Any]) -> bool:
    """Match a live version against the target or verified-image aliases."""
    if str(installed or "") == str(target or ""):
        return True
    aliases = evidence.get("reported_version_aliases") if isinstance(evidence, Mapping) else ()
    if isinstance(aliases, (list, tuple, set)) and str(installed or "") in {str(item) for item in aliases}:
        return True
    return False


class UpdateTaskState(str, Enum):
    NEW = "NEW"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    COMPLETED_WITH_WARNING = "COMPLETED_WITH_WARNING"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"
    BMC_RESTARTING = "BMC_RESTARTING"
    REBOOT_REQUIRED = "REBOOT_REQUIRED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class FirmwarePreview:
    accepted: bool
    mechanism: str
    component: str
    current_version: str
    target_version: str
    reboot_required: bool
    evidence: Mapping[str, Any]


@dataclass(frozen=True)
class UpdateTask:
    task_id: str
    state: UpdateTaskState
    detail: str = ""


class FirmwareUpdateAdapter(Protocol):
    name: str

    def preview(self, package: Path, metadata: FirmwarePackageMetadata) -> FirmwarePreview: ...

    def start(self, package: Path, metadata: FirmwarePackageMetadata) -> UpdateTask: ...

    def poll(self, task_id: str) -> UpdateTask: ...

    def read_installed_version(self, component: str) -> str: ...


class DisabledAsusFirmwareAdapter:
    """Explicit fallback for a server with no verified selectable transport."""

    name = "asus_firmware_transport_not_validated"

    def _blocked(self) -> None:
        raise FirmwareExecutionError(
            "No ASUS firmware mutation transport is enabled; authenticated endpoint and PASS 3 validation are required."
        )

    def preview(self, package: Path, metadata: FirmwarePackageMetadata) -> FirmwarePreview:
        self._blocked()
        raise AssertionError

    def start(self, package: Path, metadata: FirmwarePackageMetadata) -> UpdateTask:
        self._blocked()
        raise AssertionError

    def poll(self, task_id: str) -> UpdateTask:
        self._blocked()
        raise AssertionError

    def read_installed_version(self, component: str) -> str:
        self._blocked()
        raise AssertionError


class FirmwareUpdateExecutor:
    def __init__(self, repository: FirmwareRepository, *, max_polls: int = 120) -> None:
        if max_polls <= 0 or max_polls > 10000:
            raise ValueError("max_polls must be between 1 and 10000")
        self.repository = repository
        self.max_polls = max_polls

    def execute(
        self,
        *,
        identity: Mapping[str, Any],
        metadata: FirmwarePackageMetadata,
        applicability: ApplicabilityDecision,
        adapter: FirmwareUpdateAdapter,
        mutation_gate: MutationGate,
        run_id: str = "",
        progress_callback: Callable[[Mapping[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        if not applicability.approved_for_executor:
            raise FirmwareExecutionError(f"Firmware applicability is not approved: {applicability.status}")
        if applicability.package_sha256 != metadata.sha256.lower():
            raise FirmwareExecutionError("Applicability evidence belongs to a different firmware object")
        package = self.repository.verify(metadata.sha256)
        mutation_gate.require(
            "FIRMWARE_APPLY",
            identity,
            context={
                "run_id": run_id,
                "component": metadata.component,
                "target_version": metadata.version,
                "package_sha256": metadata.sha256,
            },
        )
        preview = adapter.preview(package, metadata)
        if not preview.accepted:
            raise FirmwareExecutionError("Firmware adapter preview rejected the package")
        if preview.target_version != metadata.version or preview.component.upper() != metadata.component.upper():
            raise FirmwareExecutionError("Firmware preview conflicts with verified package metadata")
        if progress_callback is not None:
            progress_callback(
                {
                    "phase": "ADAPTER_STARTING",
                    "component": metadata.component,
                    "target_version": metadata.version,
                    "package_sha256": metadata.sha256,
                    "run_id": run_id,
                }
            )
        task = adapter.start(package, metadata)
        if progress_callback is not None:
            progress_callback(
                {
                    "phase": "TASK_STARTED",
                    "component": metadata.component,
                    "target_version": metadata.version,
                    "package_sha256": metadata.sha256,
                    "task_id": task.task_id,
                    "task_state": task.state.value,
                    "task_detail": task.detail,
                    "run_id": run_id,
                }
            )
        if not task.task_id:
            raise FirmwareExecutionError("Firmware adapter returned no task identity")
        history = [asdict(task) | {"state": task.state.value}]
        for _ in range(self.max_polls):
            if task.state in {
                UpdateTaskState.COMPLETED,
                UpdateTaskState.COMPLETED_WITH_WARNING,
                UpdateTaskState.FAILED,
                UpdateTaskState.CANCELLED,
                UpdateTaskState.TIMED_OUT,
                UpdateTaskState.REBOOT_REQUIRED,
            }:
                break
            task = adapter.poll(task.task_id)
            history.append(asdict(task) | {"state": task.state.value})
            if progress_callback is not None:
                progress_callback(
                    {
                        "phase": "TASK_POLLED",
                        "component": metadata.component,
                        "target_version": metadata.version,
                        "package_sha256": metadata.sha256,
                        "task_id": task.task_id,
                        "task_state": task.state.value,
                        "task_detail": task.detail,
                        "run_id": run_id,
                    }
                )
        else:
            result = self._result("FAILED", "UPDATE_TASK_TIMEOUT", metadata, preview, task, history)
            if progress_callback is not None:
                progress_callback({"phase": "TASK_TERMINAL", **result})
            return result

        if task.state == UpdateTaskState.FAILED:
            result = self._result("FAILED", "FIRMWARE_UPDATE_FAILED", metadata, preview, task, history)
            if progress_callback is not None:
                progress_callback({"phase": "TASK_TERMINAL", **result})
            return result
        if task.state == UpdateTaskState.CANCELLED:
            result = self._result("FAILED", "UPDATE_TASK_CANCELLED", metadata, preview, task, history)
            if progress_callback is not None:
                progress_callback({"phase": "TASK_TERMINAL", **result})
            return result
        if task.state == UpdateTaskState.TIMED_OUT:
            result = self._result("FAILED", "UPDATE_TASK_TIMEOUT", metadata, preview, task, history)
            if progress_callback is not None:
                progress_callback({"phase": "TASK_TERMINAL", **result})
            return result
        if task.state == UpdateTaskState.REBOOT_REQUIRED:
            result = self._result("REBOOT_REQUIRED", "REBOOT_REQUIRED", metadata, preview, task, history)
            if progress_callback is not None:
                progress_callback({"phase": "TASK_TERMINAL", **result})
            return result
        if task.state not in {UpdateTaskState.COMPLETED, UpdateTaskState.COMPLETED_WITH_WARNING}:
            result = self._result("FAILED", "UPDATE_TASK_UNKNOWN", metadata, preview, task, history)
            if progress_callback is not None:
                progress_callback({"phase": "TASK_TERMINAL", **result})
            return result
        installed = adapter.read_installed_version(metadata.component)
        if not _version_matches(installed, metadata.version, preview.evidence):
            result = self._result(
                "FAILED", "POST_UPDATE_VERSION_MISMATCH", metadata, preview, task, history, installed=installed
            )
            if progress_callback is not None:
                progress_callback({"phase": "TASK_TERMINAL", **result})
            return result
        if task.state == UpdateTaskState.COMPLETED_WITH_WARNING:
            result = self._result(
                "SUCCESS_WITH_WARNING",
                "VERSION_VERIFIED_WITH_TASK_WARNING",
                metadata,
                preview,
                task,
                history,
                installed=installed,
            )
            if progress_callback is not None:
                progress_callback({"phase": "TASK_TERMINAL", **result})
            return result
        result = self._result("SUCCESS", "VERSION_VERIFIED", metadata, preview, task, history, installed=installed)
        if progress_callback is not None:
            progress_callback({"phase": "TASK_TERMINAL", **result})
        return result

    def resume_task(
        self,
        *,
        identity: Mapping[str, Any],
        metadata: FirmwarePackageMetadata,
        adapter: FirmwareUpdateAdapter,
        task_id: str,
        run_id: str = "",
        progress_callback: Callable[[Mapping[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """Reattach to a durable task without opening a second mutation gate.

        This is used after a process/service interruption while a BMC task is
        running.  The original task identity and exact package metadata are
        persisted before the interruption; the method only polls that task,
        then performs the normal installed-version proof.  It never calls
        ``adapter.start`` and therefore cannot duplicate a flash.
        """
        normalized_task = str(task_id or "")
        if not normalized_task:
            raise FirmwareExecutionError("DURABLE_FIRMWARE_TASK_ID_MISSING")
        package = self.repository.verify(metadata.sha256)
        preview = adapter.preview(package, metadata)
        if not preview.accepted:
            raise FirmwareExecutionError("DURABLE_FIRMWARE_TASK_PREVIEW_REJECTED")
        task = UpdateTask(normalized_task, UpdateTaskState.RUNNING, "RESUMED_DURABLE_TASK")
        history = [asdict(task) | {"state": task.state.value}]
        if progress_callback is not None:
            progress_callback(
                {
                    "phase": "TASK_RESUMED",
                    "component": metadata.component,
                    "target_version": metadata.version,
                    "package_sha256": metadata.sha256,
                    "task_id": normalized_task,
                    "run_id": run_id,
                }
            )
        for _ in range(self.max_polls):
            task = adapter.poll(normalized_task)
            history.append(asdict(task) | {"state": task.state.value})
            if progress_callback is not None:
                progress_callback(
                    {
                        "phase": "TASK_RESUMED_POLLED",
                        "component": metadata.component,
                        "target_version": metadata.version,
                        "package_sha256": metadata.sha256,
                        "task_id": normalized_task,
                        "task_state": task.state.value,
                        "task_detail": task.detail,
                        "run_id": run_id,
                    }
                )
            if task.state in {
                UpdateTaskState.COMPLETED,
                UpdateTaskState.COMPLETED_WITH_WARNING,
                UpdateTaskState.FAILED,
                UpdateTaskState.CANCELLED,
                UpdateTaskState.TIMED_OUT,
                UpdateTaskState.REBOOT_REQUIRED,
            }:
                break
        else:
            return self._result("FAILED", "UPDATE_TASK_TIMEOUT", metadata, preview, task, history)
        if task.state == UpdateTaskState.REBOOT_REQUIRED:
            return self._result("REBOOT_REQUIRED", "REBOOT_REQUIRED", metadata, preview, task, history)
        if task.state == UpdateTaskState.FAILED:
            return self._result("FAILED", "FIRMWARE_UPDATE_FAILED", metadata, preview, task, history)
        if task.state in {UpdateTaskState.CANCELLED, UpdateTaskState.TIMED_OUT}:
            return self._result("FAILED", f"UPDATE_TASK_{task.state.value}", metadata, preview, task, history)
        installed = adapter.read_installed_version(metadata.component)
        if not _version_matches(installed, metadata.version, preview.evidence):
            return self._result("FAILED", "POST_UPDATE_VERSION_MISMATCH", metadata, preview, task, history, installed=installed)
        status = "SUCCESS_WITH_WARNING" if task.state == UpdateTaskState.COMPLETED_WITH_WARNING else "SUCCESS"
        reason = "VERSION_VERIFIED_WITH_TASK_WARNING" if status.endswith("WARNING") else "VERSION_VERIFIED"
        return self._result(status, reason, metadata, preview, task, history, installed=installed)

    @staticmethod
    def _result(
        status: str,
        reason: str,
        metadata: FirmwarePackageMetadata,
        preview: FirmwarePreview,
        task: UpdateTask,
        history: list[dict[str, Any]],
        *,
        installed: str = "",
    ) -> dict[str, Any]:
        # ``start`` has already crossed the operator gate and attempted the
        # transport.  It is only a *started* mutation when the adapter returned
        # a real task identity; synthetic error identities (REDFISH-ERROR,
        # ASUS-PAYLOAD-ERROR, etc.) mean the BMC rejected the request before a
        # firmware task existed.
        task_identity = str(task.task_id or "")
        # A web-HPM staged task intentionally has a synthetic ASUS-* identity
        # because the BMC exposes no durable Redfish task resource.  Its
        # detail carries an explicit mutation marker and must still be treated
        # as started so final credential handoff cannot be skipped.
        mutation_started = bool(
            task_identity
            and (
                str(task.detail or "").startswith("MUTATION_STARTED:")
                or (
                    not task_identity.startswith("REDFISH-")
                    and not task_identity.startswith("ASUS-")
                )
            )
        )
        return {
            "schema_version": 1,
            "status": status,
            "reason_code": reason,
            "component": metadata.component,
            "target_version": metadata.version,
            "installed_version": installed,
            "package_sha256": metadata.sha256,
            "preview": asdict(preview),
            "task_id": task.task_id,
            "task_history": history,
            "mutation_attempted": True,
            "mutation_started": mutation_started,
        }
