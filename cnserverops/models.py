"""Durable server, runner, and production-run models."""

from __future__ import annotations

import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"RUN-{stamp}-{uuid.uuid4().hex[:12].upper()}"


def new_event_id() -> str:
    return f"EVT-{uuid.uuid4().hex.upper()}"


_RUNNER_ID = re.compile(r"^[A-Z0-9][A-Z0-9._-]{2,63}$")


def validate_runner_id(value: str) -> str:
    normalized = str(value or "").strip().upper()
    if not _RUNNER_ID.fullmatch(normalized):
        raise ValueError("RUNNER_ID must be 3-64 uppercase letters, digits, dot, underscore, or hyphen")
    return normalized


class FinalDisposition(str, Enum):
    PASS = "PASS"
    PASS_WITH_WARNINGS = "PASS_WITH_WARNINGS"
    REVIEW = "REVIEW"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"


class OperationStatus(str, Enum):
    NOT_STARTED = "NOT_STARTED"
    IN_PROGRESS = "IN_PROGRESS"
    PASS = "PASS"
    PARTIAL = "PARTIAL"
    FAIL = "FAIL"
    PENDING_UPLOAD = "PENDING_UPLOAD"
    SYNCED = "SYNCED"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class ServerRecord:
    fingerprint_sha256: str
    vendor: str
    model: str
    system_serial: str
    server_id: str = ""
    dmi_uuid: str = ""
    board_serial: str = ""
    chassis_serial: str = ""
    confidence: str = "low"
    anchors: Mapping[str, str] = field(default_factory=dict)

    @classmethod
    def from_identity(cls, identity: Mapping[str, Any]) -> "ServerRecord":
        fingerprint = str(identity.get("fingerprint_sha256") or "")
        if not fingerprint:
            raise ValueError("ServerRecord requires a validated machine fingerprint")
        anchors = {str(key): str(value) for key, value in dict(identity.get("anchors") or {}).items()}
        return cls(
            fingerprint_sha256=fingerprint,
            vendor=str(identity.get("vendor") or "UNKNOWN").upper(),
            model=str(identity.get("model") or ""),
            system_serial=str(identity.get("primary_serial") or ""),
            server_id=str(identity.get("server_id") or f"SERVER-{fingerprint.upper()}"),
            dmi_uuid=str(identity.get("dmi_uuid") or ""),
            board_serial=anchors.get("dmi_board_serial") or anchors.get("fru_board_serial", ""),
            chassis_serial=anchors.get("dmi_chassis_serial") or anchors.get("fru_chassis_serial", ""),
            confidence=str(identity.get("confidence") or "low"),
            anchors=anchors,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RunRecord:
    run_id: str
    runner_id: str
    runtime_version: str
    server_fingerprint_sha256: str
    vendor: str
    model: str
    system_serial: str
    started_at_utc: str
    workflow_mode: str = "PRODUCTION"
    test_profile: str = "STANDARD"
    boot_id: str = ""
    continuation_of_run_id: str = ""
    completed_at_utc: str = ""
    current_stage: str = "IDENTITY"
    collection_status: OperationStatus = OperationStatus.IN_PROGRESS
    export_status: OperationStatus = OperationStatus.NOT_STARTED
    central_sync_status: OperationStatus = OperationStatus.PENDING_UPLOAD
    final_disposition: FinalDisposition | None = None
    reason_codes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @classmethod
    def start(
        cls,
        server: ServerRecord,
        *,
        runner_id: str,
        runtime_version: str,
        boot_id: str = "",
        continuation_of_run_id: str = "",
        workflow_mode: str = "PRODUCTION",
        test_profile: str = "STANDARD",
    ) -> "RunRecord":
        return cls(
            run_id=new_run_id(),
            runner_id=validate_runner_id(runner_id),
            runtime_version=str(runtime_version),
            server_fingerprint_sha256=server.fingerprint_sha256,
            vendor=server.vendor,
            model=server.model,
            system_serial=server.system_serial,
            started_at_utc=utc_now(),
            workflow_mode=str(workflow_mode or "PRODUCTION").upper(),
            test_profile=str(test_profile or "STANDARD").upper(),
            boot_id=str(boot_id or ""),
            continuation_of_run_id=str(continuation_of_run_id or ""),
        )

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "RunRecord":
        values = dict(payload)
        values.setdefault("boot_id", "")
        values.setdefault("continuation_of_run_id", "")
        values.setdefault("workflow_mode", "PRODUCTION")
        values.setdefault("test_profile", "STANDARD")
        values["collection_status"] = OperationStatus(values["collection_status"])
        values["export_status"] = OperationStatus(values["export_status"])
        values["central_sync_status"] = OperationStatus(values["central_sync_status"])
        disposition = values.get("final_disposition")
        values["final_disposition"] = FinalDisposition(disposition) if disposition else None
        return cls(**values)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["collection_status"] = self.collection_status.value
        payload["export_status"] = self.export_status.value
        payload["central_sync_status"] = self.central_sync_status.value
        payload["final_disposition"] = self.final_disposition.value if self.final_disposition else None
        return payload


def run_started_event(
    run: RunRecord,
    server: ServerRecord,
    *,
    bmc: Mapping[str, Any] | None = None,
    runner: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Create an idempotent central event as soon as identity is trustworthy."""
    return {
        "schema_version": 1,
        "event_id": new_event_id(),
        "event_type": "RUN_STARTED",
        "created_at_utc": utc_now(),
        "run": run.to_dict(),
        "server": server.to_dict(),
        "runner": dict(runner or {"runner_id": run.runner_id}),
        "bmc": dict(bmc or {}),
    }


def run_completed_event(run: RunRecord, *, result: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "event_id": new_event_id(),
        "event_type": "RUN_COMPLETED",
        "created_at_utc": utc_now(),
        "run": run.to_dict(),
        "result": dict(result),
    }


def run_progress_event(run: RunRecord, *, stage_result: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "event_id": new_event_id(),
        "event_type": "RUN_PROGRESS",
        "created_at_utc": utc_now(),
        "run": run.to_dict(),
        "stage_result": dict(stage_result),
    }
