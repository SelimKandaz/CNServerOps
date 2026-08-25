"""Vendor-neutral production workflow orchestration with durable fail-safe state."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Protocol

from .disposition import Reason, decide_final_disposition
from .models import FinalDisposition, OperationStatus, RunRecord, ServerRecord, utc_now
from .safety import CLOSED_MUTATION_GATE, MutationGate
from .state import assert_workflow_resume_allowed, load_state, write_state


class WorkflowError(RuntimeError):
    pass


class WorkflowStage(str, Enum):
    IDENTITY = "IDENTITY"
    CAPABILITY_DISCOVERY = "CAPABILITY_DISCOVERY"
    INVENTORY = "INVENTORY"
    FIRMWARE_PLAN = "FIRMWARE_PLAN"
    FIRMWARE_APPLY = "FIRMWARE_APPLY"
    REBOOT_PENDING = "REBOOT_PENDING"
    POST_UPDATE_VERIFY = "POST_UPDATE_VERIFY"
    HARDWARE_TESTS = "HARDWARE_TESTS"
    DIAGNOSTICS = "DIAGNOSTICS"
    PRE_CLEAN_LOGS = "PRE_CLEAN_LOGS"
    LOG_CLEAN = "LOG_CLEAN"
    FINAL_SANITY = "FINAL_SANITY"
    FINALIZE = "FINALIZE"
    COMPLETE = "COMPLETE"
    BLOCKED = "BLOCKED"


_TRANSITIONS: dict[WorkflowStage, frozenset[WorkflowStage]] = {
    WorkflowStage.IDENTITY: frozenset({WorkflowStage.CAPABILITY_DISCOVERY, WorkflowStage.BLOCKED}),
    WorkflowStage.CAPABILITY_DISCOVERY: frozenset({WorkflowStage.INVENTORY, WorkflowStage.BLOCKED}),
    WorkflowStage.INVENTORY: frozenset({WorkflowStage.FIRMWARE_PLAN, WorkflowStage.BLOCKED}),
    WorkflowStage.FIRMWARE_PLAN: frozenset(
        {
            WorkflowStage.FIRMWARE_APPLY,
            WorkflowStage.POST_UPDATE_VERIFY,
            WorkflowStage.HARDWARE_TESTS,
            WorkflowStage.FINALIZE,
            WorkflowStage.BLOCKED,
        }
    ),
    WorkflowStage.FIRMWARE_APPLY: frozenset(
        {WorkflowStage.REBOOT_PENDING, WorkflowStage.POST_UPDATE_VERIFY, WorkflowStage.BLOCKED}
    ),
    # A resumed run must rebuild fresh local inventory before it can attest
    # firmware AFTER versions.  It remains the same durable RUN-* record;
    # CAPABILITY_DISCOVERY here is a post-reboot evidence refresh, never a
    # second operator-started workflow.
    WorkflowStage.REBOOT_PENDING: frozenset(
        {WorkflowStage.CAPABILITY_DISCOVERY, WorkflowStage.POST_UPDATE_VERIFY, WorkflowStage.BLOCKED}
    ),
    WorkflowStage.POST_UPDATE_VERIFY: frozenset({WorkflowStage.HARDWARE_TESTS, WorkflowStage.FINALIZE, WorkflowStage.BLOCKED}),
    WorkflowStage.HARDWARE_TESTS: frozenset({WorkflowStage.DIAGNOSTICS, WorkflowStage.BLOCKED}),
    WorkflowStage.DIAGNOSTICS: frozenset({WorkflowStage.PRE_CLEAN_LOGS, WorkflowStage.BLOCKED}),
    WorkflowStage.PRE_CLEAN_LOGS: frozenset({WorkflowStage.LOG_CLEAN, WorkflowStage.FINAL_SANITY, WorkflowStage.BLOCKED}),
    WorkflowStage.LOG_CLEAN: frozenset({WorkflowStage.FINAL_SANITY, WorkflowStage.BLOCKED}),
    WorkflowStage.FINAL_SANITY: frozenset({WorkflowStage.FINALIZE, WorkflowStage.BLOCKED}),
    WorkflowStage.FINALIZE: frozenset({WorkflowStage.COMPLETE, WorkflowStage.BLOCKED}),
    WorkflowStage.COMPLETE: frozenset(),
    WorkflowStage.BLOCKED: frozenset(),
}


_MUTATION_ACTION = {
    WorkflowStage.FIRMWARE_APPLY: "FIRMWARE_APPLY",
    WorkflowStage.LOG_CLEAN: "LOG_CLEAR",
}


class StageAdapter(Protocol):
    """Vendor adapters execute one already-authorized stage and return evidence."""

    name: str

    def execute(self, stage: WorkflowStage, context: Mapping[str, Any]) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class VendorRoute:
    name: str
    adapter: str
    production_supported: bool
    mutation_supported: bool
    reason: str
    allowed_mutation_actions: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "adapter": self.adapter,
            "production_supported": self.production_supported,
            "mutation_supported": self.mutation_supported,
            "reason": self.reason,
            "allowed_mutation_actions": list(self.allowed_mutation_actions),
        }


def select_vendor_route(platform: Mapping[str, Any]) -> VendorRoute:
    platform_id = str(platform.get("platform_id") or "")
    if platform_id == "DELL_POWEREDGE_R640":
        return VendorRoute(
            name="DELL_EXISTING_PRODUCTION",
            adapter="dell_existing_bridge",
            production_supported=True,
            mutation_supported=True,
            reason="Wrap the existing known-working Dell R640 path; do not reimplement RACADM/DSU/TSR.",
            allowed_mutation_actions=("FIRMWARE_APPLY", "LOG_CLEAR"),
        )
    if str(platform.get("vendor") or "").upper() == "ASUS":
        return VendorRoute(
            name="ASUS_CAPABILITY_DRIVEN",
            adapter="asus_common_production",
            production_supported=True,
            mutation_supported=True,
            reason="ASUS local production capabilities proceed independently; firmware mutation is enabled only after exact package, transport and gate checks.",
            allowed_mutation_actions=("FIRMWARE_APPLY", "LOG_CLEAR"),
        )
    return VendorRoute(
        name="SAFE_INVENTORY_ONLY",
        adapter="safe_inventory",
        production_supported=False,
        mutation_supported=False,
        reason="Unsupported platform: inventory and reporting only.",
    )


class ProductionOrchestrator:
    """Persist local authoritative state before any external sync or mutation."""

    def __init__(self, primary_root: Path, *, runtime_version: str) -> None:
        self.primary_root = primary_root
        self.runtime_version = str(runtime_version)

    def start(
        self,
        *,
        platform: Mapping[str, Any],
        identity: Mapping[str, Any],
        runner_id: str,
        continuation_of_run_id: str = "",
        workflow_mode: str = "PRODUCTION",
        test_profile: str = "STANDARD",
    ) -> dict[str, Any]:
        if not identity.get("resumable") or not identity.get("fingerprint_sha256"):
            raise WorkflowError(str(identity.get("resume_block_reason") or "trusted machine identity is required"))
        server = ServerRecord.from_identity(identity)
        run = RunRecord.start(
            server,
            runner_id=runner_id,
            runtime_version=self.runtime_version,
            boot_id=str(identity.get("boot_id") or ""),
            continuation_of_run_id=continuation_of_run_id,
            workflow_mode=workflow_mode,
            test_profile=test_profile,
        )
        route = select_vendor_route(platform)
        run_dir = self._run_dir(run.run_id)
        run_dir.mkdir(parents=True, exist_ok=False)
        context = {
            "schema_version": 1,
            "server": server.to_dict(),
            "run": run.to_dict(),
            "platform": dict(platform),
            "route": route.to_dict(),
            "stage_history": [
                {"stage": WorkflowStage.IDENTITY.value, "status": "PASS", "details": "trusted identity established"}
            ],
        }
        _atomic_json(run_dir / "run.json", context)
        write_state(
            run_dir / "workflow-state.json",
            identity,
            WorkflowStage.IDENTITY.value,
            run_id=run.run_id,
            runner_id=run.runner_id,
            runtime_version=run.runtime_version,
            expected_next_stage=WorkflowStage.CAPABILITY_DISCOVERY.value,
        )
        return context

    def resume(
        self,
        run_id: str,
        *,
        identity: Mapping[str, Any],
        runner_id: str,
    ) -> dict[str, Any]:
        run_dir = self._run_dir(run_id)
        context = _load_json(run_dir / "run.json")
        state = load_state(run_dir / "workflow-state.json")
        assert_workflow_resume_allowed(state, identity, run_id=run_id, runner_id=runner_id)
        if str(context.get("run", {}).get("server_fingerprint_sha256") or "") != identity.get("fingerprint_sha256"):
            raise WorkflowError("Local run record and current machine identity disagree.")
        return context

    def transition(
        self,
        context: dict[str, Any],
        *,
        identity: Mapping[str, Any],
        next_stage: WorkflowStage,
        adapter: StageAdapter | None = None,
        mutation_gate: MutationGate = CLOSED_MUTATION_GATE,
        details: Mapping[str, Any] | None = None,
        firmware_task_identity: str = "",
    ) -> dict[str, Any]:
        run = RunRecord.from_dict(context["run"])
        current = WorkflowStage(run.current_stage)
        if next_stage not in _TRANSITIONS[current]:
            raise WorkflowError(f"Invalid workflow transition: {current.value} -> {next_stage.value}")
        action = _MUTATION_ACTION.get(next_stage)
        if action:
            operation = dict(details or {})
            mutation_gate.require(
                action,
                identity,
                context={
                    "run_id": run.run_id,
                    "component": operation.get("component") or ("SEL" if action == "LOG_CLEAR" else ""),
                    "target_version": operation.get("target_version") or "",
                    "package_sha256": operation.get("package_sha256") or "",
                },
            )
            route = context.get("route", {})
            if not bool(route.get("mutation_supported")):
                raise WorkflowError(f"Vendor route does not permit {action}")
            if action not in set(route.get("allowed_mutation_actions") or []):
                raise WorkflowError(f"Vendor route has not validated the {action} capability")

        stage_result: Mapping[str, Any] = dict(details or {})
        if adapter is not None:
            stage_result = dict(adapter.execute(next_stage, context))
        history = list(context.get("stage_history") or [])
        history.append(
            {
                "stage": next_stage.value,
                "status": "BLOCKED" if next_stage == WorkflowStage.BLOCKED else "PASS",
                "details": dict(stage_result),
            }
        )
        run.current_stage = next_stage.value
        expected = _default_next(next_stage)
        context["run"] = run.to_dict()
        context["stage_history"] = history
        run_dir = self._run_dir(run.run_id)
        _atomic_json(run_dir / "run.json", context)
        write_state(
            run_dir / "workflow-state.json",
            identity,
            next_stage.value,
            details=stage_result,
            run_id=run.run_id,
            runner_id=run.runner_id,
            runtime_version=run.runtime_version,
            expected_next_stage=expected.value if expected else "",
            firmware_task_identity=firmware_task_identity,
        )
        return context

    def finalize(
        self,
        context: dict[str, Any],
        reasons: list[Reason],
        *,
        identity: Mapping[str, Any],
    ) -> dict[str, Any]:
        run = RunRecord.from_dict(context["run"])
        if run.current_stage not in {WorkflowStage.FINALIZE.value, WorkflowStage.BLOCKED.value}:
            raise WorkflowError("Run can be finalized only from FINALIZE or BLOCKED stage")
        decision = decide_final_disposition(reasons)
        run.final_disposition = FinalDisposition(decision["disposition"])
        run.reason_codes = [item["code"] for item in decision["reasons"]]
        # Evidence collection and final hardware disposition are independent dimensions.
        run.collection_status = (
            OperationStatus.PARTIAL if run.current_stage == WorkflowStage.BLOCKED.value else OperationStatus.PASS
        )
        run.completed_at_utc = utc_now()
        run.current_stage = WorkflowStage.COMPLETE.value
        context["run"] = run.to_dict()
        context["final_decision"] = decision
        run_dir = self._run_dir(run.run_id)
        _atomic_json(run_dir / "run.json", context)
        write_state(
            run_dir / "workflow-state.json",
            identity,
            WorkflowStage.COMPLETE.value,
            details={"final_decision": decision},
            run_id=run.run_id,
            runner_id=run.runner_id,
            runtime_version=run.runtime_version,
        )
        return context

    def _run_dir(self, run_id: str) -> Path:
        if not run_id.startswith("RUN-") or any(part in run_id for part in ("/", "\\", "..")):
            raise WorkflowError("Invalid RUN_ID path component")
        return self.primary_root / "runs" / run_id


def _default_next(stage: WorkflowStage) -> WorkflowStage | None:
    options = _TRANSITIONS[stage]
    non_blocked = [item for item in options if item != WorkflowStage.BLOCKED]
    return non_blocked[0] if len(non_blocked) == 1 else None


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise WorkflowError(f"Expected a JSON object: {path}")
    return payload


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
