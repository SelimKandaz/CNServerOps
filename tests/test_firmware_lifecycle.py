from __future__ import annotations

import tempfile
import unittest
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

from cnserverops.firmware import FirmwarePackageMetadata, FirmwareRepository
from cnserverops.firmware_executor import FirmwarePreview, UpdateTask, UpdateTaskState
from cnserverops.firmware_lifecycle import build_pending, request_controlled_reboot, validate_pending_for_resume
from cnserverops.orchestrator import ProductionOrchestrator, WorkflowStage
from cnserverops.production import ProductionConfig, ProductionWorkflow
from cnserverops.runner import bootstrap_runner
from cnserverops.safety import MutationGate
from cnserverops.sync import StoreForwardQueue


class FirmwareLifecycleCheckpointTests(unittest.TestCase):
    def _identity(self, *, boot_id: str) -> dict[str, str | bool]:
        return {
            "server_id": "ASUS-TAS0MD00001P",
            "fingerprint_sha256": "a" * 64,
            "primary_serial": "TAS0MD00001P",
            "boot_id": boot_id,
            "resumable": True,
        }

    def test_later_checkpoint_does_not_requeue_already_verified_component(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            pending = build_pending(
                run_id="RUN-ABCDEFGH",
                run_directory=Path(folder) / "RUN-ABCDEFGH",
                identity=self._identity(boot_id="boot-before"),
                runner_id="CNSSD-UNIT-001",
                workflow_mode="PRODUCTION",
                profile_id="STANDARD",
                profile_total_seconds=420,
                plan={
                    "components": [
                        {"component": "BMC", "before": "1.20", "target": "1.32", "status": "UPDATED_VERIFIED"},
                        {"component": "BIOS", "before": "0603", "target": "0903", "status": "UPDATE_REQUIRED"},
                    ]
                },
                execution={
                    "status": "REBOOT_REQUIRED",
                    "pending_component": "BIOS",
                    "components": [{"component": "BIOS", "status": "REBOOT_REQUIRED"}],
                    "mutation_started": True,
                },
                bmc_auth_changed=True,
            )
        self.assertEqual(["BIOS"], pending["activation_pending_components"])
        self.assertEqual([], pending["remaining_components"])
        self.assertEqual(420, pending["profile_total_seconds"])

    def test_checkpoint_reverifies_component_completed_before_bios_reboot(self) -> None:
        """A BMC success before a BIOS reboot needs current-boot AFTER proof."""
        with tempfile.TemporaryDirectory() as folder:
            pending = build_pending(
                run_id="RUN-ABCDEFGH",
                run_directory=Path(folder) / "RUN-ABCDEFGH",
                identity=self._identity(boot_id="boot-before"),
                runner_id="CNSSD-UNIT-001",
                workflow_mode="PRODUCTION",
                plan={
                    "components": [
                        {"component": "BMC", "before": "1.20", "target": "1.32", "status": "UPDATE_REQUIRED"},
                        {"component": "BIOS", "before": "0603", "target": "0903", "status": "UPDATE_REQUIRED"},
                    ]
                },
                execution={
                    "status": "REBOOT_REQUIRED",
                    "pending_component": "BIOS",
                    "components": [
                        {"component": "BMC", "status": "SUCCESS", "installed_version": "1.32"},
                        {"component": "BIOS", "status": "REBOOT_REQUIRED"},
                    ],
                    "mutation_started": True,
                },
                bmc_auth_changed=True,
            )
            self.assertEqual(["BMC"], pending["completed_pre_reboot_components"])
            self.assertEqual(["BIOS"], pending["activation_pending_components"])
            self.assertEqual([], pending["remaining_components"])

            workflow = ProductionWorkflow(
                ProductionConfig(primary_root=Path(folder) / "results", reports_enabled=False),
                runtime_version="unit",
            )
            workflow._read_live_firmware_version = lambda component, _inventory: {"BIOS": "0903", "BMC": "1.32"}[component]  # type: ignore[method-assign]
            verified = workflow._verify_pending_components_after_reboot(pending, {})
            self.assertEqual("UPDATED_VERIFIED", verified["status"])
            self.assertEqual({"BIOS", "BMC"}, {row["component"] for row in verified["components"]})

    def test_asmb11_refreshed_current_bmc_is_retained_in_bios_reboot_checkpoint(self) -> None:
        """A staged ASMB11 BMC success remains proof-required after re-plan."""
        with tempfile.TemporaryDirectory() as folder:
            pending = build_pending(
                run_id="RUN-ABCDEFGH",
                run_directory=Path(folder) / "RUN-ABCDEFGH",
                identity=self._identity(boot_id="boot-before"),
                runner_id="CNSSD-UNIT-001",
                workflow_mode="FIRMWARE_ONLY",
                plan={
                    "components": [
                        {
                            "component": "BMC",
                            "before": "1.01",
                            "target": "1.2.37",
                            "status": "CURRENT_VERIFIED",
                        },
                        {
                            "component": "BIOS",
                            "before": "1201",
                            "target": "2306",
                            "status": "UPDATE_REQUIRED",
                        },
                    ]
                },
                execution={
                    "status": "REBOOT_REQUIRED",
                    "pending_component": "BIOS",
                    "components": [
                        {"component": "BMC", "status": "SUCCESS", "installed_version": "1.2.37"},
                        {"component": "BIOS", "status": "REBOOT_REQUIRED"},
                    ],
                    "mutation_started": True,
                },
                bmc_auth_changed=True,
            )

        targets = {
            str(item["component"]): str(item["target"])
            for item in pending["components"]
        }
        self.assertEqual({"BIOS": "2306", "BMC": "1.2.37"}, targets)
        self.assertEqual(["BMC"], pending["completed_pre_reboot_components"])
        self.assertEqual(["BIOS"], pending["activation_pending_components"])

    def test_resume_fails_closed_when_completed_pre_reboot_component_lacks_checkpoint_target(self) -> None:
        """A matching BIOS cannot hide an uncheckpointed completed BMC."""
        workflow = ProductionWorkflow(
            ProductionConfig(primary_root=Path("unit-results"), reports_enabled=False),
            runtime_version="unit",
        )
        live_reads: list[str] = []

        def read_live(component: str, _inventory: dict[str, object]) -> str:
            live_reads.append(component)
            return {"BIOS": "2306", "BMC": "1.01"}[component]

        workflow._read_live_firmware_version = read_live  # type: ignore[method-assign]
        pending = {
            "components": [
                {
                    "component": "BIOS",
                    "before": "1201",
                    "target": "2306",
                    "plan_status": "UPDATE_REQUIRED",
                }
            ],
            "activation_pending_components": ["BIOS"],
            "completed_pre_reboot_components": ["BMC"],
            "remaining_components": [],
        }

        verified = workflow._verify_pending_components_after_reboot(pending, {})

        self.assertEqual("FAIL", verified["status"])
        self.assertEqual("PENDING_FIRMWARE_COMPONENT_TARGET_MISSING", verified["reason"])
        self.assertEqual(["BMC"], [row["component"] for row in verified["components"]])
        self.assertEqual([], live_reads)

    def test_resume_requires_same_runner_server_and_a_new_boot(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            pending = build_pending(
                run_id="RUN-ABCDEFGH",
                run_directory=Path(folder) / "RUN-ABCDEFGH",
                identity=self._identity(boot_id="boot-before"),
                runner_id="CNSSD-UNIT-001",
                workflow_mode="FIRMWARE_ONLY",
                plan={"components": [{"component": "BIOS", "target": "0903", "status": "UPDATE_REQUIRED"}]},
                execution={"status": "REBOOT_REQUIRED", "pending_component": "BIOS", "mutation_started": True},
                bmc_auth_changed=False,
            )
        validate_pending_for_resume(
            pending,
            identity=self._identity(boot_id="boot-after"),
            runner_id="CNSSD-UNIT-001",
        )
        with self.assertRaisesRegex(Exception, "RUNNER_ID_MISMATCH"):
            validate_pending_for_resume(
                pending,
                identity=self._identity(boot_id="boot-after"),
                runner_id="CNSSD-OTHER-002",
            )

    def test_foreign_pending_checkpoint_is_quarantined_without_being_resumed(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            results = root / "results"
            results.mkdir()
            source = results / "firmware-pending.json"
            pending = {
                "run_id": "RUN-FOREIGN-UNIT",
                "workflow_mode": "PRODUCTION_EXTENDED",
                "state": "REBOOT_PENDING",
                "server_id": "ASUS-OLD-SERVER",
                "fingerprint_sha256": "a" * 64,
                "runner_id": "CNSSD-UNIT-001",
                "boot_id_before": "old-boot",
                "sensitive_material_exposed": False,
            }
            original = json.dumps(pending, sort_keys=True) + "\n"
            source.write_text(original, encoding="utf-8")
            workflow = ProductionWorkflow(
                ProductionConfig(primary_root=results, reports_enabled=False),
                runtime_version="unit",
            )
            receipt = workflow._quarantine_foreign_pending(
                pending,
                identity={
                    "resumable": True,
                    "server_id": "ASUS-NEW-SERVER",
                    "fingerprint_sha256": "b" * 64,
                },
                runner_id="CNSSD-UNIT-001",
            )
            self.assertIsNotNone(receipt)
            self.assertEqual("FOREIGN_PENDING_QUARANTINED", receipt["status"])
            self.assertFalse(source.exists())
            quarantine = Path(str(receipt["quarantine_path"]))
            self.assertEqual(original, quarantine.read_text(encoding="utf-8"))
            self.assertTrue((quarantine.parent / "quarantine-receipt.json").is_file())

    def test_same_server_pending_checkpoint_remains_active(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            results = root / "results"
            results.mkdir()
            source = results / "firmware-pending.json"
            pending = {
                "run_id": "RUN-SAME-UNIT",
                "workflow_mode": "PRODUCTION",
                "state": "REBOOT_PENDING",
                "server_id": "ASUS-SAME-SERVER",
                "fingerprint_sha256": "a" * 64,
                "runner_id": "CNSSD-UNIT-001",
            }
            source.write_text(json.dumps(pending), encoding="utf-8")
            workflow = ProductionWorkflow(
                ProductionConfig(primary_root=results, reports_enabled=False),
                runtime_version="unit",
            )
            receipt = workflow._quarantine_foreign_pending(
                pending,
                identity={
                    "resumable": True,
                    "server_id": "ASUS-SAME-SERVER",
                    "fingerprint_sha256": "a" * 64,
                },
                runner_id="CNSSD-UNIT-001",
            )
            self.assertIsNone(receipt)
            self.assertTrue(source.is_file())

    def test_same_boot_validation_is_only_for_bounded_reboot_retry(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            pending = build_pending(
                run_id="RUN-ABCDEFGH",
                run_directory=Path(folder) / "RUN-ABCDEFGH",
                identity=self._identity(boot_id="boot-before"),
                runner_id="CNSSD-UNIT-001",
                workflow_mode="FIRMWARE_ONLY",
                plan={"components": [{"component": "BIOS", "target": "0903", "status": "UPDATE_REQUIRED"}]},
                execution={"status": "REBOOT_REQUIRED", "pending_component": "BIOS", "mutation_started": True},
                bmc_auth_changed=False,
            )
            validate_pending_for_resume(
                pending,
                identity=self._identity(boot_id="boot-before"),
                runner_id="CNSSD-UNIT-001",
                require_new_boot=False,
            )

    def test_resume_dispatches_option_two_checkpoint_to_extended_same_run_pipeline(self) -> None:
        """The boot service must continue Option 2, not downgrade it to Option 1."""
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            run_dir = root / "results" / "runs" / "RUN-OPTION2-UNIT"
            run_dir.mkdir(parents=True)
            workflow = ProductionWorkflow(
                ProductionConfig(primary_root=root / "results", reports_enabled=False),
                runtime_version="unit",
            )
            pending = {
                "run_id": "RUN-OPTION2-UNIT",
                "run_directory": str(run_dir),
                "workflow_mode": "PRODUCTION_EXTENDED",
                "state": "REBOOT_PENDING",
                "boot_id_before": "different-boot",
                "mutation_started": True,
            }
            workflow._load_pending_firmware = lambda: dict(pending)  # type: ignore[method-assign]
            workflow._resume_inflight_firmware_task = lambda _pending: None  # type: ignore[method-assign]
            workflow._retry_same_boot_firmware_reboot = lambda _pending: None  # type: ignore[method-assign]
            with patch.object(workflow, "run_asus_production", return_value={"status": "RESUMED"}) as production:
                result = workflow.resume_pending_firmware_only()
            self.assertEqual("RESUMED", result["status"])
            production.assert_called_once_with(extended_diagnostics=True)

    def test_unexpected_reboot_during_workload_finalizes_same_run_without_retrying_stress(self) -> None:
        """A reboot during stress is a durable FAIL, never an implicit retry."""
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "results"
            runner_path = Path(folder) / "runner.json"
            bootstrap_runner(
                runner_path,
                runner_id="CNSSD-UNIT-001",
                runtime_version="unit",
                storage_fingerprint_sha256="c" * 64,
            )
            before = {
                **self._identity(boot_id="boot-before"),
                "vendor": "ASUS",
                "model": "RS500A-E12-RS12U",
                "platform_id": "ASUS_SERVER",
                "confidence": "high",
            }
            after = {**before, "boot_id": "boot-after"}
            platform = {"platform_id": "ASUS_SERVER", "vendor": "ASUS"}
            orchestrator = ProductionOrchestrator(root, runtime_version="unit")
            context = orchestrator.start(
                platform=platform,
                identity=before,
                runner_id="CNSSD-UNIT-001",
                workflow_mode="PRODUCTION_EXTENDED",
                test_profile="STANDARD",
            )
            run_id = str(context["run"]["run_id"])
            run_dir = root / "runs" / run_id
            for stage in (
                WorkflowStage.CAPABILITY_DISCOVERY,
                WorkflowStage.INVENTORY,
                WorkflowStage.FIRMWARE_PLAN,
                WorkflowStage.POST_UPDATE_VERIFY,
                WorkflowStage.HARDWARE_TESTS,
            ):
                context = orchestrator.transition(context, identity=before, next_stage=stage, details={})
            (run_dir / "normalized-inventory.json").write_text(
                json.dumps({"system_serial": "TAS0MD00001P", "server_id": before["server_id"]}), encoding="utf-8"
            )
            (run_dir / "firmware-plan.json").write_text(json.dumps({"components": []}), encoding="utf-8")
            workflow = ProductionWorkflow(
                ProductionConfig(
                    primary_root=root,
                    runner_config=runner_path,
                    queue_database=Path(folder) / "events.sqlite3",
                    artifact_queue_database=Path(folder) / "artifacts.sqlite3",
                    reports_enabled=False,
                    artifact_sync_enabled=False,
                ),
                runtime_version="unit",
            )
            workflow._write_workload_continuation(
                run_id=run_id,
                run_dir=run_dir,
                identity=before,
                runner_id="CNSSD-UNIT-001",
                workflow_mode="PRODUCTION_EXTENDED",
                profile_id="STANDARD",
            )
            with patch("cnserverops.production.detect_current_platform_and_identity", return_value=(None, platform, after, {})):
                result = workflow.recover_interrupted_workload()
            self.assertEqual("INTERRUPTED_WORKLOAD_FINALIZED_FAIL", result["status"])
            self.assertFalse((root / "workload-continuation.json").exists())
            saved = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
            self.assertEqual("COMPLETE", saved["run"]["current_stage"])
            self.assertEqual("FAIL", saved["run"]["final_disposition"])
            interruption = json.loads((run_dir / "evidence" / "unexpected-host-reboot-during-stress.json").read_text(encoding="utf-8"))
            self.assertEqual("WORKLOAD_NOT_RETRIED; RUN_FINALIZED_FAIL", interruption["recovery_action"])

    def test_reboot_checkpoint_retries_are_bounded(self) -> None:
        class Executor:
            def run(self, _tool, _arguments, *, timeout_seconds):
                return {"status": "PASS", "exit_code": 0}

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            pending = build_pending(
                run_id="RUN-ABCDEFGH",
                run_directory=root / "RUN-ABCDEFGH",
                identity=self._identity(boot_id="boot-before"),
                runner_id="CNSSD-UNIT-001",
                workflow_mode="FIRMWARE_ONLY",
                plan={"components": [{"component": "BIOS", "target": "0903", "status": "UPDATE_REQUIRED"}]},
                execution={"status": "REBOOT_REQUIRED", "pending_component": "BIOS", "mutation_started": True},
                bmc_auth_changed=False,
            )
            result = None
            for _ in range(3):
                result = request_controlled_reboot(executor=Executor(), primary_root=root, pending=pending)
                pending = result["pending"]
            self.assertEqual(3, pending["reboot"]["retry_count"])
            blocked = request_controlled_reboot(executor=Executor(), primary_root=root, pending=pending)
            self.assertEqual("REBOOT_REQUEST_FAILED", blocked["status"])
            self.assertEqual("PENDING_FIRMWARE_REBOOT_RETRY_LIMIT_EXCEEDED", blocked["reason"])

    def test_firmware_only_resume_finishes_same_run_and_retires_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            runner_path = root / "runner.json"
            bootstrap_runner(
                runner_path,
                runner_id="CNSSD-UNIT-001",
                runtime_version="unit",
                storage_fingerprint_sha256="c" * 64,
            )
            identity_before = {
                **self._identity(boot_id="boot-before"),
                "vendor": "ASUS",
                "model": "RS700-E12-RS12U",
                "platform_id": "ASUS_SERVER",
                "confidence": "high",
                "mutation_eligible": True,
            }
            identity_after = {**identity_before, "boot_id": "boot-after"}
            platform = {"platform_id": "ASUS_SERVER", "vendor": "ASUS"}
            orchestrator = ProductionOrchestrator(root / "results", runtime_version="unit")
            context = orchestrator.start(
                platform=platform,
                identity=identity_before,
                runner_id="CNSSD-UNIT-001",
                workflow_mode="FIRMWARE_ONLY",
                test_profile="FIRMWARE_ONLY",
            )
            run_id = str(context["run"]["run_id"])
            context = orchestrator.transition(
                context, identity=identity_before, next_stage=WorkflowStage.CAPABILITY_DISCOVERY, details={}
            )
            summary = {
                "storage": {"status": "PASS"},
                "network": {"status": "PASS"},
                "sensors": {"status": "PASS"},
                "runner_storage": {"smart_status": "UNAVAILABLE"},
            }
            context = orchestrator.transition(
                context, identity=identity_before, next_stage=WorkflowStage.INVENTORY, details=summary
            )
            context = orchestrator.transition(
                context, identity=identity_before, next_stage=WorkflowStage.FIRMWARE_PLAN, details={}
            )
            gate = MutationGate(
                authorized=True,
                lab_mode=True,
                approval_id="UNIT-RESUME",
                machine_fingerprint_sha256="a" * 64,
                vendor="ASUS",
                model="RS700-E12-RS12U",
                system_serial="TAS0MD00001P",
                run_id=run_id,
                component="BIOS",
                target_version="0903",
                allowed_actions=frozenset({"FIRMWARE_APPLY"}),
            )
            context = orchestrator.transition(
                context,
                identity=identity_before,
                next_stage=WorkflowStage.FIRMWARE_APPLY,
                mutation_gate=gate,
                details={"component": "BIOS", "target_version": "0903"},
            )
            context = orchestrator.transition(
                context,
                identity=identity_before,
                next_stage=WorkflowStage.REBOOT_PENDING,
                details={"status": "REBOOT_REQUIRED"},
            )
            run_dir = root / "results" / "runs" / run_id
            plan = {
                "readiness": "UPDATE_REQUIRED",
                "components": [{"component": "BIOS", "before": "0603", "target": "0903", "status": "UPDATE_REQUIRED"}],
            }
            (run_dir / "firmware-plan.json").write_text(__import__("json").dumps(plan), encoding="utf-8")
            pending = build_pending(
                run_id=run_id,
                run_directory=run_dir,
                identity=identity_before,
                runner_id="CNSSD-UNIT-001",
                workflow_mode="FIRMWARE_ONLY",
                plan=plan,
                execution={
                    "status": "REBOOT_REQUIRED",
                    "pending_component": "BIOS",
                    "components": [{"component": "BIOS", "status": "REBOOT_REQUIRED"}],
                    "mutation_started": True,
                },
                bmc_auth_changed=False,
            )
            workflow = ProductionWorkflow(
                ProductionConfig(
                    primary_root=root / "results",
                    runner_config=runner_path,
                    queue_database=root / "events.sqlite3",
                    artifact_queue_database=root / "artifacts.sqlite3",
                    reports_enabled=False,
                    artifact_sync_enabled=False,
                ),
                runtime_version="unit",
                collector_client=type("Central", (), {"ingest": lambda *_args, **_kwargs: {"status": "ACCEPTED"}})(),
            )
            workflow._write_pending_firmware(
                run_dir=run_dir,
                identity=identity_before,
                plan=plan,
                execution={
                    "status": "REBOOT_REQUIRED",
                    "pending_component": "BIOS",
                    "components": [{"component": "BIOS", "status": "REBOOT_REQUIRED"}],
                    "mutation_started": True,
                },
                bmc_auth_changed=False,
                runner_id="CNSSD-UNIT-001",
                workflow_mode="FIRMWARE_ONLY",
                profile_id="FIRMWARE_ONLY",
            )
            normalized = {"system_serial": "TAS0MD00001P", "server_id": identity_before["server_id"]}
            workflow._collect_inventory = lambda *_args, **_kwargs: {"summary": summary, "normalized": normalized, "evidence_paths": []}  # type: ignore[method-assign]
            workflow._discover_bmc_auth = lambda *_args, **_kwargs: {"state": "BMC_AUTH_UNAVAILABLE"}  # type: ignore[method-assign]
            workflow._verify_pending_components_after_reboot = lambda *_args, **_kwargs: {  # type: ignore[method-assign]
                "status": "UPDATED_VERIFIED",
                "activation_pending_components": ["BIOS"],
                "remaining_components": [],
                "components": [{"component": "BIOS", "after": "0903", "status": "UPDATED_VERIFIED"}],
            }
            with patch(
                "cnserverops.production.detect_current_platform_and_identity",
                return_value=(object(), platform, identity_after, {}),
            ):
                result = workflow._resume_pending_firmware(pending)
            self.assertEqual(run_id, result["run"]["run_id"])
            self.assertEqual("UPDATED_VERIFIED", result["status"])
            self.assertFalse((root / "results" / "firmware-pending.json").exists())
            self.assertTrue((run_dir / "firmware-pending-completed.json").is_file())

    def test_non_reboot_task_reattach_reuses_existing_task_and_promotes_same_run(self) -> None:
        class ResumeAdapter:
            name = "unit-resume-adapter"

            def __init__(self, _client, _descriptor, *, version_reader):
                self.version_reader = version_reader
                self.start_calls = 0
                self.poll_calls = 0

            def preview(self, package, metadata):
                return FirmwarePreview(True, self.name, metadata.component, "1.0", metadata.version, False, {})

            def start(self, package, metadata):
                self.start_calls += 1
                raise AssertionError("resume must not start a second firmware task")

            def poll(self, task_id):
                self.poll_calls += 1
                return UpdateTask(task_id, UpdateTaskState.COMPLETED, "completed after process interruption")

            def read_installed_version(self, component):
                return "2.0"

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            results = root / "results"
            runner_path = root / "runner.json"
            bootstrap_runner(
                runner_path,
                runner_id="CNSSD-UNIT-001",
                runtime_version="unit",
                storage_fingerprint_sha256="c" * 64,
            )
            identity = {
                **self._identity(boot_id="boot-same"),
                "vendor": "ASUS",
                "model": "RS700-E12-RS12U",
                "platform_id": "ASUS_SERVER",
                "confidence": "high",
                "mutation_eligible": True,
            }
            platform = {"vendor": "ASUS", "platform_id": "ASUS_SERVER"}
            workflow = ProductionWorkflow(
                ProductionConfig(
                    primary_root=results,
                    runner_config=runner_path,
                    firmware_cache_root=root / "firmware-cache",
                    reports_enabled=False,
                    artifact_sync_enabled=False,
                ),
                runtime_version="unit",
            )
            payload = b"durable-bmc-task-package"
            digest = hashlib.sha256(payload).hexdigest()
            metadata = FirmwarePackageMetadata(
                vendor="ASUS",
                component="BMC",
                version="2.0",
                package_filename="bmc-2.0.bin",
                sha256=digest,
                source="unit",
                source_url="https://servers.asus.com/bmc-2.0.bin",
                compatible_models=("RS700-E12-RS12U",),
                compatible_boards=("Z14PP-D32 Series",),
                validation_status="CHECKSUM_VERIFIED",
            )
            source = root / "bmc-2.0.bin"
            source.write_bytes(payload)
            FirmwareRepository(root / "firmware-cache").ingest(source, metadata)
            run_dir = results / "runs" / "RUN-ABCDEFGH"
            run_dir.mkdir(parents=True)
            plan = {
                "readiness": "UPDATE_REQUIRED",
                "components": [{"component": "BMC", "before": "1.0", "target": "2.0", "status": "UPDATE_REQUIRED"}],
            }
            pending = workflow._write_pending_firmware(
                run_dir=run_dir,
                identity=identity,
                plan=plan,
                execution={
                    "status": "TASK_IN_PROGRESS",
                    "pending_component": "BMC",
                    "task_id": "TASK-EXISTING",
                    "components": [{"component": "BMC", "status": "RUNNING"}],
                    "mutation_started": True,
                },
                bmc_auth_changed=False,
                runner_id="CNSSD-UNIT-001",
                workflow_mode="FIRMWARE_ONLY",
                checkpoint_state="TASK_IN_PROGRESS",
            )
            record = {
                "schema_version": 1,
                "state": "TASK_STARTED",
                "run_id": "RUN-ABCDEFGH",
                "run_directory": str(run_dir),
                "component": "BMC",
                "task_id": "TASK-EXISTING",
                "metadata": metadata.to_dict(),
                "transport": {
                    "name": "UNIT_TRANSPORT",
                    "source": "UNIT",
                    "target": "/redfish/v1/UpdateService",
                    "components": ["BMC"],
                    "package_delivery": "LOCAL_PATH",
                    "reboot_behavior": "NO_REBOOT",
                    "selectable": True,
                },
            }
            (results / "firmware-inflight.json").parent.mkdir(parents=True, exist_ok=True)
            (results / "firmware-inflight.json").write_text(json.dumps(record), encoding="utf-8")
            workflow._collect_inventory = lambda *_args, **_kwargs: {  # type: ignore[method-assign]
                "summary": {},
                "normalized": {"bmc_ip": "10.1.10.200", "system_serial": "TAS0MD00001P"},
                "evidence_paths": [],
                "evidence_by_name": {},
            }
            workflow._discover_bmc_auth = lambda *_args, **_kwargs: {"state": "BMC_AUTH_AVAILABLE"}  # type: ignore[method-assign]
            workflow._authenticated_firmware_client = lambda *_args, **_kwargs: (object(), None)  # type: ignore[method-assign]
            with patch(
                "cnserverops.production.detect_current_platform_and_identity",
                return_value=(object(), platform, identity, {}),
            ), patch("cnserverops.production.AsusRedfishFirmwareAdapter", ResumeAdapter):
                result = workflow._resume_inflight_firmware_task(pending)
            self.assertTrue(result["_continue"])
            self.assertEqual("TASK_REATTACHED", result["status"])
            promoted = json.loads((results / "firmware-pending.json").read_text(encoding="utf-8"))
            self.assertEqual("TASK_RESUMED", promoted["state"])
            self.assertFalse((results / "firmware-inflight.json").exists())
            self.assertEqual("SUCCESS", result["execution"]["status"])
