import tempfile
import unittest
from pathlib import Path

from cnserverops.disposition import Reason, ReasonSeverity, decide_final_disposition
from cnserverops.identity import derive_machine_identity
from cnserverops.models import ServerRecord
from cnserverops.orchestrator import ProductionOrchestrator, WorkflowError, WorkflowStage, select_vendor_route
from cnserverops.platform import PlatformProbe, detect_platform
from cnserverops.safety import MutationBlockedError, MutationGate
from cnserverops.state import StateMismatchError
from cnserverops.state import FirmwareTaskContinuityError, assert_firmware_task_continuity


def asus_identity(serial="ASUS-001"):
    probe = PlatformProbe(
        manufacturer="ASUSTeK COMPUTER INC.",
        product_name="RS700A-E13-RS12U",
        system_serial=serial,
        board_serial=f"BOARD-{serial}",
        chassis_serial=f"CHASSIS-{serial}",
        product_uuid=f"UUID-{serial}",
    )
    platform = detect_platform(probe)
    identity = derive_machine_identity(
        platform,
        probe,
        redfish_system={"SerialNumber": serial, "UUID": f"UUID-{serial}"},
        chassis_fru={
            "FruInfo": {
                "Product": {"ProductSerial": serial},
                "Board": {"BoardSerial": f"BOARD-{serial}"},
                "Chassis": {"ChassisSerial": f"CHASSIS-{serial}"},
            }
        },
    )
    return platform, identity


class Pass2OrchestratorTests(unittest.TestCase):
    def test_server_run_and_runner_are_distinct_and_history_is_preserved(self):
        platform, identity = asus_identity()
        server = ServerRecord.from_identity(identity)
        with tempfile.TemporaryDirectory() as folder:
            engine = ProductionOrchestrator(Path(folder), runtime_version="2.0.0")
            first = engine.start(platform=platform, identity=identity, runner_id="CNSSD-01")
            second = engine.start(platform=platform, identity=identity, runner_id="CNSSD-01")
            self.assertEqual(server.fingerprint_sha256, first["server"]["fingerprint_sha256"])
            self.assertNotEqual(first["run"]["run_id"], second["run"]["run_id"])
            self.assertEqual("CNSSD-01", first["run"]["runner_id"])
            self.assertTrue((Path(folder) / "runs" / first["run"]["run_id"] / "run.json").is_file())

    def test_resume_requires_same_machine_run_and_runner(self):
        platform, identity = asus_identity("ASUS-001")
        _, other = asus_identity("ASUS-002")
        with tempfile.TemporaryDirectory() as folder:
            engine = ProductionOrchestrator(Path(folder), runtime_version="2.0.0")
            context = engine.start(platform=platform, identity=identity, runner_id="CNSSD-01")
            run_id = context["run"]["run_id"]
            engine.resume(run_id, identity=identity, runner_id="CNSSD-01")
            with self.assertRaises(StateMismatchError):
                engine.resume(run_id, identity=other, runner_id="CNSSD-01")
            with self.assertRaises(StateMismatchError):
                engine.resume(run_id, identity=identity, runner_id="CNSSD-02")

    def test_invalid_transition_and_closed_mutation_gate_fail_safe(self):
        platform, identity = asus_identity()
        with tempfile.TemporaryDirectory() as folder:
            engine = ProductionOrchestrator(Path(folder), runtime_version="2.0.0")
            context = engine.start(platform=platform, identity=identity, runner_id="CNSSD-01")
            with self.assertRaises(WorkflowError):
                engine.transition(context, identity=identity, next_stage=WorkflowStage.FIRMWARE_APPLY)
            gate = MutationGate(
                authorized=False,
                lab_mode=True,
                approval_id="PASS3-NOT-YET",
                machine_fingerprint_sha256=identity["fingerprint_sha256"],
                allowed_actions=frozenset({"FIRMWARE_APPLY"}),
            )
            with self.assertRaises(MutationBlockedError):
                gate.require("FIRMWARE_APPLY", identity)

    def test_asus_route_allows_only_physically_verified_mutations(self):
        platform, _ = asus_identity()
        route = select_vendor_route(platform)
        self.assertEqual("asus_common_production", route.adapter)
        self.assertTrue(route.production_supported)
        self.assertTrue(route.mutation_supported)
        self.assertIn("LOG_CLEAR", route.allowed_mutation_actions)
        self.assertIn("FIRMWARE_APPLY", route.allowed_mutation_actions)

    def test_central_pending_is_warning_not_automatic_fail(self):
        decision = decide_final_disposition(
            [Reason("CENTRAL_SYNC_PENDING", ReasonSeverity.WARNING, "local result is authoritative")]
        )
        self.assertEqual("PASS_WITH_WARNINGS", decision["disposition"])

    def test_reboot_resume_requires_expected_firmware_task(self):
        state = {"firmware_task_identity": "TASK-EXPECTED"}
        assert_firmware_task_continuity(
            state, observed_task_identity="TASK-EXPECTED", observed_task_state="COMPLETED"
        )
        with self.assertRaises(FirmwareTaskContinuityError):
            assert_firmware_task_continuity(state, observed_task_identity="", observed_task_state="UNKNOWN")
        with self.assertRaises(FirmwareTaskContinuityError):
            assert_firmware_task_continuity(
                state, observed_task_identity="TASK-OTHER", observed_task_state="COMPLETED"
            )

    def test_collection_success_is_separate_from_failed_final_disposition(self):
        platform, identity = asus_identity()
        with tempfile.TemporaryDirectory() as folder:
            engine = ProductionOrchestrator(Path(folder), runtime_version="2.0.0")
            context = engine.start(platform=platform, identity=identity, runner_id="CNSSD-01")
            context["run"]["current_stage"] = "FINALIZE"
            finalized = engine.finalize(
                context,
                [Reason("DIMM_TEST_FAILED", ReasonSeverity.FAIL)],
                identity=identity,
            )
            self.assertEqual("PASS", finalized["run"]["collection_status"])
            self.assertEqual("FAIL", finalized["run"]["final_disposition"])


if __name__ == "__main__":
    unittest.main()
