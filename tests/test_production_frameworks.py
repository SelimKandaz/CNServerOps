import hashlib
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from cnserverops.diagnostic_framework import evaluate_diagnostic_coverage
from cnserverops.hardware_tests import HardwareTestPlanner, HardwareValidationProfile, assess_sensor_snapshot
from cnserverops.logs import LocalIpmiSelCleanupAdapter, execute_log_cleanup, preserve_preclean_logs
from cnserverops.regression import evaluate_dell_regression
from cnserverops.release import ReleaseApproval, ReleaseError, RuntimeReleaseManager
from cnserverops.runner import RunnerIdentityError, bootstrap_runner
from cnserverops.safety import MutationBlockedError, MutationGate


class FakeLogAdapter:
    name = "simulated-log-adapter"

    def clear(self):
        return {"simulated": True}

    def verify_empty(self):
        return {"empty": True, "simulated": True}


class ProductionFrameworkTests(unittest.TestCase):
    def test_missing_smart_and_nvme_tools_are_explicit_not_supported(self):
        plan = HardwareTestPlanner().plan(
            capabilities={"sata_or_scsi_disk": True, "nvme_device": True},
            available_tools={
                "lscpu": "lscpu",
                "stress-ng": "stress-ng",
                "dmidecode": "dmidecode",
                "lsblk": "lsblk",
                "smartctl": "",
                "nvme": "",
                "ip": "ip",
                "ethtool": "ethtool",
                "lspci": "lspci",
                "ipmitool": "ipmitool",
            },
        )
        by_id = {item["spec"]["test_id"]: item for item in plan}
        self.assertEqual("NOT_SUPPORTED", by_id["storage.smart"]["plan_status"])
        self.assertIn("MISSING_TOOL:smartctl", by_id["storage.smart"]["reason_codes"])
        self.assertEqual("NOT_SUPPORTED", by_id["storage.nvme"]["plan_status"])

    def test_missing_fan_index_is_warning_without_profile_and_failure_with_profile(self):
        rows = [{"sensor": "FAN1", "status": "ok"}, {"sensor": "FAN7", "status": "ok"}]
        generic = assess_sensor_snapshot(rows)
        self.assertEqual("PASS_WITH_WARNINGS", generic.status.value)
        explicit = assess_sensor_snapshot(
            rows,
            profile=HardwareValidationProfile(profile_id="approved", expected_fan_sensors=("FAN1", "FAN6", "FAN7")),
        )
        self.assertEqual("FAIL", explicit.status.value)

    def test_diagnostic_coverage_does_not_fake_system_diagnostics(self):
        coverage = evaluate_diagnostic_coverage(
            [
                {"category": "identity_manifest", "sha256": "a" * 64},
                {"category": "dmi", "sha256": "b" * 64},
            ]
        )
        self.assertEqual("INCOMPLETE", coverage["status"])
        self.assertIn("preclean_sel", coverage["missing_required"])
        self.assertIn("system_diagnostics_artifact", coverage["missing_optional"])

    def test_log_clear_requires_preserved_bundled_evidence_and_gate(self):
        identity = {"fingerprint_sha256": "c" * 64, "mutation_eligible": True}
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            sel = root / "sel.json"
            sel.write_text('{"entries": [1]}', encoding="utf-8")
            manifest = preserve_preclean_logs(root / "preclean.json", {"ipmi_sel": sel})
            digest = manifest["artifacts"][0]["sha256"]
            with self.assertRaises(MutationBlockedError):
                execute_log_cleanup(
                    identity=identity,
                    preclean_manifest=manifest,
                    diagnostic_artifact_hashes={digest},
                    adapter=FakeLogAdapter(),
                    mutation_gate=MutationGate(),
                )
            gate = MutationGate(
                authorized=True,
                lab_mode=True,
                approval_id="SIMULATION-ONLY",
                machine_fingerprint_sha256="c" * 64,
                allowed_actions=frozenset({"LOG_CLEAR"}),
            )
            result = execute_log_cleanup(
                identity=identity,
                preclean_manifest=manifest,
                diagnostic_artifact_hashes={digest},
                adapter=FakeLogAdapter(),
                mutation_gate=gate,
            )
            self.assertEqual("SUCCESS", result["status"])

    @patch("cnserverops.logs.time.sleep", return_value=None)
    @patch("cnserverops.logs.subprocess.run")
    def test_local_ipmi_sel_adapter_uses_only_fixed_commands_and_polls_empty(self, run, _sleep):
        run.side_effect = [
            CompletedProcess(["ipmitool", "sel", "clear"], 0, "Clearing SEL.  Please allow a few seconds to erase.\n", ""),
            CompletedProcess(["ipmitool", "sel", "info"], 0, "Entries          : 1\n", ""),
            CompletedProcess(["ipmitool", "sel", "elist"], 0, "1 | test event\n", ""),
            CompletedProcess(["ipmitool", "sel", "info"], 0, "Entries          : 0\n", ""),
        ]
        adapter = LocalIpmiSelCleanupAdapter(verify_attempts=2)
        cleared = adapter.clear()
        verified = adapter.verify_empty()
        self.assertEqual(["ipmitool", "sel", "clear"], cleared["command"])
        self.assertTrue(verified["empty"])
        self.assertEqual([1, 0], verified["observed_counts"])
        self.assertEqual(
            [["ipmitool", "sel", "clear"], ["ipmitool", "sel", "info"], ["ipmitool", "sel", "elist"], ["ipmitool", "sel", "info"]],
            [call.args[0] for call in run.call_args_list],
        )

    @patch("cnserverops.logs.subprocess.run")
    def test_local_ipmi_sel_accepts_only_the_single_expected_clear_marker(self, run):
        run.side_effect = [
            CompletedProcess(["ipmitool", "sel", "info"], 0, "Entries          : 1\n", ""),
            CompletedProcess(
                ["ipmitool", "sel", "elist"],
                0,
                "1 | 08/19/2026 | 15:09:59 | Event Logging Disabled SEL_Status | Log area reset/cleared | Asserted\n",
                "",
            ),
        ]
        verified = LocalIpmiSelCleanupAdapter(verify_attempts=1).verify_empty()
        self.assertTrue(verified["empty"])
        self.assertTrue(verified["expected_clear_record"])
        self.assertEqual(1, verified["entry_count"])
        self.assertEqual(0, verified["residual_entries"])

    def test_runtime_release_is_versioned_self_tested_and_preserves_config(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            package = root / "cnserverops_update_v2.0.0.zip"
            content = b"print('runtime fixture')\n"
            installer = b"#!/bin/sh\nexit 0\n"
            manifest = {
                "schema_version": 1,
                "version": "2.0.0",
                "files": {
                    "runtime/app.py": hashlib.sha256(content).hexdigest(),
                    "runtime/install.sh": hashlib.sha256(installer).hexdigest(),
                },
            }
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("runtime/app.py", content)
                archive.writestr("runtime/install.sh", installer)
                archive.writestr("release-manifest.json", json.dumps(manifest))
            package_hash = hashlib.sha256(package.read_bytes()).hexdigest()
            config = root / "config"
            config.mkdir()
            config_file = config / "runner.json"
            config_file.write_text(
                json.dumps({"runner_id": "CNSSD-01", "runtime_version": "1.0.0"}),
                encoding="utf-8",
            )
            manager = RuntimeReleaseManager(root / "runtime", config_root=config)
            staged = manager.stage(
                package,
                expected_package_sha256=package_hash,
                self_test=lambda stage: (stage / "runtime" / "app.py").is_file(),
            )
            activated = manager.activate(
                staged,
                approval=ReleaseApproval(True, "RELEASE-APPROVAL-001", "CNSSD-01"),
            )
            self.assertEqual("READY", activated["status"])
            self.assertEqual("UPDATED", activated["runner_runtime_metadata"])
            self.assertEqual("CNSSD-01", json.loads(config_file.read_text(encoding="utf-8"))["runner_id"])
            self.assertEqual("2.0.0", json.loads(config_file.read_text(encoding="utf-8"))["runtime_version"])
            with self.assertRaisesRegex(ReleaseError, "different runner"):
                manager.activate(
                    staged,
                    approval=ReleaseApproval(True, "RELEASE-APPROVAL-WRONG-RUNNER", "CNSSD-02"),
                )
            if os.name != "nt":
                self.assertTrue((root / "runtime" / "releases" / "2.0.0" / "runtime" / "install.sh").stat().st_mode & 0o111)
            with self.assertRaises(ReleaseError):
                manager.stage(package, expected_package_sha256="0" * 64, self_test=lambda stage: True)
            def self_test_writes_file(stage: Path) -> bool:
                (stage / "self-test-output.txt").write_text("not immutable", encoding="utf-8")
                return True
            with self.assertRaisesRegex(ReleaseError, "self-test wrote unexpected files"):
                manager.stage(package, expected_package_sha256=package_hash, self_test=self_test_writes_file)

    def test_runtime_release_switches_legacy_current_symlink_atomically(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "runtime"
            previous = root / "releases" / "1.0.0"
            previous.mkdir(parents=True)
            current = root / "current"
            try:
                current.symlink_to(previous, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable on this test filesystem: {exc}")
            package = root.parent / "cnserverops_update_v2.0.0.zip"
            content = b"print('runtime fixture')\n"
            manifest = {
                "schema_version": 1,
                "version": "2.0.0",
                "files": {"runtime/app.py": hashlib.sha256(content).hexdigest()},
            }
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("runtime/app.py", content)
                archive.writestr("release-manifest.json", json.dumps(manifest))
            manager = RuntimeReleaseManager(root, config_root=root.parent / "config")
            staged = manager.stage(
                package,
                expected_package_sha256=hashlib.sha256(package.read_bytes()).hexdigest(),
                self_test=lambda stage: (stage / "runtime" / "app.py").is_file(),
            )
            activated = manager.activate(
                staged,
                approval=ReleaseApproval(True, "RELEASE-APPROVAL-SYMLINK", "CNSSD-01"),
            )
            self.assertEqual("SYMLINK_AND_JSON", activated["pointer"]["pointer_backend"])
            self.assertEqual(root / "releases" / "2.0.0", current.resolve())
            self.assertEqual("1.0.0", activated["pointer"]["previous_version"])
            self.assertTrue(any((root / "pointer-backups").glob("current-link-*.json")))

    def test_runner_id_is_stable_and_dell_regression_stays_unverified(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "runner.json"
            bootstrap_runner(path, runner_id="CNSSD-01", runtime_version="2.0.0")
            with self.assertRaises(RunnerIdentityError):
                bootstrap_runner(path, runner_id="CNSSD-02", runtime_version="2.0.0")
        result = evaluate_dell_regression({"platform.detection": {"status": "PASS", "evidence": "unit test"}})
        self.assertEqual("NOT_RUN_PHYSICAL", result["overall_status"])
        self.assertFalse(result["production_regression_claimed"])


if __name__ == "__main__":
    unittest.main()
