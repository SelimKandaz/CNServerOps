import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cnserverops.central_api import CentralApiError, central_credential_from_file
from cnserverops.cli import _service_result_exit_code
from cnserverops.collector import CentralCollector
from cnserverops.operator_console import ConsoleSnapshot, available_actions, menu_options, render_menu
from cnserverops.production import ProductionConfig, ProductionWorkflow, ProductionWorkflowError
from cnserverops.runner import bootstrap_runner
from cnserverops.secrets import SensitiveEvidenceError, assert_no_sensitive_fields


ASUS_PLATFORM = {
    "vendor": "ASUS",
    "platform_id": "ASUS_SERVER",
    "probe": {"product_name": "RS500A-E12-RS12U", "system_serial": "RAS0MD0000HU"},
}


class FakeExecutor:
    def run(self, tool, arguments, *, timeout_seconds):
        stdout = self._stdout(tool, arguments)
        status = "FAILED" if tool == "smartctl" else "PASS"
        return {
            "tool": tool,
            "command": [f"/approved/{tool}", *arguments],
            "status": status,
            "exit_code": 1 if status == "FAILED" else 0,
            "stdout": stdout,
            "stderr": "" if status == "PASS" else "USB bridge unknown",
            "started_at_utc": "2026-08-18T00:00:00+00:00",
            "completed_at_utc": "2026-08-18T00:00:01+00:00",
        }

    @staticmethod
    def _stdout(tool, arguments):
        if tool == "lscpu":
            return '{"lscpu":[{"field":"Model name:","data":"AMD EPYC"}]}\n'
        if tool == "dmidecode":
            return "Memory Device\n\tSize: 16 GB\n"
        if tool == "lsblk":
            return '{"blockdevices":[{"name":"sda","size":150000000000}]}\n'
        if tool == "lspci":
            return "01:00.0 Ethernet controller\n"
        if tool == "ip" and "link" in arguments:
            return '[{"ifname":"lo"},{"ifname":"enp5s0f0"}]\n'
        if tool == "ip":
            return '[{"ifname":"enp5s0f0","addr_info":[{"local":"10.1.10.181"}]}]\n'
        if tool == "ipmitool" and arguments[:2] == ("mc", "info"):
            return "Firmware Revision : 1.01\n"
        if tool == "ipmitool" and arguments[:2] == ("sensor", "list"):
            return "FAN1 | 8000 RPM | ok | na | na | na\nPSU1 | 100 W | ok | na | na | na\n"
        if tool == "ipmitool" and arguments[:2] == ("sdr", "elist"):
            return "FAN1 | 01h | ok\n"
        if tool == "ipmitool" and arguments[:2] == ("sel", "info"):
            return "Entries : 0\nPercent Used : 0%\n"
        if tool == "ipmitool" and arguments[:2] == ("sel", "elist"):
            return "SEL has no entries\n"
        if tool == "ipmitool" and arguments[:2] == ("fru", "print"):
            return "Product Serial : RAS0MD0000HU\nBoard Serial : BOARD1\nChassis Serial : CHASSIS1\n"
        if tool == "nvme":
            return '{"Devices":[]}\n'
        if tool == "findmnt":
            return "/dev/sda2\n"
        if tool == "smartctl":
            return "smartctl 7.4\n"
        if tool == "ethtool":
            return "Link detected: yes\n"
        if tool == "stress-ng":
            return "successful run completed\n"
        return "ok\n"


def matching_fru():
    return {
        "status": "PASS",
        "mechanism": "LOCAL_KCS_IPMITOOL_FRU_READ",
        "error": "",
        "fru": {
            "FruInfo": {
                "Product": {"ProductSerial": "RAS0MD0000HU"},
                "Board": {"BoardSerial": "BOARD1"},
                "Chassis": {"ChassisSerial": "CHASSIS1"},
            }
        },
    }


def write_dmi(root: Path, *, vendor="ASUSTeK COMPUTER INC.", product="RS500A-E12-RS12U"):
    root.mkdir(parents=True)
    values = {
        "sys_vendor": vendor,
        "product_name": product,
        "product_serial": "RAS0MD0000HU",
        "board_serial": "BOARD1",
        "chassis_serial": "CHASSIS1",
        "product_uuid": "5c8c531f-6b23-0acb-dd6c-a036bcccaa3a",
        "bios_version": "1201",
    }
    for name, value in values.items():
        (root / name).write_text(value + "\n", encoding="utf-8")


class OperatorLauncherTests(unittest.TestCase):
    def test_asus_menu_exposes_manual_production_only_after_detection(self):
        snapshot = ConsoleSnapshot(
            platform=ASUS_PLATFORM,
            identity={"primary_serial": "RAS0MD0000HU"},
            runner={"runner_id": "CNSSD-TEST"},
            central={"status": "ONLINE"},
            runtime_version="3.2.0-pass3",
        )
        screen = render_menu(snapshot)
        self.assertIn("[1] FLEET INTAKE / SERIAL + LOG COLLECTION", screen)
        self.assertIn("[2] FULL PRODUCTION + EXTENDED DIAGNOSTICS", screen)
        self.assertIn("BMC Auth (last) is historical", screen)
        self.assertIn("No test, cleanup, firmware, reset, or power action starts", screen)
        self.assertEqual("FLEET_INTAKE", available_actions(ASUS_PLATFORM)[0])
        self.assertEqual("RUN_ASUS_EXTENDED", available_actions(ASUS_PLATFORM)[1])
        options = menu_options(ASUS_PLATFORM)
        self.assertEqual("FIRMWARE_STATUS", options[4][0])
        self.assertIn("[5] Firmware Update & Verification", screen)
        self.assertIn("[4] Stress Test / Burn-In (full production profile)", screen)
        self.assertIn("[11] BMC RESET / FACTORY DEFAULT RECOVERY (KCS)", screen)
        self.assertEqual("BMC_FACTORY_RESET", options[-1][0])
        self.assertEqual(tuple(action for action, _label in options), available_actions(ASUS_PLATFORM))

    def test_bmc_reset_requires_explicit_operator_authorization(self):
        with tempfile.TemporaryDirectory() as folder:
            workflow = ProductionWorkflow(
                ProductionConfig(primary_root=Path(folder) / "results"),
                runtime_version="3.8.111-pass3-server-serial-template",
                executor=FakeExecutor(),
            )
            with self.assertRaises(ProductionWorkflowError):
                workflow.reset_bmc()

    def test_bmc_reset_uses_exact_asmb_capability_and_preserves_firmware(self):
        class BmcResetExecutor(FakeExecutor):
            @staticmethod
            def _stdout(tool, arguments):
                if tool == "ipmitool" and arguments[:2] == ("mc", "info"):
                    return "Device ID : 32\nFirmware Revision : 1.01\n"
                if tool == "ipmitool" and arguments[:2] == ("lan", "print"):
                    return (
                        "IP Address : 10.1.10.145\n"
                        "MAC Address : 00:11:22:33:44:55\n"
                    )
                if tool == "ipmitool" and arguments[:2] == ("user", "list"):
                    return "ID Name             Callin Link Auth IPMI Msg\n1 ADMIN             true   true      true\n"
                if tool == "ipmitool" and arguments[:2] == ("sel", "elist"):
                    return "SEL has no entries\n"
                return FakeExecutor._stdout(tool, arguments)

        identity = {
            "resumable": True,
            "mutation_eligible": True,
            "fingerprint_sha256": "a" * 64,
            "vendor": "ASUS",
            "model": "RS500A-E12-RS12U",
            "primary_serial": "RAS0MD0000HU",
            "server_id": "SERVER-TEST-ASMB11",
            "boot_id": "boot-test",
            "confidence": "high",
            "anchors": {"dmi_board_serial": "BOARD1", "dmi_chassis_serial": "CHASSIS1"},
        }
        platform = dict(ASUS_PLATFORM)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            workflow = ProductionWorkflow(
                ProductionConfig(primary_root=root / "results", runner_config=root / "missing-runner.json"),
                runtime_version="3.8.111-pass3-server-serial-template",
                executor=BmcResetExecutor(),
            )
            with patch(
                "cnserverops.production.detect_current_platform_and_identity",
                return_value=(None, platform, identity, {}),
            ), patch.object(
                workflow,
                "_collect_inventory",
                return_value={
                    "normalized": {
                        "vendor": "ASUS",
                        "model": "RS500A-E12-RS12U",
                        "system_serial": "RAS0MD0000HU",
                        "components": [{"category": "MANAGEMENT_MODULE", "model": "ASMB11"}],
                    },
                    "summary": {"sel": {"entry_count": 0}},
                },
            ):
                response = workflow.reset_bmc(operator_authorized=True)
            self.assertEqual("RECOVERED", response["result"]["status"])
            self.assertTrue(response["result"]["mutation_started"])
            self.assertEqual("ASMB11", response["result"]["bmc_generation"])
            self.assertEqual("1.01", response["result"]["firmware_before"])
            self.assertEqual("1.01", response["result"]["firmware_after"])
            self.assertEqual("10.1.10.145", response["result"]["bmc_ip_after"])
            run_dir = Path(response["run_directory"])
            self.assertTrue((run_dir / "bmc-recovery" / "bmc-recovery-before-users.txt").is_file())
            self.assertTrue((run_dir / "bmc-reset-result.json").is_file())

    def test_unknown_vendor_is_safe_inventory_only_and_has_no_production_option(self):
        platform = {
            "vendor": "UNKNOWN",
            "platform_id": "UNSUPPORTED_PLATFORM",
            "probe": {"product_name": "Mystery", "system_serial": "S1"},
        }
        screen = render_menu(
            ConsoleSnapshot(platform, {}, {"runner_id": "CNSSD-TEST"}, {"status": "OFFLINE"}, "3.2.0-pass3")
        )
        self.assertNotIn("Run Production Workflow", screen)
        self.assertNotIn("Run Existing Dell", screen)
        self.assertEqual(("INVENTORY_ONLY", "SHOW_LAST_RESULT", "SHELL"), available_actions(platform))

    def test_full_asus_orchestration_preserves_identity_before_workload_and_completes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            dmi = root / "dmi"
            write_dmi(dmi)
            runner_path = root / "runner.json"
            bootstrap_runner(
                runner_path,
                runner_id="CNSSD-TEST-001",
                runtime_version="3.1.3-pass3",
                storage_fingerprint_sha256="a" * 64,
            )
            collector = CentralCollector(root / "central.sqlite3")
            collector.initialize()
            config = ProductionConfig(
                primary_root=root / "results",
                runner_config=runner_path,
                central_config=root / "central.json",
                queue_database=root / "queue.sqlite3",
                artifact_queue_database=root / "artifact-queue.sqlite3",
                cpu_seconds=10,
                memory_seconds=10,
                sel_cleanup_enabled=True,
                # This orchestration test intentionally exercises the
                # no-catalog/transport gate.  Keep it deterministic and
                # offline; live ASUS discovery is covered by dedicated
                # resolver tests and must not turn the unit suite into a
                # network/download job.
                firmware_live_discovery_enabled=False,
            )
            workflow = ProductionWorkflow(
                config,
                runtime_version="3.2.0-pass3",
                executor=FakeExecutor(),
                dmi_root=dmi,
                fru_reader=matching_fru,
                collector_client=collector,
            )
            result = workflow.run_asus_production()
            run = result["run"]
            self.assertEqual("FAIL", run["final_disposition"])
            self.assertEqual("PARTIAL", run["collection_status"])
            self.assertEqual("SYNCED", result["central"]["queue_status"])
            run_dir = Path(result["run_directory"])
            self.assertTrue((run_dir / "firmware-plan.json").is_file())
            self.assertFalse((run_dir / "diagnostic-bundle.json").is_file())
            self.assertTrue((run_dir / "result-summary.json").is_file())
            self.assertFalse((run_dir / "evidence" / "hardware-test-summary.json").is_file())
            # The exact firmware gate stops before workload when no target is resolved.
            self.assertGreaterEqual(collector.counts()["events"], 2)
            self.assertEqual("3.2.0-pass3", run["runtime_version"])

    def test_asus_production_refuses_non_asus_before_creating_a_run(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            dmi = root / "dmi"
            write_dmi(dmi, vendor="Example Corp", product="Unknown Server")
            config = ProductionConfig(primary_root=root / "results", runner_config=root / "missing.json")
            workflow = ProductionWorkflow(
                config,
                runtime_version="3.2.0-pass3",
                executor=FakeExecutor(),
                dmi_root=dmi,
                fru_reader=matching_fru,
            )
            with self.assertRaises(ProductionWorkflowError):
                workflow.run_asus_production()
            self.assertFalse((root / "results" / "runs").exists())

    def test_access_file_requires_private_permissions(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "central-access"
            path.write_text("non-secret-test-value", encoding="utf-8")
            if os.name != "nt":
                os.chmod(path, 0o644)
                with self.assertRaises(CentralApiError):
                    central_credential_from_file(path)
            os.chmod(path, 0o600)
            loaded = central_credential_from_file(path)
            self.assertEqual("protected runner access file", loaded.source)
            self.assertNotIn("non-secret-test-value", repr(loaded))

    def test_systemd_unit_starts_only_the_menu(self):
        unit = Path("deployment/linux/cnserverops-console.service").read_text(encoding="utf-8")
        wrapper = Path("deployment/linux/cnserverops-console").read_text(encoding="utf-8")
        installer = Path("deployment/linux/install-production-launcher.sh").read_text(encoding="utf-8")
        firstboot_unit = Path("deployment/linux/cnserverops-clone-firstboot.service").read_text(encoding="utf-8")
        resume_unit = Path("deployment/linux/cnserverops-firmware-resume.service").read_text(encoding="utf-8")
        resume_retry_unit = Path("deployment/linux/cnserverops-firmware-resume-retry.service").read_text(encoding="utf-8")
        resume_retry_timer = Path("deployment/linux/cnserverops-firmware-resume-retry.timer").read_text(encoding="utf-8")
        central_start = Path("deployment/windows-central/Start-Central.ps1").read_text(encoding="utf-8")
        self.assertIn("ExecStart=/usr/local/sbin/cnserverops-console", unit)
        self.assertNotIn("run-production", unit)
        self.assertIn("After=local-fs.target systemd-user-sessions.service cnserverops-clone-firstboot.service cnserverops-firmware-resume.service", unit)
        self.assertIn("Wants=network-online.target cnserverops-clone-firstboot.service", unit)
        self.assertNotIn("ConditionPathExists=/etc/cnserverops/runner.json", unit)
        self.assertNotIn("After=local-fs.target systemd-user-sessions.service network-online.target", unit)
        self.assertIn("Wants=network-online.target", unit)
        self.assertIn("cnserverops.operator_console", wrapper)
        self.assertNotIn("run-production", wrapper)
        self.assertIn("disable --now smartmontools.service", installer)
        self.assertNotIn("rm ", installer)
        self.assertIn("After=local-fs.target network-online.target cnserverops-clone-firstboot.service", resume_unit)
        self.assertIn("Before=cnserverops-console.service", resume_unit)
        self.assertNotIn("Restart=on-failure", resume_unit)
        self.assertIn("After=network-online.target cnserverops-console.service", resume_retry_unit)
        self.assertIn("ExecStart=/usr/bin/python3 -m cnserverops.cli asus-firmware-resume", resume_retry_unit)
        self.assertIn("OnUnitActiveSec=60", resume_retry_timer)
        self.assertIn("cnserverops-firmware-resume-retry.timer", installer)
        self.assertIn("After=local-fs.target systemd-udev-settle.service", firstboot_unit)
        self.assertIn("Wants=network-pre.target systemd-udev-settle.service", firstboot_unit)
        # Windows PowerShell 5.1 has no null-coalescing ``??`` operator; the
        # Central launcher must remain executable on the supported host.
        self.assertNotIn("??", central_start)
        self.assertIn("IsNullOrWhiteSpace", central_start)
        self.assertIn("supportsSkipCertificateCheck", central_start)

    def test_boot_resume_exit_contract_retries_failures_without_repeating_success(self):
        self.assertEqual(0, _service_result_exit_code({"status": "NO_PENDING_FIRMWARE"}, action="asus-firmware-resume"))
        self.assertEqual(0, _service_result_exit_code({"status": "REBOOT_REQUESTED"}, action="asus-firmware-resume"))
        self.assertEqual(0, _service_result_exit_code({"status": "UPDATED_VERIFIED"}, action="asus-firmware-resume"))
        self.assertEqual(1, _service_result_exit_code({"status": "REBOOT_REQUEST_FAILED"}, action="asus-firmware-resume"))
        self.assertEqual(1, _service_result_exit_code({"status": "BLOCKED_BY_AUTH"}, action="asus-firmware-resume"))
        self.assertEqual(0, _service_result_exit_code({"status": "TERMINAL_CHECKPOINT_RETIRED"}, action="asus-firmware-resume"))
        self.assertEqual(0, _service_result_exit_code({"run": {"current_stage": "COMPLETE"}}, action="asus-firmware-resume"))

    def test_diagnostic_auth_metadata_is_secret_free(self):
        # Diagnostics may record bounded authentication outcomes, but never
        # a credential-attempts field or any username/password material.
        assert_no_sensitive_fields({"authentication_attempt_count": 1, "authentication_statuses": ["AUTH_BLOCKED"]})
        with self.assertRaises(SensitiveEvidenceError):
            assert_no_sensitive_fields({"credential_attempts": []})


if __name__ == "__main__":
    unittest.main()
