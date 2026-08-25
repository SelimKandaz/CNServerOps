import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cnserverops.evidence import (
    BmcAuthState,
    EvidenceConfidence,
    EvidenceFreshness,
    FieldObservation,
    classify_bmc_auth_state,
    fuse_field,
    read_linux_boot_id,
    resolve_capability_access,
)
from cnserverops.capabilities import apply_firmware_transport_paths, build_asus_capability_path_matrix
from cnserverops.identity import derive_machine_identity
from cnserverops.local_evidence import read_local_ipmi_fru
from cnserverops.orchestrator import ProductionOrchestrator
from cnserverops.platform import PlatformProbe, detect_platform


class EvidenceFusionTests(unittest.TestCase):
    def test_current_boot_value_wins_over_stale_bmc_value(self):
        field = fuse_field(
            "cpu_model",
            [
                FieldObservation(
                    "AMD EPYC 9754",
                    "LSCPU",
                    EvidenceFreshness.CURRENT_BOOT,
                    EvidenceConfidence.HIGH,
                    current_local=True,
                ),
                FieldObservation(
                    "AMD EPYC 9654",
                    "REDFISH_PROCESSOR",
                    EvidenceFreshness.BMC_FRESHNESS_UNKNOWN,
                    EvidenceConfidence.MEDIUM,
                    bmc_derived=True,
                ),
            ],
        )
        self.assertEqual("AMD EPYC 9754", field["value"])
        self.assertEqual("LSCPU", field["source"])
        self.assertTrue(field["bmc_conflict"])
        self.assertIn("BMC_INVENTORY_CONFLICT", field["reason_codes"])
        self.assertFalse(field["bmc_value_authoritative_for_mutation"])

    def test_bmc_auth_failure_is_capability_specific(self):
        identity = resolve_capability_access(
            "identity",
            bmc_auth_state=BmcAuthState.BMC_AUTH_UNAVAILABLE,
            verified_local_mechanism="DMI + IPMI FRU",
            verified_bmc_mechanism="Redfish Systems",
        )
        diagnostics = resolve_capability_access(
            "system_diagnostics",
            bmc_auth_state=BmcAuthState.BMC_AUTH_UNAVAILABLE,
            verified_bmc_mechanism="Authenticated ASUS OEM action",
        )
        self.assertEqual("AVAILABLE_LOCAL", identity["status"])
        self.assertFalse(identity["overall_run_blocked"])
        self.assertEqual("BLOCKED_BY_AUTH", diagnostics["status"])
        self.assertFalse(diagnostics["overall_run_blocked"])

    def test_auth_probe_supports_required_password_change(self):
        state = classify_bmc_auth_state(
            credential_supplied=True,
            http_status=403,
            password_change_required=True,
        )
        self.assertEqual(BmcAuthState.BMC_AUTH_REQUIRES_PASSWORD_CHANGE, state)

    def test_password_change_state_does_not_block_local_sensors(self):
        sensors = resolve_capability_access(
            "sensors",
            bmc_auth_state=BmcAuthState.BMC_AUTH_REQUIRES_PASSWORD_CHANGE,
            verified_local_mechanism="local KCS ipmitool sdr",
            verified_bmc_mechanism="Redfish Sensors",
        )
        self.assertEqual("AVAILABLE_LOCAL", sensors["status"])
        self.assertFalse(sensors["blocked_by_auth"])

    def test_major_capabilities_are_resolved_independently(self):
        rows = build_asus_capability_path_matrix(
            bmc_auth_state=BmcAuthState.BMC_AUTH_UNAVAILABLE,
            verified_local_mechanisms={
                "identity": "DMI + local FRU",
                "firmware_inventory": "DMI BIOS + IPMI MC",
                "hardware_inventory": "Linux current boot",
                "sensors": "local KCS SDR",
                "sel": "local KCS SEL",
            },
            verified_bmc_mechanisms={
                "bios_update": "Redfish UpdateService",
                "bmc_update": "Redfish UpdateService",
                "task_completion": "Redfish TaskService",
                "system_diagnostics": "ASUS OEM action",
            },
        )
        by_name = {row["capability"]: row for row in rows}
        self.assertEqual(9, len(rows))
        self.assertEqual("AVAILABLE_LOCAL", by_name["identity"]["status"])
        self.assertEqual("AVAILABLE_LOCAL", by_name["hardware_inventory"]["status"])
        self.assertEqual("BLOCKED_BY_AUTH", by_name["bios_update"]["status"])
        self.assertFalse(any(row["overall_run_blocked"] for row in rows))

    def test_selected_local_firmware_transport_is_reflected_per_capability(self):
        rows = build_asus_capability_path_matrix(
            bmc_auth_state=BmcAuthState.BMC_AUTH_UNAVAILABLE,
            verified_local_mechanisms={"identity": "DMI + local FRU"},
            verified_bmc_mechanisms={"bios_update": "Redfish UpdateService", "bmc_update": "Redfish UpdateService"},
        )
        plan = {
            "generic_asus_firmware_engine": {
                "components": {
                    "BIOS": {
                        "status": "READY_FOR_OPERATOR_CONFIRMATION",
                        "selected_transport": {
                            "name": "ASUS_LOCAL_OFFICIAL_UTILITY",
                            "source": "LOCAL_ASUS_TOOL_DISCOVERY",
                            "target": "/opt/asus/approved-flasher",
                            "requires_authenticated_bmc": False,
                        },
                    },
                    "BMC": {"status": "NO_SUPPORTED_TRANSPORT"},
                }
            }
        }
        by_name = {row["capability"]: row for row in apply_firmware_transport_paths(rows, plan)}
        self.assertEqual("AVAILABLE_LOCAL", by_name["bios_update"]["status"])
        self.assertEqual("ASUS_LOCAL_OFFICIAL_UTILITY", by_name["bios_update"]["selected_mechanism"])
        self.assertFalse(by_name["bios_update"]["blocked_by_auth"])
        self.assertEqual("NOT_SUPPORTED", by_name["bmc_update"]["status"])

    def test_server_run_runner_and_boot_ids_are_separate(self):
        probe = PlatformProbe(
            manufacturer="ASUSTeK COMPUTER INC.",
            product_name="RS500A-E12-RS12U",
            system_serial="ASUS-1",
            board_serial="BOARD-1",
            chassis_serial="CHASSIS-1",
        )
        platform = detect_platform(probe)
        identity = derive_machine_identity(
            platform,
            probe,
            chassis_fru={
                "FruInfo": {
                    "Product": {"ProductSerial": "ASUS-1"},
                    "Board": {"BoardSerial": "BOARD-1"},
                    "Chassis": {"ChassisSerial": "CHASSIS-1"},
                }
            },
            boot_id="11111111-2222-3333-4444-555555555555",
        )
        with tempfile.TemporaryDirectory() as folder:
            context = ProductionOrchestrator(Path(folder), runtime_version="3.1.0").start(
                platform=platform,
                identity=identity,
                runner_id="CNSSD-01",
                continuation_of_run_id="RUN-PRIOR",
            )
        self.assertTrue(identity["server_id"].startswith("SERVER-"))
        self.assertNotEqual(identity["server_id"], context["run"]["run_id"])
        self.assertNotEqual(context["run"]["run_id"], context["run"]["runner_id"])
        self.assertEqual("11111111-2222-3333-4444-555555555555", context["run"]["boot_id"])
        self.assertEqual("RUN-PRIOR", context["run"]["continuation_of_run_id"])

    def test_boot_id_reader_is_read_only_and_validates_shape(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "boot_id"
            path.write_text("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n", encoding="utf-8")
            self.assertEqual("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", read_linux_boot_id(path))
            path.write_text("not-a-boot-id\n", encoding="utf-8")
            self.assertEqual("", read_linux_boot_id(path))

    @patch("cnserverops.local_evidence.subprocess.run")
    def test_local_fru_reader_uses_fixed_read_only_command(self, run):
        run.return_value = SimpleNamespace(
            returncode=0,
            stdout="""
                Chassis Serial       : CHASSIS-1
                Board Serial         : BOARD-1
                Product Serial       : SYSTEM-1
            """,
        )
        result = read_local_ipmi_fru()
        self.assertEqual("PASS", result["status"])
        self.assertEqual("SYSTEM-1", result["fru"]["FruInfo"]["Product"]["ProductSerial"])
        run.assert_called_once_with(
            ["ipmitool", "fru", "print"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )


if __name__ == "__main__":
    unittest.main()
