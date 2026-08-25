import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from cnserverops.capabilities import CapabilityRecord, ValidationLevel
from cnserverops.diagnostics import (
    UnsafeEvidenceError,
    build_universal_bundle,
    export_bundle,
    inspect_asmb12_system_diagnostics,
)
from cnserverops.identity import derive_machine_identity
from cnserverops.platform import PlatformProbe, detect_platform
from cnserverops.state import StateMismatchError, UnsafeIdentityError, assert_resume_allowed, load_state, write_state
from cnserverops.storage import StoragePolicy, StoragePolicyError


class PlatformDetectionTests(unittest.TestCase):
    def test_dell_r640_routes_to_existing_dell_flow(self):
        decision = detect_platform(
            PlatformProbe(manufacturer="Dell Inc.", product_name="PowerEdge R640", system_serial="DELL123")
        )
        self.assertEqual("DELL_POWEREDGE_R640", decision["platform_id"])
        self.assertEqual("EXISTING_DELL_PRODUCTION", decision["production_flow"])
        self.assertFalse(decision["mutating_operations_authorized"])

    def test_asus_rs700a_routes_to_common_capability_discovery(self):
        decision = detect_platform(
            PlatformProbe(
                manufacturer="ASUSTeK COMPUTER INC.",
                product_name="RS700A-E13-RS12U",
                system_serial="ASUS123",
            )
        )
        self.assertEqual("ASUS_SERVER", decision["platform_id"])
        self.assertEqual("asus_common", decision["adapter"])
        self.assertTrue(decision["discovery_supported"])
        self.assertFalse(decision["production_supported"])
        self.assertEqual("BLOCKED_PENDING_CAPABILITY_AND_MODEL_VALIDATION", decision["firmware_policy"])

    def test_asus_rs500a_uses_same_common_adapter_and_ignores_hostname(self):
        decision = detect_platform(
            PlatformProbe.from_mapping(
                {
                    "manufacturer": "ASUSTeK COMPUTER INC.",
                    "product_name": "RS500A-E12-RS12U",
                    "system_serial": "RAS0MD0000HU",
                    "hostname": "cnstress-r640",
                }
            )
        )
        self.assertEqual("ASUS_SERVER", decision["platform_id"])
        self.assertEqual("asus_common", decision["adapter"])
        self.assertEqual("ASUS_CAPABILITY_DISCOVERY", decision["production_flow"])
        self.assertNotIn("hostname", decision["probe"])

    def test_unknown_platform_is_safe_inventory_only(self):
        decision = detect_platform(PlatformProbe(manufacturer="Example", product_name="Mystery Server"))
        self.assertFalse(decision["production_supported"])
        self.assertTrue(decision["discovery_supported"])
        self.assertEqual("SAFE_INVENTORY_ONLY", decision["production_flow"])
        self.assertEqual("BLOCKED_UNSUPPORTED_PLATFORM", decision["firmware_policy"])


class UniversalIdentityStateTests(unittest.TestCase):
    def _identity(self, manufacturer="ASUSTeK COMPUTER INC.", model="RS700A-E13-RS12U", serial="ASUS123"):
        probe = PlatformProbe(
            manufacturer=manufacturer,
            product_name=model,
            system_serial=serial,
            board_serial=f"BOARD-{serial}",
            chassis_serial=f"CHASSIS-{serial}",
        )
        decision = detect_platform(probe)
        identity = derive_machine_identity(
            decision,
            probe,
            redfish_system={"SerialNumber": serial, "Model": model},
            chassis_fru={
                "FruInfo": {
                    "Product": {"ProductSerial": serial},
                    "Board": {"BoardSerial": f"BOARD-{serial}"},
                    "Chassis": {"ChassisSerial": f"CHASSIS-{serial}"},
                }
            },
            manager={"SerialNumber": f"BMC-{serial}"},
        )
        return decision, identity

    def test_cross_vendor_state_never_resumes(self):
        _, asus_identity = self._identity()
        _, dell_identity = self._identity("Dell Inc.", "PowerEdge R640", "ASUS123")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "state.json"
            write_state(path, asus_identity, "REBOOT_REQUIRED")
            assert_resume_allowed(load_state(path), asus_identity)
            with self.assertRaises(StateMismatchError):
                assert_resume_allowed(load_state(path), dell_identity)

    def test_stale_redfish_serial_does_not_replace_current_dmi_identity(self):
        probe = PlatformProbe(
            manufacturer="ASUSTeK COMPUTER INC.",
            product_name="RS700A-E13-RS12U",
            system_serial="DMI-1",
        )
        decision = detect_platform(probe)
        identity = derive_machine_identity(decision, probe, redfish_system={"SerialNumber": "RF-2"})
        self.assertTrue(identity["resumable"])
        self.assertEqual("DMI-1", identity["primary_serial"])
        self.assertIn("system_serial", identity["bmc_conflicts"])
        self.assertIn("POSSIBLE_STALE_BMC_DATA", identity["warning_codes"])
        self.assertFalse(identity["bmc_conflicting_values_authoritative_for_mutation"])
        assert_resume_allowed(None, identity)

    def test_conflicting_board_serials_block_resume(self):
        probe = PlatformProbe(
            manufacturer="ASUSTeK COMPUTER INC.",
            product_name="RS700A-E13-RS12U",
            system_serial="ASUS123",
            board_serial="DMI-BOARD",
        )
        decision = detect_platform(probe)
        identity = derive_machine_identity(
            decision,
            probe,
            redfish_system={"SerialNumber": "ASUS123"},
            chassis_fru={"FruInfo": {"Board": {"BoardSerial": "FRU-BOARD"}}},
        )
        self.assertFalse(identity["resumable"])
        self.assertIn("board serial sources disagree", identity["conflicts"])

    def test_asmb12_fru_board_is_management_module_not_dmi_motherboard(self):
        probe = PlatformProbe(
            manufacturer="ASUSTeK COMPUTER INC.",
            product_name="RS700-E12-RS12U",
            system_serial="TAS0MD00001H",
            board_serial="250657396800036",
            chassis_serial="I025220337",
            product_uuid="d6293d03-f8b5-1158-2b5d-657396800036",
            board_name="Z14PP-D32 Series",
        )
        decision = detect_platform(probe)
        identity = derive_machine_identity(
            decision,
            probe,
            chassis_fru={
                "FruInfo": {
                    "Product": {"ProductName": "RS700-E12-RS12U", "ProductSerial": "TAS0MD00001H"},
                    "Board": {"BoardProduct": "ASMB12-SCM Series", "BoardSerial": "250657103800099"},
                    "Chassis": {"ChassisSerial": "I025220337"},
                }
            },
            boot_id="4c3b0330-1221-41c2-ac5b-d6560476b900",
        )
        self.assertTrue(identity["resumable"])
        self.assertEqual("high", identity["confidence"])
        self.assertEqual([], identity["conflicts"])
        self.assertTrue(identity["management_module"])
        self.assertEqual("250657396800036", identity["component_identities"]["MOTHERBOARD"]["serial"])
        self.assertEqual("250657103800099", identity["component_identities"]["MANAGEMENT_MODULE"]["serial"])
        self.assertEqual("CURRENT_BOOT", identity["component_identities"]["MOTHERBOARD"]["freshness"])
        self.assertEqual("STATIC_FRU", identity["component_identities"]["MANAGEMENT_MODULE"]["freshness"])


class DiagnosticBundleTests(unittest.TestCase):
    def test_collection_and_export_are_independent(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            artifact = root / "asmb12-diagnostics.bin"
            artifact.write_bytes(b"safe fixture diagnostic")
            evidence = root / "sel.json"
            evidence.write_text('{"events": []}\n', encoding="utf-8")
            artifact_record = inspect_asmb12_system_diagnostics(
                artifact,
                validation_level=ValidationLevel.SIMULATED,
            )
            platform = detect_platform(
                PlatformProbe("ASUSTeK COMPUTER INC.", "RS700A-E13-RS12U", "ASUS123")
            )
            identity = derive_machine_identity(
                platform,
                PlatformProbe("ASUSTeK COMPUTER INC.", "RS700A-E13-RS12U", "ASUS123"),
            )
            capability = CapabilityRecord(
                capability="ASMB12 System Diagnostics intake",
                mechanism_used="operator-provided fixture",
                raw_command_api="no BMC command issued",
                raw_evidence=artifact.name,
                normalized_result={"registered": True},
                supported_model="RS700A-E13-RS12U",
                failure_behavior="Reject missing or changed artifact.",
                timeout_behavior="Not applicable for local intake.",
                fallback="Build a partial OS-evidence bundle.",
                validation_level=ValidationLevel.SIMULATED,
                safe_for_production=False,
            )
            bundle, manifest = build_universal_bundle(
                root / "primary",
                platform=platform,
                identity=identity,
                evidence_paths=[evidence],
                vendor_artifact=artifact_record,
                capabilities=[capability],
            )
            self.assertEqual("SUCCESS", manifest["collection"]["status"])
            self.assertEqual("NOT_ATTEMPTED", manifest["export"]["status"])
            with zipfile.ZipFile(bundle) as archive:
                embedded = json.loads(archive.read("manifest.json"))
                self.assertEqual("SUCCESS", embedded["collection"]["status"])
                self.assertIn("vendor/asmb12-diagnostics.bin", archive.namelist())

            failed_target = root / "not-a-directory"
            failed_target.write_text("occupied", encoding="utf-8")
            receipt = export_bundle(bundle, failed_target, primary_receipt_dir=root / "primary")
            self.assertEqual("SUCCESS", receipt["collection_status"])
            self.assertEqual("FAILED", receipt["export_status"])

            successful = export_bundle(bundle, root / "CN_EXPORT", primary_receipt_dir=root / "primary")
            self.assertEqual("SUCCESS", successful["collection_status"])
            self.assertEqual("SUCCESS", successful["export_status"])
            repeated = export_bundle(bundle, root / "CN_EXPORT", primary_receipt_dir=root / "primary")
            self.assertEqual("SUCCESS", repeated["export_status"])
            self.assertIn("checksum matched", repeated["error"])
            self.assertTrue(Path(repeated["receipt"]).exists())

    def test_sensitive_filename_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            secret = Path(folder) / "bmc-password.txt"
            secret.write_text("do not bundle", encoding="utf-8")
            with self.assertRaises(UnsafeEvidenceError):
                inspect_asmb12_system_diagnostics(secret)

    def test_export_insufficient_disk_space_keeps_collection_success(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            evidence = root / "evidence.json"
            evidence.write_text('{"safe": true}', encoding="utf-8")
            platform = detect_platform(PlatformProbe("ASUSTeK COMPUTER INC.", "RS700A-E13-RS12U", "ASUS123"))
            identity = derive_machine_identity(
                platform,
                PlatformProbe("ASUSTeK COMPUTER INC.", "RS700A-E13-RS12U", "ASUS123"),
            )
            bundle, _ = build_universal_bundle(
                root / "primary", platform=platform, identity=identity, evidence_paths=[evidence]
            )
            with patch("cnserverops.diagnostics.ensure_free_space", side_effect=OSError("no space left")):
                receipt = export_bundle(bundle, root / "export")
            self.assertEqual("PARTIAL", receipt["collection_status"])
            self.assertEqual("FAILED", receipt["export_status"])


class StoragePolicyTests(unittest.TestCase):
    def test_efi_cannot_be_export_root(self):
        with self.assertRaises(StoragePolicyError):
            StoragePolicy(export_root=Path("/boot/efi/CN_EXPORT")).validate()

    def test_separate_primary_and_export_roots_are_valid(self):
        StoragePolicy().validate()


if __name__ == "__main__":
    unittest.main()
