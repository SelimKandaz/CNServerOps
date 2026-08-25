"""Mandatory cross-platform ASUS firmware lifecycle regression matrix.

The contracts in this module intentionally keep platform-specific package and
transport behavior at the capability boundary while exercising the shared
resume and final-handoff rules for both physically proven platforms.  No test
performs firmware mutation, reset, reboot, or network access.
"""

from __future__ import annotations

import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from cnserverops.asus_firmware import (
    AsusPlatformFingerprint,
    discover_asus_transports,
    select_asus_transport_for_package,
)
from cnserverops.bmc_handoff import bmc_auth_change_required
from cnserverops.bmc_recovery import asus_bmc_recovery_capability
from cnserverops.firmware import FirmwarePackageMetadata
from cnserverops.firmware_lifecycle import build_pending, validate_pending_for_resume
from cnserverops.handoff import HandoffPolicy, evaluate_handoff


class AsusPlatformMatrixTests(unittest.TestCase):
    CONTRACTS = (
        {
            "name": "RS500_ASMB11",
            "model": "RS500A-E12-RS12U",
            "board": "K14PA-U24",
            "generation": "ASMB11",
            "bios_before": "1201",
            "bios_target": "2306",
            "bmc_target": "1.2.37",
        },
        {
            "name": "RS700_ASMB12",
            "model": "RS700-E12-RS12U",
            "board": "Z14PP-D32",
            "generation": "ASMB12",
            "bios_before": "0603",
            "bios_target": "0903",
            "bmc_target": "1.32.00",
        },
    )

    @staticmethod
    def _fingerprint(contract: dict[str, str]) -> AsusPlatformFingerprint:
        return AsusPlatformFingerprint(
            vendor="ASUS",
            model=contract["model"],
            board=contract["board"],
            bmc_generation=contract["generation"],
            system_serial=f"SYS-{contract['name']}",
        )

    @staticmethod
    def _metadata(
        contract: dict[str, str],
        *,
        component: str,
        version: str,
        filename: str,
    ) -> FirmwarePackageMetadata:
        return FirmwarePackageMetadata(
            vendor="ASUS",
            component=component,
            version=version,
            package_filename=filename,
            sha256=hashlib.sha256(f"{contract['name']}-{component}-{version}".encode()).hexdigest(),
            source="ASUS_OFFICIAL_SERVER_FIRMWARE_CATALOG",
            source_url=f"https://dlcdnets.asus.com/pub/ASUS/server/{contract['model']}/{filename}",
            compatible_models=(contract["model"],),
            compatible_boards=(contract["board"],),
            compatible_bmc_generations=(contract["generation"],),
            validation_status="CHECKSUM_VERIFIED",
            official_source_verified=True,
            applicability_evidence=("EXACT_MODEL", "EXACT_BOARD", "EXACT_BMC_GENERATION"),
        )

    @staticmethod
    def _redfish(*mechanisms: dict[str, str], web_hpm: bool = False) -> dict:
        result = {
            "authentication": {"available": True},
            "normalized": {"update_mechanisms": list(mechanisms)},
            "endpoint_catalog": [{"label": "task_service", "status": 200}],
        }
        if web_hpm:
            result["web_hpm"] = {
                "supported": True,
                "components": ["BIOS"],
                "component_ids": {"BIOS": 4},
                "image_types": {"BIOS": 42},
                "endpoint_prefix": "/api/maintenance/hpm",
            }
        return result

    def test_rs500_asmb11_exact_package_transport_contract(self) -> None:
        """ASMB11 keeps KCS for BMC and routes a CAP-only BIOS to BIOSOOB."""
        contract = self.CONTRACTS[0]
        discovery = discover_asus_transports(
            redfish_discovery=self._redfish(
                {
                    "kind": "#UpdateService.BIOSFwUpdate",
                    "target": "/redfish/v1/UpdateService/Actions/Oem/UpdateService.BIOSFwUpdate",
                },
                {"kind": "MultipartHttpPushUri", "target": "/redfish/v1/UpdateService/upload"},
                web_hpm=True,
            ),
            fingerprint=self._fingerprint(contract),
            local_tools={"kcs": {"available": True, "status": "PASS"}},
        )
        self.assertEqual(
            "ASUS_ASMB11_KCS_YAFUFLASH",
            discovery["components"]["BMC"]["selected"]["name"],
        )
        self.assertFalse(
            discovery["components"]["BMC"]["selected"]["requires_authenticated_bmc"]
        )
        # Live capability ranks web-HPM first, but immutable package bytes are
        # authoritative for the second-stage transport choice.
        self.assertEqual(
            "ASUS_ASMB_WEB_HPM",
            discovery["components"]["BIOS"]["selected"]["name"],
        )
        metadata = self._metadata(
            contract,
            component="BIOS",
            version=contract["bios_target"],
            filename="K14PA-U24-ASUS-2306.zip",
        )
        with tempfile.TemporaryDirectory() as folder:
            package = Path(folder) / "verified-rs500-bios"
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("K14PA-U24-ASUS-2306.CAP", b"signed-uefi-capsule")
            selected = select_asus_transport_for_package(
                discovery,
                component="BIOS",
                package=package,
                metadata=metadata,
            )
        self.assertIsNotNone(selected)
        self.assertEqual("ASUS_REDFISH_BIOS_OOB", selected["name"])
        self.assertEqual("REDFISH_BIOS_OOB", selected["package_delivery"])
        self.assertEqual("VERIFIED", selected["package_compatibility"])
        self.assertIn("cap", selected["package_payload_capabilities"])
        self.assertNotIn("hpm_wrapped", selected["package_payload_capabilities"])

    def test_rs700_asmb12_redfish_multipart_contract_is_unchanged(self) -> None:
        """ASMB12 retains authenticated, task-tracked Redfish multipart."""
        contract = self.CONTRACTS[1]
        discovery = discover_asus_transports(
            redfish_discovery=self._redfish(
                {"kind": "MultipartHttpPushUri", "target": "/redfish/v1/UpdateService/upload"}
            ),
            fingerprint=self._fingerprint(contract),
        )
        for component, member in (
            ("BIOS", "Z14PP-D32-ASUS-0903.CAP"),
            ("BMC", "ASMB12-FW-1.32.00.IMA"),
        ):
            with self.subTest(component=component):
                initial = discovery["components"][component]["selected"]
                self.assertEqual("REDFISH_MULTIPART_PUSH", initial["name"])
                self.assertTrue(initial["requires_authenticated_bmc"])
                self.assertTrue(initial["task_tracking"])
                target = contract["bios_target"] if component == "BIOS" else contract["bmc_target"]
                metadata = self._metadata(
                    contract,
                    component=component,
                    version=target,
                    filename=f"{contract['name']}-{component}-{target}.zip",
                )
                with tempfile.TemporaryDirectory() as folder:
                    package = Path(folder) / f"verified-{component.lower()}"
                    with zipfile.ZipFile(package, "w") as archive:
                        archive.writestr(member, b"exact-official-package-payload")
                    selected = select_asus_transport_for_package(
                        discovery,
                        component=component,
                        package=package,
                        metadata=metadata,
                    )
                self.assertIsNotNone(selected)
                self.assertEqual("REDFISH_MULTIPART_PUSH", selected["name"])
                self.assertEqual("VERIFIED", selected["package_compatibility"])

    def test_recovery_adapter_matrix_is_generation_scoped(self) -> None:
        for contract in self.CONTRACTS:
            with self.subTest(platform=contract["name"]):
                capability = asus_bmc_recovery_capability(
                    normalized_inventory={
                        "bmc_ip": "192.0.2.20",
                        "components": [
                            {
                                "category": "MANAGEMENT_MODULE",
                                "model": contract["generation"],
                            }
                        ],
                    },
                    firmware_plan={
                        "generic_asus_firmware_engine": {
                            "platform": {"bmc_generation": contract["generation"]}
                        }
                    },
                )
                self.assertTrue(capability["supported"])
                self.assertEqual(contract["generation"], capability["bmc_generation"])
                self.assertEqual(
                    f"ASUS_{contract['generation']}_KCS_FACTORY_DEFAULT_RAW_32_66",
                    capability["method"],
                )

    def test_shared_resume_contract_is_same_server_and_new_boot_for_both_platforms(self) -> None:
        for index, contract in enumerate(self.CONTRACTS, start=1):
            with self.subTest(platform=contract["name"]), tempfile.TemporaryDirectory() as folder:
                identity = {
                    "server_id": f"SERVER-{contract['name']}",
                    "fingerprint_sha256": f"{index:x}" * 64,
                    "primary_serial": f"SERIAL-{contract['name']}",
                    "boot_id": f"boot-before-{index}",
                    "resumable": True,
                }
                run_id = f"RUN-MATRIX-{index:08d}"
                pending = build_pending(
                    run_id=run_id,
                    run_directory=Path(folder) / run_id,
                    identity=identity,
                    runner_id="CNSSD-MATRIX-001",
                    workflow_mode="PRODUCTION_EXTENDED",
                    plan={
                        "components": [
                            {
                                "component": "BMC",
                                "before": contract["bmc_target"],
                                "target": contract["bmc_target"],
                                "status": "CURRENT_VERIFIED",
                            },
                            {
                                "component": "BIOS",
                                "before": contract["bios_before"],
                                "target": contract["bios_target"],
                                "status": "UPDATE_REQUIRED",
                            },
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
                after = identity | {"boot_id": f"boot-after-{index}"}
                validate_pending_for_resume(
                    pending,
                    identity=after,
                    runner_id="CNSSD-MATRIX-001",
                )
                targets = {row["component"]: row["target"] for row in pending["components"]}
                self.assertEqual(
                    {"BIOS": contract["bios_target"], "BMC": contract["bmc_target"]},
                    targets,
                )
                with self.assertRaises(Exception):
                    validate_pending_for_resume(
                        pending,
                        identity=after | {"fingerprint_sha256": "f" * 64},
                        runner_id="CNSSD-MATRIX-001",
                    )

    def test_shared_handoff_contract_is_mandatory_only_after_auth_mutation(self) -> None:
        policy = HandoffPolicy.from_mapping(
            {
                "required_pass": ["collection", "identity"],
                "required_for_production": [],
            }
        )
        statuses = {"collection": "PASS", "identity": "PASS"}
        for contract in self.CONTRACTS:
            with self.subTest(platform=contract["name"]):
                self.assertFalse(
                    bmc_auth_change_required(
                        {"state": "BMC_AUTH_AVAILABLE", "platform": contract["generation"]}
                    )
                )
                self.assertTrue(
                    bmc_auth_change_required(
                        {
                            "platform": contract["generation"],
                            "provisioning": {"mutation_performed": True},
                        }
                    )
                )
                untouched = evaluate_handoff(
                    statuses,
                    workflow_mode="PRODUCTION_EXTENDED",
                    policy=policy,
                    bmc_auth_changed=False,
                )
                self.assertNotIn("bmc_auth_handoff", untouched["component_statuses"])
                handed_off = evaluate_handoff(
                    statuses,
                    workflow_mode="PRODUCTION_EXTENDED",
                    policy=policy,
                    bmc_auth_changed=True,
                    bmc_handoff_status="PASS",
                )
                self.assertEqual("READY_FOR_HANDOFF", handed_off["handoff_status"])
                failed = evaluate_handoff(
                    statuses,
                    workflow_mode="PRODUCTION_EXTENDED",
                    policy=policy,
                    bmc_auth_changed=True,
                    bmc_handoff_status="FAIL",
                )
                self.assertEqual("NOT_READY", failed["handoff_status"])
                self.assertEqual("FAIL", failed["component_statuses"]["bmc_auth_handoff"])


if __name__ == "__main__":
    unittest.main()
