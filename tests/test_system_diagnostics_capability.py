import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cnserverops.capabilities import classify_asus_system_diagnostics_platform
from cnserverops.production import ProductionConfig, ProductionWorkflow


class SystemDiagnosticsCapabilityTests(unittest.TestCase):
    def test_rs500a_asmb11_firmware_descriptor_preempts_auth(self):
        # This mirrors the current physical normalized shape: management
        # generation is retained by the firmware planner, not as a top-level
        # normalized-inventory field.
        inventory = {
            "normalized": {
                "bmc_ip": "192.0.2.10",
                "components": [
                    {"category": "MANAGEMENT_MODULE", "model": "Unknown (0x002E)"},
                ],
            }
        }
        firmware = {
            "generic_asus_firmware_engine": {
                "platform": {
                    "model": "RS500A-E12-RS12U",
                    "bmc_model": "ASMB11-iKVM",
                    "bmc_generation": "ASMB11",
                }
            }
        }
        with tempfile.TemporaryDirectory() as folder:
            with patch(
                "cnserverops.production.execute_asmb12_diagnostics",
                side_effect=AssertionError("ASMB11 must not authenticate or call the ASMB12 API"),
            ):
                result = ProductionWorkflow._run_extended_diagnostics(
                    object(),
                    Path(folder),
                    inventory=inventory,
                    bmc_auth_state="BMC_AUTH_UNAVAILABLE",
                    platform={"platform_id": "ASUS_SERVER"},
                    firmware=firmware,
                )
        self.assertEqual("PLATFORM_UNSUPPORTED", result["status"])
        self.assertEqual("ASMB11_SYSTEM_DIAGNOSTICS_ENDPOINT_NOT_ADVERTISED", result["reason"])
        self.assertEqual("ASMB11", result["platform_capability"]["bmc_generation"])
        self.assertEqual(
            "ASUS_EXACT_FIRMWARE_PLATFORM_DESCRIPTOR",
            result["platform_capability"]["bmc_generation_source"],
        )

    def test_management_component_is_a_safe_asmb11_fallback(self):
        result = classify_asus_system_diagnostics_platform(
            normalized_inventory={
                "components": [
                    {"category": "MANAGEMENT_MODULE", "model": "ASMB11-iKVM"},
                ]
            },
        )
        self.assertEqual("PLATFORM_UNSUPPORTED", result["status"])
        self.assertEqual("ASMB11", result["bmc_generation"])
        self.assertEqual("NORMALIZED_COMPONENT:MANAGEMENT_MODULE:model", result["bmc_generation_source"])

    def test_asmb12_without_auth_is_capability_blocked_not_unsupported(self):
        with tempfile.TemporaryDirectory() as folder:
            result = ProductionWorkflow._run_extended_diagnostics(
                object(),
                Path(folder),
                inventory={"normalized": {"bmc_ip": "192.0.2.10", "bmc_generation": "ASMB12"}},
                bmc_auth_state="BMC_AUTH_UNAVAILABLE",
                platform={"bmc_generation": "ASMB12"},
            )
        self.assertEqual("BLOCKED_BY_AUTH", result["status"])
        self.assertEqual("BMC_AUTH_UNAVAILABLE", result["reason"])
        self.assertEqual("CANDIDATE_REQUIRES_AUTHENTICATED_DISCOVERY", result["platform_capability"]["status"])

    def test_adapter_auth_block_is_normalized_but_missing_implementation_is_not(self):
        with tempfile.TemporaryDirectory() as folder:
            workflow = ProductionWorkflow(
                ProductionConfig(primary_root=Path(folder)),
                runtime_version="unit",
            )
            kwargs = {
                "inventory": {"normalized": {"bmc_ip": "192.0.2.10", "bmc_generation": "ASMB12", "server_id": "SERVER-UNIT"}},
                "bmc_auth_state": "BMC_AUTH_AVAILABLE",
                "bmc_auth_discovery": {"attempts": [{"account": {"kind": "PROVISIONED"}, "status": "PASS"}]},
                "platform": {"bmc_generation": "ASMB12"},
            }
            with patch("cnserverops.production.runtime_credential_candidates", return_value=[("admin", "secret", "PROVISIONED")]):
                with patch(
                    "cnserverops.production.execute_asmb12_diagnostics",
                    return_value={"status": "AUTH_BLOCKED", "reason": "DIAGNOSTIC_CAPABILITY_NOT_AVAILABLE"},
                ):
                    auth_blocked = workflow._run_extended_diagnostics(Path(folder), **kwargs)
                with patch(
                    "cnserverops.production.execute_asmb12_diagnostics",
                    return_value={"status": "UNSUPPORTED", "reason": "DIAGNOSTIC_CAPABILITY_NOT_AVAILABLE"},
                ):
                    implementation_missing = workflow._run_extended_diagnostics(Path(folder), **kwargs)
        self.assertEqual("BLOCKED_BY_AUTH", auth_blocked["status"])
        self.assertEqual("AUTH_BLOCKED", auth_blocked["adapter_status"])
        self.assertEqual("UNSUPPORTED", implementation_missing["status"])
        self.assertNotIn("adapter_status", implementation_missing)


if __name__ == "__main__":
    unittest.main()
