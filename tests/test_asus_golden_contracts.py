"""Cross-platform golden-contract regression coverage.

These tests intentionally exercise the shared planner gates with the two
physical ASUS contracts.  They do not perform firmware, reset, reboot, or
stress operations.
"""

from __future__ import annotations

import hashlib
import unittest

from cnserverops.asus_firmware import AsusPlatformFingerprint, discover_asus_transports
from cnserverops.production import _exact_current_versions_verified, _firmware_requires_authenticated_bmc


class AsusGoldenContractTests(unittest.TestCase):
    CONTRACTS = (
        {
            "name": "RS500-ASMB11",
            "model": "RS500A-E12-RS12U",
            "board": "K14PA-U24",
            "generation": "ASMB11",
            "bios": "2306",
            "bmc": "1.2.37",
        },
        {
            "name": "RS700-ASMB12",
            "model": "RS700-E12-RS12U",
            "board": "Z14PP-D32",
            "generation": "ASMB12",
            "bios": "0903",
            "bmc": "1.32.00",
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
    def _current_component(component: str, version: str, contract: dict[str, str]) -> dict:
        digest = hashlib.sha256(f"{contract['name']}-{component}-{version}".encode()).hexdigest()
        metadata = {
            "vendor": "ASUS",
            "component": component,
            "version": version,
            "package_filename": f"{contract['name']}-{component}-{version}.zip",
            "sha256": digest,
            "source": "ASUS_OFFICIAL_SERVER_FIRMWARE_CATALOG",
            "source_url": "https://dlcdnets.asus.com/pub/ASUS/server/exact-package.zip",
            "compatible_models": [contract["model"]],
            "compatible_boards": [contract["board"]],
            "compatible_bmc_generations": [contract["generation"]],
            "validation_status": "CHECKSUM_VERIFIED",
            "official_source_verified": True,
            "applicability_evidence": ["exact ASUS compatibility row"],
        }
        return {
            "status": "CURRENT",
            "target_version": version,
            "selected_package": {
                "match": {"exact_match": True},
                "metadata": metadata,
            },
        }

    def test_both_contracts_accept_exact_current_bios_and_bmc_without_reflash(self):
        for contract in self.CONTRACTS:
            with self.subTest(contract=contract["name"]):
                components = {
                    "BIOS": self._current_component("BIOS", contract["bios"], contract),
                    "BMC": self._current_component("BMC", contract["bmc"], contract),
                }
                self.assertTrue(
                    _exact_current_versions_verified(
                        components,
                        current_versions={"BIOS": contract["bios"], "BMC": contract["bmc"]},
                    )
                )

    def test_asmb11_prefers_credential_free_kcs_bmc_transport(self):
        contract = self.CONTRACTS[0]
        discovery = discover_asus_transports(
            redfish_discovery={
                "authentication": {"available": True},
                "normalized": {"update_mechanisms": [{"kind": "MultipartHttpPushUri", "target": "/upload"}]},
                "endpoint_catalog": [{"label": "task_service", "status": 200}],
            },
            fingerprint=self._fingerprint(contract),
            local_tools={"kcs": {"available": True, "status": "PASS"}},
        )
        selected = discovery["components"]["BMC"]["selected"]
        self.assertEqual("ASUS_ASMB11_KCS_YAFUFLASH", selected["name"])
        self.assertFalse(selected["requires_authenticated_bmc"])

    def test_asmb12_prefers_authenticated_redfish_multipart(self):
        contract = self.CONTRACTS[1]
        discovery = discover_asus_transports(
            redfish_discovery={
                "authentication": {"available": True},
                "normalized": {"update_mechanisms": [{"kind": "MultipartHttpPushUri", "target": "/upload"}]},
                "endpoint_catalog": [{"label": "task_service", "status": 200}],
            },
            fingerprint=self._fingerprint(contract),
        )
        selected = discovery["components"]["BMC"]["selected"]
        self.assertEqual("REDFISH_MULTIPART_PUSH", selected["name"])
        self.assertTrue(selected["requires_authenticated_bmc"])
        self.assertTrue(selected["task_tracking"])

    def test_asmb11_bmc_first_kcs_stage_defers_bios_auth_then_requires_it(self):
        contract = self.CONTRACTS[0]
        base = {
            "generic_asus_firmware_engine": {
                "platform": {"bmc_generation": contract["generation"]},
                "components": {
                    "BMC": {
                        "selected_transport": {
                            "name": "ASUS_ASMB11_KCS_YAFUFLASH",
                            "selectable": True,
                            "requires_authenticated_bmc": False,
                        }
                    },
                    "BIOS": {"selected_transport": None},
                },
            }
        }
        both_old = base | {
            "components": [
                {"component": "BMC", "status": "UPDATE_REQUIRED"},
                {"component": "BIOS", "status": "UPDATE_REQUIRED"},
            ]
        }
        self.assertFalse(_firmware_requires_authenticated_bmc(both_old))
        after_bmc = base | {
            "components": [
                {"component": "BMC", "status": "CURRENT"},
                {"component": "BIOS", "status": "UPDATE_REQUIRED"},
            ]
        }
        self.assertTrue(_firmware_requires_authenticated_bmc(after_bmc))

    def test_asmb12_outdated_component_requires_auth_but_current_components_do_not(self):
        contract = self.CONTRACTS[1]
        redfish = {
            "name": "REDFISH_MULTIPART_PUSH",
            "selectable": True,
            "requires_authenticated_bmc": True,
        }
        base = {
            "generic_asus_firmware_engine": {
                "platform": {"bmc_generation": contract["generation"]},
                "components": {"BIOS": {"selected_transport": redfish}, "BMC": {"selected_transport": redfish}},
            }
        }
        self.assertTrue(
            _firmware_requires_authenticated_bmc(
                base | {"components": [{"component": "BIOS", "status": "UPDATE_REQUIRED"}, {"component": "BMC", "status": "CURRENT"}]}
            )
        )
        self.assertFalse(
            _firmware_requires_authenticated_bmc(
                base | {"components": [{"component": "BIOS", "status": "CURRENT"}, {"component": "BMC", "status": "CURRENT"}]}
            )
        )


if __name__ == "__main__":
    unittest.main()
