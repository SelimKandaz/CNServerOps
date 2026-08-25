import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock
from pathlib import Path

from cnserverops.asus_firmware import (
    AsusFirmwareEngine,
    AsusOfficialCatalogSource,
    AsusPlatformFingerprint,
    AsusTransportDescriptor,
    discover_asus_transports,
    match_asus_package,
    select_asus_transport_for_package,
    _version_key,
)
from cnserverops.firmware import FirmwarePackageMetadata
from cnserverops.firmware import FirmwareRepository
from cnserverops.asus_firmware_transport import (
    AsusAsmb11KcsBmcFirmwareAdapter,
    AsusAsmbLinuxBmcFirmwareAdapter,
    AsusLocalFirmwareUtilityAdapter,
    AsusRedfishFirmwareAdapter,
    AsusAsmbWebHpmFirmwareAdapter,
    parse_asus_hpm_image,
)
from cnserverops.firmware_executor import UpdateTaskState
from cnserverops.production import (
    ProductionConfig,
    ProductionWorkflow,
    _discover_local_asus_firmware_tools,
    _exact_current_versions_verified,
    _firmware_requires_authenticated_bmc,
    _merge_post_recovery_inventory,
)
from cnserverops.handoff import HandoffPolicy, evaluate_handoff


class GenericAsusFirmwareTests(unittest.TestCase):
    def setUp(self):
        self.fingerprint = AsusPlatformFingerprint.from_sources(
            local={
                "manufacturer": "ASUSTeK COMPUTER INC.",
                "product_name": "RS700-E12-RS12U",
                "board_name": "Z14PP-D32",
                "system_serial": "SYS-1",
                "board_serial": "BOARD-1",
            },
            redfish={"manager": {"Model": "ASMB12-iKVM"}},
        )
        self.digest = hashlib.sha256(b"firmware").hexdigest()

    def _metadata(self, *, model="RS700-E12-RS12U", version="2.0", status="CHECKSUM_VERIFIED"):
        return FirmwarePackageMetadata(
            vendor="ASUS",
            component="BMC",
            version=version,
            package_filename="asus.zip",
            sha256=self.digest,
            source="ASUS_OFFICIAL_SERVER_FIRMWARE_CATALOG",
            source_url="https://dlcdnets.asus.com/pub/ASUS/server/asus.zip",
            compatible_models=(model,),
            compatible_boards=("Z14PP-D32",),
            compatible_bmc_generations=("ASMB12",),
            validation_status=status,
            official_source_verified=True,
            provenance_level="OFFICIAL_SOURCE_EXACT_PLATFORM",
            package_signature_status="NOT_PUBLISHED",
            package_metadata_evidence=("archive_members=README.txt",),
            applicability_evidence=("official ASUS compatibility row",),
        )

    @staticmethod
    def _handoff_package_alias(*, sha256="a" * 64):
        """Exact current-plan alias consumed by the handoff continuity reader."""
        return {
            "component": "BMC",
            "target_version": "1.2.37",
            "package_sha256": sha256,
            "package_filename": "ASMB11_FW1237_RS500A-E12-RS12U.zip",
            "source_url": "https://dlcdnets.asus.com/pub/ASUS/server/RS500A-E12-RS12U/BMC/ASMB11_FW1237_RS500A-E12-RS12U.zip",
            "compatible_models": ("RS500A-E12-RS12U",),
            "compatible_boards": ("K14PA-U24",),
            "compatible_bmc_generations": ("ASMB11",),
            "alias_strength": "PINNED_PACKAGE_SHA256",
        }

    def test_post_recovery_inventory_uses_kcs_ip_and_exact_generation_when_collector_is_empty(self):
        merged = _merge_post_recovery_inventory(
            {"system_serial": "RAS0MD0000HT", "bmc_ip": ""},
            recovery={
                "bmc_ip_after": "172.16.50.199",
                "status": "RECOVERED",
                "bmc_endpoint_status": "DISCOVERED",
                "bmc_endpoint_source": "LOCAL_KCS_IPMI_LAN",
            },
            firmware={
                "generic_asus_firmware_engine": {
                    "platform": {"bmc_generation": "ASMB11"}
                }
            },
        )
        self.assertEqual("172.16.50.199", merged["bmc_ip"])
        self.assertEqual("ASMB11", merged["bmc_generation"])
        self.assertEqual("LOCAL_KCS_IPMI_LAN", merged["bmc_ip_evidence"]["source"])
        self.assertEqual("ASUS_EXACT_FIRMWARE_PLATFORM_DESCRIPTOR", merged["bmc_generation_evidence"]["source"])

    def test_verified_post_recovery_endpoint_replaces_pre_reset_inventory_ip(self):
        merged = _merge_post_recovery_inventory(
            {"bmc_ip": "172.16.50.210", "bmc_generation": "ASMB12"},
            recovery={"bmc_ip_after": "172.16.50.199", "bmc_endpoint_status": "DISCOVERED"},
            firmware={"generic_asus_firmware_engine": {"platform": {"bmc_generation": "ASMB11"}}},
        )
        self.assertEqual("172.16.50.199", merged["bmc_ip"])
        self.assertEqual("172.16.50.210", merged["bmc_ip_before_reset"])
        self.assertEqual("ASMB12", merged["bmc_generation"])

    def test_unverified_post_recovery_endpoint_never_replaces_inventory_ip(self):
        merged = _merge_post_recovery_inventory(
            {"bmc_ip": "172.16.50.210"},
            recovery={"bmc_ip_after": "172.16.50.199", "bmc_endpoint_status": "UNAVAILABLE"},
            firmware={},
        )
        self.assertEqual("172.16.50.210", merged["bmc_ip"])

    def test_post_recovery_inventory_preserves_verified_bmc_firmware_evidence(self):
        merged = _merge_post_recovery_inventory(
            {
                "bmc_firmware": "1.01",
                "components": [
                    {"category": "MANAGEMENT_MODULE", "firmware": "1.01"},
                    {"category": "FIRMWARE", "slot": "BMC", "version": "1.01"},
                    {"category": "FIRMWARE", "slot": "BIOS", "version": "1201"},
                ],
            },
            recovery={"firmware_after": "1.02", "kcs_after": "PASS"},
            firmware={},
        )

        self.assertEqual("1.02", merged["bmc_firmware"])
        self.assertEqual(
            "ASUS_KCS_RECOVERY_POST_RESET_MC_INFO",
            merged["bmc_firmware_evidence"]["source"],
        )
        management = merged["components"][0]
        bmc_firmware = merged["components"][1]
        bios_firmware = merged["components"][2]
        self.assertEqual("1.02", management["firmware"])
        self.assertEqual("1.02", management["version"])
        self.assertEqual("1.02", bmc_firmware["firmware"])
        self.assertEqual("1.02", bmc_firmware["version"])
        self.assertEqual(
            "ASUS_KCS_RECOVERY_POST_RESET_MC_INFO",
            bmc_firmware["field_evidence"]["firmware"]["source"],
        )
        self.assertEqual("1201", bios_firmware["version"])

    def test_unverified_post_recovery_bmc_firmware_never_replaces_inventory_value(self):
        merged = _merge_post_recovery_inventory(
            {"bmc_firmware": "1.01"},
            recovery={"firmware_after": "1.02", "kcs_after": "FAIL"},
            firmware={},
        )
        self.assertEqual("1.01", merged["bmc_firmware"])

    def test_same_server_factory_handoff_binds_short_kcs_revision_to_exact_target(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            run = root / "results" / "runs" / "RUN-UNIT-HANDOFF"
            run.mkdir(parents=True)
            (run / "run.json").write_text(
                json.dumps(
                    {
                        "server": {
                            "server_id": "SERVER-RS500A-UNIT",
                            "system_serial": "RAS0MD0000HT",
                            "model": "RS500A-E12-RS12U",
                            "board_serial": "BOARD-UNIT",
                        }
                    }
                ),
                encoding="utf-8",
            )
            (run / "normalized-inventory.json").write_text(
                json.dumps(
                    {
                        "server_id": "SERVER-RS500A-UNIT",
                        "system_serial": "RAS0MD0000HT",
                        "model": "RS500A-E12-RS12U",
                        "board_serial": "BOARD-UNIT",
                    }
                ),
                encoding="utf-8",
            )
            (run / "firmware-plan.json").write_text(
                json.dumps(
                    {
                        "components": [
                            {
                                "component": "BMC",
                                "before": "1.02.37",
                                "target": "1.2.37",
                                "status": "CURRENT",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (run / "bmc-handoff.json").write_text(
                json.dumps(
                    {
                        "status": "PASS",
                        "default_state": "FACTORY_DEFAULT_FIRST_LOGIN",
                        "firmware_after": "1.02",
                    }
                ),
                encoding="utf-8",
            )
            workflow = ProductionWorkflow(
                ProductionConfig(primary_root=root / "results"), runtime_version="unit"
            )
            evidence = workflow._load_same_server_bmc_handoff_continuity(
                normalized_inventory={
                    "server_id": "SERVER-RS500A-UNIT",
                    "system_serial": "RAS0MD0000HT",
                    "model": "RS500A-E12-RS12U",
                    "board_serial": "BOARD-UNIT",
                },
                live_kcs_version="1.02",
                exact_target="1.2.37",
                exact_package_alias=self._handoff_package_alias(),
            )
            self.assertTrue(evidence["verified"], evidence)
            self.assertEqual("1.2.37", evidence["exact_version"])
            self.assertEqual("BOARD_SERIAL_MATCH", evidence["board_identity_binding"])
            self.assertEqual(
                "LEGACY_EXACT_TARGET_RECEIPT_CURRENT_PACKAGE_ALIAS_VERIFIED",
                evidence["package_identity_binding"],
            )

    def test_factory_handoff_continuity_rejects_other_server_or_target(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            run = root / "results" / "runs" / "RUN-UNIT-HANDOFF"
            run.mkdir(parents=True)
            (run / "run.json").write_text(
                json.dumps({"server": {"server_id": "SERVER-OTHER", "system_serial": "OTHER", "model": "RS500A-E12-RS12U", "board_serial": "OTHER-BOARD"}}),
                encoding="utf-8",
            )
            (run / "normalized-inventory.json").write_text(
                json.dumps({"server_id": "SERVER-OTHER", "system_serial": "OTHER", "model": "RS500A-E12-RS12U", "board_serial": "OTHER-BOARD"}),
                encoding="utf-8",
            )
            (run / "firmware-plan.json").write_text(
                json.dumps({"components": [{"component": "BMC", "before": "1.02.37", "target": "1.2.37", "status": "CURRENT"}]}),
                encoding="utf-8",
            )
            (run / "bmc-handoff.json").write_text(
                json.dumps({"status": "PASS", "default_state": "FACTORY_DEFAULT_FIRST_LOGIN", "firmware_after": "1.02"}),
                encoding="utf-8",
            )
            workflow = ProductionWorkflow(
                ProductionConfig(primary_root=root / "results"), runtime_version="unit"
            )
            evidence = workflow._load_same_server_bmc_handoff_continuity(
                normalized_inventory={
                    "server_id": "SERVER-RS500A-UNIT",
                    "system_serial": "RAS0MD0000HT",
                    "model": "RS500A-E12-RS12U",
                    "board_serial": "BOARD-UNIT",
                },
                live_kcs_version="1.02",
                exact_target="1.2.37",
                exact_package_alias=self._handoff_package_alias(),
            )
            self.assertFalse(evidence["verified"], evidence)

    def test_factory_handoff_continuity_reads_board_serial_from_motherboard_component(self):
        """Normalized inventory does not duplicate board_serial at top level."""
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            run = root / "results" / "runs" / "RUN-COMPONENT-BOARD"
            run.mkdir(parents=True)
            server_id = "SERVER-" + "a" * 64
            (run / "run.json").write_text(
                json.dumps(
                    {
                        "server": {
                            "server_id": server_id,
                            "system_serial": "RAS0MD0000HT",
                            "model": "RS500A-E12-RS12U",
                            "board_serial": "BOARD-COMPONENT",
                            "fingerprint_sha256": "a" * 64,
                        },
                        "run": {"server_fingerprint_sha256": "a" * 64},
                    }
                ),
                encoding="utf-8",
            )
            (run / "normalized-inventory.json").write_text(
                json.dumps(
                    {
                        "server_id": server_id,
                        "system_serial": "RAS0MD0000HT",
                        "model": "RS500A-E12-RS12U",
                        "components": [
                            {"category": "MOTHERBOARD", "serial": "BOARD-COMPONENT"}
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (run / "firmware-plan.json").write_text(
                json.dumps(
                    {
                        "components": [
                            {
                                "component": "BMC",
                                "before": "1.02.37",
                                "target": "1.2.37",
                                "status": "CURRENT",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (run / "bmc-handoff.json").write_text(
                json.dumps(
                    {
                        "status": "PASS",
                        "default_state": "FACTORY_DEFAULT_FIRST_LOGIN",
                        "firmware_after": "1.02",
                    }
                ),
                encoding="utf-8",
            )
            workflow = ProductionWorkflow(
                ProductionConfig(primary_root=root / "results"), runtime_version="unit"
            )
            evidence = workflow._load_same_server_bmc_handoff_continuity(
                normalized_inventory={
                    "server_id": server_id,
                    "system_serial": "RAS0MD0000HT",
                    "model": "RS500A-E12-RS12U",
                    # This is the current, schema-realistic representation:
                    # no top-level board_serial exists.
                    "components": [
                        {"category": "MOTHERBOARD", "serial": "BOARD-COMPONENT"}
                    ],
                },
                live_kcs_version="1.02",
                exact_target="1.2.37",
                exact_package_alias=self._handoff_package_alias(),
            )
            self.assertTrue(evidence["verified"], evidence)
            self.assertEqual("BOARD_SERIAL_MATCH", evidence["board_identity_binding"])

    def test_factory_handoff_continuity_rejects_different_pinned_package_alias(self):
        """Same version cannot bind a new/re-published BMC image by accident."""
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            run = root / "results" / "runs" / "RUN-PACKAGE-ALIAS"
            run.mkdir(parents=True)
            (run / "run.json").write_text(
                json.dumps(
                    {
                        "server": {
                            "server_id": "SERVER-RS500A-UNIT",
                            "system_serial": "RAS0MD0000HT",
                            "model": "RS500A-E12-RS12U",
                            "board_serial": "BOARD-UNIT",
                        }
                    }
                ),
                encoding="utf-8",
            )
            (run / "normalized-inventory.json").write_text(
                json.dumps(
                    {
                        "server_id": "SERVER-RS500A-UNIT",
                        "system_serial": "RAS0MD0000HT",
                        "model": "RS500A-E12-RS12U",
                        "components": [{"category": "MOTHERBOARD", "serial": "BOARD-UNIT"}],
                    }
                ),
                encoding="utf-8",
            )
            prior_metadata = self._handoff_package_alias(sha256="b" * 64) | {
                "vendor": "ASUS",
                "version": "1.2.37",
                "validation_status": "CHECKSUM_VERIFIED",
                "official_source_verified": True,
                "applicability_evidence": ["official ASUS compatibility row"],
            }
            (run / "firmware-plan.json").write_text(
                json.dumps(
                    {
                        "generic_asus_firmware_engine": {
                            "components": {
                                "BMC": {
                                    "current_version": "1.02.37",
                                    "target_version": "1.2.37",
                                    "status": "CURRENT",
                                    "selected_package": {
                                        "match": {"exact_match": True},
                                        "metadata": prior_metadata,
                                    },
                                }
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            (run / "bmc-handoff.json").write_text(
                json.dumps(
                    {
                        "status": "PASS",
                        "default_state": "FACTORY_DEFAULT_FIRST_LOGIN",
                        "firmware_after": "1.02",
                    }
                ),
                encoding="utf-8",
            )
            workflow = ProductionWorkflow(
                ProductionConfig(primary_root=root / "results"), runtime_version="unit"
            )
            evidence = workflow._load_same_server_bmc_handoff_continuity(
                normalized_inventory={
                    "server_id": "SERVER-RS500A-UNIT",
                    "system_serial": "RAS0MD0000HT",
                    "model": "RS500A-E12-RS12U",
                    "components": [{"category": "MOTHERBOARD", "serial": "BOARD-UNIT"}],
                },
                live_kcs_version="1.02",
                exact_target="1.2.37",
                exact_package_alias=self._handoff_package_alias(sha256="a" * 64),
            )
            self.assertFalse(evidence["verified"], evidence)

    def test_platform_fingerprint_keeps_exact_model_and_bmc_generation(self):
        self.assertEqual("RS700-E12-RS12U", self.fingerprint.model)
        self.assertEqual("Z14PP-D32", self.fingerprint.board)
        self.assertEqual("ASMB12", self.fingerprint.bmc_generation)

    def test_official_catalog_filename_version_fallback_ignores_model_numbers(self):
        source = AsusOfficialCatalogSource(timeout_seconds=1)
        self.assertEqual("0903", source._version_from_filename("Z14PP-D32-ASUS-0903.zip"))
        self.assertEqual("1.32.00", source._version_from_filename("ASMB12_FW1.32.00_RS700-E12.zip"))
        self.assertEqual("", source._version_from_filename("RS700-E12-RS12U-support.zip"))

    def test_product_v2_api_requires_exact_model_and_extracts_asmb_generation(self):
        class Source(AsusOfficialCatalogSource):
            def _request(self, url, **kwargs):
                return json.dumps(
                    {
                        "Result": {
                            "Model": "RS500A-E12-RS12U",
                            "Obj": [
                                {"Name": "BIOS", "Files": [{"Version": "2306", "DownloadUrl": {"Global": "/pub/ASUS/server/RS500A-E12-RS4U/BIOS/K14PA-U24-ASUS-2306.zip"}, "sha256": "a" * 64}]},
                                {"Name": "Firmware", "Files": [{"Version": "1.2.37", "DownloadUrl": {"Global": "/pub/ASUS/server/RS500A-E12-RS12U/BMC/ASMB11_FW1237_RS500A-E12-RS12U.zip"}, "sha256": "b" * 64}]},
                            ],
                        }
                    }
                ).encode()
        source = Source(timeout_seconds=1)
        fingerprint = AsusPlatformFingerprint(model="RS500A-E12-RS12U", board="K14PA-U24")
        result = source._discover_product_firmware_api(fingerprint)
        self.assertEqual("EXACT_ENTRIES_FOUND", result["status"])
        self.assertEqual({"BIOS", "BMC"}, {item["component"] for item in result["entries"]})
        bmc = next(item for item in result["entries"] if item["component"] == "BMC")
        self.assertEqual("ASMB11", bmc["compatible_bmc_generations"][0])
        self.assertTrue(bmc["source_url"].startswith("https://dlcdnets.asus.com/"))

    def test_asmb11_kcs_descriptor_is_selected_without_bmc_auth_when_local_kcs_is_current(self):
        discovery = discover_asus_transports(
            redfish_discovery={"authentication": {"available": False}},
            local_tools={"kcs": {"available": True, "status": "PASS", "source": "IPMI_MC_LOCAL_KCS"}},
            fingerprint=AsusPlatformFingerprint(model="RS500A-E12-RS12U", bmc_generation="ASMB11"),
        )
        selected = discovery["components"]["BMC"]["selected"]
        self.assertIsNotNone(selected)
        self.assertEqual("ASUS_ASMB11_KCS_YAFUFLASH", selected["name"])
        self.assertFalse(selected["requires_authenticated_bmc"])
        self.assertEqual("ASUS_ASMB_LINUX_OFFICIAL", discovery["components"]["BMC"]["candidates"][1]["name"])
        self.assertFalse(discovery["components"]["BMC"]["candidates"][1]["selectable"])

    def test_asmb_linux_adapter_validates_package_and_keeps_credentials_out_of_task(self):
        image = b"asmb-image-bytes"
        updater = bytearray(32)
        updater[:4] = b"\x7fELF"
        updater[4] = 2
        updater[5] = 1
        updater[18:20] = (0x3E).to_bytes(2, "little")
        descriptor = AsusTransportDescriptor(
            name="ASUS_ASMB_LINUX_OFFICIAL", source="fixture", target="builtin://asus-asmb-linux-yafuflash",
            components=("BMC",), requires_authenticated_bmc=True, package_delivery="ASUS_ASMB_LINUX_ZIP",
            selectable=True, local_timeout_seconds=60,
        )
        metadata = self._metadata(version="1.2.37").to_dict() | {"package_filename": "ASMB11.zip"}
        with tempfile.TemporaryDirectory() as folder:
            package = Path(folder) / "ASMB11.zip"
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("Linux/Yafuflash", bytes(updater))
                archive.writestr("Image/firmware.ima", image)
                archive.writestr("Image/firmware.md5", hashlib.md5(image).hexdigest() + "  firmware.ima\n")
            adapter = AsusAsmbLinuxBmcFirmwareAdapter(
                descriptor, username="admin", password="runtime-only", version_reader=lambda _: "1.2.37",
                interface_resolver=lambda: "enxfixture", sleep_fn=lambda _seconds: None,
            )
            preview = adapter.preview(package, FirmwarePackageMetadata.from_dict(metadata))
            self.assertTrue(preview.accepted)
            self.assertNotIn("runtime-only", json.dumps(preview.evidence))

    def test_asmb11_kcs_adapter_uses_package_owned_credential_free_command_after_read_only_preflight(self):
        image = b"ASMB11 image 1.2.370000"
        updater = bytearray(32)
        updater[:4] = b"\x7fELF"
        updater[4] = 2
        updater[5] = 1
        updater[18:20] = (0x3E).to_bytes(2, "little")
        metadata = FirmwarePackageMetadata.from_dict(
            self._metadata(model="RS500A-E12-RS12U", version="1.2.37").to_dict()
            | {
                "package_filename": "ASMB11_FW1237_RS500A-E12-RS12U.zip",
                "compatible_boards": ["K14PA-U24"],
                "compatible_bmc_generations": ["ASMB11"],
            }
        )
        descriptor = AsusTransportDescriptor(
            name="ASUS_ASMB11_KCS_YAFUFLASH",
            source="fixture",
            target="builtin://asus-asmb11-yafuflash-kcs",
            components=("BMC",),
            requires_authenticated_bmc=False,
            package_delivery="ASUS_ASMB_LINUX_ZIP",
            selectable=True,
            local_timeout_seconds=60,
        )
        info_calls: list[list[str]] = []
        mutation_calls: list[list[str]] = []
        updated = {"value": False}

        def yafu_output(version: str) -> str:
            return (
                "Firmware Details\n"
                "ModuleName   Description   Version          Version\n"
                f"10. ast2600e                 {version}      {version}\n"
            )

        def info_runner(argv: list[str], _timeout: int) -> tuple[int, str]:
            info_calls.append(list(argv))
            return 0, yafu_output("1.2.370000" if updated["value"] else "1.1.000000")

        def mutation_runner(argv: list[str], _timeout: int) -> int:
            mutation_calls.append(list(argv))
            updated["value"] = True
            return 0

        with tempfile.TemporaryDirectory() as folder:
            package = Path(folder) / metadata.package_filename
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("Linux/Yafuflash", bytes(updater))
                archive.writestr("Image/firmware.ima", image)
                archive.writestr("Image/firmware.md5", hashlib.md5(image).hexdigest() + "  firmware.ima\n")
            adapter = AsusAsmb11KcsBmcFirmwareAdapter(
                descriptor,
                fingerprint=AsusPlatformFingerprint(
                    vendor="ASUS", model="RS500A-E12-RS12U", board="K14PA-U24", bmc_generation="ASMB11"
                ),
                version_reader=lambda _component: "1.01",
                kcs_probe=lambda: {"available": True, "status": "PASS"},
                info_runner=info_runner,
                command_runner=mutation_runner,
                sleep_fn=lambda _seconds: None,
                version_wait_seconds=5,
            )
            preview = adapter.preview(package, metadata)
            self.assertTrue(preview.accepted, preview.evidence)
            self.assertFalse(mutation_calls, "-info preflight must not flash")
            task = adapter.start(package, metadata)

        self.assertEqual(UpdateTaskState.COMPLETED, task.state)
        self.assertEqual("1.2.37", adapter.read_installed_version("BMC"))
        self.assertTrue(any("-info" in argv for argv in info_calls))
        self.assertEqual(1, len(mutation_calls))
        self.assertIn("-kcs", mutation_calls[0])
        self.assertIn("-preserve-config", mutation_calls[0])
        self.assertIn("-ignore-same-image", mutation_calls[0])
        all_argv = " ".join(" ".join(argv) for argv in [*info_calls, *mutation_calls])
        for prohibited in ("-U", "-P", "admin", "secret", "169.254.0.17"):
            self.assertNotIn(prohibited, all_argv)

    def test_asmb11_kcs_adapter_rejects_wrong_exact_platform_before_kcs_probe(self):
        image = b"ASMB11 image 1.2.370000"
        updater = bytearray(32)
        updater[:4] = b"\x7fELF"
        updater[4] = 2
        updater[5] = 1
        updater[18:20] = (0x3E).to_bytes(2, "little")
        metadata = FirmwarePackageMetadata.from_dict(
            self._metadata(model="RS700A-E12-RS12U", version="1.2.37").to_dict()
            | {
                "package_filename": "wrong-platform-asmb11.zip",
                "compatible_boards": ["K14PA-U24"],
                "compatible_bmc_generations": ["ASMB11"],
            }
        )
        descriptor = AsusTransportDescriptor(
            name="ASUS_ASMB11_KCS_YAFUFLASH",
            source="fixture",
            components=("BMC",),
            requires_authenticated_bmc=False,
            package_delivery="ASUS_ASMB_LINUX_ZIP",
            selectable=True,
        )
        info_calls: list[list[str]] = []
        with tempfile.TemporaryDirectory() as folder:
            package = Path(folder) / metadata.package_filename
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("Linux/Yafuflash", bytes(updater))
                archive.writestr("Image/firmware.ima", image)
                archive.writestr("Image/firmware.md5", hashlib.md5(image).hexdigest() + "  firmware.ima\n")
            adapter = AsusAsmb11KcsBmcFirmwareAdapter(
                descriptor,
                fingerprint=AsusPlatformFingerprint(
                    vendor="ASUS", model="RS500A-E12-RS12U", board="K14PA-U24", bmc_generation="ASMB11"
                ),
                version_reader=lambda _component: "1.01",
                kcs_probe=lambda: {"available": True, "status": "PASS"},
                info_runner=lambda argv, _timeout: (info_calls.append(list(argv)) or (0, "")),
            )
            preview = adapter.preview(package, metadata)
        self.assertFalse(preview.accepted)
        self.assertEqual("ASUS_ASMB11_KCS_EXACT_PLATFORM_REQUIRED", preview.evidence["reason"])
        self.assertFalse(info_calls, "wrong platform must fail before a KCS/YAFU probe")

    def test_asmb_linux_runner_answers_vendor_confirmation_without_capture(self):
        with mock.patch("cnserverops.asus_firmware_transport.subprocess.run") as run:
            run.return_value.returncode = 0
            self.assertEqual(
                0,
                AsusAsmbLinuxBmcFirmwareAdapter._run_command(["/tmp/Yafuflash"], 30),
            )
            kwargs = run.call_args.kwargs
            self.assertEqual(b"Y\n", kwargs.get("input"))
            self.assertNotIn("stdin", kwargs)
            self.assertIs(kwargs.get("stdout"), subprocess.DEVNULL)
            self.assertIs(kwargs.get("stderr"), subprocess.DEVNULL)

    def test_asmb_image_version_alias_is_bound_to_official_target(self):
        image = (b"old 1.01.000000 " + b"x" * 1000 + b"new 1.02.37 " + b"x" * 1000)
        aliases = AsusAsmbLinuxBmcFirmwareAdapter._reported_version_aliases(image, "1.2.37")
        self.assertEqual(("1.02.37",), aliases)
        self.assertEqual((), AsusAsmbLinuxBmcFirmwareAdapter._reported_version_aliases(image, "2.2.37"))

    def test_asmb11_two_part_preupdate_revision_is_not_a_target_alias(self):
        image = b"ASMB11 image reports 1.02 before activation and 1.02.37 after activation"
        aliases = AsusAsmbLinuxBmcFirmwareAdapter._reported_version_aliases(image, "1.2.37")
        self.assertNotIn("1.02", aliases)
        self.assertIn("1.02.37", aliases)

    def test_asmb11_yafu_info_uses_exact_existing_image_not_short_ipmi_revision(self):
        output = (
            "Firmware Details\\n"
            "ModuleName   Description   Version          Version\\n"
            "10. ast2600e                 1.2.370000      1.2.370000\\n"
        )
        self.assertEqual("1.2.370000", AsusAsmbLinuxBmcFirmwareAdapter._parse_yafu_existing_version(output))
        self.assertEqual((1, 2), AsusAsmbLinuxBmcFirmwareAdapter._version_tuple("1.02"))
        self.assertEqual((1, 2, 37), AsusAsmbLinuxBmcFirmwareAdapter._version_tuple("1.2.370000")[:3])

    def test_similarly_named_model_is_rejected(self):
        decision = match_asus_package(self._metadata(model="RS700A-E12-RS12U"), self.fingerprint)
        self.assertFalse(decision.exact_match)
        self.assertIn("EXACT_MODEL_MISMATCH", decision.reason_codes)

    def test_family_only_package_is_rejected(self):
        metadata = FirmwarePackageMetadata(
            vendor="ASUS",
            component="BIOS",
            version="2.0",
            package_filename="asus.bin",
            sha256=self.digest,
            source="ASUS",
            source_url="https://dlcdnets.asus.com/pub/ASUS/server/asus.bin",
            compatible_families=("E12",),
            validation_status="CHECKSUM_VERIFIED",
        )
        decision = match_asus_package(metadata, self.fingerprint)
        self.assertFalse(decision.exact_match)
        self.assertIn("EXACT_PLATFORM_APPLICABILITY_MISSING", decision.reason_codes)

    def test_transport_selection_prefers_multipart_and_requires_auth_and_tasks(self):
        discovery = discover_asus_transports(
            redfish_discovery={
                "authentication": {"available": True},
                "normalized": {
                    "update_mechanisms": [
                        {"kind": "#UpdateService.SimpleUpdate", "target": "/simple"},
                        {"kind": "MultipartHttpPushUri", "target": "/upload"},
                    ]
                },
                "endpoint_catalog": [{"label": "task_service", "status": 200}],
            }
        )
        selected = discovery["components"]["BMC"]["selected"]
        self.assertEqual("REDFISH_MULTIPART_PUSH", selected["name"])
        self.assertTrue(selected["task_tracking"])

    def test_asmb11_kcs_transport_precedes_generic_redfish_when_local_kcs_is_current(self):
        discovery = discover_asus_transports(
            redfish_discovery={
                "authentication": {"available": True},
                "normalized": {
                    "update_mechanisms": [
                        {"kind": "MultipartHttpPushUri", "target": "/upload"},
                    ]
                },
                "endpoint_catalog": [{"label": "task_service", "status": 200}],
            },
            fingerprint=AsusPlatformFingerprint(
                model="RS500A-E12-RS12U", bmc_generation="ASMB11"
            ),
            local_tools={"kcs": {"available": True, "status": "PASS"}},
        )
        selected = discovery["components"]["BMC"]["selected"]
        self.assertEqual("ASUS_ASMB11_KCS_YAFUFLASH", selected["name"])
        self.assertEqual("ASUS_ASMB_LINUX_ZIP", selected["package_delivery"])
        self.assertFalse(selected["requires_authenticated_bmc"])

    def test_asmb_web_hpm_descriptor_is_selected_only_from_live_capability(self):
        discovery = discover_asus_transports(
            redfish_discovery={
                "authentication": {"available": True},
                "web_hpm": {
                    "supported": True,
                    "components": ["BIOS"],
                    "component_ids": {"BIOS": 4},
                    "image_types": {"BIOS": 42},
                    "endpoint_prefix": "/api/maintenance/hpm",
                },
            }
        )
        selected = discovery["components"]["BIOS"]["selected"]
        self.assertEqual("ASUS_ASMB_WEB_HPM", selected["name"])
        self.assertEqual("ASUS_HPM_WRAPPED_IMAGE", selected["package_delivery"])

    def test_cap_package_skips_higher_ranked_web_hpm_and_selects_bios_oob(self):
        discovery = discover_asus_transports(
            redfish_discovery={
                "authentication": {"available": True},
                "web_hpm": {
                    "supported": True,
                    "components": ["BIOS"],
                    "component_ids": {"BIOS": 4},
                    "image_types": {"BIOS": 42},
                    "endpoint_prefix": "/api/maintenance/hpm",
                },
                "normalized": {
                    "update_mechanisms": [
                        {
                            "kind": "#UpdateService.BIOSFwUpdate",
                            "target": "/redfish/v1/UpdateService/Actions/Oem/UpdateService.BIOSFwUpdate",
                        },
                    ],
                },
            }
        )
        self.assertEqual("ASUS_ASMB_WEB_HPM", discovery["components"]["BIOS"]["selected"]["name"])
        metadata = FirmwarePackageMetadata(
            **(
                self._metadata(version="2306").to_dict()
                | {
                    "component": "BIOS",
                    "package_filename": "K14PA-U24-ASUS-2306.zip",
                }
            )
        )
        with tempfile.TemporaryDirectory() as folder:
            package = Path(folder) / "verified-object"
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
        self.assertIn("cap", selected["package_payload_capabilities"])
        self.assertNotIn("hpm_wrapped", selected["package_payload_capabilities"])

    def test_valid_hpm_package_keeps_higher_ranked_web_hpm_transport(self):
        discovery = discover_asus_transports(
            redfish_discovery={
                "authentication": {"available": True},
                "web_hpm": {
                    "supported": True,
                    "components": ["BIOS"],
                    "component_ids": {"BIOS": 4},
                    "image_types": {"BIOS": 42},
                    "endpoint_prefix": "/api/maintenance/hpm",
                },
                "normalized": {
                    "update_mechanisms": [
                        {
                            "kind": "#UpdateService.BIOSFwUpdate",
                            "target": "/redfish/v1/UpdateService/Actions/Oem/UpdateService.BIOSFwUpdate",
                        },
                    ],
                },
            }
        )
        raw = bytearray(240)
        raw[:8] = b"PICMGFWU"
        raw[36] = 0x10
        raw[65:69] = (171).to_bytes(4, "little")
        raw[73:77] = (83).to_bytes(4, "little")
        raw[110:112] = (42).to_bytes(2, "little")
        metadata = FirmwarePackageMetadata(
            **(
                self._metadata(version="0903").to_dict()
                | {"component": "BIOS", "package_filename": "Z14PP-D32-ASUS-0903.zip"}
            )
        )
        with tempfile.TemporaryDirectory() as folder:
            package = Path(folder) / "verified-object"
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("Z14PP-D32-ASUS-0903.HPM", raw)
            selected = select_asus_transport_for_package(
                discovery,
                component="BIOS",
                package=package,
                metadata=metadata,
            )
        self.assertIsNotNone(selected)
        self.assertEqual("ASUS_ASMB_WEB_HPM", selected["name"])
        self.assertIn("hpm_wrapped", selected["package_payload_capabilities"])

    def test_real_asus_hpm_header_is_parsed_without_execution(self):
        package = Path("C:/Users/TechTrade Operations/Desktop/PhotoIntelligence_Portable/tmp/Z14PP-D32-ASUS-0903.HPM")
        if not package.exists():
            self.skipTest("local ASUS HPM fixture unavailable")
        parsed = parse_asus_hpm_image(package.read_bytes())
        self.assertEqual(4, parsed.component_id)
        self.assertEqual(42, parsed.image_type)
        self.assertEqual(83, parsed.section_flash)
        self.assertEqual("Z14PPD32", parsed.name)
        self.assertEqual("0903", parsed.version)
        self.assertEqual((9, 3), (parsed.version_major, parsed.version_minor))

    def test_asmb_web_hpm_staged_lifecycle_marks_reboot_required(self):
        class Session:
            def __init__(self):
                self.calls = []
            def post_empty(self, path):
                self.calls.append(("POST_EMPTY", path))
                return type("R", (), {"status": 200, "payload": {}})()
            def post_json(self, path, payload):
                self.calls.append(("POST", path, dict(payload)))
                return type("R", (), {"status": 200, "payload": {}})()
            def put_json(self, path, payload):
                self.calls.append(("PUT", path, dict(payload)))
                return type("R", (), {"status": 200, "payload": {"unique_id": "u1"} if path.endswith("updatemode") else {}})()
            def post_multipart(self, path, field, filename, payload):
                self.calls.append(("UPLOAD", path, field, filename, len(payload)))
                return type("R", (), {"status": 200, "payload": {}})()
        raw = bytearray(240)
        raw[:8] = b"PICMGFWU"
        raw[36] = 0x10
        raw[65:69] = (171).to_bytes(4, "little")
        raw[73:77] = (83).to_bytes(4, "little")
        raw[44:52] = b"Z14PPD32"
        raw[110:112] = (42).to_bytes(2, "little")
        raw[112:117] = b"\x01 903"
        with tempfile.TemporaryDirectory() as folder:
            package = Path(folder) / "bios.hpm"
            package.write_bytes(raw)
            descriptor = AsusTransportDescriptor(
                name="ASUS_ASMB_WEB_HPM", source="fixture", target="/api/maintenance/hpm",
                components=("BIOS",), selectable=True, package_delivery="ASUS_HPM_WRAPPED_IMAGE",
                web_update_method="STAGED", web_component_ids={"BIOS": 4},
                web_component_image_types={"BIOS": 42}, web_endpoint_prefix="/api/maintenance/hpm",
            )
            session = Session()
            metadata = FirmwarePackageMetadata(**(self._metadata(version="0903").to_dict() | {"component": "BIOS", "package_filename": "bios.hpm"}))
            adapter = AsusAsmbWebHpmFirmwareAdapter(session, descriptor, version_reader=lambda _: "0603")
            started = adapter.start(package, metadata)
        self.assertEqual(UpdateTaskState.REBOOT_REQUIRED, started.state)
        self.assertTrue(started.detail.startswith("MUTATION_STARTED:"))
        self.assertEqual("/api/maintenance/oob/start-lmedia", session.calls[0][1])
        prepare = next(call for call in session.calls if call[1].endswith("preparecomponents"))
        self.assertEqual(1, prepare[2]["HPM_FLAG"])

    def test_transport_candidates_remain_nonselectable_without_authentication(self):
        discovery = discover_asus_transports(
            redfish_discovery={
                "authentication": {"available": False},
                "normalized": {"update_mechanisms": [{"kind": "MultipartHttpPushUri", "target": "/upload"}]},
                "endpoint_catalog": [{"label": "task_service", "status": 200}],
            }
        )
        self.assertIsNone(discovery["components"]["BIOS"]["selected"])
        self.assertEqual("REDFISH_MULTIPART_PUSH", discovery["components"]["BIOS"]["candidates"][0]["name"])

    def test_explicit_exact_local_tool_is_the_only_non_bmc_transport(self):
        tool = Path(sys.executable)
        candidate = {
            "path": str(tool),
            "sha256": hashlib.sha256(tool.read_bytes()).hexdigest(),
            "status": "APPROVED",
            "official_source_verified": True,
            "exact_platform_verified": True,
            "compatible_models": ["RS700-E12-RS12U"],
            "compatible_boards": ["Z14PP-D32"],
            "components": ["BIOS"],
            "command": ["-c", "import sys; open(sys.argv[1], 'rb').read()", "{package}"],
            "reboot_behavior": "NO_REBOOT",
        }
        discovery = discover_asus_transports(local_tools={"candidates": [candidate]})
        selected = discovery["components"]["BIOS"]["selected"]
        self.assertIsNotNone(selected)
        self.assertEqual("ASUS_LOCAL_OFFICIAL_UTILITY", selected["name"])
        self.assertFalse(selected["requires_authenticated_bmc"])
        self.assertEqual([], discovery["components"]["BMC"]["candidates"])

    def test_local_tool_config_is_exact_platform_and_hash_bound(self):
        tool = Path(sys.executable)
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "local-tools.json"
            config.write_text(
                json.dumps(
                    {
                        "tools": [
                            {
                                "path": str(tool),
                                "sha256": hashlib.sha256(tool.read_bytes()).hexdigest(),
                                "official_source_verified": True,
                                "compatible_models": ["RS700-E12-RS12U"],
                                "compatible_boards": ["Z14PP-D32"],
                                "components": ["BIOS"],
                                "command": ["-c", "import sys; open(sys.argv[1], 'rb').read()", "{package}"],
                                "reboot_behavior": "NO_REBOOT",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            found = _discover_local_asus_firmware_tools(config, fingerprint=self.fingerprint)
            mismatch = _discover_local_asus_firmware_tools(
                config,
                fingerprint=AsusPlatformFingerprint(model="RS700A-E12-RS12U", board="Z14PP-D32"),
            )
        self.assertEqual("APPROVED", found["configured_candidates"][0]["status"])
        self.assertEqual("CONFIG_INVALID", mismatch["configured_candidates"][0]["status"])

    def test_local_adapter_runs_only_pinned_executable_and_returns_terminal_task(self):
        tool = Path(sys.executable)
        descriptor = AsusTransportDescriptor(
            name="ASUS_LOCAL_OFFICIAL_UTILITY",
            source="fixture",
            target=str(tool),
            components=("BIOS",),
            requires_authenticated_bmc=False,
            package_delivery="LOCAL_PATH",
            reboot_behavior="NO_REBOOT",
            local_command=("-c", "import sys; open(sys.argv[1], 'rb').read()", "{package}"),
            local_tool_sha256=hashlib.sha256(tool.read_bytes()).hexdigest(),
            selectable=True,
        )
        metadata = FirmwarePackageMetadata.from_dict(
            self._metadata(version="0903").to_dict() | {"component": "BIOS", "package_filename": "bios.zip"}
        )
        with tempfile.TemporaryDirectory() as folder:
            package = Path(folder) / "bios.zip"
            package.write_bytes(b"firmware")
            adapter = AsusLocalFirmwareUtilityAdapter(descriptor, version_reader=lambda _component: "0903")
            preview = adapter.preview(package, metadata)
            self.assertTrue(preview.accepted)
            task = adapter.start(package, metadata)
            self.assertEqual(UpdateTaskState.COMPLETED, task.state)
            self.assertEqual(task, adapter.poll(task.task_id))

    def test_outdated_local_plan_does_not_require_bmc_auth(self):
        plan = {
            "components": [{"component": "BIOS", "status": "UPDATE_REQUIRED"}],
            "generic_asus_firmware_engine": {
                "components": {
                    "BIOS": {
                        "selected_transport": {
                            "name": "ASUS_LOCAL_OFFICIAL_UTILITY",
                            "requires_authenticated_bmc": False,
                        }
                    }
                }
            },
        }
        self.assertFalse(_firmware_requires_authenticated_bmc(plan))

    def test_asmb11_kcs_bmc_update_defers_bios_auth_until_after_bmc_is_current(self):
        base = {
            "generic_asus_firmware_engine": {
                "platform": {"bmc_generation": "ASMB11"},
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
            },
        }
        before_bmc_update = base | {
            "components": [
                {"component": "BMC", "status": "UPDATE_REQUIRED"},
                {"component": "BIOS", "status": "UPDATE_REQUIRED"},
            ]
        }
        self.assertFalse(_firmware_requires_authenticated_bmc(before_bmc_update))
        after_bmc_update = base | {
            "components": [
                {"component": "BMC", "status": "CURRENT"},
                {"component": "BIOS", "status": "UPDATE_REQUIRED"},
            ]
        }
        self.assertTrue(_firmware_requires_authenticated_bmc(after_bmc_update))

    def test_engine_chooses_latest_exact_vendor_validated_candidate(self):
        docs = [
            {
                "source": "fixture",
                "entries": [
                    {
                        **self._metadata(version="1.9").to_dict(),
                        "component": "BMC",
                    },
                    {
                        **self._metadata(version="2.0").to_dict(),
                        "component": "BMC",
                    },
                    {
                        **self._metadata(model="RS700A-E12-RS12U", version="9.9").to_dict(),
                        "component": "BMC",
                    },
                ],
            }
        ]
        plan = AsusFirmwareEngine().plan(
            fingerprint=self.fingerprint,
            current_versions={"BIOS": "1.0", "BMC": "1.0"},
            redfish_discovery={
                "authentication": {"available": True},
                "normalized": {"update_mechanisms": [{"kind": "MultipartHttpPushUri", "target": "/upload"}]},
                "endpoint_catalog": [{"label": "task_service", "status": 200}],
            },
            catalog_documents=docs,
        )
        component = plan.components["BMC"]
        self.assertEqual("READY_FOR_OPERATOR_CONFIRMATION", component["status"])
        self.assertEqual("2.0", component["target_version"])
        self.assertEqual("REDFISH_MULTIPART_PUSH", component["selected_transport"]["name"])

    def test_engine_carries_exact_official_provenance_candidate_to_download_phase(self):
        dynamic = self._metadata(version="2.5").to_dict() | {
            "sha256": "0" * 64,
            "validation_status": "PROVENANCE_VERIFIED",
            "provenance_level": "OFFICIAL_SOURCE_EXACT_PLATFORM",
            "package_metadata_evidence": (),
        }
        plan = AsusFirmwareEngine().plan(
            fingerprint=self.fingerprint,
            current_versions={"BIOS": "1.0", "BMC": "1.0"},
            catalog_documents=[{"source": "live-official", "entries": [dynamic]}],
        ).to_dict()
        component = plan["components"]["BMC"]
        self.assertEqual("2.5", component["target_version"])
        self.assertEqual("NO_SUPPORTED_TRANSPORT", component["status"])
        self.assertTrue(component["selected_package"]["match"]["exact_match"])

    def test_dynamic_provenance_candidate_is_own_hashed_before_executor_use(self):
        dynamic = self._metadata(version="2.5").to_dict() | {
            "sha256": "0" * 64,
            "validation_status": "PROVENANCE_VERIFIED",
            "provenance_level": "OFFICIAL_SOURCE_EXACT_PLATFORM",
            "package_metadata_evidence": (),
        }
        plan = AsusFirmwareEngine().plan(
            fingerprint=self.fingerprint,
            current_versions={"BIOS": "1.0", "BMC": "1.0"},
            catalog_documents=[{"source": "live-official", "entries": [dynamic]}],
        )
        class Downloader:
            def download(self, source_url, destination):
                destination.write_bytes(b"dynamic-firmware")
        with tempfile.TemporaryDirectory() as folder:
            prepared = AsusFirmwareEngine.prepare_plan_packages(
                plan,
                repository=FirmwareRepository(Path(folder) / "repo"),
                downloader=Downloader(),
                components=("BMC",),
            )
        self.assertEqual("PACKAGE_READY", prepared["BMC"]["status"])
        self.assertEqual(hashlib.sha256(b"dynamic-firmware").hexdigest(), prepared["BMC"]["sha256"])
        self.assertEqual(prepared["BMC"]["sha256"], prepared["BMC"]["metadata"]["sha256"])

    def test_package_fetch_pins_own_hash_without_vendor_hash_and_reuses_verified_cache(self):
        class Downloader:
            def download(self, source_url, destination):
                destination.write_bytes(b"firmware")

        metadata = self._metadata(status="CHECKSUM_VERIFIED_WITHOUT_VENDOR_HASH")
        with tempfile.TemporaryDirectory() as folder:
            repository = FirmwareRepository(Path(folder) / "repo")
            path, status = AsusFirmwareEngine.fetch_verified_package(
                metadata, repository=repository, downloader=Downloader()
            )
            self.assertEqual("DOWNLOADED_AND_CHECKSUM_VERIFIED", status)
            self.assertEqual(self.digest, path.name)
            class Never:
                def download(self, source_url, destination):
                    raise AssertionError("verified cache should be reused")
            _, second = AsusFirmwareEngine.fetch_verified_package(
                metadata, repository=repository, downloader=Never()
            )
            self.assertEqual("CACHE_HIT_CHECKSUM_VERIFIED", second)

    def test_pinned_fetch_uses_package_source_not_support_page(self):
        class Downloader:
            def __init__(self):
                self.urls = []

            def download(self, source_url, destination):
                self.urls.append(source_url)
                destination.write_bytes(b"firmware")

        metadata = FirmwarePackageMetadata.from_dict(
            self._metadata(status="CHECKSUM_VERIFIED_WITHOUT_VENDOR_HASH").to_dict()
            | {
                "source_url": "https://dlcdnets.asus.com/pub/ASUS/server/exact.zip",
                "official_release_url": "https://www.asus.com/supportonly/exact/helpdesk_bios/",
            }
        )
        with tempfile.TemporaryDirectory() as folder:
            downloader = Downloader()
            AsusFirmwareEngine.fetch_verified_package(
                metadata,
                repository=FirmwareRepository(Path(folder) / "repo"),
                downloader=downloader,
            )
        self.assertEqual(["https://dlcdnets.asus.com/pub/ASUS/server/exact.zip"], downloader.urls)

    def test_package_fetch_rejects_weak_no_vendor_hash_provenance(self):
        class Downloader:
            def download(self, source_url, destination):
                destination.write_bytes(b"firmware")
        metadata = FirmwarePackageMetadata.from_dict(self._metadata().to_dict() | {"official_source_verified": False, "provenance_level": "UNVERIFIED", "package_metadata_evidence": ()})
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(Exception, "STRONG_OFFICIAL_PROVENANCE_REQUIRED_WITHOUT_VENDOR_HASH"):
                AsusFirmwareEngine.fetch_verified_package(metadata, repository=FirmwareRepository(Path(folder) / "repo"), downloader=Downloader())

    def test_prepare_plan_packages_resolves_exact_candidates_without_mutation(self):
        metadata = self._metadata(version="2.5", status="CHECKSUM_VERIFIED_WITHOUT_VENDOR_HASH")
        plan = AsusFirmwareEngine().plan(
            fingerprint=self.fingerprint,
            current_versions={"BIOS": "1.0", "BMC": "1.0"},
            catalog_documents=[{"entries": [metadata.to_dict()]}],
        )
        class Downloader:
            def download(self, source_url, destination):
                destination.write_bytes(b"firmware")
        with tempfile.TemporaryDirectory() as folder:
            prepared = AsusFirmwareEngine.prepare_plan_packages(
                plan,
                repository=FirmwareRepository(Path(folder) / "repo"),
                downloader=Downloader(),
                components=("BMC",),
            )
        self.assertEqual("PACKAGE_READY", prepared["BMC"]["status"])
        self.assertEqual(self.digest, prepared["BMC"]["sha256"])
        self.assertEqual("NOT_PUBLISHED", prepared["BMC"]["vendor_sha256"])

    def test_prepare_plan_packages_reuses_exact_dynamic_catalog_cache(self):
        dynamic = self._metadata(version="2.6", status="PROVENANCE_VERIFIED").to_dict() | {
            "sha256": "0" * 64,
            "source_url": "https://dlcdnets.asus.com/pub/ASUS/server/exact-2.6.zip",
            "official_release_url": "https://www.asus.com/supportonly/exact/helpdesk_bios/",
            "official_source_verified": True,
            "provenance_level": "OFFICIAL_SOURCE_EXACT_PLATFORM",
            "applicability_evidence": ["exact model catalog"],
            "package_metadata_evidence": ["exact release metadata"],
        }
        plan = AsusFirmwareEngine().plan(
            fingerprint=self.fingerprint,
            current_versions={"BIOS": "1.0", "BMC": "1.0"},
            catalog_documents=[{"source": "live-official", "entries": [dynamic]}],
        )
        class Downloader:
            def download(self, _source_url, destination):
                destination.write_bytes(b"dynamic-cache-firmware")
        with tempfile.TemporaryDirectory() as folder:
            repository = FirmwareRepository(Path(folder) / "repo")
            first = AsusFirmwareEngine.prepare_plan_packages(
                plan, repository=repository, downloader=Downloader(), components=("BMC",)
            )
            self.assertEqual("PACKAGE_READY", first["BMC"]["status"])

            class Never:
                def download(self, _source_url, _destination):
                    raise AssertionError("exact verified dynamic cache should be reused")

            second = AsusFirmwareEngine.prepare_plan_packages(
                plan, repository=repository, downloader=Never(), components=("BMC",)
            )
        self.assertEqual("CACHE_HIT_PROVENANCE_VERIFIED", second["BMC"]["resolution"])
        self.assertEqual(first["BMC"]["sha256"], second["BMC"]["sha256"])

    def test_production_plan_resolves_exact_target_from_configured_catalog(self):
        """An outdated fixture must expose a target; auth is not discovery."""
        metadata = self._metadata(version="2.5", status="CHECKSUM_VERIFIED_WITHOUT_VENDOR_HASH")
        bios_metadata = FirmwarePackageMetadata.from_dict(metadata.to_dict() | {"component": "BIOS", "package_filename": "asus-bios.zip"})
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            catalog = root / "firmware-catalog.json"
            catalog.write_text(json.dumps({"entries": [metadata.to_dict(), bios_metadata.to_dict()]}) + "\n", encoding="utf-8")
            config = ProductionConfig(
                primary_root=root / "results",
                firmware_catalog_path=catalog,
                firmware_current_proof=root / "missing-proof.json",
            )
            workflow = ProductionWorkflow(config, runtime_version="audit", executor=type("E", (), {"run": lambda *_a, **_k: {"stdout": ""}})())
            inventory = {
                "raw": {"ipmi_mc": {"stdout": "Firmware Revision : 1.0\n"}},
                "normalized": {
                    "vendor": "ASUS",
                    "model": "RS700-E12-RS12U",
                    "system_serial": "SYS-1",
                    "components": [
                        {"category": "MOTHERBOARD", "model": "Z14PP-D32", "serial": "BOARD-1"},
                        {"category": "MANAGEMENT_MODULE", "model": "ASMB12-iKVM", "serial": "BMC-1"},
                    ],
                },
            }
            plan = workflow._firmware_plan(inventory, {"state": "BMC_AUTH_UNAVAILABLE"})
            self.assertEqual("UPDATE_REQUIRED", plan["readiness"])
            bios = next(item for item in plan["components"] if item["component"] == "BIOS")
            bmc = next(item for item in plan["components"] if item["component"] == "BMC")
            self.assertEqual("2.5", bios["target"])
            self.assertEqual("2.5", bmc["target"])
            self.assertEqual("UPDATE_REQUIRED", bios["status"])
            self.assertFalse(plan["mutation_started"])

    def test_authenticated_web_hpm_probe_uses_current_server_bound_credential(self):
        metadata = self._metadata(version="2.5", status="CHECKSUM_VERIFIED_WITHOUT_VENDOR_HASH")
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            catalog = root / "firmware-catalog.json"
            catalog.write_text(json.dumps({"entries": [metadata.to_dict()]}) + "\n", encoding="utf-8")
            workflow = ProductionWorkflow(
                ProductionConfig(
                    primary_root=root / "results",
                    firmware_catalog_path=catalog,
                    firmware_current_proof=root / "missing-proof.json",
                    firmware_live_discovery_enabled=False,
                ),
                runtime_version="audit",
                executor=type("E", (), {"run": lambda *_a, **_k: {"stdout": ""}})(),
            )
            inventory = {
                "raw": {"ipmi_mc": {"stdout": "Firmware Revision : 1.0\n"}},
                "normalized": {
                    "vendor": "ASUS",
                    "model": "RS700-E12-RS12U",
                    "server_id": "SERVER-CURRENT",
                    "system_serial": "SYS-1",
                    "bmc_ip": "172.16.50.244",
                    "components": [
                        {"category": "MOTHERBOARD", "model": "Z14PP-D32", "serial": "BOARD-1"},
                        {"category": "MANAGEMENT_MODULE", "model": "ASMB12-iKVM", "serial": "BMC-1"},
                    ],
                },
            }
            discovery = {
                "state": "BMC_AUTH_AVAILABLE",
                "attempts": [{"status": "PASS", "account": {"kind": "PROVISIONED"}}],
                "authenticated_discovery": {"normalized": {}, "endpoint_catalog": []},
            }
            with mock.patch(
                "cnserverops.production.runtime_credential_candidates",
                return_value=(("admin", "test-only-secret", "PROVISIONED"),),
            ) as candidates:
                with mock.patch("cnserverops.production.discover_asus_web_hpm_capability", return_value={}):
                    workflow._firmware_plan(inventory, discovery)

            self.assertEqual("SERVER-CURRENT", candidates.call_args.kwargs["server_id"])
            self.assertFalse(candidates.call_args.kwargs["allow_default_if_discovered"])

    def test_production_plan_fuses_asmb11_redfish_image_with_truncated_ipmi(self):
        """ASMB11 IPMI 1.02 plus Redfish 1.02.37 is one current BMC."""
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            dmi = root / "dmi"
            dmi.mkdir()
            (dmi / "bios_version").write_text("2306\n", encoding="utf-8")
            digest = hashlib.sha256(b"official-asus-package").hexdigest()
            bios = FirmwarePackageMetadata(
                vendor="ASUS", component="BIOS", version="2306", package_filename="bios.zip",
                sha256=digest, source="ASUS_OFFICIAL_SERVER_FIRMWARE_CATALOG",
                source_url="https://dlcdnets.asus.com/pub/ASUS/server/bios.zip",
                compatible_models=("RS500A-E12-RS12U",), validation_status="CHECKSUM_VERIFIED",
                official_source_verified=True, provenance_level="OFFICIAL_SOURCE_EXACT_PLATFORM",
                applicability_evidence=("official ASUS exact-model row",),
            )
            bmc = FirmwarePackageMetadata(
                vendor="ASUS", component="BMC", version="1.2.37", package_filename="bmc.zip",
                sha256=digest, source="ASUS_OFFICIAL_SERVER_FIRMWARE_CATALOG",
                source_url="https://dlcdnets.asus.com/pub/ASUS/server/bmc.zip",
                compatible_models=("RS500A-E12-RS12U",), compatible_bmc_generations=("ASMB11",),
                validation_status="CHECKSUM_VERIFIED", official_source_verified=True,
                provenance_level="OFFICIAL_SOURCE_EXACT_PLATFORM",
                applicability_evidence=("official ASUS exact-model row",),
            )
            catalog = root / "catalog.json"
            catalog.write_text(json.dumps({"entries": [bios.to_dict(), bmc.to_dict()]}), encoding="utf-8")
            workflow = ProductionWorkflow(
                ProductionConfig(
                    primary_root=root / "results", firmware_catalog_path=catalog,
                    firmware_live_discovery_enabled=False, firmware_current_proof=root / "missing-proof.json",
                ), runtime_version="audit", dmi_root=dmi,
                executor=type("E", (), {"run": lambda *_a, **_k: {"stdout": ""}})(),
            )
            inventory = {
                "raw": {"ipmi_mc": {"stdout": "Firmware Revision : 1.02\n"}},
                "normalized": {
                    "vendor": "ASUS", "model": "RS500A-E12-RS12U", "system_serial": "SYS-1",
                    "components": [
                        {"category": "MOTHERBOARD", "model": "K14PA-U24", "serial": "BOARD-1"},
                        {"category": "MANAGEMENT_MODULE", "model": "ASMB11", "serial": "BMC-1"},
                    ],
                },
            }
            discovery = {
                "state": "BMC_AUTH_UNAVAILABLE",
                "authenticated_discovery": {
                    "normalized": {
                        "firmware_inventory": [
                            {"Id": "BMCImage1", "Name": "BMCImage1", "Version": "1.02.37"},
                            {"Id": "BMCImage2", "Name": "BMCImage2", "Version": "0.0.0"},
                        ]
                    }
                },
            }
            plan = workflow._firmware_plan(inventory, discovery)
            self.assertEqual("1.02.37", plan["bmc"]["value"])
            self.assertEqual("REDFISH_FIRMWARE_INVENTORY_PLUS_IPMI_MC_LOCAL_KCS", plan["bmc"]["source"])
            self.assertEqual("BMC_CURRENT_CONFIRMED", plan["bmc"]["freshness"])
            self.assertEqual("CURRENT", next(item for item in plan["components"] if item["component"] == "BMC")["status"])
            self.assertEqual("CURRENT_VERIFIED", plan["readiness"])

    def test_historical_proof_cannot_hide_newer_exact_official_target(self):
        """A same-server old proof is evidence, not a future update waiver."""
        bios_metadata = FirmwarePackageMetadata.from_dict(
            self._metadata(version="2.6").to_dict()
            | {"component": "BIOS", "package_filename": "asus-bios.zip"}
        )
        bmc_metadata = self._metadata(version="2.6")
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            dmi = root / "dmi"
            dmi.mkdir()
            (dmi / "bios_version").write_text("2.5\n", encoding="utf-8")
            catalog = root / "firmware-catalog.json"
            catalog.write_text(json.dumps({"entries": [bios_metadata.to_dict(), bmc_metadata.to_dict()]}) + "\n", encoding="utf-8")
            proof = root / "old-proof.json"
            proof.write_text(
                json.dumps(
                    {
                        "system_serial": "SYS-1",
                        "model": "RS700-E12-RS12U",
                        "current_versions": {"BIOS": "2.5", "BMC": "2.5"},
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            workflow = ProductionWorkflow(
                ProductionConfig(
                    primary_root=root / "results",
                    firmware_catalog_path=catalog,
                    firmware_current_proof=proof,
                ),
                runtime_version="audit",
                dmi_root=dmi,
                executor=type("E", (), {"run": lambda *_a, **_k: {"stdout": ""}})(),
            )
            inventory = {
                "raw": {"ipmi_mc": {"stdout": "Firmware Revision : 2.5\n"}},
                "normalized": {
                    "vendor": "ASUS",
                    "model": "RS700-E12-RS12U",
                    "system_serial": "SYS-1",
                    "components": [
                        {"category": "MOTHERBOARD", "model": "Z14PP-D32", "serial": "BOARD-1"},
                        {"category": "MANAGEMENT_MODULE", "model": "ASMB12-iKVM", "serial": "BMC-1"},
                    ],
                },
            }
            plan = workflow._firmware_plan(inventory, {"state": "BMC_AUTH_UNAVAILABLE"})
        self.assertEqual("UPDATE_REQUIRED", plan["readiness"])
        self.assertTrue(plan["current_verification"]["verified"])
        self.assertEqual("PHYSICAL_LIFECYCLE_VERIFIED", plan["current_verification"]["reason"])

    def test_current_versions_match_exact_official_targets_without_old_proof_file(self):
        """A stale/missing server-bound proof must not block exact current state."""
        bios_metadata = FirmwarePackageMetadata.from_dict(
            self._metadata(version="2.5").to_dict()
            | {"component": "BIOS", "package_filename": "asus-bios.zip"}
        )
        bmc_metadata = self._metadata(version="2.5")
        plan = AsusFirmwareEngine().plan(
            fingerprint=self.fingerprint,
            current_versions={"BIOS": "2.5", "BMC": "2.5"},
            catalog_documents=[{"entries": [bios_metadata.to_dict(), bmc_metadata.to_dict()]}],
        ).to_dict()
        self.assertTrue(
            _exact_current_versions_verified(
                plan["components"], current_versions={"BIOS": "2.5", "BMC": "2.5"}
            )
        )
        plan["components"]["BIOS"]["selected_package"]["match"]["exact_match"] = False
        self.assertFalse(
            _exact_current_versions_verified(
                plan["components"], current_versions={"BIOS": "2.5", "BMC": "2.5"}
            )
        )

    def test_current_versions_accept_exact_official_provenance_without_transfer(self):
        entries = []
        for component in ("BIOS", "BMC"):
            entries.append(
                self._metadata(version="2.5").to_dict()
                | {
                    "component": component,
                    "sha256": "0" * 64,
                    "validation_status": "PROVENANCE_VERIFIED",
                    "provenance_level": "OFFICIAL_SOURCE_EXACT_PLATFORM",
                    "package_metadata_evidence": (),
                }
            )
        plan = AsusFirmwareEngine().plan(
            fingerprint=self.fingerprint,
            current_versions={"BIOS": "2.5", "BMC": "2.5"},
            catalog_documents=[{"source": "live-official", "entries": entries}],
        ).to_dict()
        self.assertTrue(
            _exact_current_versions_verified(
                plan["components"], current_versions={"BIOS": "2.5", "BMC": "2.5"}
            )
        )

    def test_update_required_firmware_cannot_be_ready_for_production(self):
        policy = HandoffPolicy.from_mapping({"required_for_production": ["firmware_update"]})
        handoff = evaluate_handoff(
            {"firmware_update": "UPDATE_REQUIRED"},
            workflow_mode="PRODUCTION",
            policy=policy,
        )
        self.assertEqual("NOT_READY", handoff["handoff_status"])
        self.assertEqual("UPDATE_REQUIRED", handoff["failures"][0]["status"])

    def test_trailing_zero_firmware_versions_are_not_seen_as_newer(self):
        self.assertEqual(_version_key("1.32"), _version_key("1.32.00"))

    def test_redfish_adapter_uses_advertised_target_and_tracks_task(self):
        class Response:
            status = 202
            payload = {"TaskState": "Running"}
            location = "/redfish/v1/TaskService/Tasks/77"

        class Client:
            def __init__(self):
                self.calls = []
            def post_multipart(self, path, package, **kwargs):
                self.calls.append(("POST", path, package.name))
                return Response()
            def get_json(self, path):
                return type("R", (), {"payload": {"TaskState": "Completed"}})()

        descriptor = AsusTransportDescriptor(
            name="REDFISH_MULTIPART_PUSH",
            source="fixture",
            target="/upload",
            selectable=True,
            task_tracking=True,
            package_delivery="MULTIPART_FILE",
        )
        client = Client()
        adapter = AsusRedfishFirmwareAdapter(client, descriptor, version_reader=lambda component: "1.0")
        metadata = self._metadata(version="2.0")
        with tempfile.TemporaryDirectory() as folder:
            package = Path(folder) / "asus.zip"
            package.write_bytes(b"firmware")
            adapter.simple_update_targets["BMC"] = ["/redfish/v1/UpdateService/FirmwareInventory/BMCImage1"]
            started = adapter.start(package, metadata)
            self.assertEqual(UpdateTaskState.RUNNING, started.state)
            self.assertEqual("/upload", client.calls[0][1])
            self.assertEqual(UpdateTaskState.COMPLETED, adapter.poll(started.task_id).state)

    def test_redfish_adapter_extracts_signed_inner_hpm_and_sets_asus_image_type(self):
        class Response:
            status = 202
            payload = {"TaskState": "Running"}
            location = "/redfish/v1/TaskService/Tasks/78"

        class Client:
            def __init__(self):
                self.call = None
            def post_multipart(self, path, package, **kwargs):
                self.call = (path, package.name, package.read_bytes(), kwargs)
                return Response()
            def get_json(self, path):
                return type("R", (), {"payload": {}})()

        descriptor = AsusTransportDescriptor(
            name="REDFISH_MULTIPART_PUSH", source="fixture", target="/upload",
            selectable=True, task_tracking=True, package_delivery="MULTIPART_FILE",
        )
        client = Client()
        adapter = AsusRedfishFirmwareAdapter(client, descriptor, version_reader=lambda component: "1.0", simple_update_targets={"BMC": ["/redfish/v1/UpdateService/FirmwareInventory/BMCImage1"]})
        metadata = self._metadata(version="2.0")
        with tempfile.TemporaryDirectory() as folder:
            package = Path(folder) / "ASMB12_FW.zip"
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("BHS_Gen_2.0.0_enc.hpm", b"signed-hpm")
            started = adapter.start(package, metadata)
            self.assertEqual(UpdateTaskState.RUNNING, started.state)
            self.assertIsNotNone(client.call)
            self.assertEqual(b"signed-hpm", client.call[2])
            self.assertEqual("BMC", client.call[3]["oem_parameters"]["ImageType"])
            self.assertEqual(["/redfish/v1/UpdateService/FirmwareInventory/BMCImage1"], client.call[3]["update_parameters"]["Targets"])

    def test_redfish_adapter_supports_hpm_only_bios_payload_as_explicit_fallback(self):
        class Response:
            status = 202
            payload = {"TaskState": "Running"}
            location = "/redfish/v1/TaskService/Tasks/79"

        class Client:
            def __init__(self):
                self.call = None
            def post_multipart(self, path, package, **kwargs):
                self.call = (path, package.name, package.read_bytes(), kwargs)
                return Response()
            def get_json(self, path):
                return type("R", (), {"payload": {}})()

        descriptor = AsusTransportDescriptor(
            name="REDFISH_MULTIPART_PUSH", source="fixture", target="/upload",
            selectable=True, task_tracking=True, package_delivery="MULTIPART_FILE",
        )
        client = Client()
        adapter = AsusRedfishFirmwareAdapter(
            client, descriptor, version_reader=lambda component: "0603",
            simple_update_targets={"BIOS": ["/redfish/v1/UpdateService/FirmwareInventory/BIOS"]},
        )
        metadata = self._metadata(version="0903")
        metadata = FirmwarePackageMetadata(**(metadata.to_dict() | {"component": "BIOS", "package_filename": "Z14PP-D32-ASUS-0903.zip"}))
        with tempfile.TemporaryDirectory() as folder:
            package = Path(folder) / "Z14PP-D32-ASUS-0903.zip"
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("Z14PP-D32-ASUS-0903.HPM", b"signed-bios-hpm")
            started = adapter.start(package, metadata)
            self.assertEqual(UpdateTaskState.RUNNING, started.state)
            self.assertEqual("HPM", client.call[3]["oem_parameters"]["ImageType"])
            self.assertEqual(["/redfish/v1/UpdateService/FirmwareInventory/BIOS"], client.call[3]["update_parameters"]["Targets"])

    def test_redfish_adapter_selects_cap_bios_image_and_bios_image_type(self):
        class Response:
            status = 202
            payload = {"TaskState": "Running"}
            location = "/redfish/v1/TaskService/Tasks/80"

        class Client:
            def __init__(self):
                self.call = None
            def post_multipart(self, path, package, **kwargs):
                self.call = (path, package.name, package.read_bytes(), kwargs)
                return Response()
            def get_json(self, path):
                return type("R", (), {"payload": {}})()

        descriptor = AsusTransportDescriptor(
            name="REDFISH_MULTIPART_PUSH", source="fixture", target="/upload",
            selectable=True, task_tracking=True, package_delivery="MULTIPART_FILE",
            component_payload_preferences={"BIOS": ("cap", "bin")},
            component_image_types={"BIOS": "BIOS"},
        )
        client = Client()
        adapter = AsusRedfishFirmwareAdapter(
            client, descriptor, version_reader=lambda component: "0603",
            simple_update_targets={"BIOS": ["/redfish/v1/UpdateService/FirmwareInventory/BIOS"]},
        )
        metadata = self._metadata(version="0903")
        metadata = FirmwarePackageMetadata(**(metadata.to_dict() | {"component": "BIOS", "package_filename": "Z14PP-D32-ASUS-0903.zip"}))
        with tempfile.TemporaryDirectory() as folder:
            package = Path(folder) / "Z14PP-D32-ASUS-0903.zip"
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("Z14PP-D32-ASUS-0903.HPM", b"wrong-bios-container")
                archive.writestr("Z14PP-D32-ASUS-0903.CAP", b"signed-bios-cap")
            started = adapter.start(package, metadata)
            self.assertEqual(UpdateTaskState.RUNNING, started.state)
            self.assertEqual(b"signed-bios-cap", client.call[2])
            self.assertEqual("BIOS", client.call[3]["oem_parameters"]["ImageType"])
            self.assertEqual(["/redfish/v1/UpdateService/FirmwareInventory/BIOS"], client.call[3]["update_parameters"]["Targets"])

    def test_redfish_asmb11_bios_oob_uses_advertised_multipart_contract(self):
        class Response:
            status = 202
            payload = {"TaskState": "Running"}
            location = "/redfish/v1/TaskService/Tasks/81"

        class Client:
            base_url = "https://172.16.50.247"

            def __init__(self):
                self.call = None

            def get_json(self, path):
                self.assert_path = path
                return type("R", (), {"payload": {"MultipartHttpPushUri": "/redfish/v1/UpdateService/upload"}})()

            def post_multipart(self, path, package, **kwargs):
                self.call = (path, package.name, package.read_bytes(), kwargs)
                return Response()

        descriptor = AsusTransportDescriptor(
            name="ASUS_REDFISH_BIOS_OOB",
            source="fixture",
            target="/redfish/v1/UpdateService/Actions/Oem/UpdateService.BIOSFwUpdate",
            selectable=True,
            task_tracking=True,
            package_delivery="REDFISH_BIOS_OOB",
        )
        client = Client()
        adapter = AsusRedfishFirmwareAdapter(client, descriptor, version_reader=lambda component: "1201")
        metadata = self._metadata(version="2306")
        metadata = FirmwarePackageMetadata(**(metadata.to_dict() | {"component": "BIOS", "package_filename": "RS500A-E12-RS12U.zip"}))
        with tempfile.TemporaryDirectory() as folder:
            package = Path(folder) / "RS500A-E12-RS12U.zip"
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("K14PA-U24-ASUS-2306.CAP", b"signed-bios-cap")
            started = adapter.start(package, metadata)
            self.assertEqual(UpdateTaskState.RUNNING, started.state)
            self.assertIsNotNone(client.call)
            self.assertEqual("/redfish/v1/UpdateService/upload", client.call[0])
            self.assertEqual(b"signed-bios-cap", client.call[2])
            self.assertEqual("BIOSOOB", client.call[3]["oem_parameters"]["ImageType"])
            self.assertEqual(1, client.call[3]["oem_parameters"]["BIOSOOBEnable"])
            self.assertEqual(
                ["/redfish/v1/UpdateService/FirmwareInventory/BIOS"],
                client.call[3]["update_parameters"]["Targets"],
            )

    def test_redfish_asmb11_bios_oob_completed_task_requires_reboot_until_flag_clears(self):
        class Response:
            status = 202
            payload = {"TaskState": "Running"}
            location = "/redfish/v1/TaskService/Tasks/82"

        class Client:
            base_url = "https://172.16.50.247"

            def get_json(self, path):
                if path.endswith("/Tasks/82"):
                    return type("R", (), {"payload": {"TaskState": "Completed"}})()
                return type("R", (), {"payload": {"Oem": {"BMC": {"BIOSOOB": {"BIOSOOBEnable": "1", "BIOSOOBStatus": "BIOSOOB image is ready"}}}}})()

            def post_multipart(self, path, package, **kwargs):
                return Response()

        descriptor = AsusTransportDescriptor(
            name="ASUS_REDFISH_BIOS_OOB",
            source="fixture",
            target="/redfish/v1/UpdateService/Actions/Oem/UpdateService.BIOSFwUpdate",
            selectable=True,
            task_tracking=True,
            package_delivery="REDFISH_BIOS_OOB",
        )
        client = Client()
        adapter = AsusRedfishFirmwareAdapter(client, descriptor, version_reader=lambda component: "1201")
        task = adapter.poll("/redfish/v1/TaskService/Tasks/82")
        self.assertEqual(UpdateTaskState.REBOOT_REQUIRED, task.state)
        self.assertEqual("ASUS_BIOS_OOB_STAGED_REBOOT_REQUIRED", task.detail)

    def test_official_catalog_parser_rejects_related_models_as_exact_matches(self):
        class Source(AsusOfficialCatalogSource):
            def _request(self, url, **kwargs):
                if kwargs.get("method", "GET") == "GET":
                    return b'<script>var pageConfig={ webSiteCode: "global" };</script><input name="FilterField1" value="1"><input name="FilterField2" value="42">'
                return b'{"code":200,"data":[{"field1":"Rack Servers","field2":"RS700A-E12-RS12U","version":"1.2.3","downloadUrl":"https://dlcdnets.asus.com/pub/ASUS/server/RS700A.zip"}]}'
        result = Source().discover(self.fingerprint)
        self.assertEqual("NO_EXACT_OFFICIAL_MATCH", result["status"])
        self.assertEqual(0, result["exact_entry_count"])


if __name__ == "__main__":
    unittest.main()
