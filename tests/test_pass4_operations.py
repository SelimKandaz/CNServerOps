import hashlib
import io
import json
import os
import tempfile
import unittest
import zipfile
from urllib.error import HTTPError
from pathlib import Path
from unittest.mock import patch

from cnserverops.artifact_sync import ArtifactStoreForwardQueue
from cnserverops.bmc_auth import (
    BmcAuthPolicy,
    discover_bmc_auth,
    provisioned_account_binding_matches,
    runtime_credential_candidates,
    write_provisioned_account_binding,
)
from cnserverops.bmc_provisioning import provision_bmc_password
from cndellops_asus.redfish import RedfishFailureKind, RedfishRequestError
from cnserverops.central_api import CentralApiApp, CentralApiCredential
from cnserverops.collector import CentralCollector
from cnserverops.handoff import HandoffPolicy, evaluate_handoff
from cnserverops.inventory_model import build_normalized_inventory, physical_nic_rows, serial_rows
from cnserverops.models import RunRecord, ServerRecord, run_started_event
from cnserverops.operator_console import ConsoleSnapshot, OperatorConsole, available_actions, render_menu
from cnserverops.production import (
    ProductionConfig,
    ProductionWorkflow,
    ProductionWorkflowError,
    _public_readiness_label,
    _parse_ipmi_sensors,
    _smart_health_status,
    human_status_summary,
    last_production_result,
)
from cnserverops.reports import (
    generate_human_reports,
    report_manifest_complete,
    validate_xlsx,
    write_serial_workbook,
    write_server_serial_template_workbook,
)
from cnserverops.runner import bootstrap_runner
from cnserverops.secrets import SensitiveEvidenceError, assert_no_sensitive_fields
from cnserverops.stress_profiles import (
    PROFILES,
    StressProfileError,
    _LocalKcsHostWatchdog,
    _parse_sensor_sample,
    memory_working_set,
    production_resource_plan,
    resolve_profile,
)

from tests.test_operator_launcher import FakeExecutor, matching_fru, write_dmi


DMI = """Handle 0x0001, DMI type 1, 27 bytes
System Information
    Manufacturer: ASUSTeK COMPUTER INC.
    Product Name: RS500A-E12-RS12U
    Serial Number: RAS0MD0000HU
Handle 0x0002, DMI type 2, 15 bytes
Base Board Information
    Manufacturer: ASUSTeK COMPUTER INC.
    Product Name: K14PP-D24
    Serial Number: BOARD1
Handle 0x0003, DMI type 3, 22 bytes
Chassis Information
    Manufacturer: ASUS
    Serial Number: CHASSIS1
Handle 0x0004, DMI type 4, 48 bytes
Processor Information
    Socket Designation: P0
    Manufacturer: Advanced Micro Devices, Inc.
    Version: AMD EPYC 9454P
    Status: Populated, Enabled
    Core Count: 48
    Thread Count: 96
Handle 0x0011, DMI type 17, 92 bytes
Memory Device
    Size: 32 GB
    Locator: A2
    Manufacturer: Samsung
    Serial Number: DIMM-A2
    Part Number: M321R4GA3BB6
    Configured Memory Speed: 4800 MT/s
Handle 0x0012, DMI type 17, 92 bytes
Memory Device
    Size: 32 GB
    Locator: G2
    Manufacturer: Samsung
    Serial Number: DIMM-G2
    Part Number: M321R4GA3BB6
    Configured Memory Speed: 4800 MT/s
"""


def _command(stdout):
    return {"status": "PASS", "exit_code": 0, "stdout": stdout, "stderr": ""}


def _identity(*, system_serial="RAS0MD0000HU", conflicts=None, management=False):
    reason_codes = ["LOCAL_EVIDENCE_CONFLICT"] if conflicts else []
    return {
        "server_id": "SERVER-" + "A" * 64 if system_serial else "",
        "fingerprint_sha256": "a" * 64 if system_serial else "",
        "model": "RS500A-E12-RS12U",
        "primary_serial": system_serial,
        "anchors": {
            "dmi_system_serial": system_serial,
            "fru_product_serial": "DIFFERENT" if conflicts else system_serial,
            "dmi_board_serial": "BOARD1",
            "fru_board_serial": "BOARD1",
            "dmi_chassis_serial": "CHASSIS1",
            "fru_chassis_serial": "CHASSIS1",
            "fru_board_product": "ASMB12-SCM Series" if management else "",
            "fru_management_module_serial": "ASMB-SERIAL-1" if management else "",
            "fru_management_module_model": "ASMB12-SCM Series" if management else "",
        },
        "field_evidence": {
            "system_serial": {
                "value": system_serial,
                "source": "DMI_SMBIOS",
                "freshness": "CONFLICTING" if conflicts else "CURRENT_BOOT",
                "confidence": "LOW" if conflicts else "HIGH",
                "observations": [
                    {"value": system_serial, "source": "DMI_SMBIOS", "freshness": "CURRENT_BOOT", "confidence": "HIGH"}
                ],
                "local_conflict": bool(conflicts),
                "bmc_conflict": False,
                "reason_codes": reason_codes,
            },
            "board_serial": {
                "value": "BOARD1", "source": "DMI_SMBIOS", "freshness": "CURRENT_BOOT", "confidence": "HIGH",
                "observations": [], "reason_codes": [],
            },
            "chassis_serial": {
                "value": "CHASSIS1", "source": "DMI_SMBIOS", "freshness": "CURRENT_BOOT", "confidence": "HIGH",
                "observations": [], "reason_codes": [],
            },
        },
        "conflicts": list(conflicts or []),
        "bmc_conflicts": [],
        "component_identities": {
            "MANAGEMENT_MODULE": {
                "model": "ASMB12-SCM Series",
                "serial": "ASMB-SERIAL-1",
                "source": "IPMI_FRU_LOCAL_KCS",
                "freshness": "STATIC_FRU",
                "confidence": "HIGH",
            }
        } if management else {},
    }


def normalized_fixture(*, nic_count=2, conflicts=None, system_serial="RAS0MD0000HU", management=False):
    links = [
        {"ifname": "lo", "address": "00:00:00:00:00:00", "link_type": "loopback", "operstate": "UNKNOWN"},
        {"ifname": "docker0", "address": "02:42:99:88:77:66", "link_type": "bridge", "operstate": "UP"},
    ]
    sysfs = {}
    ethtool = {}
    for index in range(nic_count):
        name = f"enp5s0f{index}"
        links.append({"ifname": name, "address": f"00:11:22:33:44:{55 + index:02X}", "operstate": "UP", "phys_port_name": f"p{index}"})
        payload = b"V1" + bytes([10]) + b"Intel X550" + b"PN" + bytes([5]) + b"PN-55" + b"SN" + bytes([8]) + f"NIC-{index:04d}".encode()
        vpd_blob = b"\x90" + len(payload).to_bytes(2, "little") + payload
        sysfs[name] = {"device_path": f"/sys/devices/pci0000:00/0000:05:00.{index}", "pci_address": f"0000:05:00.{index}", "phys_port_name": f"p{index}", "vpd_hex": vpd_blob.hex()}
        ethtool[name] = _command(f"driver: ixgbe\nversion: 6.1\nfirmware-version: 1.{index}\nbus-info: 0000:05:00.{index}\n")
    raw = {
        "lscpu": _command('{"lscpu":[{"field":"Architecture:","data":"x86_64"},{"field":"CPU(s):","data":"96"},{"field":"Model name:","data":"AMD EPYC 9454P"}]}'),
        "dmidecode": _command(DMI if system_serial else DMI.replace("RAS0MD0000HU", "Unknown")),
        "lsblk": _command(json.dumps({"blockdevices": [
            {"name": "sda", "path": "/dev/sda", "type": "disk", "size": 1000000000, "vendor": "ATA", "model": "Disk A", "serial": "DISK-A", "wwn": "WWN-A", "rev": "1.0", "tran": "sata"},
            {"name": "nvme0n1", "path": "/dev/nvme0n1", "type": "disk", "size": 2000000000, "vendor": "NVMe", "model": "Disk B", "serial": "DISK-B", "wwn": "WWN-B", "rev": "2.0", "tran": "nvme"},
        ]})),
        "lspci": _command("05:00.0 Ethernet controller: Intel X550\n05:00.1 Ethernet controller: Intel X550\n01:00.0 RAID bus controller: Broadcom MegaRAID\n41:00.0 VGA compatible controller: NVIDIA A2\n"),
        "ip_link": _command(json.dumps(links)),
        "ip_route": _command(json.dumps([{"dst": "default", "dev": "enp5s0f0"}]) if nic_count else "[]"),
        "ipmi_mc": _command("Firmware Revision : 1.2.37\nManufacturer Name : ASUS\n"),
        "ipmi_fru": _command("""FRU Device Description : PSU1
 Product Manufacturer : Delta
 Product Name : DPS-1200
 Product Part Number : P1
 Product Serial : PSU-ONE
FRU Device Description : PSU2
 Product Manufacturer : Delta
 Product Name : DPS-1200
 Product Part Number : P2
 Product Serial : PSU-TWO
"""),
        "ipmi_lan": {"1": _command("IP Address : 10.1.10.99\nMAC Address : 00:AA:BB:CC:DD:EE\n")},
        "nvme": _command('{"Devices":[{"DevicePath":"/dev/nvme0n1","SerialNumber":"DISK-B","ModelNumber":"Disk B","Firmware":"2.0","NGUID":"NGUID-B","EUI64":"EUI-B"}]}'),
        "ethtool": ethtool,
    }
    return build_normalized_inventory(
        identity=_identity(system_serial=system_serial, conflicts=conflicts, management=management),
        platform={"vendor": "ASUS"},
        probe={"sys_vendor": "ASUS", "product_name": "RS500A-E12-RS12U", "system_serial": system_serial, "bios_version": "2306"},
        raw=raw,
        run_id="RUN-20260818T120000Z-ABCDEF123456",
        runner_id="CNSSD-TEST-001",
        boot_id="11111111-2222-3333-4444-555555555555",
        bmc_auth_state="BMC_AUTH_UNAVAILABLE",
        network_sysfs=sysfs,
    ).to_dict()


class NormalizedInventoryTests(unittest.TestCase):
    def test_asmb12_management_module_is_separate_from_dmi_motherboard(self):
        inventory = normalized_fixture(management=True)
        modules = [item for item in inventory["components"] if item["category"] == "MANAGEMENT_MODULE"]
        boards = [item for item in inventory["components"] if item["category"] == "MOTHERBOARD"]
        self.assertEqual(1, len(modules))
        self.assertEqual("ASMB-SERIAL-1", modules[0]["serial"])
        self.assertEqual("ASMB12-SCM Series", modules[0]["model"])
        self.assertEqual(1, len(boards))
        self.assertEqual("BOARD1", boards[0]["serial"])

    def test_multiple_components_and_dynamic_physical_nics(self):
        inventory = normalized_fixture(nic_count=2)
        counts = inventory["component_counts"]
        self.assertEqual(2, counts["MEMORY"])
        self.assertEqual(2, counts["STORAGE"])
        self.assertEqual(2, counts["PSU"])
        self.assertEqual(2, counts["NIC/OCP"])
        self.assertEqual(1, counts["RAID/HBA"])
        self.assertEqual(1, counts["GPU/ACCELERATOR"])
        self.assertEqual("00:11:22:33:44:37", inventory["primary_host_mac"])
        self.assertEqual({"enp5s0f0", "enp5s0f1"}, {row["interface"] for row in physical_nic_rows(inventory)})
        self.assertEqual({"NIC-0000", "NIC-0001"}, {row["adapter_serial"] for row in physical_nic_rows(inventory)})
        self.assertEqual({"PN-55"}, {row["part_number"] for row in physical_nic_rows(inventory)})
        self.assertEqual({"PCIe VPD (Linux sysfs)"}, {row["source"] for row in physical_nic_rows(inventory)})
        self.assertNotIn("Linux sysfs/ip link", {row["source"] for row in physical_nic_rows(inventory)})
        self.assertEqual({"NIC-0000", "NIC-0001"}, {row["adapter_serial"] for row in inventory["nic_identity_anchors"]})
        self.assertEqual("NOT_USED_PRIMARY_SYSTEM_SERIAL_TRUSTED", inventory["identity_fallback"]["state"])
        self.assertNotIn("docker0", json.dumps(inventory))

    def test_zero_one_and_many_nics_are_not_hardcoded(self):
        for count in (0, 1, 5):
            with self.subTest(count=count):
                inventory = normalized_fixture(nic_count=count)
                self.assertEqual(count, inventory["component_counts"]["NIC/OCP"])
                self.assertEqual(count, len(physical_nic_rows(inventory)))

    def test_missing_serial_stays_missing_and_cpu_serial_is_not_invented(self):
        inventory = normalized_fixture(system_serial="")
        self.assertEqual("", inventory["system_serial"])
        self.assertEqual("AMBIGUOUS_MULTIPLE_NIC_SERIALS", inventory["identity_fallback"]["state"])
        self.assertEqual("", inventory["identity_fallback"]["value"])
        cpu = next(item for item in inventory["components"] if item["category"] == "CPU")
        self.assertEqual("NOT_EXPOSED", cpu["serial"])

    def test_single_nic_serial_is_fallback_candidate_only(self):
        inventory = normalized_fixture(system_serial="", nic_count=1)
        self.assertEqual("", inventory["system_serial"])
        self.assertEqual("FALLBACK_CANDIDATE_ONLY", inventory["identity_fallback"]["state"])
        self.assertEqual("NIC-0000", inventory["identity_fallback"]["value"])
        self.assertEqual("PCIe VPD (Linux sysfs)", inventory["identity_fallback"]["source"])

    def test_conflicting_serial_preserves_field_provenance_and_conflict(self):
        inventory = normalized_fixture(conflicts=["system serial sources disagree"])
        system = next(item for item in inventory["components"] if item["category"] == "SYSTEM")
        evidence = system["field_evidence"]["serial"]
        self.assertEqual("CONFLICTING", evidence["freshness"])
        self.assertEqual("LOW", evidence["confidence"])
        self.assertIn("LOCAL_EVIDENCE_CONFLICT", evidence["conflict"])
        self.assertTrue(inventory["conflicts"])

    def test_serial_rows_are_one_row_per_dimm_and_disk(self):
        rows = serial_rows(normalized_fixture())
        self.assertEqual({"A2", "G2"}, {row["slot_location"] for row in rows if row["category"] == "MEMORY"})
        self.assertEqual({"DISK-A", "DISK-B"}, {row["serial"] for row in rows if row["category"] == "STORAGE"})


class ReportTests(unittest.TestCase):
    def test_xlsx_pdf_firmware_proof_and_html_generation(self):
        inventory = normalized_fixture()
        run = {
            "run_id": inventory["run_id"], "server_id": inventory["server_id"], "runner_id": inventory["runner_id"],
            "boot_id": inventory["boot_id"], "runtime_version": "3.3.0-pass3", "workflow_mode": "DRY_RUN",
            "test_profile": "DRY_RUN", "final_disposition": "REVIEW", "started_at_utc": "2026-08-18T12:00:00Z",
            "completed_at_utc": "2026-08-18T12:01:00Z",
        }
        result = {"overall": "REVIEW", "handoff_status": "REVIEW_REQUIRED", "serial_inventory": "PASS", "cpu": "NOT_TESTED", "ram": "NOT_TESTED", "storage": "PASS", "nic": "PASS", "psu": "PASS", "fans": "PASS", "sensors": "PASS", "new_critical_sel": 0, "kernel_hw_errors": 0}
        firmware = {"policy": "LATEST_AVAILABLE", "components": [{"component": "BIOS", "before": "2306", "target": "", "after": "", "status": "UNVERIFIED"}], "mutation_started": False}
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            manifest = generate_human_reports(root, inventory=inventory, run=run, result=result, firmware=firmware, tests={"status": "NOT_TESTED"}, finalization={"bmc_soft_reset": "NOT_PERFORMED"}, central={"artifact_status": "LOCAL_COMPLETE"}, evidence_manifest={"artifacts": []})
            self.assertEqual(6, len(manifest["artifacts"]))
            paths = {item["type"]: Path(item["path"]) for item in manifest["artifacts"]}
            with zipfile.ZipFile(paths["SERIALS_XLSX"]) as archive:
                names = set(archive.namelist())
                workbook = archive.read("xl/workbook.xml").decode("utf-8")
                all_xml = b"".join(archive.read(name) for name in names if name.endswith(".xml"))
            self.assertIn("Serials", workbook)
            self.assertIn("Server Access", workbook)
            self.assertIn(b"DIMM-A2", all_xml)
            self.assertNotIn(b"must-not-persist", all_xml.lower())
            hardware_validation = validate_xlsx(
                paths["HARDWARE_INVENTORY_XLSX"],
                expected_sheets=("Hardware",),
                required_values=(inventory["system_serial"],),
            )
            self.assertEqual("VALID", hardware_validation["status"])
            self.assertTrue(paths["PRODUCTION_PDF"].read_bytes().startswith(b"%PDF-1.4"))
            self.assertTrue(paths["FIRMWARE_PROOF_PDF"].read_bytes().startswith(b"%PDF-1.4"))
            template_path = paths["SERVER_SERIAL_TEMPLATE_XLSX"]
            template_validation = validate_xlsx(
                template_path,
                expected_sheets=("Server SNs",),
                required_values=(inventory["system_serial"], "DIMM-A2", "DISK-A", "NIC-0000"),
            )
            self.assertEqual("VALID", template_validation["status"])
            template_xml = zipfile.ZipFile(template_path).read("xl/worksheets/sheet1.xml").decode("utf-8")
            self.assertIn("Server SN:", template_xml)
            self.assertEqual(2, template_xml.count(inventory["system_serial"]))  # title + one data-row identity cell
            self.assertNotIn("NOT_EXPOSED", template_xml)
            html = paths["DIAGNOSTIC_HTML"].read_text(encoding="utf-8")
            self.assertIn("Evidence Manifest", html)
            self.assertNotIn("Dell", html)
            self.assertTrue(report_manifest_complete(manifest))
            final_manifest = generate_human_reports(
                root,
                inventory=inventory,
                run=run,
                result=result | {"overall": "PASS", "readiness": "READY_FOR_SALE", "handoff_status": "READY_FOR_HANDOFF"},
                firmware=firmware,
                tests={"status": "PASS"},
                finalization={"bmc_soft_reset": "NOT_PERFORMED"},
                central={"artifact_status": "SYNCED"},
                evidence_manifest={"artifacts": []},
                report_variant="FINAL",
            )
            final_pdf = next(item for item in final_manifest["artifacts"] if item["type"] == "PRODUCTION_PDF")
            self.assertIn("_FINAL.pdf", final_pdf["name"])
            self.assertEqual("FINAL", final_manifest["variant"])

    def test_server_serial_template_leaves_unknown_cpu_blank_and_never_uses_mac(self):
        inventory = normalized_fixture()
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "server-serials.xlsx"
            write_server_serial_template_workbook(output, inventory)
            validation = validate_xlsx(output, expected_sheets=("Server SNs",), required_values=(inventory["system_serial"],))
            self.assertEqual("VALID", validation["status"])
            with zipfile.ZipFile(output) as archive:
                xml = archive.read("xl/worksheets/sheet1.xml").decode("utf-8")
            self.assertIn("DIMM-A2", xml)
            self.assertIn("DISK-A", xml)
            self.assertIn("NIC-0000", xml)
            self.assertNotIn("00:11:22:33:44:37", xml)
            self.assertIn("<t></t>", xml)  # CPU serial remains a manual-fill blank.

    def test_report_manifest_completeness_is_type_based_not_count_based(self):
        complete = {
            "artifacts": [
                {
                    "type": item,
                    "name": f"{item}.bin",
                    "path": f"/tmp/{item}.bin",
                    "sha256": "a" * 64,
                    "size_bytes": 1,
                    "state": "LOCAL_COMPLETE",
                    **({"validation": {"status": "VALID"}} if item.endswith("_XLSX") else {}),
                }
                for item in ("SERIALS_XLSX", "HARDWARE_INVENTORY_XLSX", "PRODUCTION_PDF", "FIRMWARE_PROOF_PDF", "DIAGNOSTIC_HTML")
            ]
            + [{"type": "SEL_LOG", "name": "SEL.txt", "path": "/tmp/SEL.txt", "sha256": "b" * 64, "size_bytes": 1, "state": "LOCAL_COMPLETE"}],
        }
        self.assertTrue(report_manifest_complete(complete))
        missing_required = [item for item in complete["artifacts"] if item.get("type") != "HARDWARE_INVENTORY_XLSX"]
        self.assertFalse(report_manifest_complete({"artifacts": missing_required}))
        self.assertFalse(report_manifest_complete(complete, extended_diagnostics=True))

    def test_credential_named_field_is_rejected_before_workbook_creation(self):
        inventory = normalized_fixture()
        inventory["bmc_password"] = "must-not-persist"
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "serials.xlsx"
            with self.assertRaises(SensitiveEvidenceError):
                write_serial_workbook(output, inventory)
            self.assertFalse(output.exists())


class ArtifactDeliveryTests(unittest.TestCase):
    class Offline:
        def upload_artifact(self, *args, **kwargs):
            raise ConnectionError("offline")

    class Duplicate:
        def upload_artifact(self, *args, **kwargs):
            return {"status": "DUPLICATE_ACCEPTED"}

    class PrimaryArchivePending:
        def upload_artifact(self, *args, **kwargs):
            return {
                "status": "ACCEPTED",
                "primary_archive": {"status": "FAILED", "path": "", "sha256": ""},
                "secondary_archive": {"status": "PENDING_RETRY", "path": "", "sha256": ""},
            }

    class ImmutableConflict:
        def upload_artifact(self, *args, **kwargs):
            error = RuntimeError("Central artifact upload returned HTTP 409")
            error.http_status = 409
            raise error

    def test_offline_retry_and_duplicate_acceptance(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            artifact = root / "Production_Report.pdf"
            artifact.write_bytes(b"report")
            queue = ArtifactStoreForwardQueue(root / "queue.sqlite3")
            run_id = "RUN-20260818T120000Z-ABCDEF123456"
            queue.enqueue(run_id, artifact, artifact_type="PRODUCTION_PDF")
            first = queue.drain(self.Offline())
            self.assertEqual(1, first["pending"])
            self.assertEqual("PENDING_UPLOAD", queue.status_for_run(run_id))
            second = queue.drain(self.Duplicate())
            self.assertEqual(1, second["duplicates"])
            self.assertEqual("SYNCED", queue.status_for_run(run_id))

    def test_primary_archive_failure_keeps_binary_artifact_queued(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            artifact = root / "Production_Report.pdf"
            artifact.write_bytes(b"report")
            queue = ArtifactStoreForwardQueue(root / "queue.sqlite3")
            run_id = "RUN-20260818T120000Z-ARCHIVE001"
            queue.enqueue(run_id, artifact, artifact_type="PRODUCTION_PDF")
            result = queue.drain(self.PrimaryArchivePending())
            self.assertEqual(1, result["failed"])
            self.assertEqual("PENDING_UPLOAD", queue.status_for_run(run_id))

    def test_immutable_http_409_is_terminal_and_not_retried_forever(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            artifact = root / "bmc-handoff.json"
            artifact.write_bytes(b"new immutable handoff proof")
            queue = ArtifactStoreForwardQueue(root / "queue.sqlite3")
            run_id = "RUN-20260824T120000Z-CONFLICT001"
            queue.enqueue(run_id, artifact, artifact_type="RAW_BMC_HANDOFF")

            first = queue.drain(self.ImmutableConflict())
            self.assertEqual(
                {"attempted": 1, "synced": 0, "duplicates": 0, "pending": 0, "failed": 1},
                first,
            )
            self.assertEqual("UPLOAD_FAILED", queue.status_for_run(run_id))
            record = queue.records_for_run(run_id)[0]
            self.assertEqual("IDEMPOTENCY_CONFLICT", record["last_delivery_state"])
            self.assertEqual(1, record["attempts"])

            second = queue.drain(self.ImmutableConflict())
            self.assertEqual(0, second["attempted"])
            self.assertEqual(1, queue.records_for_run(run_id)[0]["attempts"])

    def test_legacy_pending_http_409_is_migrated_out_of_retry_set(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            artifact = root / "bmc-handoff.json"
            artifact.write_bytes(b"legacy conflict")
            queue = ArtifactStoreForwardQueue(root / "queue.sqlite3")
            run_id = "RUN-20260824T120000Z-LEGACY409"
            queued = queue.enqueue(run_id, artifact, artifact_type="RAW_BMC_HANDOFF")
            with queue._connection() as connection:
                connection.execute(
                    "UPDATE artifact_queue SET last_error=? WHERE artifact_id=?",
                    (
                        "CentralApiError: Central artifact upload returned HTTP 409",
                        queued["artifact_id"],
                    ),
                )

            # initialize() performs the compatibility migration before drain.
            result = queue.drain(self.Duplicate())
            self.assertEqual(0, result["attempted"])
            record = queue.records_for_run(run_id)[0]
            self.assertEqual("UPLOAD_FAILED", record["status"])
            self.assertEqual("IDEMPOTENCY_CONFLICT", record["last_delivery_state"])

    def test_retry_summary_separates_historical_terminal_conflicts(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            artifact = root / "bmc-handoff.json"
            artifact.write_bytes(b"historical conflict")
            config = ProductionConfig(
                primary_root=root / "results",
                queue_database=root / "events.sqlite3",
                artifact_queue_database=root / "artifacts.sqlite3",
            )
            queue = ArtifactStoreForwardQueue(config.artifact_queue_database)
            queued = queue.enqueue(
                "RUN-20260824T120000Z-SUMMARY409",
                artifact,
                artifact_type="RAW_BMC_HANDOFF",
            )
            with queue._connection() as connection:
                connection.execute(
                    "UPDATE artifact_queue SET last_error=? WHERE artifact_id=?",
                    (
                        "CentralApiError: Central artifact upload returned HTTP 409",
                        queued["artifact_id"],
                    ),
                )
            workflow = ProductionWorkflow(
                config,
                runtime_version="test",
                collector_client=self.Duplicate(),
            )
            with patch.object(
                workflow,
                "_retry_pending_bmc_handoffs",
                return_value={"attempted": 0, "completed": 0, "deferred": 0, "failed": 0},
            ):
                result = workflow.retry_pending_sync()

            self.assertEqual(0, result["artifacts"]["attempted"])
            self.assertEqual(0, result["artifacts"]["failed"])
            self.assertEqual(1, result["artifacts"]["terminal_failed"])
            self.assertEqual(1, result["artifacts"]["counts"]["UPLOAD_FAILED"])

    def test_superseded_filename_does_not_block_unique_replacement(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            artifact = root / "bmc-handoff.json"
            artifact.write_bytes(b"pre-reset")
            queue = ArtifactStoreForwardQueue(root / "queue.sqlite3")
            run_id = "RUN-20260818T120000Z-HANDOFF001"
            queue.enqueue(run_id, artifact, artifact_type="RAW_BMC_HANDOFF")
            self.assertEqual(1, queue.drain(self.Duplicate())["duplicates"])
            artifact.write_bytes(b"post-reset")
            queue.enqueue(run_id, artifact, artifact_type="RAW_BMC_HANDOFF")
            queue.supersede_for_run(
                run_id,
                filename=artifact.name,
                reason="replaced by immutable post-handoff proof",
            )
            successor = root / "bmc-handoff-retry.json"
            successor.write_bytes(b"post-reset-proof")
            queue.enqueue(run_id, successor, artifact_type="RAW_BMC_HANDOFF_RETRY")
            queue.drain(self.Duplicate())
            self.assertEqual("SYNCED", queue.status_for_run(run_id))

    def test_authenticated_central_artifact_upload_is_sha_idempotent(self):
        server = ServerRecord(fingerprint_sha256="b" * 64, vendor="ASUS", model="RS500A-E12-RS12U", system_serial="SERIAL-001", confidence="high")
        run = RunRecord.start(server, runner_id="CNSSD-01", runtime_version="3.3.0-pass3")
        payload = b"pdf fixture"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            collector = CentralCollector(root / "central.sqlite3")
            collector.ingest_event(run_started_event(run, server))
            app = CentralApiApp(collector, credential=CentralApiCredential("artifact-test-value"), artifact_root=root / "Servers")
            statuses = []

            def start_response(status, headers):
                statuses.append(status)

            def request():
                environ = {
                    "REQUEST_METHOD": "PUT",
                    "PATH_INFO": f"/v1/artifacts/{run.run_id}/{digest}/Production_Report.pdf",
                    "HTTP_AUTHORIZATION": "Bearer artifact-test-value",
                    "HTTP_X_CNSERVEROPS_ARTIFACT_TYPE": "PRODUCTION_PDF",
                    "CONTENT_LENGTH": str(len(payload)),
                    "wsgi.input": io.BytesIO(payload),
                }
                return json.loads(b"".join(app(environ, start_response)).decode("utf-8"))

            first = request()
            second = request()
            self.assertEqual("ACCEPTED", first["status"])
            self.assertEqual("DUPLICATE_ACCEPTED", second["status"])
            self.assertEqual(1, collector.counts()["artifacts"])
            self.assertTrue((root / "Servers" / "SERIAL-001" / run.run_id / "Production_Report.pdf").is_file())

    def test_central_primary_and_secondary_archives_are_hash_verified(self):
        server = ServerRecord(fingerprint_sha256="c" * 64, vendor="ASUS", model="RS700-E12-RS12U", system_serial="SERIAL-002", confidence="high")
        run = RunRecord.start(server, runner_id="CNSSD-02", runtime_version="3.6.9-pass3-readiness-archive")
        payload = b"archive fixture"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            collector = CentralCollector(root / "central.sqlite3")
            collector.ingest_event(run_started_event(run, server))
            app = CentralApiApp(
                collector,
                credential=CentralApiCredential("archive-test-value"),
                artifact_root=root / "Servers",
                fleet_archive_root=root / "primary",
                secondary_archive_root=root / "secondary",
            )
            environ = {
                "REQUEST_METHOD": "PUT",
                "PATH_INFO": f"/v1/artifacts/{run.run_id}/{digest}/Production_Report.pdf",
                "HTTP_AUTHORIZATION": "Bearer archive-test-value",
                "HTTP_X_CNSERVEROPS_ARTIFACT_TYPE": "PRODUCTION_PDF",
                "CONTENT_LENGTH": str(len(payload)),
                "wsgi.input": io.BytesIO(payload),
            }
            response = json.loads(b"".join(app(environ, lambda *_: None)).decode("utf-8"))
            self.assertEqual("SYNCED", response["primary_archive"]["status"])
            self.assertEqual("SYNCED", response["secondary_archive"]["status"])
            self.assertIn("FULL_PRODUCTION", response["primary_archive"]["path"])
            self.assertEqual(digest, response["secondary_archive"]["sha256"])


class StressAndHandoffTests(unittest.TestCase):
    def test_public_readiness_labels_are_explicit_for_sale_workflows(self):
        self.assertEqual("READY_FOR_SALE", _public_readiness_label(workflow_mode="PRODUCTION", overall="PASS"))
        self.assertEqual("REVIEW_REQUIRED", _public_readiness_label(workflow_mode="PRODUCTION", overall="REVIEW"))
        self.assertEqual("NOT_READY_FOR_SALE", _public_readiness_label(workflow_mode="PRODUCTION", overall="FAIL"))
        self.assertEqual("READY_FOR_HANDOFF", _public_readiness_label(workflow_mode="FIRMWARE_ONLY", overall="PASS"))

    def test_profile_durations_and_custom_bounds(self):
        self.assertEqual(210, PROFILES["QUICK"].total_seconds)
        self.assertEqual(420, PROFILES["STANDARD"].total_seconds)
        self.assertEqual(2 * 3600, PROFILES["EXTENDED"].total_seconds)
        self.assertEqual(8 * 3600, PROFILES["OVERNIGHT"].total_seconds)
        self.assertEqual(3 * 3600, resolve_profile("CUSTOM", custom_hours=3).total_seconds)
        for hours in (0.5, 18.1):
            with self.assertRaises(StressProfileError):
                resolve_profile("CUSTOM", custom_hours=hours)

    def test_adaptive_memory_leaves_headroom(self):
        sizing = memory_working_set(total_bytes=128 * 1024**3, available_bytes=100 * 1024**3, worker_count=8)
        self.assertLess(sizing["target_bytes"], sizing["available_bytes"])
        self.assertGreaterEqual(sizing["reserved_bytes"], int(128 * 1024**3 * 0.20))
        small = memory_working_set(total_bytes=2 * 1024**3, available_bytes=1024**3, worker_count=1)
        self.assertGreaterEqual(small["target_bytes"], 64 * 1024**2)

    def test_standard_profile_retains_large_host_resource_reserve(self):
        standard = production_resource_plan(PROFILES["STANDARD"], cpu_count=256)
        self.assertEqual(128, standard["cpu_workers"])
        self.assertEqual(128, standard["reserved_cpu_count"])
        self.assertEqual("STANDARD_RESPONSIVE_RESERVE", standard["cpu_policy"])
        self.assertEqual(0.50, standard["memory_max_total_fraction"])
        quick = production_resource_plan(PROFILES["QUICK"], cpu_count=8)
        self.assertEqual(6, quick["cpu_workers"])
        self.assertEqual(2, quick["reserved_cpu_count"])

    def test_explicit_burn_in_retains_maximum_cpu_contract(self):
        burn_in = production_resource_plan(PROFILES["EXTENDED"], cpu_count=256)
        self.assertEqual(255, burn_in["cpu_workers"])
        self.assertEqual(1, burn_in["reserved_cpu_count"])
        self.assertEqual("BURN_IN_MAXIMUM_WITH_ONE_SCHEDULER_RESERVE", burn_in["cpu_policy"])
        self.assertEqual(0.70, burn_in["memory_max_total_fraction"])

    def test_local_kcs_watchdog_is_bounded_and_cleared_after_stress_phase(self):
        class WatchdogExecutor:
            def __init__(self):
                self.calls = []

            def run(self, tool, arguments, *, timeout_seconds):
                self.calls.append((tool, arguments, timeout_seconds))
                return {"status": "PASS", "exit_code": 0, "stdout": "", "stderr": ""}

        executor = WatchdogExecutor()
        watchdog = _LocalKcsHostWatchdog(executor, timeout_seconds=300)
        self.assertTrue(watchdog.arm())
        self.assertTrue(watchdog.pet())
        watchdog.disarm()
        self.assertEqual(
            [
                ("mc", "watchdog", "get"),
                ("mc", "watchdog", "set", "timeout=300", "action=reset", "use=sms", "clear=sms"),
                ("mc", "watchdog", "reset"),
                ("mc", "watchdog", "reset"),
                ("mc", "watchdog", "off"),
            ],
            [arguments for _, arguments, _ in executor.calls],
        )
        receipt = watchdog.evidence()
        self.assertEqual("ACTIVE_AND_CLEARED", receipt["status"])
        self.assertTrue(receipt["armed"])
        self.assertTrue(receipt["disarmed"])

    def test_runner_smart_bridge_is_not_customer_storage_failure(self):
        self.assertEqual("PASS", _smart_health_status({"stdout": "SMART overall-health self-assessment test result: PASSED\n"}))
        self.assertEqual("UNAVAILABLE", _smart_health_status({"stdout": "smartctl: bridge does not support SMART\n"}))

    def test_handoff_separates_overall_from_capability_specific_auth(self):
        statuses = {"collection": "PASS", "serial_inventory": "PASS", "identity": "PASS", "storage": "PASS", "nic": "PASS", "sensors": "PASS", "cpu": "PASS", "ram": "PASS", "firmware_update": "BLOCKED_BY_AUTH", "system_diagnostics": "BLOCKED_BY_AUTH", "sel_entries": 0, "global_run_blocked_by_bmc": False}
        strict = evaluate_handoff(statuses, workflow_mode="PRODUCTION")
        self.assertEqual("REVIEW", strict["overall"])
        self.assertEqual("REVIEW_REQUIRED", strict["handoff_status"])
        permissive = evaluate_handoff(statuses, workflow_mode="PRODUCTION", policy=HandoffPolicy(allow_optional_review_for_ready=True))
        self.assertEqual("PASS", permissive["overall"])
        self.assertEqual("READY_FOR_HANDOFF", permissive["handoff_status"])
        self.assertNotIn("sel_entries", permissive["component_statuses"])


class DashboardAndDryRunTests(unittest.TestCase):
    def test_inventory_retries_transient_kcs_mc_read_for_firmware_provenance(self):
        class FlakyMcExecutor(FakeExecutor):
            def __init__(self):
                self.mc_calls = 0

            def run(self, tool, arguments, *, timeout_seconds):
                if tool == "ipmitool" and arguments[:2] == ("mc", "info"):
                    self.mc_calls += 1
                    if self.mc_calls == 1:
                        return {
                            "tool": tool,
                            "command": [f"/approved/{tool}", *arguments],
                            "status": "FAILED",
                            "exit_code": 1,
                            "stdout": "",
                            "stderr": "Get Device ID command failed",
                        }
                return super().run(tool, arguments, timeout_seconds=timeout_seconds)

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            executor = FlakyMcExecutor()
            workflow = ProductionWorkflow(
                ProductionConfig(primary_root=root, reports_enabled=False, artifact_sync_enabled=False),
                runtime_version="3.8.68-pass3-kcs-firmware-retry",
                executor=executor,
            )

            class ProbeStub:
                def to_dict(self):
                    return {
                        "sys_vendor": "ASUSTeK COMPUTER INC.",
                        "product_name": "RS500A-E12-RS12U",
                        "product_serial": "RAS0MD0000HU",
                        "board_serial": "BOARD1",
                        "chassis_serial": "CHASSIS1",
                        "bios_version": "1201",
                    }

            collected = workflow._collect_inventory(
                root / "inventory",
                identity=_identity(),
                platform={"platform_id": "ASUS_SERVER", "vendor": "ASUS"},
                probe=ProbeStub(),
                run_id="",
                runner_id="CNSSD-TEST",
            )
            bmc = next(item for item in collected["normalized"]["components"] if item["category"] == "BMC")
            self.assertEqual("1.01", bmc["firmware"])
            # Initial collection, the standard-module/KCS availability probe,
            # and the evidence capture after restoration are deliberately
            # separate read-only calls.  This keeps the restore receipt and
            # normalized inventory independently verifiable.
            self.assertEqual(3, executor.mc_calls)

    def test_active_bmc_auth_marker_never_repeats_raw_recovery(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            marker = root / "bmc-auth-change-state.json"
            marker.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "active": True,
                        "server_id": "SERVER-X",
                        "method": "ASUS_ASMB12_KCS_FACTORY_DEFAULT_RAW_32_66",
                        "changed_at_utc": "2026-08-21T00:00:00Z",
                        "sensitive_material_exposed": False,
                    }
                ),
                encoding="utf-8",
            )
            config = ProductionConfig(
                primary_root=root,
                bmc_auth_change_marker=marker,
                reports_enabled=False,
                artifact_sync_enabled=False,
            )
            workflow = ProductionWorkflow(config, runtime_version="3.8.45-pass3-final-lifecycle", executor=FakeExecutor())
            identity = {"server_id": "SERVER-X", "primary_serial": "SERIAL-X", "model": "RS700"}
            inventory = {"normalized": {"bmc_ip": "10.0.0.5"}}
            discovery = {"state": "BMC_AUTH_UNAVAILABLE", "usable_for_authenticated_get": False}
            rediscovered = {"state": "BMC_AUTH_UNAVAILABLE", "usable_for_authenticated_get": False}
            with patch.object(workflow, "_discover_bmc_auth", return_value=rediscovered) as discover, patch(
                "cnserverops.production.recover_asmb12_bmc"
            ) as recover:
                _, observed, result = workflow._ensure_authenticated_firmware_access(
                    run_dir=root / "run",
                    identity=identity,
                    platform={},
                    probe=None,
                    inventory=inventory,
                    firmware={"readiness": "UPDATE_REQUIRED"},
                    run_id="RUN-AAAAAAAA",
                    runner_id="RUNNER-X",
                    discovery=discovery,
                )
            # Legacy markers do not carry post-reset endpoint provenance.
            # The hardened workflow refuses to probe their historical IP,
            # rather than risking a BMC request to a DHCP-reused address.
            discover.assert_not_called()
            recover.assert_not_called()
            self.assertEqual("BLOCKED_BY_AUTH", result["status"])
            self.assertEqual("BMC_ENDPOINT_NOT_DISCOVERABLE_POST_RECOVERY", result["reason"])
            self.assertNotIn("bmc_auth_change_marker", observed)

    def test_last_result_filter_never_presents_another_server_as_current(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "results"

            def write_result(name, fingerprint, disposition, modified_at):
                path = root / "runs" / name / "result-summary.json"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    json.dumps(
                        {
                            "run": {
                                "run_id": name,
                                "server_fingerprint_sha256": fingerprint,
                                "final_disposition": disposition,
                            },
                            "server": {"fingerprint_sha256": fingerprint},
                            "normalized_result": {
                                "handoff_status": "READY_FOR_HANDOFF",
                                "bmc_access_state": "BMC_AUTH_UNAVAILABLE",
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                os.utime(path, (modified_at, modified_at))

            write_result("RUN-20260821T000000Z-SERVERA", "a" * 64, "PASS", 100)
            write_result("RUN-20260821T000001Z-SERVERB", "b" * 64, "FAIL", 200)

            # Unfiltered CLI history remains global; a current-server lookup
            # must never adopt the newer record from a different machine.
            self.assertEqual("RUN-20260821T000001Z-SERVERB", last_production_result(root)["run_id"])
            current = last_production_result(root, expected_fingerprint="a" * 64)
            self.assertEqual("FOUND", current["status"])
            self.assertEqual("RUN-20260821T000000Z-SERVERA", current["run_id"])
            self.assertEqual("NO_RESULT", last_production_result(root, expected_fingerprint="c" * 64)["status"])

    def test_ipmi_sensor_parser_uses_health_column_not_units(self):
        rows = _parse_ipmi_sensors(
            "CPU1 Temperature | 33.000 | degrees C | ok | na\n"
            "TR2 Temperature | na | degrees C | na | na\n"
            "FRNT_FAN1 | 14300.000 | RPM | ok | 0\n"
            "CPU1_ECC1 | 0x40 | discrete | ok | na\n"
        )
        self.assertEqual(["ok", "na", "ok", "ok"], [row["status"] for row in rows])

    def test_stress_monitor_sensor_parser_uses_health_column_not_units(self):
        summary = _parse_sensor_sample(
            "Volt_12VSB | 11.712 | volts | ok | na\n"
            "SYS_FAN1-F | 10080.000 | rpm | ok | na\n"
            "Temp_P1 | 48.000 | degrees C | ok | na\n"
            "Status_PSU1 | 0x1 | discrete | ok | na\n"
        )
        self.assertEqual(4, summary["row_count"])
        self.assertEqual(0, summary["critical_count"])
        self.assertEqual(48.0, summary["current_max_temp_c"])

    def test_human_summary_explains_dry_run_non_execution_and_storage_review(self):
        handoff = evaluate_handoff(
            {
                "collection": "PASS",
                "serial_inventory": "PASS",
                "identity": "PASS",
                "storage": "REVIEW",
                "nic": "PASS",
                "sensors": "PASS",
                "cpu": "NOT_TESTED",
                "ram": "NOT_TESTED",
            },
            workflow_mode="DRY_RUN",
        )
        summary = human_status_summary(
            statuses=handoff["component_statuses"],
            handoff=handoff,
            workflow_mode="DRY_RUN",
            central_sync="SYNCED",
            artifact_status="SYNCED",
            reports_status="PASS",
        )
        self.assertEqual("REVIEW", summary["overall"])
        self.assertEqual("PASS", summary["central_sync"])
        self.assertIn("intentionally not exercised", summary["reason_text"])
        self.assertIn("USB bridge", summary["reason_text"])

    def test_controlled_default_bmc_probe_never_persists_secret(self):
        class FakeResponse:
            status = 200

        class FakeClient:
            def get_json(self, path):
                self.path = path
                return FakeResponse()

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            env_name = "CN_TEST_ASUS_DEFAULT_SECRET"
            old = os.environ.get(env_name)
            os.environ[env_name] = "fixture-only"
            try:
                calls = []

                def factory(host, candidate, policy):
                    calls.append(candidate.kind)
                    return FakeClient()

                result = discover_bmc_auth(
                    "192.0.2.20",
                    policy=BmcAuthPolicy(
                        default_password_env=env_name,
                        default_password_file=root / "missing",
                        collect_authenticated_get_only=False,
                    ),
                    primary_root=root / "results",
                    server_id="SERVER-NEW",
                    redfish_factory=factory,
                )
            finally:
                if old is None:
                    os.environ.pop(env_name, None)
                else:
                    os.environ[env_name] = old
            self.assertEqual("BMC_AUTH_DEFAULT_AVAILABLE", result["state"])
            self.assertEqual(["DEFAULT"], calls)
            serialized = json.dumps(result)
            self.assertNotIn("fixture-only", serialized)
            self.assertNotIn("password", serialized.lower())

    def test_recovery_override_probes_factory_credential_for_seen_server(self):
        """An exact factory recovery must not be blocked by old local history."""
        class FakeResponse:
            status = 200

        class FakeClient:
            def get_json(self, _path):
                return FakeResponse()

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            runs = root / "results" / "runs" / "RUN-OLD-SERVER"
            runs.mkdir(parents=True)
            (runs / "run.json").write_text(
                json.dumps({"server": {"server_id": "SERVER-SEEN"}}), encoding="utf-8"
            )
            env_name = "CN_TEST_ASUS_RECOVERY_DEFAULT_SECRET"
            old = os.environ.get(env_name)
            os.environ[env_name] = "fixture-only"
            calls = []
            try:
                def factory(_host, candidate, _policy):
                    calls.append(candidate.kind)
                    return FakeClient()

                policy = BmcAuthPolicy(
                    default_password_env=env_name,
                    default_password_file=root / "missing-default",
                    collect_authenticated_get_only=False,
                )
                suppressed = discover_bmc_auth(
                    "192.0.2.25", policy=policy, primary_root=root / "results",
                    server_id="SERVER-SEEN", redfish_factory=factory,
                )
                self.assertEqual("NO_APPROVED_SECRET_REFERENCE_AVAILABLE", suppressed["reason"])
                self.assertEqual([], calls)
                recovered = discover_bmc_auth(
                    "192.0.2.25", policy=policy, primary_root=root / "results",
                    server_id="SERVER-SEEN", redfish_factory=factory,
                    allow_default_probe_after_recovery=True,
                )
            finally:
                if old is None:
                    os.environ.pop(env_name, None)
                else:
                    os.environ[env_name] = old
            self.assertEqual("BMC_AUTH_DEFAULT_AVAILABLE", recovered["state"])
            self.assertEqual(["DEFAULT"], calls)
            assert_no_sensitive_fields(recovered)

    def test_factory_recovery_never_submits_pre_reset_operational_secret(self):
        """A raw factory reset starts a new auth epoch at the default account."""
        class FakeResponse:
            status = 200

        class FakeClient:
            def get_json(self, _path):
                return FakeResponse()

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            default_env = "CN_TEST_ASUS_FACTORY_EPOCH_DEFAULT"
            provisioned_env = "CN_TEST_ASUS_FACTORY_EPOCH_OLD"
            old_default = os.environ.get(default_env)
            old_provisioned = os.environ.get(provisioned_env)
            os.environ[default_env] = "fixture-default"
            os.environ[provisioned_env] = "fixture-pre-reset-operational"
            calls = []
            try:
                policy = BmcAuthPolicy(
                    default_password_env=default_env,
                    default_password_file=root / "missing-default",
                    provisioned_username="admin",
                    provisioned_password_env=provisioned_env,
                    provisioned_password_file=root / "missing-operational",
                    collect_authenticated_get_only=False,
                )
                self.assertTrue(write_provisioned_account_binding(policy, "SERVER-RECOVERED"))
                result = discover_bmc_auth(
                    "192.0.2.28",
                    policy=policy,
                    primary_root=root / "results",
                    server_id="SERVER-RECOVERED",
                    allow_default_probe_after_recovery=True,
                    ignore_provisioned_candidates=True,
                    redfish_factory=lambda _host, candidate, _policy: (calls.append(candidate.kind) or FakeClient()),
                )
            finally:
                if old_default is None:
                    os.environ.pop(default_env, None)
                else:
                    os.environ[default_env] = old_default
                if old_provisioned is None:
                    os.environ.pop(provisioned_env, None)
                else:
                    os.environ[provisioned_env] = old_provisioned
            self.assertEqual("BMC_AUTH_DEFAULT_AVAILABLE", result["state"])
            self.assertEqual(["DEFAULT"], calls)
            self.assertNotIn("fixture-pre-reset-operational", json.dumps(result))
            assert_no_sensitive_fields(result)

    def test_provisioned_admin_alias_is_bounded_after_bmc_firmware_reset(self):
        class FakeResponse:
            status = 200

        class FakeClient:
            def get_json(self, path):
                return FakeResponse()

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            env_name = "CN_TEST_ASUS_PROVISIONED_ALIAS_SECRET"
            old = os.environ.get(env_name)
            os.environ[env_name] = "fixture-only"
            calls = []
            try:
                def factory(host, candidate, policy):
                    calls.append(candidate.username)
                    if candidate.username == "Administrator":
                        raise RedfishRequestError("/redfish/v1/Systems", RedfishFailureKind.BLOCKED_BY_AUTH, http_status=401)
                    return FakeClient()

                policy = BmcAuthPolicy(
                    mode="PROVISIONED_ONLY",
                    default_username="admin",
                    default_probe_enabled=False,
                    provisioned_username="Administrator",
                    provisioned_password_env=env_name,
                    provisioned_password_file=root / "missing",
                    collect_authenticated_get_only=False,
                )
                self.assertTrue(write_provisioned_account_binding(policy, "SERVER-ALIAS"))
                result = discover_bmc_auth(
                    "192.0.2.22",
                    policy=policy,
                    primary_root=root / "results",
                    server_id="SERVER-ALIAS",
                    redfish_factory=factory,
                )
            finally:
                if old is None:
                    os.environ.pop(env_name, None)
                else:
                    os.environ[env_name] = old
            self.assertEqual("BMC_AUTH_PROVISIONED", result["state"])
            self.assertEqual(["Administrator", "admin"], calls)

    def test_public_service_root_does_not_mask_password_change_required(self):
        class FakeResponse:
            status = 200

        class FakeClient:
            def get_json(self, path):
                if path == "/redfish/v1/Systems":
                    raise RedfishRequestError(
                        path,
                        RedfishFailureKind.PASSWORD_CHANGE_REQUIRED,
                        http_status=403,
                    )
                return FakeResponse()

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            env_name = "CN_TEST_ASUS_DEFAULT_SECRET_PASSWORD_CHANGE"
            old = os.environ.get(env_name)
            os.environ[env_name] = "fixture-only"
            try:
                result = discover_bmc_auth(
                    "192.0.2.21",
                    policy=BmcAuthPolicy(
                        default_password_env=env_name,
                        default_password_file=root / "missing",
                    ),
                    primary_root=root / "results",
                    server_id="SERVER-NEW",
                    allow_password_provisioning=False,
                    redfish_factory=lambda host, candidate, policy: FakeClient(),
                )
            finally:
                if old is None:
                    os.environ.pop(env_name, None)
                else:
                    os.environ[env_name] = old
            self.assertEqual("BMC_PASSWORD_CHANGE_REQUIRED", result["state"])
            self.assertEqual("BMC_PASSWORD_CHANGE_REQUIRED", result["reason"])
            self.assertEqual(403, result["attempts"][0]["http_status"])

    def test_first_login_generates_temporary_root_only_operational_secret(self):
        class FakeResponse:
            status = 200

        class FakeClient:
            def get_json(self, path):
                if path == "/redfish/v1/Systems":
                    return FakeResponse()
                return FakeResponse()

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            env_name = "CN_TEST_ASUS_DEFAULT_SECRET_GENERATED"
            old = os.environ.get(env_name)
            os.environ[env_name] = "fixture-default"
            calls = []

            def factory(host, candidate, policy):
                calls.append(candidate.kind)
                if candidate.kind == "DEFAULT":
                    raise RedfishRequestError(
                        "/redfish/v1/Systems",
                        RedfishFailureKind.PASSWORD_CHANGE_REQUIRED,
                        http_status=403,
                    )
                return FakeClient()

            def fake_urlopen(request, **_kwargs):
                class Response:
                    status = 200
                    headers = {"ETag": '"fixture-etag"'}

                    def __enter__(self):
                        return self

                    def __exit__(self, *_args):
                        return False

                    def read(self, _limit=-1):
                        if request.method == "GET" and request.full_url.endswith("/Accounts/4"):
                            return b'{"PasswordChangeRequired":true}'
                        return b'{"Members":[]}'

                return Response()

            secret = root / "secrets" / "asus-bmc-password"
            try:
                with patch("cnserverops.bmc_provisioning.urlopen", side_effect=fake_urlopen):
                    policy = BmcAuthPolicy(
                        default_password_env=env_name,
                        default_password_file=root / "missing-default",
                        provisioned_username="admin",
                        provisioned_password_file=secret,
                        collect_authenticated_get_only=False,
                    )
                    result = discover_bmc_auth(
                        "192.0.2.24",
                        policy=policy,
                        primary_root=root / "results",
                        server_id="SERVER-GENERATED",
                        redfish_factory=factory,
                    )
            finally:
                if old is None:
                    os.environ.pop(env_name, None)
                else:
                    os.environ[env_name] = old
            self.assertEqual("BMC_AUTH_PROVISIONED", result["state"])
            self.assertEqual(["DEFAULT", "PROVISIONED"], calls)
            self.assertTrue(secret.is_file())
            self.assertTrue(provisioned_account_binding_matches(policy, "SERVER-GENERATED"))
            self.assertFalse(provisioned_account_binding_matches(policy, "SERVER-OTHER"))
            if os.name != "nt":
                self.assertEqual(0o600, secret.stat().st_mode & 0o777)
            serialized = json.dumps(result)
            self.assertNotIn("fixture-default", serialized)
            self.assertNotIn(secret.read_text(encoding="utf-8").strip(), serialized)
            assert_no_sensitive_fields(result)

    def test_first_login_uses_configured_target_and_binds_it_without_leaking(self):
        """An approved first-login target is used once, then bound per server."""
        class FakeResponse:
            status = 200

        class FakeClient:
            def get_json(self, _path):
                return FakeResponse()

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            default_env = "CN_TEST_ASUS_DEFAULT_TARGET"
            old = os.environ.get(default_env)
            os.environ[default_env] = "fixture-default"
            target = root / "secrets" / "first-login"
            target.parent.mkdir(parents=True)
            target.write_text("approved-target-secret\n", encoding="utf-8")
            if os.name != "nt":
                os.chmod(target, 0o600)
            operational = root / "secrets" / "operational"
            calls = []

            def factory(_host, candidate, _policy):
                calls.append(candidate.kind)
                if candidate.kind == "DEFAULT":
                    raise RedfishRequestError(
                        "/redfish/v1/Systems",
                        RedfishFailureKind.PASSWORD_CHANGE_REQUIRED,
                        http_status=403,
                    )
                return FakeClient()

            def fake_urlopen(request, **_kwargs):
                class Response:
                    status = 200
                    headers = {"ETag": '"fixture-etag"'}

                    def __enter__(self):
                        return self

                    def __exit__(self, *_args):
                        return False

                    def read(self, _limit=-1):
                        if request.method == "GET" and request.full_url.endswith("/Accounts/4"):
                            return b'{"PasswordChangeRequired":true}'
                        return b'{"Members":[]}'

                return Response()

            try:
                policy = BmcAuthPolicy(
                    default_password_env=default_env,
                    default_password_file=root / "missing-default",
                    first_login_password_file=target,
                    first_login_password_env="CN_TEST_MISSING_FIRST_LOGIN_ENV",
                    provisioned_password_file=operational,
                    collect_authenticated_get_only=False,
                )
                with patch("cnserverops.bmc_provisioning.urlopen", side_effect=fake_urlopen):
                    result = discover_bmc_auth(
                        "192.0.2.25",
                        policy=policy,
                        primary_root=root / "results",
                        server_id="SERVER-TARGET",
                        redfish_factory=factory,
                    )
            finally:
                if old is None:
                    os.environ.pop(default_env, None)
                else:
                    os.environ[default_env] = old
            self.assertEqual("BMC_AUTH_PROVISIONED", result["state"])
            self.assertEqual(["DEFAULT", "PROVISIONED"], calls)
            self.assertEqual("approved-target-secret", operational.read_text(encoding="utf-8").strip())
            self.assertTrue(provisioned_account_binding_matches(policy, "SERVER-TARGET"))
            serialized = json.dumps(result)
            self.assertNotIn("approved-target-secret", serialized)
            assert_no_sensitive_fields(result)

    def test_generated_operational_secret_defaults_to_documented_account_for_resume(self):
        """A generated secret remains usable even when username is omitted in config."""
        if os.name == "nt":
            self.skipTest("root-only POSIX secret permission semantics are not representable on Windows")
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            secret = root / "secrets" / "asus-bmc-password"
            secret.parent.mkdir(parents=True)
            secret.write_text("generated-fixture-secret\n", encoding="utf-8")
            if os.name != "nt":
                os.chmod(secret, 0o600)
            policy = BmcAuthPolicy(
                mode="PROVISIONED_ONLY",
                provisioned_username="",
                provisioned_password_file=secret,
                default_username="admin",
                default_password_file=root / "missing-default",
            )
            self.assertTrue(write_provisioned_account_binding(policy, "SERVER-GENERATED"))
            candidates = runtime_credential_candidates(policy, server_id="SERVER-GENERATED")
            self.assertEqual(("admin", "generated-fixture-secret", "PROVISIONED"), candidates[0])

    def test_operational_account_binding_is_not_written_until_post_provision_authenticates(self):
        class FakeProvisioned:
            def to_dict(self):
                return {
                    "status": "PROVISIONED",
                    "account_path": "/redfish/v1/AccountService/Accounts/4",
                    "mutation_performed": True,
                    "sensitive_material_persisted": False,
                }

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            env_name = "CN_TEST_BINDING_AFTER_PROVISION"
            old = os.environ.get(env_name)
            os.environ[env_name] = "fixture-default"
            secret = root / "secrets" / "asus-bmc-password"
            policy = BmcAuthPolicy(
                default_password_env=env_name,
                default_password_file=root / "missing-default",
                provisioned_password_file=secret,
                collect_authenticated_get_only=False,
            )

            def factory(_host, candidate, _policy):
                if candidate.kind == "DEFAULT":
                    raise RedfishRequestError(
                        "/redfish/v1/Systems",
                        RedfishFailureKind.PASSWORD_CHANGE_REQUIRED,
                        http_status=403,
                    )
                raise RuntimeError("fixture post-provision transport failure")

            try:
                with patch("cnserverops.bmc_auth._provision_with_bounded_retry", return_value=FakeProvisioned()):
                    result = discover_bmc_auth(
                        "192.0.2.27",
                        policy=policy,
                        primary_root=root / "results",
                        server_id="SERVER-BINDING-FAILURE",
                        redfish_factory=factory,
                    )
            finally:
                if old is None:
                    os.environ.pop(env_name, None)
                else:
                    os.environ[env_name] = old
            self.assertTrue(result["provisioning"]["mutation_performed"])
            self.assertEqual("FAILED", result["provisioning"]["post_provision_authentication"])
            self.assertFalse(provisioned_account_binding_matches(policy, "SERVER-BINDING-FAILURE"))
            assert_no_sensitive_fields(result)

    def test_unbound_or_cross_server_operational_secret_is_never_submitted(self):
        """A moved SSD must not probe an old server's operational secret."""
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            secret = root / "secrets" / "asus-bmc-password"
            env_name = "CN_TEST_CROSS_SERVER_OPERATIONAL_SECRET"
            old = os.environ.get(env_name)
            os.environ[env_name] = "fixture-operational-secret"
            policy = BmcAuthPolicy(
                mode="PROVISIONED_ONLY",
                default_probe_enabled=False,
                provisioned_username="admin",
                provisioned_password_env=env_name,
                provisioned_password_file=secret,
                default_password_file=root / "missing-default",
            )

            calls: list[str] = []
            try:
                unbound = discover_bmc_auth(
                    "192.0.2.26",
                    policy=policy,
                    primary_root=root / "results",
                    server_id="SERVER-NEW",
                    redfish_factory=lambda _host, candidate, _policy: calls.append(candidate.username),
                )
                self.assertEqual("NO_APPROVED_SECRET_REFERENCE_AVAILABLE", unbound["reason"])
                self.assertEqual([], calls)
                self.assertEqual((), runtime_credential_candidates(policy, server_id="SERVER-NEW"))

                self.assertTrue(write_provisioned_account_binding(policy, "SERVER-OLD"))
                moved = discover_bmc_auth(
                    "192.0.2.26",
                    policy=policy,
                    primary_root=root / "results",
                    server_id="SERVER-NEW",
                    redfish_factory=lambda _host, candidate, _policy: calls.append(candidate.username),
                )
                self.assertEqual("NO_APPROVED_SECRET_REFERENCE_AVAILABLE", moved["reason"])
                self.assertEqual([], calls)
                self.assertEqual((), runtime_credential_candidates(policy, server_id="SERVER-NEW"))
                same_server = runtime_credential_candidates(policy, server_id="SERVER-OLD")
                self.assertEqual(("admin", "fixture-operational-secret", "PROVISIONED"), same_server[0])
                self.assertNotIn("fixture-operational-secret", json.dumps(moved))
                assert_no_sensitive_fields(moved)
            finally:
                if old is None:
                    os.environ.pop(env_name, None)
                else:
                    os.environ[env_name] = old

    def test_generated_operational_secret_fits_asmb_password_ceiling_and_is_complex(self):
        from cnserverops.bmc_auth import _generate_operational_secret

        with tempfile.TemporaryDirectory() as folder:
            secret_path = Path(folder) / "secrets" / "asus-bmc-password"
            value = _generate_operational_secret(secret_path)
            self.assertGreaterEqual(len(value), 16)
            self.assertLessEqual(len(value), 20)
            self.assertRegex(value, r"[A-Z]")
            self.assertRegex(value, r"[a-z]")
            self.assertRegex(value, r"[2-9]")
            self.assertRegex(value, r"^[A-Za-z2-9]+$")
            self.assertEqual(value, secret_path.read_text(encoding="utf-8").strip())

    def test_bmc_first_login_provisioning_is_bounded_and_secret_free(self):
        class FakeResponse:
            def __init__(self, status, body=b"{}", headers=None):
                self.status = status
                self._body = body
                self.headers = headers or {}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit=-1):
                return self._body

        calls = []

        def fake_urlopen(request, **_kwargs):
            calls.append(request)
            if request.method == "GET" and request.full_url.endswith("/Accounts/4"):
                return FakeResponse(200, b'{"PasswordChangeRequired":true}', {"ETag": '"fixture-etag"'})
            if request.method == "PATCH":
                return FakeResponse(204, b"")
            return FakeResponse(200, b'{"Members":[]}', {})

        with patch("cnserverops.bmc_provisioning.urlopen", side_effect=fake_urlopen):
            result = provision_bmc_password(
                "198.51.100.20",
                "admin",
                "old-password",
                "AdminAdmin",
                verify_tls=False,
            )
        self.assertEqual("PROVISIONED", result.status)
        self.assertTrue(result.mutation_performed)
        self.assertEqual(["GET", "PATCH", "GET"], [request.method for request in calls])
        self.assertEqual(b'{"Password":"AdminAdmin"}', calls[1].data)
        serialized = json.dumps(result.to_dict())
        self.assertNotIn("AdminAdmin", serialized)
        self.assertNotIn("old-password", serialized)
        assert_no_sensitive_fields(result.to_dict())
        self.assertNotIn("password", serialized.lower())

    def test_bmc_first_login_uses_ami_if_none_match_precondition(self):
        """ASMB11/AMI first-login password PATCH follows the vendor header."""
        class FakeResponse:
            def __init__(self, status, body=b"{}", headers=None):
                self.status = status
                self._body = body
                self.headers = headers or {}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit=-1):
                return self._body

        calls = []

        def fake_urlopen(request, **_kwargs):
            calls.append(request)
            if request.method == "GET" and request.full_url.endswith("/Accounts/4"):
                return FakeResponse(200, b'{"PasswordChangeRequired":true}', {"ETag": '"fixture-etag"'})
            if request.method == "PATCH":
                self.assertEqual("*", request.get_header("If-none-match"))
                self.assertIsNone(request.get_header("If-match"))
                return FakeResponse(204)
            return FakeResponse(200, b'{"Members":[]}')

        with patch("cnserverops.bmc_provisioning.urlopen", side_effect=fake_urlopen):
            result = provision_bmc_password(
                "198.51.100.21", "admin", "old-password", "temporary-password",
                verify_tls=False,
            )
        self.assertEqual("PROVISIONED", result.status)
        self.assertEqual("IF_NONE_MATCH", result.patch_precondition)

    def test_bmc_first_login_falls_back_to_etag_for_legacy_ami(self):
        class FakeResponse:
            def __init__(self, status, body=b"{}", headers=None):
                self.status = status
                self._body = body
                self.headers = headers or {}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit=-1):
                return self._body

        patch_headers = []

        def fake_urlopen(request, **_kwargs):
            if request.method == "GET" and request.full_url.endswith("/Accounts/4"):
                return FakeResponse(200, b'{"PasswordChangeRequired":true}', {"ETag": '"fixture-etag"'})
            if request.method == "PATCH":
                patch_headers.append((request.get_header("If-none-match"), request.get_header("If-match")))
                if request.get_header("If-none-match") == "*":
                    raise HTTPError(request.full_url, 412, "precondition", {}, None)
                return FakeResponse(204)
            return FakeResponse(200, b'{"Members":[]}')

        with patch("cnserverops.bmc_provisioning.urlopen", side_effect=fake_urlopen):
            result = provision_bmc_password(
                "198.51.100.22", "admin", "old-password", "temporary-password",
                verify_tls=False,
            )
        self.assertEqual("PROVISIONED", result.status)
        self.assertEqual("IF_MATCH_ETAG", result.patch_precondition)
        self.assertEqual(("*", None), patch_headers[0])
        self.assertEqual((None, '"fixture-etag"'), patch_headers[1])

    def test_bmc_first_login_uses_restricted_session_after_basic_patch_forbidden(self):
        """AMI MegaRAC permits the first-login PATCH only with a session token."""
        class FakeResponse:
            def __init__(self, status, body=b"{}", headers=None):
                self.status = status
                self._body = body
                self.headers = headers or {}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit=-1):
                return self._body

        calls = []

        def fake_urlopen(request, **_kwargs):
            calls.append(request)
            if request.method == "GET" and request.full_url.endswith("/Accounts/4"):
                return FakeResponse(200, b'{"PasswordChangeRequired":true}', {"ETag": '"fixture-etag"'})
            if request.method == "PATCH" and request.get_header("X-auth-token") is None:
                raise HTTPError(request.full_url, 403, "password change required", {}, None)
            if request.method == "POST" and request.full_url.endswith("/SessionService/Sessions"):
                # AMI returns 400 but still creates the restricted session.
                raise HTTPError(
                    request.full_url,
                    400,
                    "password change required",
                    {"X-Auth-Token": "fixture-token", "Location": "/redfish/v1/SessionService/Sessions/fixture"},
                    None,
                )
            if request.method == "PATCH":
                self.assertEqual("fixture-token", request.get_header("X-auth-token"))
                return FakeResponse(204)
            if request.method == "DELETE":
                return FakeResponse(204)
            return FakeResponse(200, b'{"Members":[]}')

        with patch("cnserverops.bmc_provisioning.urlopen", side_effect=fake_urlopen):
            result = provision_bmc_password(
                "198.51.100.23", "admin", "old-password", "temporary-password",
                verify_tls=False,
            )
        self.assertEqual("PROVISIONED", result.status)
        self.assertEqual("REDFISH_PASSWORD_CHANGE_SESSION", result.patch_authentication)
        self.assertEqual("SESSION_IF_NONE_MATCH", result.patch_precondition)
        self.assertEqual(["GET", "PATCH", "PATCH", "POST", "PATCH", "DELETE", "GET"], [request.method for request in calls])

    def test_professional_asus_dashboard_has_eight_safe_actions(self):
        platform = {"vendor": "ASUS", "platform_id": "ASUS_SERVER", "probe": {"product_name": "RS500A-E12-RS12U", "system_serial": "RAS0MD0000HU"}}
        runner_id = "CNSSD-80B38F7DF1BD49C5BC085B"
        last_run = "RUN-20260818T194138Z-33D07F123456"
        snapshot = ConsoleSnapshot(platform, {"primary_serial": "RAS0MD0000HU"}, {"runner_id": runner_id}, {"status": "ONLINE"}, "3.3.0-pass3", motherboard_serial="BOARD1", bios_version="2306", bmc_version="1.2.37", last_result={"run_id": last_run, "disposition": "REVIEW", "handoff_status": "REVIEW_REQUIRED"})
        screen = render_menu(snapshot)
        self.assertEqual(11, len(available_actions(platform)))
        for label in ("FULL PRODUCTION / PREPARE FOR SALE", "Dry Run / Serial Collection", "Firmware Update & Verification", "Finalize Server"):
            self.assertIn(label, screen)
        self.assertIn("Motherboard Serial", screen)
        self.assertIn("BMC Auth", screen)
        self.assertIn(runner_id, screen)
        self.assertIn(last_run, screen)
        self.assertTrue(all(len(line) <= 86 for line in screen.splitlines()))

    def test_snapshot_reads_real_platform_probe_bios_without_optional_attribute_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            dmi = root / "dmi"
            write_dmi(dmi)
            runner = root / "runner.json"
            bootstrap_runner(runner, runner_id="CNSSD-SNAPSHOT-001", runtime_version="3.3.1-pass3", storage_fingerprint_sha256="e" * 64)
            workflow = ProductionWorkflow(
                ProductionConfig(primary_root=root / "results", runner_config=runner, central_config=root / "missing-central.json"),
                runtime_version="3.3.1-pass3", executor=FakeExecutor(), dmi_root=dmi, fru_reader=matching_fru,
            )
            snapshot = OperatorConsole(
                workflow.config,
                runtime_version="3.3.1-pass3",
                workflow=workflow,
                output=io.StringIO(),
                clear_screen=False,
            ).snapshot()
            self.assertEqual("1201", snapshot.bios_version)
            self.assertEqual("1.01", snapshot.bmc_version)
            self.assertEqual("RAS0MD0000HU", snapshot.identity["primary_serial"])

    def test_real_dry_run_generates_reports_and_never_calls_stress_or_cleanup(self):
        class TrackingExecutor(FakeExecutor):
            def __init__(self):
                self.calls = []

            def run(self, tool, arguments, *, timeout_seconds):
                self.calls.append((tool, tuple(arguments)))
                return super().run(tool, arguments, timeout_seconds=timeout_seconds)

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            dmi = root / "dmi"
            write_dmi(dmi)
            runner = root / "runner.json"
            bootstrap_runner(runner, runner_id="CNSSD-DRY-001", runtime_version="3.3.0-pass3", storage_fingerprint_sha256="d" * 64)
            collector = CentralCollector(root / "central.sqlite3")
            executor = TrackingExecutor()
            workflow = ProductionWorkflow(
                ProductionConfig(primary_root=root / "results", runner_config=runner, central_config=root / "central.json", queue_database=root / "events.sqlite3", artifact_queue_database=root / "artifacts.sqlite3", sel_cleanup_enabled=True),
                runtime_version="3.3.0-pass3", executor=executor, dmi_root=dmi, fru_reader=matching_fru, collector_client=collector,
            )
            result = workflow.run_dry_run()
            self.assertEqual("DRY_RUN", result["run"]["workflow_mode"])
            self.assertTrue(all(value is False for value in result["result"]["dry_run_safety"].values()))
            self.assertFalse(any(tool == "stress-ng" for tool, _ in executor.calls))
            self.assertEqual(3, collector.counts()["events"])
            self.assertEqual(6, len(result["reports"]["artifacts"]))
            self.assertTrue(Path(result["run_directory"], "normalized-inventory.json").is_file())
            self.assertFalse(result["finalization"]["firmware_reverified"])
            with self.assertRaisesRegex(ProductionWorkflowError, "explicit operator authorization"):
                workflow.finalize_server()
            final = workflow.finalize_server(operator_authorized=True)
            self.assertEqual("NOT_REQUIRED", final["finalization"]["sel_cleanup"])
            self.assertFalse(final["finalization"]["firmware_reverified"])
            self.assertFalse(final["safety"]["bmc_soft_reset_performed"])
            self.assertFalse(final["safety"]["host_reboot_performed"])
            self.assertEqual(4, collector.counts()["events"])


if __name__ == "__main__":
    unittest.main()
