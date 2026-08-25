import os
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from cnserverops.bmc_auth import BmcAuthPolicy
from cnserverops.bmc_handoff import BmcHandoffResult, bmc_auth_change_required, perform_asus_factory_handoff
from cnserverops.bmc_recovery import (
    asus_bmc_recovery_capability,
    discover_local_bmc_endpoint,
    recover_asus_bmc,
    restore_local_ipmi_kcs,
)
from cnserverops.handoff import HandoffPolicy, evaluate_handoff
from cnserverops.orchestrator import ProductionOrchestrator, WorkflowStage
from cnserverops.secrets import assert_no_sensitive_fields
from cnserverops.production import ProductionConfig, ProductionWorkflow, _bmc_handoff_delivery_ready
from cnserverops.safety import MutationGate
from cndellops_asus.redfish import RedfishFailureKind, RedfishRequestError


class FakeExecutor:
    def __init__(self, firmware="1.32"):
        self.firmware = firmware
        self.calls = []

    def run(self, tool, arguments, *, timeout_seconds):
        self.calls.append((tool, arguments))
        if arguments[:2] == ("mc", "info"):
            return {"status": "PASS", "exit_code": 0, "stdout": f"Firmware Revision : {self.firmware}\n", "stderr": ""}
        if arguments[:2] == ("lan", "print"):
            return {"status": "PASS", "exit_code": 0, "stdout": "IP Address : 10.1.10.200\n", "stderr": ""}
        if arguments[:2] == ("sensor", "list"):
            return {
                "status": "PASS",
                "exit_code": 0,
                "stdout": "FAN1 | 18000 RPM | ok\nCPU Temp | 35 degrees C | ok\n",
                "stderr": "",
            }
        if arguments[:2] == ("raw", "0x32"):
            return {"status": "PASS", "exit_code": 0, "stdout": "", "stderr": ""}
        return {"status": "UNAVAILABLE", "exit_code": 1, "stdout": "", "stderr": ""}


class KcsDelayedExecutor(FakeExecutor):
    def __init__(self):
        super().__init__()
        self.mc_reads = 0

    def run(self, tool, arguments, *, timeout_seconds):
        if arguments[:2] == ("mc", "info"):
            self.mc_reads += 1
            if self.mc_reads == 1:
                return {"status": "FAILED", "exit_code": 1, "stdout": "", "stderr": "busy"}
        return super().run(tool, arguments, timeout_seconds=timeout_seconds)


class MissingThenRestoredKcsExecutor(FakeExecutor):
    """Models Yafuflash leaving the standard Linux IPMI device unloaded."""

    def __init__(self):
        super().__init__(firmware="1.02")
        self.loaded = False

    def run(self, tool, arguments, *, timeout_seconds):
        self.calls.append((tool, arguments))
        if tool == "modprobe":
            if arguments == ("ipmi_devintf",):
                self.loaded = True
            return {"status": "PASS", "exit_code": 0, "stdout": "", "stderr": ""}
        if tool == "ipmitool" and arguments[:2] == ("mc", "info"):
            if not self.loaded:
                return {
                    "status": "FAIL",
                    "exit_code": 1,
                    "stdout": "",
                    "stderr": "Could not open device at /dev/ipmi0",
                }
            return {
                "status": "PASS",
                "exit_code": 0,
                "stdout": (
                    "Firmware Revision : 1.02\n"
                    "Manufacturer ID : 2623\n"
                    "Manufacturer Name : ASUSTek Computer Inc.\n"
                    "Aux Firmware Rev Info :\n"
                    " 0x25\n 0x00\n 0x00\n 0x00\n"
                ),
                "stderr": "",
            }
        return {"status": "UNAVAILABLE", "exit_code": 1, "stdout": "", "stderr": ""}


class MacBoundEndpointExecutor(FakeExecutor):
    """KCS returns a BMC MAC but DHCP has not yet populated LAN IPMI data."""

    def __init__(self, *, neighbours=None):
        super().__init__()
        self.neighbours = list(neighbours or [])

    def run(self, tool, arguments, *, timeout_seconds):
        if tool == "ipmitool" and arguments[:2] == ("lan", "print"):
            self.calls.append((tool, arguments))
            return {
                "status": "PASS",
                "exit_code": 0,
                "stdout": "IP Address : 0.0.0.0\nMAC Address : 02:11:22:33:44:55\n",
                "stderr": "",
            }
        if tool == "ip":
            self.calls.append((tool, arguments))
            return {"status": "PASS", "exit_code": 0, "stdout": json.dumps(self.neighbours), "stderr": ""}
        return super().run(tool, arguments, timeout_seconds=timeout_seconds)


class MismatchedLanExecutor(FakeExecutor):
    def run(self, tool, arguments, *, timeout_seconds):
        if tool == "ipmitool" and arguments[:2] == ("lan", "print"):
            self.calls.append((tool, arguments))
            return {
                "status": "PASS",
                "exit_code": 0,
                "stdout": "IP Address : 172.16.50.88\nMAC Address : 02:aa:bb:cc:dd:ee\n",
                "stderr": "",
            }
        if tool == "ip":
            self.calls.append((tool, arguments))
            return {"status": "PASS", "exit_code": 0, "stdout": "[]", "stderr": ""}
        return super().run(tool, arguments, timeout_seconds=timeout_seconds)


class PostResetSensorFaultExecutor(FakeExecutor):
    def __init__(self):
        super().__init__()
        self.reset_seen = False

    def run(self, tool, arguments, *, timeout_seconds):
        if arguments[:2] == ("raw", "0x32"):
            self.reset_seen = True
        if arguments[:2] == ("sensor", "list"):
            self.calls.append((tool, arguments))
            health = "cr" if self.reset_seen else "ok"
            return {
                "status": "PASS",
                "exit_code": 0,
                "stdout": f"FAN1 | 18000 RPM | {health}\nCPU Temp | 35 degrees C | ok\n",
                "stderr": "",
            }
        return super().run(tool, arguments, timeout_seconds=timeout_seconds)


class TransientRecoveryExecutor(FakeExecutor):
    """The first post-reset KCS reply is stale, then the BMC is unavailable."""

    def __init__(self):
        super().__init__(firmware="1.02")
        self.reset_seen = False
        self.post_reset_mc_reads = 0

    def run(self, tool, arguments, *, timeout_seconds):
        if arguments[:2] == ("raw", "0x32"):
            self.reset_seen = True
            self.calls.append((tool, arguments))
            return {"status": "PASS", "exit_code": 0, "stdout": "", "stderr": ""}
        if arguments[:2] == ("mc", "info") and self.reset_seen:
            self.post_reset_mc_reads += 1
            if self.post_reset_mc_reads == 1:
                # A stale-looking successful response can occur immediately
                # before the controller enters its reset/update phase.
                return {"status": "PASS", "exit_code": 0, "stdout": "Firmware Revision : 1.02\n", "stderr": ""}
            if self.post_reset_mc_reads <= 3:
                return {"status": "FAILED", "exit_code": 1, "stdout": "", "stderr": "busy"}
        if tool == "ipmitool" and arguments[:2] == ("lan", "print"):
            self.calls.append((tool, arguments))
            return {
                "status": "PASS", "exit_code": 0,
                "stdout": "IP Address : 172.16.50.247\nMAC Address : a0:36:bc:cc:aa:d8\n",
                "stderr": "",
            }
        return super().run(tool, arguments, timeout_seconds=timeout_seconds)


class FakeRedfish:
    def get_json(self, path):
        self.path = path
        return type("R", (), {"payload": {"UserName": "admin", "PasswordChangeRequired": True}})()


class FlakyRedfishFactory:
    """Models Redfish becoming ready shortly after the KCS reset."""

    def __init__(self):
        self.calls = 0

    def __call__(self, host, username, password, verify_tls):
        self.calls += 1
        if self.calls == 1:
            class NotReady:
                def get_json(self, path):
                    raise RedfishRequestError(path, RedfishFailureKind.TRANSPORT_ERROR)
            return NotReady()
        return FakeRedfish()


class BmcHandoffTests(unittest.TestCase):
    def setUp(self):
        self.env_name = "CN_TEST_BMC_DEFAULT_PASSWORD"
        self.old = os.environ.get(self.env_name)
        os.environ[self.env_name] = "test-only-default-secret"

    def tearDown(self):
        if self.old is None:
            os.environ.pop(self.env_name, None)
        else:
            os.environ[self.env_name] = self.old

    def test_standard_ipmi_modules_are_restored_after_vendor_kcs_updater(self):
        executor = MissingThenRestoredKcsExecutor()

        result = restore_local_ipmi_kcs(executor, timeout_seconds=5)

        self.assertEqual("PASS", result["status"])
        self.assertEqual("STANDARD_IPMI_MODULE_RESTORE", result["action"])
        self.assertEqual("1.02.37", result["firmware_version"])
        self.assertEqual(
            [
                ("modprobe", ("ipmi_msghandler",)),
                ("modprobe", ("ipmi_si",)),
                ("modprobe", ("ipmi_devintf",)),
            ],
            [call for call in executor.calls if call[0] == "modprobe"],
        )
        self.assertNotIn("password", json.dumps(result).lower())

    def test_available_kcs_is_not_reloaded(self):
        executor = FakeExecutor(firmware="1.32")

        result = restore_local_ipmi_kcs(executor, timeout_seconds=5)

        self.assertEqual("PASS", result["status"])
        self.assertEqual("ALREADY_AVAILABLE", result["action"])
        self.assertFalse(any(tool == "modprobe" for tool, _arguments in executor.calls))

    def test_post_yafu_restore_forces_bounded_driver_reprobe(self):
        executor = MissingThenRestoredKcsExecutor()

        result = restore_local_ipmi_kcs(
            executor,
            timeout_seconds=5,
            wait_seconds=2,
            force_reprobe=True,
            sleep_fn=lambda _seconds: None,
        )

        self.assertEqual("PASS", result["status"])
        self.assertTrue(result["forced_reprobe"])
        self.assertIn(("modprobe", ("-r", "ipmi_devintf")), executor.calls)
        self.assertIn(("modprobe", ("-r", "ipmi_si")), executor.calls)

    def test_force_reprobe_does_not_short_circuit_on_initial_mc_info_success(self):
        executor = FakeExecutor(firmware="1.32")

        result = restore_local_ipmi_kcs(
            executor,
            timeout_seconds=5,
            wait_seconds=0,
            force_reprobe=True,
            sleep_fn=lambda _seconds: None,
        )

        self.assertEqual("PASS", result["status"])
        self.assertEqual("STANDARD_IPMI_MODULE_RESTORE", result["action"])
        self.assertTrue(result["forced_reprobe"])
        self.assertIn(("modprobe", ("-r", "ipmi_devintf")), executor.calls)
        self.assertIn(("modprobe", ("-r", "ipmi_si")), executor.calls)

    def test_untouched_bmc_does_not_require_handoff(self):
        self.assertFalse(bmc_auth_change_required({"state": "BMC_AUTH_AVAILABLE"}))
        result = evaluate_handoff(
            {"cpu": "PASS", "ram": "PASS"},
            workflow_mode="PRODUCTION",
            policy=HandoffPolicy.from_mapping({"required_for_production": ["cpu", "ram"]}),
        )
        self.assertNotIn("bmc_auth_handoff", result["component_statuses"])

    def test_provisioned_bmc_requires_successful_handoff(self):
        changed = {"provisioning": {"mutation_performed": True}}
        self.assertTrue(bmc_auth_change_required(changed))
        result = evaluate_handoff(
            {"cpu": "PASS", "ram": "PASS"},
            workflow_mode="PRODUCTION",
            policy=HandoffPolicy.from_mapping({"required_for_production": ["cpu", "ram"]}),
            bmc_auth_changed=True,
            bmc_handoff_status="FAIL",
        )
        self.assertEqual("NOT_READY", result["handoff_status"])
        self.assertTrue(any(item["capability"] == "bmc_auth_handoff" for item in result["failures"]))

    def test_extended_provisioned_bmc_cannot_release_without_handoff(self):
        result = evaluate_handoff(
            {
                "collection": "PASS",
                "serial_inventory": "PASS",
                "identity": "PASS",
                "storage": "PASS",
                "nic": "PASS",
                "sensors": "PASS",
                "cpu": "PASS",
                "ram": "PASS",
                "system_diagnostics": "PASS",
            },
            workflow_mode="PRODUCTION_EXTENDED",
            policy=HandoffPolicy.from_mapping({"required_for_production": ["system_diagnostics"]}),
            bmc_auth_changed=True,
            bmc_handoff_status="FAIL",
        )
        self.assertEqual("NOT_READY", result["handoff_status"])
        self.assertEqual("FAIL", result["component_statuses"]["bmc_auth_handoff"])

    def test_handoff_metadata_is_safe_for_authoritative_result(self):
        result = evaluate_handoff(
            {"collection": "PASS", "serial_inventory": "PASS", "identity": "PASS"},
            workflow_mode="PRODUCTION",
            policy=HandoffPolicy(allow_optional_review_for_ready=True),
            bmc_auth_changed=True,
            bmc_handoff_status="PASS",
        )
        assert_no_sensitive_fields(result)
        self.assertEqual("PASS", result["component_statuses"]["bmc_auth_handoff"])

    def test_factory_handoff_preserves_firmware_and_default_first_login(self):
        executor = FakeExecutor()
        result = perform_asus_factory_handoff(
            executor=executor,
            normalized_inventory={
                "bmc_ip": "10.1.10.147",
                "components": [{"category": "MANAGEMENT_MODULE", "model": "ASMB12-iKVM"}],
            },
            expected_bmc_version="1.32.0",
            policy=BmcAuthPolicy(
                default_password_env=self.env_name,
                default_password_file=Path("C:/does-not-exist"),
            ),
            wait_seconds=1,
            poll_seconds=0,
            redfish_factory=lambda host, username, password, verify_tls: FakeRedfish(),
        )
        self.assertEqual("PASS", result.status)
        self.assertEqual("FACTORY_DEFAULT_FIRST_LOGIN", result.default_state)
        self.assertEqual("1.32", result.firmware_after)
        self.assertEqual("STABLE", result.post_reset_fan_status)
        self.assertEqual("PASS", result.post_reset_sensor_status)
        self.assertTrue(any(args[:2] == ("raw", "0x32") for _, args in executor.calls))
        assert_no_sensitive_fields(result.to_dict())
        self.assertNotIn("password", result.to_dict())

    def test_deferred_handoff_verifies_after_prior_reset_without_second_raw_reset(self):
        """A retry must never factory-reset a BMC for a second time."""
        executor = FakeExecutor()
        result = perform_asus_factory_handoff(
            executor=executor,
            normalized_inventory={
                "bmc_ip": "10.1.10.147",
                "components": [{"category": "MANAGEMENT_MODULE", "model": "ASMB11-iKVM"}],
            },
            expected_bmc_version="1.32",
            policy=BmcAuthPolicy(
                default_password_env=self.env_name,
                default_password_file=Path("C:/does-not-exist"),
            ),
            wait_seconds=1,
            poll_seconds=0,
            reset_already_requested=True,
            redfish_factory=lambda host, username, password, verify_tls: FakeRedfish(),
        )
        self.assertEqual("PASS", result.status)
        self.assertEqual("BMC_HANDOFF_VERIFIED_AFTER_PREVIOUS_RESET", result.reason)
        self.assertFalse(any(args[:2] == ("raw", "0x32") for _, args in executor.calls))

    def test_factory_handoff_retries_redfish_after_bmc_restart(self):
        executor = FakeExecutor()
        factory = FlakyRedfishFactory()
        result = perform_asus_factory_handoff(
            executor=executor,
            normalized_inventory={
                "bmc_ip": "10.1.10.147",
                "components": [{"category": "MANAGEMENT_MODULE", "model": "ASMB11-iKVM"}],
            },
            expected_bmc_version="1.32.0",
            policy=BmcAuthPolicy(
                default_password_env=self.env_name,
                default_password_file=Path("C:/does-not-exist"),
            ),
            wait_seconds=1,
            poll_seconds=0,
            sleep_fn=lambda _seconds: None,
            redfish_factory=factory,
        )
        self.assertEqual("PASS", result.status)
        self.assertGreaterEqual(factory.calls, 2)
        self.assertEqual("FACTORY_DEFAULT_FIRST_LOGIN", result.default_state)

    def test_factory_handoff_retries_kcs_before_reset(self):
        executor = KcsDelayedExecutor()
        result = perform_asus_factory_handoff(
            executor=executor,
            normalized_inventory={
                "bmc_ip": "10.1.10.147",
                "components": [{"category": "MANAGEMENT_MODULE", "model": "ASMB11-iKVM"}],
            },
            expected_bmc_version="1.32.0",
            policy=BmcAuthPolicy(
                default_password_env=self.env_name,
                default_password_file=Path("C:/does-not-exist"),
            ),
            wait_seconds=1,
            poll_seconds=0,
            sleep_fn=lambda _seconds: None,
            redfish_factory=lambda host, username, password, verify_tls: FakeRedfish(),
        )
        self.assertEqual("PASS", result.status)
        self.assertGreaterEqual(executor.mc_reads, 2)

    def test_recovery_capability_does_not_require_a_preexisting_bmc_ip(self):
        capability = asus_bmc_recovery_capability(
            normalized_inventory={
                "components": [{"category": "MANAGEMENT_MODULE", "model": "ASMB11-iKVM"}],
            },
            firmware_plan={"generic_asus_firmware_engine": {"platform": {"bmc_generation": "ASMB11"}}},
        )
        self.assertTrue(capability["supported"])
        self.assertFalse(capability["bmc_ip_present"])
        self.assertEqual("ASUS_ASMB11_KCS_FACTORY_DEFAULT_RAW_32_66", capability["method"])

    def test_recovery_waits_for_stable_kcs_after_transient_reset_response(self):
        executor = TransientRecoveryExecutor()
        identity = {
            "fingerprint_sha256": "f" * 64,
            "mutation_eligible": True,
            "vendor": "ASUS",
            "model": "RS500A-E12-RS12U",
            "primary_serial": "TAS0MD00001P",
        }
        gate = MutationGate(
            authorized=True,
            lab_mode=True,
            approval_id="BMC-RESET-TEST",
            machine_fingerprint_sha256="f" * 64,
            vendor="ASUS",
            model="RS500A-E12-RS12U",
            system_serial="TAS0MD00001P",
            run_id="RUN-STABILITY-TEST",
            component="BMC",
            allowed_actions=frozenset({"BMC_FACTORY_RECOVERY"}),
        )
        with TemporaryDirectory() as folder:
            result = recover_asus_bmc(
                executor=executor,
                identity=identity,
                normalized_inventory={
                    "model": "RS500A-E12-RS12U",
                    "board": "K14PA-U24 Series",
                    "bmc_mac": "a0:36:bc:cc:aa:d8",
                    "components": [
                        {"category": "SYSTEM", "model": "RS500A-E12-RS12U", "status": "PRESENT"},
                        {"category": "MOTHERBOARD", "model": "K14PA-U24 Series", "status": "PRESENT"},
                        {
                            "category": "BMC", "manufacturer": "ASUSTek Computer Inc.",
                            "interface": "LOCAL_KCS/IPMI", "status": "PRESENT",
                        },
                    ],
                },
                firmware_plan={"generic_asus_firmware_engine": {"platform": {}}},
                mutation_gate=gate,
                run_id="RUN-STABILITY-TEST",
                evidence_dir=Path(folder),
                wait_seconds=2,
                poll_seconds=0,
                sleep_fn=lambda _seconds: None,
            )
        self.assertEqual("RECOVERED", result.status)
        self.assertIn("STABLE_KCS_SAMPLES_3", result.reason)
        self.assertGreaterEqual(executor.post_reset_mc_reads, 6)

    def test_recovery_capability_uses_exact_rs500a_board_when_management_fru_is_blank(self):
        """RS500A field evidence has no MANAGEMENT_MODULE FRU row."""
        capability = asus_bmc_recovery_capability(
            normalized_inventory={
                "model": "RS500A-E12-RS12U",
                "board": "K14PA-U24 Series",
                "bmc_ip": "172.16.50.247",
                "components": [
                    {
                        "category": "SYSTEM",
                        "model": "RS500A-E12-RS12U",
                        "status": "PRESENT",
                    },
                    {
                        "category": "MOTHERBOARD",
                        "model": "K14PA-U24 Series",
                        "status": "PRESENT",
                    },
                    {
                        "category": "BMC",
                        "manufacturer": "ASUSTek Computer Inc.",
                        "interface": "LOCAL_KCS/IPMI",
                        "status": "PRESENT",
                    },
                ],
            },
            firmware_plan={"generic_asus_firmware_engine": {"platform": {}}},
        )
        self.assertTrue(capability["supported"])
        self.assertEqual("ASMB11", capability["bmc_generation"])
        self.assertEqual("ASUS_ASMB11_KCS_FACTORY_DEFAULT_RAW_32_66", capability["method"])
        self.assertTrue(str(capability["generation_evidence"]).startswith("EXACT_ASUS_MODEL_BOARD:"))

    def test_exact_model_board_without_current_local_asus_kcs_stays_unsupported(self):
        capability = asus_bmc_recovery_capability(
            normalized_inventory={
                "model": "RS500A-E12-RS12U",
                "board": "K14PA-U24",
                "components": [
                    {"category": "SYSTEM", "model": "RS500A-E12-RS12U", "status": "PRESENT"},
                    {"category": "MOTHERBOARD", "model": "K14PA-U24", "status": "PRESENT"},
                ],
            },
            firmware_plan={"generic_asus_firmware_engine": {"platform": {}}},
        )
        self.assertFalse(capability["supported"])
        self.assertEqual("UNKNOWN", capability["bmc_generation"])

    def test_mac_bound_neighbour_is_used_when_local_lan_omits_dhcp_address(self):
        executor = MacBoundEndpointExecutor(
            neighbours=[
                {"dst": "172.16.50.249", "lladdr": "02:11:22:33:44:55", "state": ["STALE"]},
            ]
        )
        endpoint = discover_local_bmc_endpoint(
            executor,
            normalized_inventory={"bmc_ip": "10.1.10.147", "bmc_mac": "02:11:22:33:44:55"},
        )
        self.assertEqual("DISCOVERED", endpoint.status)
        self.assertEqual("172.16.50.249", endpoint.ip)
        self.assertEqual("LOCAL_MAC_BOUND_NEIGHBOUR", endpoint.source)

    def test_mismatched_local_lan_mac_cannot_authorize_an_endpoint(self):
        endpoint = discover_local_bmc_endpoint(
            MismatchedLanExecutor(),
            normalized_inventory={"bmc_ip": "10.1.10.147", "bmc_mac": "02:11:22:33:44:55"},
        )
        self.assertEqual("UNAVAILABLE", endpoint.status)
        self.assertEqual("", endpoint.ip)
        self.assertNotEqual("10.1.10.147", endpoint.ip)
        self.assertNotEqual("172.16.50.88", endpoint.ip)

    def test_handoff_never_uses_stale_inventory_ip_when_endpoint_is_not_currently_proven(self):
        executor = MacBoundEndpointExecutor(neighbours=[])
        factory_calls = []

        def factory(host, username, password, verify_tls):
            factory_calls.append(host)
            return FakeRedfish()

        result = perform_asus_factory_handoff(
            executor=executor,
            normalized_inventory={
                "bmc_ip": "10.1.10.147",
                "bmc_mac": "02:11:22:33:44:55",
                "components": [{"category": "MANAGEMENT_MODULE", "model": "ASMB11-iKVM"}],
            },
            expected_bmc_version="1.32",
            policy=BmcAuthPolicy(default_password_env=self.env_name, default_password_file=Path("C:/does-not-exist")),
            wait_seconds=1,
            poll_seconds=0.05,
            redfish_factory=factory,
        )
        self.assertEqual("FAIL", result.status)
        self.assertEqual("", result.bmc_ip)
        self.assertEqual("UNAVAILABLE", result.bmc_endpoint_status)
        self.assertTrue(result.reason.startswith("BMC_ENDPOINT_REDISCOVERY_FAILED:"), result.reason)
        self.assertEqual([], factory_calls)

    def test_handoff_fails_if_local_sensor_health_does_not_stabilize_after_reset(self):
        executor = PostResetSensorFaultExecutor()
        result = perform_asus_factory_handoff(
            executor=executor,
            normalized_inventory={
                "bmc_ip": "10.1.10.147",
                "components": [{"category": "MANAGEMENT_MODULE", "model": "ASMB12-iKVM"}],
            },
            expected_bmc_version="1.32",
            policy=BmcAuthPolicy(default_password_env=self.env_name, default_password_file=Path("C:/does-not-exist")),
            wait_seconds=1,
            poll_seconds=0,
            sleep_fn=lambda _seconds: None,
            redfish_factory=lambda host, username, password, verify_tls: FakeRedfish(),
        )
        self.assertEqual("FAIL", result.status)
        self.assertEqual("FAIL", result.post_reset_sensor_status)
        self.assertEqual("FAULT", result.post_reset_fan_status)
        self.assertEqual("BMC_POST_RESET_SENSOR_FAULT", result.reason)

    def test_unknown_bmc_generation_refuses_raw_factory_handoff(self):
        executor = FakeExecutor()
        result = perform_asus_factory_handoff(
            executor=executor,
            normalized_inventory={"bmc_ip": "10.1.10.147", "components": [{"category": "MANAGEMENT_MODULE", "model": "ASMB13-iKVM"}]},
            expected_bmc_version="1.32",
            policy=BmcAuthPolicy(default_password_env=self.env_name, default_password_file=Path("C:/does-not-exist")),
        )
        self.assertEqual("UNSUPPORTED", result.status)
        self.assertFalse(result.reset_requested)
        self.assertFalse(any(args[:2] == ("raw", "0x32") for _, args in executor.calls))

    def test_successful_handoff_removes_operational_secret_and_marker(self):
        with TemporaryDirectory() as folder:
            root = Path(folder)
            secret = root / "asus-bmc-password"
            binding = root / "asus-bmc-password.binding.json"
            marker = root / "bmc-auth-change-state.json"
            secret.write_text("test-only-operational-secret\n", encoding="utf-8")
            binding.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "scope": "CN_SERVEROPS_TEMPORARY_BMC_OPERATIONAL_ACCOUNT",
                        "server_id": "SERVER-CURRENT",
                        "sensitive_material_persisted": False,
                    }
                ),
                encoding="utf-8",
            )
            marker.write_text('{"active":true}\n', encoding="utf-8")
            config = ProductionConfig(
                primary_root=root / "results",
                bmc_auth_change_marker=marker,
                bmc_auth_policy={
                    "provisioned_password_file": str(secret),
                    "default_password_file": str(root / "default-password"),
                },
            )
            workflow = ProductionWorkflow(config, runtime_version="test", executor=FakeExecutor())
            result = BmcHandoffResult(
                status="PASS",
                required=True,
                method="ASUS_ASMB12_KCS_FACTORY_DEFAULT_RAW_32_66",
                reset_requested=True,
                bmc_ip="10.1.10.147",
                kcs_status="PASS",
                firmware_before="1.32",
                firmware_after="1.32",
                default_state="FACTORY_DEFAULT_FIRST_LOGIN",
                password_change_required=True,
            )
            with patch("cnserverops.production.perform_asus_factory_handoff", return_value=result):
                payload = workflow._perform_bmc_handoff(
                    run_dir=root / "run",
                    normalized_inventory={"bmc_ip": "10.1.10.147"},
                    expected_bmc_version="1.32",
                )
            self.assertEqual("PASS", payload["status"])
            self.assertFalse(secret.exists())
            self.assertFalse(binding.exists())
            self.assertFalse(marker.exists())
            self.assertFalse(payload["sensitive_material_exposed"])

    def test_enrollment_quarantine_paths_include_secret_binding_and_auth_marker(self):
        with TemporaryDirectory() as folder:
            root = Path(folder)
            secret = root / "asus-bmc-password"
            marker = root / "bmc-auth-change-state.json"
            workflow = ProductionWorkflow(
                ProductionConfig(
                    primary_root=root / "results",
                    bmc_auth_change_marker=marker,
                    bmc_auth_policy={"provisioned_password_file": str(secret)},
                ),
                runtime_version="test",
                executor=FakeExecutor(),
            )

            self.assertEqual(
                (secret, secret.with_name(secret.name + ".binding.json"), marker),
                workflow._server_specific_enrollment_paths(),
            )

    def test_handoff_uses_exact_firmware_plan_generation_when_inventory_is_ambiguous(self):
        with TemporaryDirectory() as folder:
            root = Path(folder)
            workflow = ProductionWorkflow(ProductionConfig(primary_root=root / "results"), runtime_version="test", executor=FakeExecutor())
            observed = {}

            def fake_handoff(**kwargs):
                observed.update(kwargs["normalized_inventory"])
                return BmcHandoffResult(
                    status="UNSUPPORTED", required=True,
                    method="ASUS_ASMB11_KCS_FACTORY_DEFAULT_RAW_32_66",
                    reset_requested=False,
                )

            with patch("cnserverops.production.perform_asus_factory_handoff", side_effect=fake_handoff):
                workflow._perform_bmc_handoff(
                    run_dir=root / "run",
                    normalized_inventory={"bmc_ip": "10.1.10.200", "components": []},
                    expected_bmc_version="1.02",
                    firmware_plan={"generic_asus_firmware_engine": {"platform": {"bmc_generation": "ASMB11"}}},
                )
            self.assertEqual("ASMB11", observed.get("bmc_generation"))

    def test_bmc_provisioning_persists_secret_free_resume_marker(self):
        with TemporaryDirectory() as folder:
            root = Path(folder)
            marker = root / "bmc-auth-change-state.json"
            config = ProductionConfig(
                primary_root=root / "results",
                bmc_auth_change_marker=marker,
            )
            workflow = ProductionWorkflow(config, runtime_version="test", executor=FakeExecutor())
            discovery = {
                "state": "BMC_AUTH_PROVISIONED",
                "host": "10.1.10.147",
                "provisioning": {
                    "status": "PROVISIONED",
                    "mutation_performed": True,
                    "account_path": "/redfish/v1/AccountService/Accounts/4",
                    "sensitive_material_persisted": False,
                },
            }
            with patch("cnserverops.production.discover_bmc_auth", return_value=discovery):
                result = workflow._discover_bmc_auth(
                    {"bmc_ip": "10.1.10.147"},
                    {"server_id": "SERVER-TEST"},
                )
            self.assertTrue(result["bmc_auth_change_marker_persisted"])
            payload = json.loads(marker.read_text(encoding="utf-8"))
            self.assertTrue(payload["active"])
            self.assertEqual("SERVER-TEST", payload["server_id"])
            self.assertNotIn("test-only", json.dumps(payload).lower())
            self.assertNotIn("password", payload)
            assert_no_sensitive_fields(result)

    def test_factory_recovery_reset_alone_requires_final_handoff(self):
        """A reset is an auth-state mutation even when password patching fails."""
        with TemporaryDirectory() as folder:
            root = Path(folder)
            marker = root / "bmc-auth-change-state.json"
            config = ProductionConfig(
                primary_root=root / "results",
                bmc_auth_change_marker=marker,
            )
            workflow = ProductionWorkflow(config, runtime_version="test", executor=FakeExecutor())
            identity = {
                "server_id": "SERVER-RECOVERY-TEST",
                "fingerprint_sha256": "a" * 64,
                "model": "RS700-E12-RS12U",
                "primary_serial": "TAS0MD00001P",
            }
            inventory = {
                "normalized": {
                    "bmc_ip": "10.1.10.147",
                    "components": [{"category": "MANAGEMENT_MODULE", "model": "ASMB12-SCM"}],
                },
                "summary": {},
            }
            refreshed = {
                "normalized": dict(inventory["normalized"]),
                "summary": {},
            }
            recovery = SimpleNamespace(
                to_dict=lambda: {
                    "status": "RECOVERED",
                    "reset_requested": True,
                    "method": "ASUS_ASMB12_KCS_FACTORY_DEFAULT_RAW_32_66",
                }
            )
            plan = {
                "generic_asus_firmware_engine": {
                    "platform": {"bmc_generation": "ASMB12"}
                }
            }
            with patch("cnserverops.production.recover_asmb12_bmc", return_value=recovery):
                with patch.object(workflow, "_collect_inventory", return_value=refreshed):
                    with patch.object(workflow, "_discover_bmc_auth", return_value={"state": "BMC_AUTH_UNAVAILABLE"}):
                        _inventory, discovery, _recovery = workflow._ensure_authenticated_firmware_access(
                            run_dir=root / "run",
                            identity=identity,
                            platform={"platform_id": "ASUS_SERVER", "vendor": "ASUS"},
                            probe=SimpleNamespace(),
                            inventory=inventory,
                            firmware=plan,
                            run_id="RUN-RECOVERY-TEST",
                            runner_id="CNSSD-RECOVERY-TEST",
                            discovery={"state": "BMC_AUTH_UNAVAILABLE"},
                        )
            self.assertTrue(discovery["bmc_auth_change_started"])
            self.assertTrue(bmc_auth_change_required(discovery))
            payload = json.loads(marker.read_text(encoding="utf-8"))
            self.assertTrue(payload["active"])
            self.assertEqual("CNServerOps_ASMB12_FACTORY_RECOVERY", discovery["auth_change_provenance"])
            self.assertNotIn("password", json.dumps(payload).lower())

    def test_observed_first_login_provisions_before_factory_recovery(self):
        """A fresh BMC's required first-login patch is not reset gratuitously."""
        with TemporaryDirectory() as folder:
            root = Path(folder)
            workflow = ProductionWorkflow(
                ProductionConfig(primary_root=root / "results"),
                runtime_version="test",
                executor=FakeExecutor(),
            )
            identity = {
                "server_id": "SERVER-FIRST-LOGIN",
                "fingerprint_sha256": "a" * 64,
                "model": "RS500A-E12-RS12U",
                "primary_serial": "RAS0MD0000HU",
            }
            inventory = {
                "normalized": {
                    "bmc_ip": "10.1.10.200",
                    "components": [{"category": "MANAGEMENT_MODULE", "model": "ASMB11-iKVM"}],
                },
                "summary": {},
            }
            first_login_provisioned = {
                "state": "BMC_AUTH_PROVISIONED",
                "usable_for_authenticated_get": True,
                "host": "10.1.10.200",
            }
            with patch.object(
                workflow,
                "_discover_bmc_auth",
                return_value=first_login_provisioned,
            ) as discover, patch("cnserverops.production.recover_asus_bmc") as recover:
                observed_inventory, observed, receipt = workflow._ensure_authenticated_firmware_access(
                    run_dir=root / "run",
                    identity=identity,
                    platform={"platform_id": "ASUS_SERVER", "vendor": "ASUS"},
                    probe=SimpleNamespace(),
                    inventory=inventory,
                    firmware={
                        "generic_asus_firmware_engine": {
                            "platform": {"bmc_generation": "ASMB11"}
                        }
                    },
                    run_id="RUN-FIRST-LOGIN",
                    runner_id="CNSSD-FIRST-LOGIN",
                    discovery={
                        "state": "BMC_PASSWORD_CHANGE_REQUIRED",
                        "host": "10.1.10.200",
                    },
                )
            self.assertEqual(inventory, observed_inventory)
            self.assertEqual("BMC_AUTH_PROVISIONED", observed["state"])
            self.assertTrue(observed["first_login_provisioning_attempted"])
            self.assertEqual(
                "DOCUMENTED_FIRST_LOGIN_PROVISIONED_WITHOUT_FACTORY_RECOVERY",
                receipt["reason"],
            )
            self.assertFalse(receipt["factory_recovery_started"])
            recover.assert_not_called()
            discover.assert_called_once()
            self.assertFalse(discover.call_args.kwargs["read_only"])
            self.assertTrue(discover.call_args.kwargs["allow_default_probe_after_observed_first_login"])
            self.assertTrue(discover.call_args.kwargs["ignore_provisioned_candidates"])

    def test_stale_first_login_endpoint_cannot_authorize_default_provisioning(self):
        """A saved password-change state is not trusted after the BMC IP moves."""
        with TemporaryDirectory() as folder:
            root = Path(folder)
            workflow = ProductionWorkflow(
                ProductionConfig(primary_root=root / "results"),
                runtime_version="test",
                executor=FakeExecutor(),
            )
            identity = {
                "server_id": "SERVER-FIRST-LOGIN-MISMATCH",
                "fingerprint_sha256": "b" * 64,
                "model": "RS700-E12-RS12U",
                "primary_serial": "TAS0MD00001P",
            }
            inventory = {
                "normalized": {
                    "bmc_ip": "10.1.10.201",
                    "components": [{"category": "MANAGEMENT_MODULE", "model": "ASMB12-SCM"}],
                },
                "summary": {},
            }
            recovery = SimpleNamespace(
                to_dict=lambda: {
                    "status": "FAILED",
                    "reset_requested": False,
                    "method": "ASUS_ASMB12_KCS_FACTORY_DEFAULT_RAW_32_66",
                }
            )
            with patch.object(workflow, "_discover_bmc_auth") as discover, patch(
                "cnserverops.production.recover_asmb12_bmc",
                return_value=recovery,
            ) as recover:
                _inventory, observed, _receipt = workflow._ensure_authenticated_firmware_access(
                    run_dir=root / "run",
                    identity=identity,
                    platform={"platform_id": "ASUS_SERVER", "vendor": "ASUS"},
                    probe=SimpleNamespace(),
                    inventory=inventory,
                    firmware={
                        "generic_asus_firmware_engine": {
                            "platform": {"bmc_generation": "ASMB12"}
                        }
                    },
                    run_id="RUN-FIRST-LOGIN-MISMATCH",
                    runner_id="CNSSD-FIRST-LOGIN-MISMATCH",
                    discovery={
                        "state": "BMC_PASSWORD_CHANGE_REQUIRED",
                        "host": "10.1.10.200",
                    },
                )
            discover.assert_not_called()
            recover.assert_called_once()
            self.assertEqual("BMC_PASSWORD_CHANGE_REQUIRED", observed["state"])

    def test_handoff_waits_for_central_and_primary_archive_hash_proof(self):
        base = {"reports": "PASS", "artifact_delivery": "PASS", "primary_archive": "PASS"}
        self.assertFalse(
            _bmc_handoff_delivery_ready(
                base,
                artifact_sync={"status": "PENDING_UPLOAD"},
                event_queue_status="SYNCED",
            )
        )
        self.assertFalse(
            _bmc_handoff_delivery_ready(
                base,
                artifact_sync={"status": "SYNCED"},
                event_queue_status="PENDING_UPLOAD",
            )
        )
        self.assertTrue(
            _bmc_handoff_delivery_ready(
                base,
                artifact_sync={"status": "SYNCED"},
                event_queue_status="SYNCED",
            )
        )

    def test_option5_handoff_waits_for_final_report_delivery(self):
        """Option 5 may reset BMC auth only after its final report is archived."""
        with TemporaryDirectory() as folder:
            root = Path(folder)
            results = root / "results"
            identity = {
                "resumable": True,
                "server_id": "SERVER-OPTION5",
                "fingerprint_sha256": "a" * 64,
                "primary_serial": "SERIAL-OPTION5",
                "vendor": "ASUS",
                "platform_id": "ASUS_SERVER",
                "model": "RS500A-E12-RS12U",
                "confidence": "high",
                "boot_id": "boot-option5",
            }
            platform = {"platform_id": "ASUS_SERVER", "vendor": "ASUS"}
            orchestrator = ProductionOrchestrator(results, runtime_version="unit")
            context = orchestrator.start(
                platform=platform,
                identity=identity,
                runner_id="CNSSD-OPTION5-UNIT",
                workflow_mode="FIRMWARE_ONLY",
                test_profile="FIRMWARE_ONLY",
            )
            context = orchestrator.transition(
                context,
                identity=identity,
                next_stage=WorkflowStage.CAPABILITY_DISCOVERY,
                details={},
            )
            context = orchestrator.transition(
                context,
                identity=identity,
                next_stage=WorkflowStage.INVENTORY,
                details={
                    "storage": {"status": "PASS"},
                    "network": {"status": "PASS"},
                    "pcie": {"status": "PASS"},
                    "sensors": {"status": "PASS"},
                    "runner_storage": {"smart_status": "UNAVAILABLE"},
                },
            )
            context = orchestrator.transition(
                context,
                identity=identity,
                next_stage=WorkflowStage.FIRMWARE_PLAN,
                details={},
            )
            run_id = str(context["run"]["run_id"])
            run_dir = results / "runs" / run_id
            normalized = {
                "system_serial": identity["primary_serial"],
                "server_id": identity["server_id"],
                "vendor": "ASUS",
            }
            inventory = {
                "normalized": normalized,
                "summary": {"runner_storage": {"smart_status": "UNAVAILABLE"}},
            }
            plan = {
                "readiness": "CURRENT_VERIFIED",
                "components": [
                    {
                        "component": "BMC",
                        "before": "1.2.37",
                        "current": "1.2.37",
                        "target": "1.2.37",
                        "status": "CURRENT_VERIFIED",
                    }
                ],
            }

            class Queue:
                @staticmethod
                def status_for_run(_run_id):
                    return "SYNCED"

            workflow = ProductionWorkflow(
                ProductionConfig(primary_root=results),
                runtime_version="unit",
                executor=FakeExecutor(),
            )
            order = []
            report_counter = 0

            def reports(*_args, **kwargs):
                nonlocal report_counter
                report_counter += 1
                variant = str(kwargs.get("report_variant") or "BASE")
                order.append("report:" + variant)
                return {
                    "artifacts": [
                        {
                            "type": "PRODUCTION_PDF",
                            "path": str(run_dir / f"report-{report_counter}.pdf"),
                            "sha256": str(report_counter) * 64,
                        }
                    ]
                }

            def synced(_run_id, manifest, _client):
                kinds = {str(item.get("type") or "") for item in manifest.get("artifacts") or []}
                marker = "ADDENDUM" if "OPTION5_POST_HANDOFF_ADDENDUM" in kinds else "REPORT"
                order.append("sync:" + marker)
                return {
                    "status": "SYNCED",
                    "records": [
                        {
                            "central_response": {
                                "primary_archive": {"status": "SYNCED", "sha256": "b" * 64},
                                "secondary_archive": {"status": "SYNCED", "sha256": "b" * 64},
                            }
                        }
                    ],
                }

            def handoff(**_kwargs):
                order.append("handoff")
                self.assertIn("report:FINAL_PRE_HANDOFF", order)
                self.assertGreater(order.index("handoff"), order.index("report:FINAL_PRE_HANDOFF"))
                self.assertGreater(order.index("handoff"), order.index("sync:REPORT"))
                return {
                    "schema_version": 1,
                    "status": "PASS",
                    "reset_requested": True,
                    "default_state": "VERIFIED",
                    "sensitive_material_exposed": False,
                }

            with patch("cnserverops.production.generate_human_reports", side_effect=reports), patch(
                "cnserverops.production.report_manifest_complete", return_value=True
            ), patch.object(workflow, "_sync_artifacts", side_effect=synced), patch.object(
                workflow, "_perform_bmc_handoff", side_effect=handoff
            ), patch.object(
                workflow, "_enqueue_and_drain", return_value={"queue_status": "SYNCED"}
            ):
                result = workflow._complete_firmware_only_run(
                    orchestrator=orchestrator,
                    context=context,
                    identity=identity,
                    inventory=inventory,
                    discovery={"state": "BMC_AUTH_PROVISIONED"},
                    plan=plan,
                    execution={"status": "CURRENT_VERIFIED", "mutation_started": False},
                    run_dir=run_dir,
                    client=object(),
                    central_runtime={"status": "TEST_OVERRIDE"},
                    queue=Queue(),
                    bmc_auth_changed=True,
                    resumed=False,
                )

            self.assertEqual(2, report_counter)
            self.assertLess(order.index("report:FINAL_PRE_HANDOFF"), order.index("handoff"))
            self.assertLess(order.index("handoff"), order.index("sync:ADDENDUM"))
            addenda = list(run_dir.glob("CNServerOps_Option5_Post_Handoff_*.json"))
            self.assertEqual(1, len(addenda))
            addendum = json.loads(addenda[0].read_text(encoding="utf-8"))
            self.assertEqual("CNSERVEROPS_OPTION5_POST_HANDOFF_ADDENDUM", addendum["record_type"])
            self.assertEqual("PASS", addendum["status"])
            self.assertEqual("SYNCED", result["result"]["post_handoff_addendum_delivery"]["status"])
            self.assertNotIn("password", json.dumps(addendum).lower())

    def test_deferred_handoff_cannot_cross_server_identity(self):
        with TemporaryDirectory() as folder:
            root = Path(folder)
            runs = root / "results" / "runs" / "RUN-20260821T000000Z-ABCDEF12"
            runs.mkdir(parents=True)
            (runs / "bmc-handoff-pending.json").write_text(
                json.dumps(
                    {
                        "status": "PENDING",
                        "run_id": runs.name,
                        "server_id": "SERVER-OTHER",
                        "fingerprint_sha256": "b" * 64,
                    }
                ),
                encoding="utf-8",
            )
            workflow = ProductionWorkflow(
                ProductionConfig(primary_root=root / "results"),
                runtime_version="test",
                executor=FakeExecutor(),
            )
            with patch(
                "cnserverops.production.detect_current_platform_and_identity",
                return_value=(SimpleNamespace(), {}, {"resumable": True, "server_id": "SERVER-CURRENT", "fingerprint_sha256": "a" * 64}, {}),
            ):
                result = workflow._retry_pending_bmc_handoffs(object())
            self.assertEqual(0, result["attempted"])
            self.assertEqual(1, result["deferred"])
            self.assertTrue((runs / "bmc-handoff-pending.json").exists())

    def test_deferred_handoff_publishes_post_handoff_final_report(self):
        """A delayed factory reset must update human reports after it passes."""
        with TemporaryDirectory() as folder:
            root = Path(folder)
            run_dir = root / "results" / "runs" / "RUN-20260821T000001Z-HANDOFF"
            (run_dir / "evidence").mkdir(parents=True)
            (run_dir / "diagnostics").mkdir(parents=True)
            identity = {
                "resumable": True,
                "server_id": "SERVER-CURRENT",
                "fingerprint_sha256": "a" * 64,
                "primary_serial": "SERIAL-HANDOFF",
            }
            (run_dir / "bmc-handoff-pending.json").write_text(
                json.dumps(
                    {
                        "status": "PENDING",
                        "run_id": run_dir.name,
                        "server_id": identity["server_id"],
                        "fingerprint_sha256": identity["fingerprint_sha256"],
                        "expected_bmc_version": "1.32",
                    }
                ),
                encoding="utf-8",
            )
            # Option 5 post-reboot resume writes the fresh inventory under a
            # phase-qualified name and may have no canonical inventory file.
            # The durable handoff retry must consume this exact same-server
            # snapshot instead of failing with FileNotFoundError.
            (run_dir / "normalized-inventory-post-reboot.json").write_text(
                json.dumps(
                    {
                        "run_id": run_dir.name,
                        "server_id": identity["server_id"],
                        "system_serial": "SERIAL-HANDOFF",
                        "vendor": "ASUS",
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "firmware-plan.json").write_text(json.dumps({"components": []}), encoding="utf-8")
            (run_dir / "evidence" / "hardware-test-summary.json").write_text(
                json.dumps({"status": "PASS"}), encoding="utf-8"
            )
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run": {"run_id": run_dir.name, "workflow_mode": "PRODUCTION_EXTENDED", "final_disposition": "REVIEW"},
                        "finalization": {},
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "result-summary.json").write_text(
                json.dumps(
                    {
                        "normalized_result": {
                            "overall": "REVIEW",
                            "reports": "PASS",
                            "system_diagnostics": "UNSUPPORTED",
                        }
                    }
                ),
                encoding="utf-8",
            )

            class Queue:
                def __init__(self, *_args, **_kwargs):
                    pass

                def status_for_run(self, _run_id):
                    return "SYNCED"

            workflow = ProductionWorkflow(
                ProductionConfig(primary_root=root / "results"),
                runtime_version="test",
                executor=FakeExecutor(),
            )
            sync_results = iter(
                [
                    {"status": "SYNCED", "artifacts": []},
                    {"status": "SYNCED", "artifacts": []},
                ]
            )
            with patch(
                "cnserverops.production.detect_current_platform_and_identity",
                return_value=(SimpleNamespace(), {}, identity, {}),
            ), patch("cnserverops.production.ArtifactStoreForwardQueue", Queue), patch(
                "cnserverops.production.StoreForwardQueue", Queue
            ), patch.object(
                workflow,
                "_perform_bmc_handoff",
                return_value={"status": "PASS", "reset_requested": True, "sensitive_material_exposed": False},
            ), patch.object(workflow, "_sync_artifacts", side_effect=lambda *_args, **_kwargs: next(sync_results)), patch(
                "cnserverops.production.evaluate_handoff",
                return_value={"overall": "PASS", "handoff_status": "PASS", "component_statuses": {}},
            ) as handoff_eval_mock, patch(
                "cnserverops.production.generate_human_reports",
                return_value={"artifacts": [{"type": "PRODUCTION_PDF"}]},
            ) as report_mock, patch(
                "cnserverops.production.run_completed_event", return_value={"event": "RUN_COMPLETED"}
            ), patch(
                "cnserverops.production.RunRecord.from_dict", return_value=SimpleNamespace()
            ), patch.object(
                workflow, "_enqueue_and_drain", return_value={"status": "SYNCED"}
            ):
                result = workflow._retry_pending_bmc_handoffs(object())

            self.assertEqual(1, result["completed"], result)
            self.assertFalse((run_dir / "bmc-handoff-pending.json").exists())
            variants = [call.kwargs.get("report_variant") for call in report_mock.call_args_list]
            self.assertTrue(
                any(str(variant or "").startswith("HANDOFF_FINAL_") for variant in variants),
                variants,
            )
            policy = handoff_eval_mock.call_args.kwargs["policy"]
            for required in ("firmware_update", "reports", "artifact_delivery", "primary_archive"):
                self.assertIn(required, policy.required_for_production)

    def test_deferred_handoff_inventory_fallback_is_ordered_and_identity_bound(self):
        with TemporaryDirectory() as folder:
            run_dir = Path(folder) / "RUN-20260824T000001Z-FALLBACK"
            run_dir.mkdir()
            pending = {
                "run_id": run_dir.name,
                "server_id": "SERVER-CURRENT",
                "system_serial": "SERIAL-CURRENT",
            }
            identity = {
                "server_id": "SERVER-CURRENT",
                "primary_serial": "SERIAL-CURRENT",
            }
            recovery = {
                "run_id": run_dir.name,
                "server_id": "SERVER-CURRENT",
                "system_serial": "SERIAL-CURRENT",
                "source_marker": "POST_RECOVERY",
            }
            canonical = dict(recovery) | {"source_marker": "CANONICAL"}
            (run_dir / "normalized-inventory-post-bmc-recovery.json").write_text(
                json.dumps(recovery), encoding="utf-8"
            )
            (run_dir / "normalized-inventory.json").write_text(
                json.dumps(canonical), encoding="utf-8"
            )

            loaded = ProductionWorkflow._load_pending_handoff_inventory(
                run_dir=run_dir,
                pending=pending,
                current_identity=identity,
            )
            self.assertEqual("POST_RECOVERY", loaded["source_marker"])

            # An existing fresher snapshot from another physical server must
            # fail closed; it may not silently fall through to older matching
            # evidence and authorize a BMC factory handoff.
            (run_dir / "normalized-inventory-post-reboot.json").write_text(
                json.dumps(
                    {
                        "run_id": run_dir.name,
                        "server_id": "SERVER-OTHER",
                        "system_serial": "SERIAL-OTHER",
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "HANDOFF_INVENTORY_IDENTITY_MISMATCH"):
                ProductionWorkflow._load_pending_handoff_inventory(
                    run_dir=run_dir,
                    pending=pending,
                    current_identity=identity,
                )


if __name__ == "__main__":
    unittest.main()
