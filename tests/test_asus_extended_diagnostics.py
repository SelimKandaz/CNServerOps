import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from cnserverops.asus_diagnostics import (
    Asmb12WebClient,
    Asmb12WebError,
    DiagnosticCredentials,
    discover_asmb12_diagnostics,
    execute_asmb12_diagnostics,
)
from cnserverops.central_api import _archive_run_type
from cnserverops.handoff import HandoffPolicy, evaluate_handoff
from cnserverops.production import ProductionWorkflow, _final_decision_from_handoff


def _zip_bytes(text: str = "diagnostic complete\n") -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("system-diagnostics.txt", text)
    return stream.getvalue()


class FakeAsmb12Client:
    artifact = _zip_bytes()
    mode = "pass"
    instances = 0

    def __init__(self, host, credentials, *, verify_tls=False, timeout_seconds=30):
        type(self).instances += 1
        self.polls = 0

    def login(self):
        return {"status": "AUTHENTICATED", "privilege": "administrator", "csrf_present": True}

    def get_json(self, path):
        if path == "/api/configuration/project":
            features = [{"feature": "SYSTEM_DIAGNOSTICS"}] if self.mode != "unsupported" else []
            return 200, features
        if path == "/api/system_diagnostics/log":
            self.polls += 1
            if self.mode == "unsupported":
                raise Asmb12WebError(path, "UNSUPPORTED", http_status=404)
            if self.polls == 1:
                return 200, []
            return 200, [{"file_name": "diag.zip", "fileinfo": "complete"}]
        if path == "/api/system_diagnostics/generate_system_diagnostics_logs":
            return 200, {"status": "accepted"}
        raise AssertionError(path)

    def get_bytes(self, path, *, query=None):
        self.assert_path(path)
        return 200, self.artifact, "application/zip"

    @staticmethod
    def assert_path(path):
        if path != "/api/system_diagnostics/download_system_diagnostics_log":
            raise AssertionError(path)


class ExtendedDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        FakeAsmb12Client.instances = 0
        FakeAsmb12Client.mode = "pass"
        FakeAsmb12Client.artifact = _zip_bytes()

    def test_missing_credentials_is_auth_blocked_without_network(self):
        result = discover_asmb12_diagnostics("192.0.2.10", credentials=None)
        self.assertEqual("AUTH_BLOCKED", result["status"])
        self.assertEqual("NO_APPROVED_AUTHENTICATED_BMC_CREDENTIAL", result["reason"])

    def test_capability_discovery_marks_absent_feature_unsupported(self):
        FakeAsmb12Client.mode = "unsupported"
        with patch("cnserverops.asus_diagnostics.Asmb12WebClient", FakeAsmb12Client):
            result = discover_asmb12_diagnostics(
                "192.0.2.10", credentials=DiagnosticCredentials("admin", "secret")
            )
        self.assertEqual("UNSUPPORTED", result["status"])
        self.assertFalse(result["feature_advertised"])
        self.assertEqual(404, result["endpoint_status"]["log"])
        self.assertNotIn("secret", json.dumps(result))

    def test_client_constructs_cookie_aware_https_opener(self):
        client = Asmb12WebClient("192.0.2.10", DiagnosticCredentials("admin", "secret"))
        self.assertTrue(client.base_url.startswith("https://192.0.2.10/"))

    def test_asmb12_zero_ok_login_is_success(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return b'{"ok":0,"privilege":4,"user_id":3,"CSRFToken":"csrf"}'

        class Opener:
            def open(self, request, timeout):
                return Response()

        client = Asmb12WebClient("192.0.2.10", DiagnosticCredentials("admin", "secret"))
        client.opener = Opener()
        login = client.login()
        self.assertEqual("AUTHENTICATED", login["status"])
        self.assertTrue(login["csrf_present"])

    def test_supported_lifecycle_downloads_validates_and_hashes_vendor_zip(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch("cnserverops.asus_diagnostics.Asmb12WebClient", FakeAsmb12Client):
                result = execute_asmb12_diagnostics(
                    "192.0.2.10",
                    credentials=DiagnosticCredentials("admin", "secret"),
                    output_dir=Path(folder),
                    poll_seconds=0,
                    max_polls=3,
                )
            self.assertEqual("PASS", result["status"])
            artifact = result["artifact"]
            self.assertTrue(artifact["zip_valid"])
            self.assertEqual(hashlib.sha256(FakeAsmb12Client.artifact).hexdigest(), artifact["sha256"])
            self.assertTrue(Path(artifact["path"]).is_file())
            self.assertNotIn("secret", json.dumps(result))

    def test_vendor_findings_become_hardware_failure(self):
        FakeAsmb12Client.artifact = _zip_bytes("FAN ERROR: tachometer stopped\n")
        with tempfile.TemporaryDirectory() as folder:
            with patch("cnserverops.asus_diagnostics.Asmb12WebClient", FakeAsmb12Client):
                result = execute_asmb12_diagnostics(
                    "192.0.2.10",
                    credentials=DiagnosticCredentials("admin", "secret"),
                    output_dir=Path(folder),
                    poll_seconds=0,
                    max_polls=3,
                )
        self.assertEqual("HARDWARE_FAILURE", result["status"])
        self.assertTrue(result["findings"])
        FakeAsmb12Client.artifact = _zip_bytes()

    def test_extended_archive_type_and_required_diagnostic_policy(self):
        self.assertEqual("FULL_PRODUCTION_EXTENDED", _archive_run_type({"workflow_mode": "PRODUCTION_EXTENDED"}))
        statuses = {
            "collection": "PASS",
            "identity": "PASS",
            "serial_inventory": "PASS",
            "storage": "PASS",
            "nic": "PASS",
            "sensors": "PASS",
            "cpu": "PASS",
            "ram": "PASS",
            "firmware_update": "CURRENT",
            "system_diagnostics": "UNSUPPORTED",
            "sel_entries": 0,
            "sel_cleanup": "SUCCESS",
            "reports": "PASS",
            "central_sync": "PASS",
        }
        result = evaluate_handoff(
            statuses,
            workflow_mode="PRODUCTION_EXTENDED",
            policy=HandoffPolicy.from_mapping({"required_for_production": ["identity", "system_diagnostics"]}),
        )
        self.assertEqual("REVIEW_REQUIRED", result["handoff_status"])
        self.assertIn("system_diagnostics", result["required_capabilities"])
        self.assertTrue(any(item["capability"] == "system_diagnostics" for item in result["reviews"]))

    def test_option2_unsupported_diagnostics_does_not_leave_stale_review_decision(self):
        handoff = {
            "overall": "PASS",
            "handoff_status": "READY_FOR_HANDOFF",
            "failures": [],
            "reviews": [
                {"capability": "system_diagnostics", "status": "UNSUPPORTED"},
                {"capability": "runner_storage_smart", "status": "UNAVAILABLE"},
            ],
        }
        decision = _final_decision_from_handoff(handoff, workflow_mode="PRODUCTION_EXTENDED")
        self.assertEqual("PASS", decision["disposition"])
        self.assertEqual([], decision["reasons"])

    @staticmethod
    def _option2_final_statuses():
        return {
            "collection": "PASS",
            "serial_inventory": "PASS",
            "identity": "PASS",
            "storage": "PASS",
            "nic": "PASS",
            "pcie": "PASS",
            "sensors": "PASS",
            "cpu": "PASS",
            "ram": "PASS",
            "psu": "PASS",
            "fans": "PASS",
            "sel": "PASS",
            "firmware_update": "CURRENT",
            "reports": "PASS",
            "central_link": "PASS",
            "artifact_delivery": "PASS",
            "primary_archive": "PASS",
            "secondary_archive": "PASS",
            "system_diagnostics": "PLATFORM_UNSUPPORTED",
            "runner_storage_smart": "UNAVAILABLE",
            "bmc_access_state": "BMC_AUTH_UNAVAILABLE",
            "bmc_soft_reset": "NOT_PERFORMED",
            # These values were emitted by the earlier provisional handoff
            # evaluation and must not be evaluated as capabilities again.
            "overall": "REVIEW",
            "handoff_status": "REVIEW_REQUIRED",
            "readiness": "REVIEW_REQUIRED",
        }

    @staticmethod
    def _option2_final_policy():
        return HandoffPolicy.from_mapping(
            {
                "required_for_production": [
                    "cpu",
                    "ram",
                    "firmware_update",
                    "reports",
                    "artifact_delivery",
                    "primary_archive",
                ],
                "allow_optional_review_for_ready": True,
            }
        )

    def test_option2_final_handoff_ignores_optional_and_stale_aggregate_reviews(self):
        # This mirrors the final Option 2 re-evaluation: the mandatory
        # hardware, firmware, report, and delivery evidence passed, while
        # runner SMART is unavailable through its USB bridge, BMC access was
        # not needed, and the disabled soft reset remains explicit.  The
        # ASMB11 diagnostics limitation is recorded rather than treated as a
        # failed advertised capability.  The first (provisional) evaluation
        # left aggregate REVIEW values in the payload, which must not
        # recursively downgrade the final result.
        result = evaluate_handoff(
            self._option2_final_statuses(),
            workflow_mode="PRODUCTION_EXTENDED",
            policy=self._option2_final_policy(),
            bmc_auth_changed=False,
        )

        self.assertEqual("PASS", result["overall"])
        self.assertEqual("READY_FOR_HANDOFF", result["handoff_status"])
        self.assertNotIn("overall", result["component_statuses"])
        self.assertNotIn("handoff_status", result["component_statuses"])
        self.assertNotIn("readiness", result["component_statuses"])
        self.assertEqual(
            {
                ("system_diagnostics", "PLATFORM_UNSUPPORTED"),
                ("runner_storage_smart", "UNAVAILABLE"),
                ("bmc_access_state", "BMC_AUTH_UNAVAILABLE"),
                ("bmc_soft_reset", "NOT_PERFORMED"),
            },
            {(item["capability"], item["status"]) for item in result["reviews"]},
        )

    def test_option2_final_handoff_keeps_update_required_blocking(self):
        statuses = self._option2_final_statuses()
        statuses["firmware_update"] = "UPDATE_REQUIRED"
        result = evaluate_handoff(
            statuses,
            workflow_mode="PRODUCTION_EXTENDED",
            policy=self._option2_final_policy(),
        )

        self.assertEqual("FAIL", result["overall"])
        self.assertEqual("NOT_READY", result["handoff_status"])
        self.assertIn(
            {"capability": "firmware_update", "status": "UPDATE_REQUIRED"}, result["failures"]
        )

    def test_option2_final_handoff_keeps_changed_bmc_handoff_mandatory(self):
        result = evaluate_handoff(
            self._option2_final_statuses(),
            workflow_mode="PRODUCTION_EXTENDED",
            policy=self._option2_final_policy(),
            bmc_auth_changed=True,
            bmc_handoff_status="FAIL",
        )

        self.assertEqual("FAIL", result["overall"])
        self.assertEqual("NOT_READY", result["handoff_status"])
        self.assertIn({"capability": "bmc_auth_handoff", "status": "FAIL"}, result["failures"])

    def test_asmb11_option2_reports_platform_unsupported_without_bmc_auth(self):
        # ASMB11 does not advertise ASUS' ASMB12 System Diagnostics WebUI
        # API.  This must not trigger BMC recovery/provisioning or downgrade
        # the Option 2 result merely because its default account requires a
        # password change.
        with tempfile.TemporaryDirectory() as folder:
            result = ProductionWorkflow._run_extended_diagnostics(
                object(),
                Path(folder),
                inventory={"normalized": {"bmc_ip": "192.0.2.10", "bmc_generation": "ASMB11"}},
                bmc_auth_state="BMC_AUTH_REQUIRES_PASSWORD_CHANGE",
                bmc_auth_discovery={},
                platform={"bmc_generation": "ASMB11"},
            )
        self.assertEqual("PLATFORM_UNSUPPORTED", result["status"])
        self.assertEqual("ASMB11_SYSTEM_DIAGNOSTICS_ENDPOINT_NOT_ADVERTISED", result["reason"])

    def test_final_decision_keeps_real_handoff_failure(self):
        handoff = {
            "overall": "FAIL",
            "handoff_status": "NOT_READY",
            "failures": [{"capability": "cpu", "status": "FAIL"}],
            "reviews": [],
        }
        decision = _final_decision_from_handoff(handoff, workflow_mode="PRODUCTION_EXTENDED")
        self.assertEqual("FAIL", decision["disposition"])
        self.assertEqual("CPU_FAILED", decision["reasons"][0]["code"])


if __name__ == "__main__":
    unittest.main()
