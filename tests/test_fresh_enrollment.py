import json
import tempfile
import unittest
from pathlib import Path

from cnserverops.enrollment import reconcile_server_enrollment


class FreshEnrollmentTests(unittest.TestCase):
    def test_new_server_quarantines_only_explicit_current_state_and_preserves_runner(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            old_run = root / "runs" / "RUN-OLD"
            old_run.mkdir(parents=True)
            (old_run / "run.json").write_text(
                json.dumps(
                    {
                        "server": {
                            "server_id": "SERVER-OLD",
                            "fingerprint_sha256": "a" * 64,
                            "vendor": "ASUS",
                            "model": "RS500A-E12-RS12U",
                            "system_serial": "RAS0MD0000HU",
                        },
                        "run": {"run_id": "RUN-OLD", "started_at_utc": "2026-08-19T10:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            stale = root / "current-run.json"
            stale.write_text('{"server_id":"SERVER-OLD"}\n', encoding="utf-8")
            identity = {
                "identity_state": "TRUSTED_CURRENT",
                "fingerprint_sha256": "b" * 64,
                "server_id": "SERVER-NEW",
                "vendor": "ASUS",
                "model": "RS700-E12-RS12U",
                "primary_serial": "TAS0MD00001H",
                "boot_id": "4c3b0330-1221-41c2-ac5b-d6560476b900",
            }
            result = reconcile_server_enrollment(root, identity, runner_id="CNSSD-TEST")
            self.assertEqual("NEW_SERVER_ENROLLED", result["status"])
            self.assertEqual("CNSSD-TEST", result["runner_id_preserved"])
            self.assertFalse(result["previous_run_resumed"])
            self.assertFalse(result["old_mutation_gate_transferred"])
            self.assertEqual(["current-run.json"], result["quarantined_paths"])
            self.assertFalse(stale.exists())
            quarantine = Path(result["quarantine_directory"])
            self.assertEqual('{"server_id":"SERVER-OLD"}\n', (quarantine / "current-run.json").read_text())
            self.assertTrue((old_run / "run.json").is_file())

    def test_untrusted_identity_does_not_quarantine_or_enroll(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            stale = root / "current-run.json"
            stale.write_text("stale\n", encoding="utf-8")
            result = reconcile_server_enrollment(
                root,
                {"fingerprint_sha256": "", "identity_state": "UNTRUSTED", "resume_block_reason": "board conflict"},
                runner_id="CNSSD-TEST",
            )
            self.assertEqual("UNTRUSTED_IDENTITY", result["status"])
            self.assertTrue(stale.is_file())

    def test_new_server_quarantines_server_specific_bmc_secret_without_reading_it(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            old_run = root / "runs" / "RUN-OLD"
            old_run.mkdir(parents=True)
            (old_run / "run.json").write_text(
                json.dumps({
                    "server": {"server_id": "SERVER-OLD", "fingerprint_sha256": "a" * 64},
                    "run": {"run_id": "RUN-OLD", "started_at_utc": "2026-08-19T10:00:00Z"},
                }),
                encoding="utf-8",
            )
            secret = root / "secrets" / "asus-bmc-password"
            binding = root / "secrets" / "asus-bmc-password.binding.json"
            marker = root / "secrets" / "bmc-auth-change-state.json"
            secret.parent.mkdir(parents=True)
            secret.write_bytes(b"do-not-read-or-copy-into-evidence")
            binding.write_text(
                json.dumps({"schema_version": 1, "scope": "CN_SERVEROPS_TEMPORARY_BMC_OPERATIONAL_ACCOUNT", "server_id": "SERVER-OLD", "sensitive_material_persisted": False}),
                encoding="utf-8",
            )
            marker.write_text(
                json.dumps({"active": True, "server_id": "SERVER-OLD", "sensitive_material_exposed": False}),
                encoding="utf-8",
            )
            identity = {
                "identity_state": "TRUSTED_CURRENT",
                "fingerprint_sha256": "b" * 64,
                "server_id": "SERVER-NEW",
                "vendor": "ASUS",
                "model": "RS500A-E12-RS12U",
                "primary_serial": "RAS0MD0000HT",
                "boot_id": "new-boot",
            }
            result = reconcile_server_enrollment(
                root,
                identity,
                runner_id="CNSSD-TEST",
                server_specific_paths=(secret, binding, marker),
            )
            self.assertEqual("NEW_SERVER_ENROLLED", result["status"])
            self.assertFalse(secret.exists())
            self.assertFalse(binding.exists())
            self.assertFalse(marker.exists())
            self.assertIn("external-state/asus-bmc-password", result["quarantined_paths"])
            self.assertIn("external-state/asus-bmc-password.binding.json", result["quarantined_paths"])
            self.assertIn("external-state/bmc-auth-change-state.json", result["quarantined_paths"])
            quarantine = Path(result["quarantine_directory"])
            self.assertEqual(b"do-not-read-or-copy-into-evidence", (quarantine / "external-state/asus-bmc-password").read_bytes())


if __name__ == "__main__":
    unittest.main()
