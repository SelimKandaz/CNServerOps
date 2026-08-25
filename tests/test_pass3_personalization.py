import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cnserverops.clone_firstboot import storage_fingerprint_from_properties
from cnserverops.personalization import (
    ClonePersonalizationError,
    _refresh_runtime_pointer,
    personalize_clone,
    prepare_clone_template,
)


def make_template(root: Path, *, template_id: str = "GOLDEN-001", storage_required: bool = True) -> None:
    marker = root / "etc/cnserverops/clone-template.json"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "state": "READY_FOR_CLONE",
                "template_id": template_id,
                "regenerate_machine_id": True,
                "regenerate_ssh_host_keys": False,
                "require_storage_fingerprint": storage_required,
                "stale_state_paths": ["var/lib/cnserverops/runs", "var/lib/cnserverops/upload-queue.sqlite3"],
            }
        ),
        encoding="utf-8",
    )
    machine_id = root / "etc/machine-id"
    machine_id.parent.mkdir(parents=True, exist_ok=True)
    machine_id.write_text("0" * 32 + "\n", encoding="ascii")


class Pass3PersonalizationTests(unittest.TestCase):
    def test_prepare_template_quarantines_existing_runner_and_requires_explicit_acknowledgement(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            runner = root / "etc/cnserverops/runner.json"
            runner.parent.mkdir(parents=True, exist_ok=True)
            runner.write_text("{}", encoding="utf-8")
            with self.assertRaises(ClonePersonalizationError):
                prepare_clone_template(root, template_id="GOLDEN-002", authorized=False)
            result = prepare_clone_template(root, template_id="GOLDEN-002", authorized=True)
            self.assertEqual("READY_FOR_CLONE", result["state"])
            self.assertFalse(runner.exists())
            self.assertTrue(
                (root / "var/lib/cnserverops/template-quarantine/GOLDEN-002/etc/cnserverops/runner.json").is_file()
            )

    def test_prepare_template_quarantines_all_server_specific_state_before_clone(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            paths = (
                "var/lib/cnserverops/production/current.json",
                "CN_STRESS_RESULTS/runs/RUN-001/result.json",
                "etc/netplan/99-cnserverops-static.yaml",
                "etc/cnserverops/firmware-current-proof.json",
                "etc/cnserverops/secrets/asus-bmc-password",
                "etc/cnserverops/secrets/asus-bmc-password.binding.json",
                "var/lib/cnserverops/bmc-auth-change-state.json",
            )
            for relative in paths:
                source = root / relative
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text("server-specific\n", encoding="utf-8")

            result = prepare_clone_template(root, template_id="GOLDEN-003", authorized=True)
            self.assertEqual("READY_FOR_CLONE", result["state"])
            self.assertIn("var/lib/cnserverops/production", result["quarantined_stale_state_paths"])
            self.assertIn("CN_STRESS_RESULTS/runs", result["quarantined_stale_state_paths"])
            self.assertIn("etc/netplan/99-cnserverops-static.yaml", result["quarantined_network_paths"])
            for relative in paths:
                self.assertFalse((root / relative).exists())
                quarantine = root / "var/lib/cnserverops/template-quarantine/GOLDEN-003"
                bucket = "network" if relative.startswith("etc/netplan/") else "stale-state"
                self.assertTrue((quarantine / bucket / relative).exists())
            marker = json.loads((root / "etc/cnserverops/clone-template.json").read_text(encoding="utf-8"))
            self.assertEqual(set(result["quarantined_stale_state_paths"]), set(marker["quarantined_stale_state_paths"]))

    def test_existing_template_marker_finishes_stale_state_quarantine_idempotently(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            result = prepare_clone_template(root, template_id="GOLDEN-004", authorized=True)
            stale = root / "var/lib/cnserverops/production/current.json"
            stale.parent.mkdir(parents=True, exist_ok=True)
            stale.write_text("late-state\n", encoding="utf-8")
            restored_runner = root / "etc/cnserverops/runner.json"
            restored_runner.parent.mkdir(parents=True, exist_ok=True)
            restored_runner.write_text(
                json.dumps({"runner_id": "CNSSD-TEST", "local_runner_uuid": "UUID-TEST", "runtime_version": "2.0"}),
                encoding="utf-8",
            )
            quarantine_runner = root / "var/lib/cnserverops/template-quarantine/GOLDEN-004/etc/cnserverops/runner.json"
            quarantine_runner.parent.mkdir(parents=True, exist_ok=True)
            quarantine_runner.write_text(
                json.dumps({"runner_id": "CNSSD-TEST", "local_runner_uuid": "UUID-TEST", "runtime_version": "1.0"}),
                encoding="utf-8",
            )
            resumed = prepare_clone_template(root, template_id="GOLDEN-004", authorized=True)
            self.assertIn("var/lib/cnserverops/production", resumed["quarantined_stale_state_paths"])
            self.assertFalse(stale.exists())
            self.assertFalse(restored_runner.exists())
            self.assertTrue(
                (quarantine_runner.parent / "runner.json.reactivated").is_file()
            )
            self.assertTrue(
                (root / "var/lib/cnserverops/template-quarantine/GOLDEN-004/stale-state/var/lib/cnserverops/production/current.json").is_file()
            )

    def test_prepare_template_quarantines_current_server_enrollment_and_runtime_pointer(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            enrollment = root / "CN_STRESS_RESULTS/enrollment/latest.json"
            pointer = root / "opt/cnserverops/current.json"
            for path in (enrollment, pointer):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('{"server_id":"OLD"}\n', encoding="utf-8")
            result = prepare_clone_template(root, template_id="GOLDEN-005", authorized=True)
            self.assertIn("CN_STRESS_RESULTS/enrollment/latest.json", result["quarantined_stale_state_paths"])
            self.assertIn("opt/cnserverops/current.json", result["quarantined_stale_state_paths"])
            self.assertFalse(enrollment.exists())
            self.assertFalse(pointer.exists())
            enrollment.parent.mkdir(parents=True, exist_ok=True)
            pointer.parent.mkdir(parents=True, exist_ok=True)
            enrollment.write_text('{"server_id":"REINTRODUCED"}\n', encoding="utf-8")
            pointer.write_text('{"runner_id":"GOLDEN"}\n', encoding="utf-8")
            prepare_clone_template(root, template_id="GOLDEN-005", authorized=True)
            self.assertFalse(enrollment.exists())
            self.assertFalse(pointer.exists())
            quarantine = root / "var/lib/cnserverops/template-quarantine/GOLDEN-005/stale-state"
            self.assertTrue((quarantine / "CN_STRESS_RESULTS/enrollment/latest.json.reactivated").is_file())
            self.assertTrue((quarantine / "opt/cnserverops/current.json.reactivated").is_file())

    def test_personalize_refreshes_runtime_pointer_when_managed_symlink_exists(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            make_template(root)
            release = root / "opt/cnserverops/releases/3.0"
            release.mkdir(parents=True, exist_ok=True)
            current = root / "opt/cnserverops/current"
            try:
                current.symlink_to(release, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink creation unavailable on this test filesystem: {exc}")
            result = personalize_clone(root, runtime_version="3.0", storage_fingerprint="c" * 64)
            self.assertEqual("REFRESHED", result["receipt"]["runtime_pointer"]["status"])
            pointer = json.loads((root / "opt/cnserverops/current.json").read_text(encoding="utf-8"))
            self.assertEqual(result["runner_id"], pointer["runner_id"])
            self.assertEqual("CLONE_FIRSTBOOT", pointer["approval_id"])

    def test_personalize_reports_missing_runtime_symlink_without_failing(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            make_template(root)
            result = personalize_clone(root, runtime_version="3.0", storage_fingerprint="d" * 64)
            self.assertEqual("NOT_REFRESHED_NO_RUNTIME_SYMLINK", result["runtime_pointer"]["status"])

    def test_storage_fingerprint_uses_hardware_anchors_not_hostname(self):
        first = storage_fingerprint_from_properties({"ID_SERIAL": "SSD-001", "ID_WWN": "WWN-001"})
        second = storage_fingerprint_from_properties({"ID_SERIAL": "SSD-002", "ID_WWN": "WWN-002"})
        self.assertEqual(64, len(first))
        self.assertNotEqual(first, second)

    def test_unmarked_filesystem_is_never_modified(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ClonePersonalizationError) as raised:
                personalize_clone(Path(folder), runtime_version="3.0")
            self.assertEqual("CLONE_TEMPLATE_MARKER_MISSING", str(raised.exception))

    def test_first_boot_quarantines_stale_state_and_is_stable_afterward(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            make_template(root)
            stale = root / "var/lib/cnserverops/runs/stale.json"
            stale.parent.mkdir(parents=True, exist_ok=True)
            stale.write_text("{}", encoding="utf-8")
            storage = "a" * 64
            first = personalize_clone(root, runtime_version="3.0", storage_fingerprint=storage)
            second = personalize_clone(root, runtime_version="3.0", storage_fingerprint=storage)
            self.assertEqual("PERSONALIZED", first["status"])
            self.assertEqual("ALREADY_PERSONALIZED", second["status"])
            self.assertEqual(first["runner_id"], second["runner_id"])
            self.assertFalse(stale.exists())
            quarantined = root / "var/lib/cnserverops/quarantine" / first["transaction_id"] / "stale-state/var/lib/cnserverops/runs/stale.json"
            self.assertTrue(quarantined.is_file())
            self.assertEqual(32, len((root / "etc/machine-id").read_text(encoding="ascii").strip()))

    def test_first_boot_publishes_generic_netplan_and_native_networkd_dhcp(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            make_template(root)
            marker_path = root / "etc/cnserverops/clone-template.json"
            marker = json.loads(marker_path.read_text(encoding="utf-8"))
            marker["network_policy"] = {
                "mode": "DHCP_GENERIC",
                "path": "etc/netplan/99-cnserverops-dhcp.yaml",
                "networkd_path": "etc/systemd/network/10-cnserverops-dhcp.network",
            }
            marker_path.write_text(json.dumps(marker), encoding="utf-8")
            result = personalize_clone(root, runtime_version="3.0", storage_fingerprint="e" * 64)
            network = result["network"]
            self.assertFalse(network["static_address_present"])
            self.assertEqual(
                "etc/netplan/99-cnserverops-dhcp.yaml",
                network["path"],
            )
            self.assertEqual(
                "etc/systemd/network/10-cnserverops-dhcp.network",
                network["networkd_path"],
            )
            self.assertEqual(["en*", "eth*", "eno*"], network["matched_interface_globs"])
            netplan = (root / "etc/netplan/99-cnserverops-dhcp.yaml").read_text(encoding="utf-8")
            networkd = (root / "etc/systemd/network/10-cnserverops-dhcp.network").read_text(encoding="utf-8")
            self.assertIn("dhcp4: true", netplan)
            self.assertIn("Name=en* eth* eno*", networkd)
            self.assertIn("DHCP=ipv4", networkd)
            self.assertNotIn("10.1.10.155", netplan + networkd)

    def test_copied_personalized_runner_is_detected_on_different_storage(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            make_template(root)
            personalize_clone(root, runtime_version="3.0", storage_fingerprint="a" * 64)
            with self.assertRaises(ClonePersonalizationError) as raised:
                personalize_clone(root, runtime_version="3.0", storage_fingerprint="b" * 64)
            self.assertEqual("DUPLICATE_RUNNER_STORAGE_MISMATCH", str(raised.exception))

    def test_six_clones_receive_unique_runner_and_machine_ids(self):
        with tempfile.TemporaryDirectory() as folder:
            roots = []
            for index in range(6):
                root = Path(folder) / f"clone-{index}"
                root.mkdir()
                make_template(root)
                roots.append(root)
            with ThreadPoolExecutor(max_workers=6) as pool:
                results = list(
                    pool.map(
                        lambda pair: personalize_clone(
                            pair[1],
                            runtime_version="3.0",
                            storage_fingerprint=f"{pair[0] + 1:064x}",
                        ),
                        enumerate(roots),
                    )
                )
            self.assertEqual(6, len({item["runner_id"] for item in results}))
            self.assertEqual(6, len({(root / "etc/machine-id").read_text().strip() for root in roots}))


if __name__ == "__main__":
    unittest.main()
