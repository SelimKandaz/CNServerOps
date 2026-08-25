import hashlib
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cnserverops.firmware import (
    FirmwareApplicabilityStatus,
    FirmwarePackageMetadata,
    FirmwareRepository,
    FirmwareRepositoryError,
    RunFirmwareTarget,
    RunFirmwareTargetStore,
    evaluate_applicability,
)
from cnserverops.firmware_executor import (
    FirmwarePreview,
    FirmwareUpdateExecutor,
    UpdateTask,
    UpdateTaskState,
)
from cnserverops.safety import MutationBlockedError, MutationGate


class NeverDownloader:
    def __init__(self):
        self.called = False

    def download(self, source_url, destination):
        self.called = True
        raise AssertionError("cache hit must not download")


class CountingDownloader:
    def __init__(self, payload):
        self.payload = payload
        self.calls = 0
        self.lock = threading.Lock()

    def download(self, source_url, destination):
        with self.lock:
            self.calls += 1
        time.sleep(0.1)
        destination.write_bytes(self.payload)


class FakeUpdateAdapter:
    name = "simulated-update-adapter"

    def __init__(self, terminal=UpdateTaskState.COMPLETED, installed="2.0"):
        self.terminal = terminal
        self.installed = installed
        self.poll_count = 0

    def preview(self, package, metadata):
        return FirmwarePreview(True, self.name, metadata.component, "1.0", metadata.version, False, {"simulated": True})

    def start(self, package, metadata):
        return UpdateTask("TASK-001", UpdateTaskState.RUNNING)

    def poll(self, task_id):
        self.poll_count += 1
        return UpdateTask(task_id, self.terminal, "simulated terminal state")

    def read_installed_version(self, component):
        return self.installed


class SequenceUpdateAdapter(FakeUpdateAdapter):
    def __init__(self, states, installed="2.0"):
        super().__init__(installed=installed)
        self.states = list(states)

    def poll(self, task_id):
        self.poll_count += 1
        state = self.states.pop(0) if self.states else UpdateTaskState.UNKNOWN
        return UpdateTask(task_id, state, "simulated state transition")


class FirmwareEngineTests(unittest.TestCase):
    def setUp(self):
        self.payload = b"fixture firmware package bytes"
        self.digest = hashlib.sha256(self.payload).hexdigest()
        self.metadata = FirmwarePackageMetadata(
            vendor="ASUS",
            component="BMC",
            version="2.0",
            package_filename="asus-bmc-2.0.bin",
            sha256=self.digest,
            source="unit-test fixture",
            source_url="https://vendor.example/asus-bmc-2.0.bin",
            compatible_models=("RS700A-E13-RS12U",),
            compatible_boards=("BOARD-X",),
            install_mechanism="SIMULATED",
            reboot_requirement="NO",
            validation_status="CHECKSUM_VERIFIED",
            applicability_evidence=("fixture catalog",),
        )
        self.identity = {
            "vendor": "ASUS",
            "model": "RS700A-E13-RS12U",
            "fingerprint_sha256": "a" * 64,
            "mutation_eligible": True,
        }
        self.catalog = {
            "catalog_id": "CAT-001",
            "component": "BMC",
            "version": "2.0",
            "applicability": "APPLICABLE",
        }

    def test_repository_rejects_checksum_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "package.bin"
            source.write_bytes(b"wrong bytes")
            with self.assertRaises(FirmwareRepositoryError):
                FirmwareRepository(Path(folder) / "repo").ingest(source, self.metadata)

    def test_cache_hit_is_verified_without_redownload(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "package.bin"
            source.write_bytes(self.payload)
            repository = FirmwareRepository(Path(folder) / "repo")
            repository.ingest(source, self.metadata)
            downloader = NeverDownloader()
            path, status = repository.fetch_if_missing(self.metadata, downloader=downloader)
            self.assertEqual("CACHE_HIT_CHECKSUM_VERIFIED", status)
            self.assertEqual(self.digest, path.name)
            self.assertFalse(downloader.called)

    def test_six_concurrent_runners_download_identical_binary_once(self):
        with tempfile.TemporaryDirectory() as folder:
            repository = FirmwareRepository(Path(folder) / "repo")
            downloader = CountingDownloader(self.payload)
            with ThreadPoolExecutor(max_workers=6) as pool:
                results = list(
                    pool.map(
                        lambda _: repository.fetch_if_missing(self.metadata, downloader=downloader),
                        range(6),
                    )
                )
            self.assertEqual(1, downloader.calls)
            self.assertEqual(1, sum(status == "DOWNLOADED_AND_CHECKSUM_VERIFIED" for _, status in results))
            self.assertEqual(5, sum(status == "CACHE_HIT_CHECKSUM_VERIFIED" for _, status in results))
            self.assertTrue(all(path.name == self.digest for path, _ in results))

    def test_run_target_cannot_change_after_latest_selection_is_locked(self):
        with tempfile.TemporaryDirectory() as folder:
            store = RunFirmwareTargetStore(Path(folder) / "targets")
            target = RunFirmwareTarget(
                component="BMC",
                version="2.0",
                package_sha256=self.digest,
                package_filename=self.metadata.package_filename,
                catalog_id="CAT-001",
                source_url=self.metadata.source_url,
            )
            first = store.lock("RUN-001", target)
            second = store.lock("RUN-001", target)
            self.assertEqual(first, second)
            with self.assertRaises(FirmwareRepositoryError):
                store.lock(
                    "RUN-001",
                    RunFirmwareTarget(
                        component="BMC",
                        version="2.1",
                        package_sha256="f" * 64,
                        package_filename="new.bin",
                        catalog_id="CAT-002",
                        source_url="https://vendor.example/new.bin",
                    ),
                )

    def test_cached_file_does_not_bypass_applicability(self):
        mismatch = evaluate_applicability(
            self.metadata,
            identity={**self.identity, "model": "UNRELATED-MODEL"},
            current_version="1.0",
            catalog_entry=self.catalog,
        )
        self.assertEqual(FirmwareApplicabilityStatus.BLOCKED, mismatch.status)
        self.assertIn("PACKAGE_PLATFORM_MISMATCH", mismatch.reason_codes)
        unavailable = evaluate_applicability(
            self.metadata,
            identity=self.identity,
            current_version="1.0",
            catalog_entry=None,
        )
        self.assertEqual(FirmwareApplicabilityStatus.BLOCKED, unavailable.status)

    def test_executor_gate_and_failed_task_are_fail_safe(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "package.bin"
            source.write_bytes(self.payload)
            repository = FirmwareRepository(Path(folder) / "repo")
            repository.ingest(source, self.metadata)
            decision = evaluate_applicability(
                self.metadata, identity=self.identity, current_version="1.0", catalog_entry=self.catalog
            )
            executor = FirmwareUpdateExecutor(repository)
            with self.assertRaises(MutationBlockedError):
                executor.execute(
                    identity=self.identity,
                    metadata=self.metadata,
                    applicability=decision,
                    adapter=FakeUpdateAdapter(),
                    mutation_gate=MutationGate(),
                )
            gate = MutationGate(
                authorized=True,
                lab_mode=True,
                approval_id="SIMULATION-ONLY",
                machine_fingerprint_sha256="a" * 64,
                allowed_actions=frozenset({"FIRMWARE_APPLY"}),
            )
            result = executor.execute(
                identity=self.identity,
                metadata=self.metadata,
                applicability=decision,
                adapter=FakeUpdateAdapter(terminal=UpdateTaskState.FAILED),
                mutation_gate=gate,
            )
            self.assertEqual("FAILED", result["status"])
            self.assertEqual("FIRMWARE_UPDATE_FAILED", result["reason_code"])

    def test_executor_simulation_verifies_post_update_version(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "package.bin"
            source.write_bytes(self.payload)
            repository = FirmwareRepository(Path(folder) / "repo")
            repository.ingest(source, self.metadata)
            decision = evaluate_applicability(
                self.metadata, identity=self.identity, current_version="1.0", catalog_entry=self.catalog
            )
            gate = MutationGate(
                authorized=True,
                lab_mode=True,
                approval_id="SIMULATION-ONLY",
                machine_fingerprint_sha256="a" * 64,
                allowed_actions=frozenset({"FIRMWARE_APPLY"}),
            )
            result = FirmwareUpdateExecutor(repository).execute(
                identity=self.identity,
                metadata=self.metadata,
                applicability=decision,
                adapter=FakeUpdateAdapter(),
                mutation_gate=gate,
            )
            self.assertEqual("SUCCESS", result["status"])
            self.assertEqual("VERSION_VERIFIED", result["reason_code"])

    def test_executor_resume_polls_existing_task_without_starting_again(self):
        class NoStartAdapter(FakeUpdateAdapter):
            def __init__(self):
                super().__init__()
                self.start_calls = 0

            def start(self, package, metadata):
                self.start_calls += 1
                raise AssertionError("durable task resume must not call adapter.start")

        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "package.bin"
            source.write_bytes(self.payload)
            repository = FirmwareRepository(Path(folder) / "repo")
            repository.ingest(source, self.metadata)
            adapter = NoStartAdapter()
            result = FirmwareUpdateExecutor(repository).resume_task(
                identity=self.identity,
                metadata=self.metadata,
                adapter=adapter,
                task_id="TASK-EXISTING",
                run_id="RUN-RESUME",
            )
            self.assertEqual("SUCCESS", result["status"])
            self.assertEqual(0, adapter.start_calls)
            self.assertEqual("TASK-EXISTING", result["task_id"])

    def test_expected_bmc_restart_transition_can_recover_before_completion(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "package.bin"
            source.write_bytes(self.payload)
            repository = FirmwareRepository(Path(folder) / "repo")
            repository.ingest(source, self.metadata)
            decision = evaluate_applicability(
                self.metadata, identity=self.identity, current_version="1.0", catalog_entry=self.catalog
            )
            gate = MutationGate(
                authorized=True,
                lab_mode=True,
                approval_id="SIMULATION-ONLY",
                machine_fingerprint_sha256="a" * 64,
                allowed_actions=frozenset({"FIRMWARE_APPLY"}),
            )
            result = FirmwareUpdateExecutor(repository).execute(
                identity=self.identity,
                metadata=self.metadata,
                applicability=decision,
                adapter=SequenceUpdateAdapter(
                    [UpdateTaskState.BMC_RESTARTING, UpdateTaskState.RUNNING, UpdateTaskState.COMPLETED]
                ),
                mutation_gate=gate,
            )
            self.assertEqual("SUCCESS", result["status"])
            self.assertIn("BMC_RESTARTING", [item["state"] for item in result["task_history"]])

    def test_cancelled_and_completed_with_warning_states_are_not_hidden(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "package.bin"
            source.write_bytes(self.payload)
            repository = FirmwareRepository(Path(folder) / "repo")
            repository.ingest(source, self.metadata)
            decision = evaluate_applicability(
                self.metadata, identity=self.identity, current_version="1.0", catalog_entry=self.catalog
            )
            gate = MutationGate(
                authorized=True,
                lab_mode=True,
                approval_id="SIMULATION-ONLY",
                machine_fingerprint_sha256="a" * 64,
                allowed_actions=frozenset({"FIRMWARE_APPLY"}),
            )
            cancelled = FirmwareUpdateExecutor(repository).execute(
                identity=self.identity,
                metadata=self.metadata,
                applicability=decision,
                adapter=FakeUpdateAdapter(terminal=UpdateTaskState.CANCELLED),
                mutation_gate=gate,
            )
            warning = FirmwareUpdateExecutor(repository).execute(
                identity=self.identity,
                metadata=self.metadata,
                applicability=decision,
                adapter=FakeUpdateAdapter(terminal=UpdateTaskState.COMPLETED_WITH_WARNING),
                mutation_gate=gate,
            )
            self.assertEqual("UPDATE_TASK_CANCELLED", cancelled["reason_code"])
            self.assertEqual("SUCCESS_WITH_WARNING", warning["status"])

    def test_exact_lab_authorization_binds_run_component_target_and_package(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "package.bin"
            source.write_bytes(self.payload)
            repository = FirmwareRepository(Path(folder) / "repo")
            repository.ingest(source, self.metadata)
            decision = evaluate_applicability(
                self.metadata, identity=self.identity, current_version="1.0", catalog_entry=self.catalog
            )
            gate = MutationGate(
                authorized=True,
                lab_mode=True,
                approval_id="PASS3-BOUND-SIMULATION",
                machine_fingerprint_sha256="a" * 64,
                vendor="ASUS",
                model="RS700A-E13-RS12U",
                run_id="RUN-EXACT",
                component="BMC",
                target_version="2.0",
                package_sha256=self.digest,
                allowed_actions=frozenset({"FIRMWARE_APPLY"}),
            )
            with self.assertRaises(MutationBlockedError):
                FirmwareUpdateExecutor(repository).execute(
                    identity=self.identity,
                    metadata=self.metadata,
                    applicability=decision,
                    adapter=FakeUpdateAdapter(),
                    mutation_gate=gate,
                    run_id="RUN-WRONG",
                )
            result = FirmwareUpdateExecutor(repository).execute(
                identity=self.identity,
                metadata=self.metadata,
                applicability=decision,
                adapter=FakeUpdateAdapter(),
                mutation_gate=gate,
                run_id="RUN-EXACT",
            )
            self.assertEqual("SUCCESS", result["status"])


if __name__ == "__main__":
    unittest.main()
