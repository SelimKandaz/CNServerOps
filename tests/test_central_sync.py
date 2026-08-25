import io
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cnserverops.collector import CentralCollector, IdempotencyConflict
from cnserverops.central_api import CentralApiApp, CentralApiCredential
from cnserverops.models import RunRecord, ServerRecord, run_started_event
from cnserverops.sync import StoreForwardQueue, SyncQueueError
from cnserverops.secrets import SensitiveEvidenceError


class DownCollector:
    def ingest_event(self, event):
        raise ConnectionError("central unavailable")


class AcceptThenLoseResponse:
    def __init__(self, collector):
        self.collector = collector

    def ingest_event(self, event):
        self.collector.ingest_event(event)
        raise ConnectionError("response interrupted after commit")


def fixture_server():
    return ServerRecord(
        fingerprint_sha256="b" * 64,
        vendor="ASUS",
        model="RS700A-E13-RS12U",
        system_serial="SERIAL-001",
        board_serial="BOARD-001",
        chassis_serial="CHASSIS-001",
        confidence="high",
    )


class CentralSyncTests(unittest.TestCase):
    def test_queue_requires_local_authoritative_record(self):
        server = fixture_server()
        run = RunRecord.start(server, runner_id="CNSSD-01", runtime_version="2.0.0")
        event = run_started_event(run, server)
        with tempfile.TemporaryDirectory() as folder:
            queue = StoreForwardQueue(Path(folder) / "queue.sqlite3")
            with self.assertRaises((SyncQueueError, FileNotFoundError)):
                queue.enqueue(event, authoritative_record=Path(folder) / "missing.json")

    def test_central_outage_does_not_lose_or_fail_local_run(self):
        server = fixture_server()
        run = RunRecord.start(server, runner_id="CNSSD-01", runtime_version="2.0.0")
        event = run_started_event(run, server)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            authoritative = root / "run.json"
            authoritative.write_text(json.dumps(run.to_dict()), encoding="utf-8")
            queue = StoreForwardQueue(root / "queue.sqlite3")
            queue.enqueue(event, authoritative_record=authoritative)
            result = queue.drain(DownCollector())
            self.assertEqual(1, result["pending"])
            self.assertEqual("PENDING_UPLOAD", queue.status_for_run(run.run_id))
            self.assertTrue(authoritative.is_file())

    def test_invalid_event_can_be_quarantined_without_deletion(self):
        server = fixture_server()
        run = RunRecord.start(server, runner_id="CNSSD-01", runtime_version="3.1.2")
        event = run_started_event(run, server, bmc={"credential_state": "UNAVAILABLE"})
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            authoritative = root / "run.json"
            authoritative.write_text(json.dumps(run.to_dict()), encoding="utf-8")
            queue = StoreForwardQueue(root / "queue.sqlite3")
            queued = queue.enqueue(event, authoritative_record=authoritative)
            result = queue.quarantine(queued["event_id"], reason_code="SENSITIVE_FIELD_REJECTED")
            self.assertEqual("QUARANTINED", result["status"])
            self.assertEqual("SYNCED_WITH_QUARANTINED", queue.status_for_run(run.run_id))
            self.assertTrue(authoritative.is_file())

    def test_interrupted_upload_retries_idempotently(self):
        server = fixture_server()
        run = RunRecord.start(server, runner_id="CNSSD-01", runtime_version="2.0.0")
        event = run_started_event(run, server)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            authoritative = root / "run.json"
            authoritative.write_text(json.dumps(run.to_dict()), encoding="utf-8")
            queue = StoreForwardQueue(root / "queue.sqlite3")
            central = CentralCollector(root / "central.sqlite3")
            queue.enqueue(event, authoritative_record=authoritative)
            first = queue.drain(AcceptThenLoseResponse(central))
            self.assertEqual(1, first["pending"])
            second = queue.drain(central)
            self.assertEqual(1, second["synced"])
            self.assertEqual("SYNCED", queue.status_for_run(run.run_id))
            self.assertEqual(1, central.counts()["events"])
            self.assertEqual("SYNCED", json.loads(authoritative.read_text(encoding="utf-8"))["central_sync_status"])

    def test_same_server_serial_keeps_separate_run_history(self):
        server = fixture_server()
        first = RunRecord.start(server, runner_id="CNSSD-01", runtime_version="2.0.0")
        second = RunRecord.start(server, runner_id="CNSSD-02", runtime_version="2.0.0")
        with tempfile.TemporaryDirectory() as folder:
            central = CentralCollector(Path(folder) / "central.sqlite3")
            central.ingest_event(run_started_event(first, server))
            central.ingest_event(run_started_event(second, server))
            counts = central.counts()
            self.assertEqual(1, counts["servers"])
            self.assertEqual(2, counts["runs"])
            self.assertEqual(2, central.inventory()[0]["run_count"])

    def test_six_runners_ingest_concurrently_without_key_collisions(self):
        with tempfile.TemporaryDirectory() as folder:
            central = CentralCollector(Path(folder) / "central.sqlite3")
            events = []
            for index in range(6):
                server = ServerRecord(
                    fingerprint_sha256=f"{index + 1:064x}",
                    vendor="ASUS",
                    model="RS500A-E12-RS12U",
                    system_serial=f"SERIAL-{index + 1:03d}",
                    confidence="high",
                )
                run = RunRecord.start(server, runner_id=f"CNSSD-{index + 1:02d}", runtime_version="3.0.0")
                events.append(
                    run_started_event(
                        run,
                        server,
                        runner={
                            "runner_id": run.runner_id,
                            "local_runner_uuid": f"runner-uuid-{index + 1}",
                            "storage_fingerprint_sha256": f"{index + 101:064x}",
                        },
                    )
                )
            with ThreadPoolExecutor(max_workers=6) as pool:
                results = list(pool.map(central.ingest_event, events))
            self.assertTrue(all(item["status"] == "ACCEPTED" for item in results))
            self.assertEqual({"runners": 6, "servers": 6, "runs": 6, "events": 6, "artifacts": 0}, central.counts())
            export = central.export_production_csv(Path(folder) / "ASUS_PRODUCTION_MASTER.csv")
            self.assertEqual(6, export["row_count"])
            self.assertTrue(Path(export["path"]).is_file())

    def test_runner_id_collision_on_different_physical_ssd_is_explicit(self):
        server = fixture_server()
        first = RunRecord.start(server, runner_id="CNSSD-01", runtime_version="3.0.0")
        second = RunRecord.start(server, runner_id="CNSSD-01", runtime_version="3.0.0")
        with tempfile.TemporaryDirectory() as folder:
            central = CentralCollector(Path(folder) / "central.sqlite3")
            central.ingest_event(
                run_started_event(
                    first,
                    server,
                    runner={"runner_id": "CNSSD-01", "local_runner_uuid": "uuid-1", "storage_fingerprint_sha256": "a" * 64},
                )
            )
            with self.assertRaisesRegex(IdempotencyConflict, "RUNNER_ID_COLLISION"):
                central.ingest_event(
                    run_started_event(
                        second,
                        server,
                        runner={"runner_id": "CNSSD-01", "local_runner_uuid": "uuid-1", "storage_fingerprint_sha256": "b" * 64},
                    )
                )

    def test_same_event_id_with_changed_content_is_rejected(self):
        server = fixture_server()
        run = RunRecord.start(server, runner_id="CNSSD-01", runtime_version="2.0.0")
        event = run_started_event(run, server)
        with tempfile.TemporaryDirectory() as folder:
            central = CentralCollector(Path(folder) / "central.sqlite3")
            central.ingest_event(event)
            changed = json.loads(json.dumps(event))
            changed["bmc"] = {"ip": "different"}
            with self.assertRaises(IdempotencyConflict):
                central.ingest_event(changed)

    def test_central_rejects_credential_fields(self):
        server = fixture_server()
        run = RunRecord.start(server, runner_id="CNSSD-01", runtime_version="2.0.0")
        event = run_started_event(run, server, bmc={"password": "must-not-persist"})
        with tempfile.TemporaryDirectory() as folder:
            central = CentralCollector(Path(folder) / "central.sqlite3")
            with self.assertRaises(SensitiveEvidenceError):
                central.ingest_event(event)

    def test_authenticated_api_receives_event_without_exposing_token(self):
        server = fixture_server()
        run = RunRecord.start(server, runner_id="CNSSD-01", runtime_version="2.0.0")
        event = run_started_event(run, server)
        body = json.dumps(event).encode("utf-8")
        with tempfile.TemporaryDirectory() as folder:
            central = CentralCollector(Path(folder) / "central.sqlite3")
            credential = CentralApiCredential("fixture-api-token")
            self.assertNotIn("fixture-api-token", repr(credential))
            app = CentralApiApp(central, credential=credential)
            statuses = []

            def start_response(status, headers):
                statuses.append(status)

            unauthorized = {
                "REQUEST_METHOD": "POST",
                "PATH_INFO": "/v1/events",
                "HTTP_AUTHORIZATION": "Bearer wrong",
                "CONTENT_LENGTH": str(len(body)),
                "wsgi.input": io.BytesIO(body),
            }
            list(app(unauthorized, start_response))
            self.assertEqual("401 Unauthorized", statuses[-1])
            authorized = dict(unauthorized)
            authorized["HTTP_AUTHORIZATION"] = "Bearer fixture-api-token"
            authorized["wsgi.input"] = io.BytesIO(body)
            list(app(authorized, start_response))
            self.assertEqual("200 OK", statuses[-1])
            self.assertEqual(1, central.counts()["events"])


if __name__ == "__main__":
    unittest.main()
