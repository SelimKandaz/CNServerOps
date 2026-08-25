"""Durable central inventory/run collector with idempotent event ingestion."""

from __future__ import annotations

import hashlib
import csv
import json
import os
import sqlite3
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Mapping

from .models import utc_now, validate_runner_id
from .secrets import assert_no_sensitive_fields


class CollectorError(RuntimeError):
    pass


class IdempotencyConflict(CollectorError):
    pass


def _canonical(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class CentralCollector:
    """SQLite reference backend; production schema is supplied for PostgreSQL."""

    def __init__(self, database: Path) -> None:
        self.database = database
        self._initialize_lock = threading.Lock()
        self._initialized = False

    def initialize(self) -> None:
        if self._initialized:
            return
        with self._initialize_lock:
            if self._initialized:
                return
            self.database.parent.mkdir(parents=True, exist_ok=True)
            with self._connection() as connection:
                connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS runners (
                    runner_id TEXT PRIMARY KEY,
                    runtime_version TEXT NOT NULL,
                    local_runner_uuid TEXT NOT NULL DEFAULT '',
                    storage_fingerprint_sha256 TEXT NOT NULL DEFAULT '',
                    first_seen_utc TEXT NOT NULL,
                    last_seen_utc TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS servers (
                    fingerprint_sha256 TEXT PRIMARY KEY,
                    server_id TEXT NOT NULL DEFAULT '',
                    vendor TEXT NOT NULL,
                    model TEXT NOT NULL,
                    system_serial TEXT NOT NULL,
                    board_serial TEXT NOT NULL DEFAULT '',
                    chassis_serial TEXT NOT NULL DEFAULT '',
                    confidence TEXT NOT NULL,
                    identity_json TEXT NOT NULL,
                    first_seen_utc TEXT NOT NULL,
                    last_seen_utc TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS servers_serial_idx ON servers(vendor, system_serial);
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    server_fingerprint_sha256 TEXT NOT NULL REFERENCES servers(fingerprint_sha256),
                    runner_id TEXT NOT NULL REFERENCES runners(runner_id),
                    runtime_version TEXT NOT NULL,
                    boot_id TEXT NOT NULL DEFAULT '',
                    continuation_of_run_id TEXT NOT NULL DEFAULT '',
                    started_at_utc TEXT NOT NULL,
                    workflow_mode TEXT NOT NULL DEFAULT 'PRODUCTION',
                    test_profile TEXT NOT NULL DEFAULT 'STANDARD',
                    completed_at_utc TEXT NOT NULL DEFAULT '',
                    current_stage TEXT NOT NULL,
                    collection_status TEXT NOT NULL,
                    export_status TEXT NOT NULL,
                    central_sync_status TEXT NOT NULL,
                    final_disposition TEXT,
                    reason_codes_json TEXT NOT NULL DEFAULT '[]',
                    result_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS runs_server_idx ON runs(server_fingerprint_sha256, started_at_utc);
                CREATE INDEX IF NOT EXISTS runs_runner_idx ON runs(runner_id, started_at_utc);
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    received_at_utc TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS events_run_idx ON events(run_id, received_at_utc);
                CREATE TABLE IF NOT EXISTS artifacts (
                    run_id TEXT NOT NULL REFERENCES runs(run_id),
                    artifact_sha256 TEXT NOT NULL,
                    artifact_type TEXT NOT NULL,
                    uri TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    PRIMARY KEY(run_id, artifact_sha256, artifact_type)
                );
                """
            )
                columns = {row[1] for row in connection.execute("PRAGMA table_info(runners)").fetchall()}
                if "local_runner_uuid" not in columns:
                    connection.execute("ALTER TABLE runners ADD COLUMN local_runner_uuid TEXT NOT NULL DEFAULT ''")
                if "storage_fingerprint_sha256" not in columns:
                    connection.execute("ALTER TABLE runners ADD COLUMN storage_fingerprint_sha256 TEXT NOT NULL DEFAULT ''")
                server_columns = {row[1] for row in connection.execute("PRAGMA table_info(servers)").fetchall()}
                if "server_id" not in server_columns:
                    connection.execute("ALTER TABLE servers ADD COLUMN server_id TEXT NOT NULL DEFAULT ''")
                run_columns = {row[1] for row in connection.execute("PRAGMA table_info(runs)").fetchall()}
                if "boot_id" not in run_columns:
                    connection.execute("ALTER TABLE runs ADD COLUMN boot_id TEXT NOT NULL DEFAULT ''")
                if "continuation_of_run_id" not in run_columns:
                    connection.execute("ALTER TABLE runs ADD COLUMN continuation_of_run_id TEXT NOT NULL DEFAULT ''")
                if "workflow_mode" not in run_columns:
                    connection.execute("ALTER TABLE runs ADD COLUMN workflow_mode TEXT NOT NULL DEFAULT 'PRODUCTION'")
                if "test_profile" not in run_columns:
                    connection.execute("ALTER TABLE runs ADD COLUMN test_profile TEXT NOT NULL DEFAULT 'STANDARD'")
            self._initialized = True

    def ingest_event(self, event: Mapping[str, Any]) -> dict[str, Any]:
        self.initialize()
        assert_no_sensitive_fields(event)
        event_id = str(event.get("event_id") or "")
        event_type = str(event.get("event_type") or "")
        run = event.get("run")
        if not event_id or event_type not in {"RUN_STARTED", "RUN_PROGRESS", "RUN_COMPLETED"}:
            raise CollectorError("Event ID and supported event type are required")
        if not isinstance(run, Mapping) or not run.get("run_id"):
            raise CollectorError("Event requires a run object and RUN_ID")
        run_id = str(run["run_id"])
        payload_json = _canonical(event)
        digest = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        now = utc_now()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT payload_sha256 FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
            if existing:
                if existing[0] != digest:
                    raise IdempotencyConflict("Event ID was already used for different content")
                return {"status": "DUPLICATE_ACCEPTED", "event_id": event_id, "run_id": run_id}
            if event_type == "RUN_STARTED":
                self._upsert_started(connection, event, now)
            else:
                present = connection.execute("SELECT 1 FROM runs WHERE run_id = ?", (run_id,)).fetchone()
                if not present:
                    raise CollectorError("RUN_STARTED must be ingested before progress/completion")
                if event_type == "RUN_COMPLETED":
                    self._complete_run(connection, run, event.get("result") or {})
                else:
                    self._update_progress(connection, run)
            connection.execute(
                "INSERT INTO events(event_id, run_id, event_type, payload_sha256, payload_json, received_at_utc) VALUES(?,?,?,?,?,?)",
                (event_id, run_id, event_type, digest, payload_json, now),
            )
        return {"status": "ACCEPTED", "event_id": event_id, "run_id": run_id}

    def register_artifact(self, run_id: str, artifact: Mapping[str, Any]) -> dict[str, Any]:
        self.initialize()
        assert_no_sensitive_fields(artifact)
        digest = str(artifact.get("sha256") or "").lower()
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise CollectorError("Artifact SHA256 is invalid")
        with self._connection() as connection:
            if not connection.execute("SELECT 1 FROM runs WHERE run_id = ?", (run_id,)).fetchone():
                raise CollectorError("Artifact RUN_ID does not exist")
            existing = connection.execute(
                "SELECT 1 FROM artifacts WHERE run_id=? AND artifact_sha256=? AND artifact_type=?",
                (run_id, digest, str(artifact.get("type") or "UNKNOWN")),
            ).fetchone()
            if existing:
                return {"status": "DUPLICATE_ACCEPTED", "run_id": run_id, "sha256": digest}
            connection.execute(
                """
                INSERT INTO artifacts(run_id, artifact_sha256, artifact_type, uri, size_bytes, metadata_json)
                VALUES(?,?,?,?,?,?) ON CONFLICT(run_id, artifact_sha256, artifact_type) DO UPDATE SET
                uri=excluded.uri, size_bytes=excluded.size_bytes, metadata_json=excluded.metadata_json
                """,
                (
                    run_id,
                    digest,
                    str(artifact.get("type") or "UNKNOWN"),
                    str(artifact.get("uri") or ""),
                    int(artifact.get("size_bytes") or 0),
                    _canonical(dict(artifact.get("metadata") or {})),
                ),
            )
        return {"status": "REGISTERED", "run_id": run_id, "sha256": digest}

    def update_artifact_delivery_metadata(
        self,
        run_id: str,
        artifact_sha256: str,
        artifact_type: str,
        metadata_patch: Mapping[str, Any],
    ) -> None:
        """Atomically update non-secret Central archive delivery metadata.

        A secondary UNC mirror can recover after the original HTTPS upload was
        accepted.  The retry worker must be able to turn its earlier
        ``PENDING_RETRY`` receipt into a durable ``SYNCED`` record without
        re-uploading or modifying the binary artifact itself.
        """
        self.initialize()
        digest = str(artifact_sha256 or "").lower()
        artifact_kind = str(artifact_type or "UNKNOWN")
        with self._connection() as connection:
            row = connection.execute(
                "SELECT metadata_json FROM artifacts WHERE run_id=? AND artifact_sha256=? AND artifact_type=?",
                (str(run_id), digest, artifact_kind),
            ).fetchone()
            if not row:
                raise CollectorError("Artifact delivery record does not exist")
            try:
                metadata = json.loads(str(row[0] or "{}"))
            except json.JSONDecodeError:
                metadata = {}
            if not isinstance(metadata, dict):
                metadata = {}
            metadata.update(dict(metadata_patch))
            assert_no_sensitive_fields(metadata)
            connection.execute(
                "UPDATE artifacts SET metadata_json=? WHERE run_id=? AND artifact_sha256=? AND artifact_type=?",
                (_canonical(metadata), str(run_id), digest, artifact_kind),
            )

    def artifact_context(self, run_id: str) -> dict[str, str]:
        """Resolve a Central artifact destination from an accepted RUN_STARTED."""
        self.initialize()
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT r.run_id,s.server_id,s.system_serial,s.vendor,s.model,r.workflow_mode,r.started_at_utc
                FROM runs r JOIN servers s ON s.fingerprint_sha256=r.server_fingerprint_sha256
                WHERE r.run_id=?
                """,
                (run_id,),
            ).fetchone()
        if not row:
            raise CollectorError("Artifact RUN_ID does not exist")
        return {
            "run_id": str(row[0]),
            "server_id": str(row[1]),
            "system_serial": str(row[2]),
            "vendor": str(row[3]),
            "model": str(row[4]),
            "workflow_mode": str(row[5] or "PRODUCTION"),
            "started_at_utc": str(row[6] or ""),
        }

    def inventory(self) -> list[dict[str, Any]]:
        self.initialize()
        with self._connection() as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """
                SELECT s.vendor, s.model, s.system_serial, s.fingerprint_sha256,
                       COUNT(r.run_id) AS run_count,
                       MAX(r.started_at_utc) AS last_run_utc,
                       MAX(CASE WHEN r.final_disposition = 'PASS' THEN 1 ELSE 0 END) AS has_pass
                FROM servers s LEFT JOIN runs r ON r.server_fingerprint_sha256=s.fingerprint_sha256
                GROUP BY s.fingerprint_sha256 ORDER BY s.vendor, s.system_serial
                """
            ).fetchall()
            return [dict(row) for row in rows]

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        self.initialize()
        with self._connection() as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
            return dict(row) if row else None

    def counts(self) -> dict[str, int]:
        self.initialize()
        with self._connection() as connection:
            return {
                table: int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in ("runners", "servers", "runs", "events", "artifacts")
            }

    def production_rows(self, *, vendor: str = "ASUS") -> list[dict[str, Any]]:
        """Return a normalized operational view; SQLite remains authoritative."""
        self.initialize()
        with self._connection() as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """
                SELECT r.run_id,r.runner_id,ru.local_runner_uuid,ru.storage_fingerprint_sha256,
                       s.server_id,s.fingerprint_sha256,s.vendor,s.model,s.system_serial,s.board_serial,s.chassis_serial,
                       r.runtime_version,r.boot_id,r.continuation_of_run_id,r.workflow_mode,r.test_profile,
                       r.started_at_utc,r.completed_at_utc,r.current_stage,
                       r.final_disposition,r.reason_codes_json,r.result_json
                FROM runs r
                JOIN servers s ON s.fingerprint_sha256=r.server_fingerprint_sha256
                JOIN runners ru ON ru.runner_id=r.runner_id
                WHERE UPPER(s.vendor)=UPPER(?)
                ORDER BY r.started_at_utc,r.run_id
                """,
                (vendor,),
            ).fetchall()
        normalized: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            try:
                result = json.loads(item.pop("result_json") or "{}")
            except json.JSONDecodeError:
                result = {"parse_error": True}
            item["reason_codes"] = item.pop("reason_codes_json")
            item.update(
                {
                    "bios_before": _nested(result, "firmware", "bios", "before") or _json_cell(result.get("bios_before")),
                    "bios_after": _nested(result, "firmware", "bios", "after") or _json_cell(result.get("bios_after")),
                    "bmc_before": _nested(result, "firmware", "bmc", "before") or _json_cell(result.get("bmc_before")),
                    "bmc_after": _nested(result, "firmware", "bmc", "after") or _json_cell(result.get("bmc_after")),
                    "cpu": _json_cell(result.get("cpu")),
                    "ram": _json_cell(result.get("ram")),
                    "storage": _json_cell(result.get("storage")),
                    "nic": _json_cell(result.get("nic")),
                    "update_result": _json_cell(result.get("update_result")),
                    "test_result": _json_cell(result.get("test_result")),
                    "diagnostic_result": _json_cell(result.get("diagnostic_result")),
                    "log_clean_result": _json_cell(result.get("log_clean_result")),
                }
            )
            normalized.append(item)
        return normalized

    def export_production_csv(self, destination: Path, *, vendor: str = "ASUS") -> dict[str, Any]:
        rows = self.production_rows(vendor=vendor)
        columns = [
            "run_id", "runner_id", "local_runner_uuid", "storage_fingerprint_sha256",
            "server_id", "fingerprint_sha256", "vendor", "model", "system_serial", "board_serial", "chassis_serial",
            "runtime_version", "boot_id", "continuation_of_run_id", "workflow_mode", "test_profile",
            "started_at_utc", "completed_at_utc", "current_stage", "final_disposition",
            "reason_codes", "bios_before", "bios_after", "bmc_before", "bmc_after", "cpu", "ram",
            "storage", "nic", "update_result", "test_result", "diagnostic_result", "log_clean_result",
        ]
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=destination.name + ".", suffix=".tmp", dir=destination.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8-sig", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(rows)
                stream.flush()
                os.fsync(stream.fileno())
            Path(temporary_name).replace(destination)
        finally:
            temporary = Path(temporary_name)
            if temporary.exists():
                temporary.unlink()
        return {"status": "EXPORTED", "path": str(destination), "row_count": len(rows), "authoritative": False}

    def _upsert_started(self, connection: sqlite3.Connection, event: Mapping[str, Any], now: str) -> None:
        run = dict(event["run"])
        server = event.get("server")
        if not isinstance(server, Mapping):
            raise CollectorError("RUN_STARTED requires a server identity object")
        runner_id = validate_runner_id(str(run.get("runner_id") or ""))
        runner_details = event.get("runner") if isinstance(event.get("runner"), Mapping) else {}
        supplied_runner_id = str(runner_details.get("runner_id") or runner_id)
        if validate_runner_id(supplied_runner_id) != runner_id:
            raise IdempotencyConflict("RUNNER_ID_COLLISION: event runner and run runner do not match")
        local_runner_uuid = str(runner_details.get("local_runner_uuid") or "")
        storage_fingerprint = str(runner_details.get("storage_fingerprint_sha256") or "").lower()
        if storage_fingerprint and (
            len(storage_fingerprint) != 64
            or any(character not in "0123456789abcdef" for character in storage_fingerprint)
        ):
            raise CollectorError("Runner storage fingerprint is invalid")
        fingerprint = str(server.get("fingerprint_sha256") or "")
        if not fingerprint or fingerprint != str(run.get("server_fingerprint_sha256") or ""):
            raise CollectorError("Run and server fingerprints do not match")
        existing_runner = connection.execute(
            "SELECT local_runner_uuid,storage_fingerprint_sha256 FROM runners WHERE runner_id=?",
            (runner_id,),
        ).fetchone()
        if existing_runner:
            if local_runner_uuid and existing_runner[0] and local_runner_uuid != existing_runner[0]:
                raise IdempotencyConflict("RUNNER_ID_COLLISION: local runner UUID changed")
            if storage_fingerprint and existing_runner[1] and storage_fingerprint != existing_runner[1]:
                raise IdempotencyConflict("RUNNER_ID_COLLISION: physical SSD fingerprint changed")
        connection.execute(
            """
            INSERT INTO runners(runner_id,runtime_version,local_runner_uuid,storage_fingerprint_sha256,first_seen_utc,last_seen_utc)
            VALUES(?,?,?,?,?,?) ON CONFLICT(runner_id) DO UPDATE SET
            runtime_version=excluded.runtime_version,
            local_runner_uuid=CASE WHEN excluded.local_runner_uuid='' THEN runners.local_runner_uuid ELSE excluded.local_runner_uuid END,
            storage_fingerprint_sha256=CASE WHEN excluded.storage_fingerprint_sha256='' THEN runners.storage_fingerprint_sha256 ELSE excluded.storage_fingerprint_sha256 END,
            last_seen_utc=excluded.last_seen_utc
            """,
            (runner_id, str(run.get("runtime_version") or ""), local_runner_uuid, storage_fingerprint, now, now),
        )
        identity_json = _canonical(dict(server))
        connection.execute(
            """
            INSERT INTO servers(fingerprint_sha256,server_id,vendor,model,system_serial,board_serial,chassis_serial,confidence,identity_json,first_seen_utc,last_seen_utc)
            VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(fingerprint_sha256) DO UPDATE SET
            server_id=excluded.server_id,
            vendor=excluded.vendor,model=excluded.model,system_serial=excluded.system_serial,
            board_serial=excluded.board_serial,chassis_serial=excluded.chassis_serial,
            confidence=excluded.confidence,identity_json=excluded.identity_json,last_seen_utc=excluded.last_seen_utc
            """,
            (
                fingerprint,
                str(server.get("server_id") or f"SERVER-{fingerprint.upper()}"),
                str(server.get("vendor") or "UNKNOWN"),
                str(server.get("model") or ""),
                str(server.get("system_serial") or ""),
                str(server.get("board_serial") or ""),
                str(server.get("chassis_serial") or ""),
                str(server.get("confidence") or "low"),
                identity_json,
                now,
                now,
            ),
        )
        existing = connection.execute(
            "SELECT server_fingerprint_sha256,runner_id FROM runs WHERE run_id=?", (str(run["run_id"]),)
        ).fetchone()
        if existing and (existing[0] != fingerprint or existing[1] != runner_id):
            raise IdempotencyConflict("RUN_ID already belongs to another server or runner")
        connection.execute(
            """
            INSERT OR IGNORE INTO runs(run_id,server_fingerprint_sha256,runner_id,runtime_version,boot_id,continuation_of_run_id,started_at_utc,
                workflow_mode,test_profile,current_stage,collection_status,export_status,central_sync_status,reason_codes_json)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                str(run["run_id"]),
                fingerprint,
                runner_id,
                str(run.get("runtime_version") or ""),
                str(run.get("boot_id") or ""),
                str(run.get("continuation_of_run_id") or ""),
                str(run.get("started_at_utc") or now),
                str(run.get("workflow_mode") or "PRODUCTION"),
                str(run.get("test_profile") or "STANDARD"),
                str(run.get("current_stage") or "IDENTITY"),
                str(run.get("collection_status") or "IN_PROGRESS"),
                str(run.get("export_status") or "NOT_STARTED"),
                "SYNCED",
                _canonical(run.get("reason_codes") or []),
            ),
        )

    def _update_progress(self, connection: sqlite3.Connection, run: Mapping[str, Any]) -> None:
        connection.execute(
            "UPDATE runs SET current_stage=?,collection_status=?,export_status=?,central_sync_status=? WHERE run_id=?",
            (
                str(run.get("current_stage") or ""),
                str(run.get("collection_status") or ""),
                str(run.get("export_status") or ""),
                "SYNCED",
                str(run["run_id"]),
            ),
        )

    def _complete_run(self, connection: sqlite3.Connection, run: Mapping[str, Any], result: Mapping[str, Any]) -> None:
        connection.execute(
            """
            UPDATE runs SET completed_at_utc=?,current_stage=?,collection_status=?,export_status=?,
            central_sync_status=?,final_disposition=?,reason_codes_json=?,result_json=? WHERE run_id=?
            """,
            (
                str(run.get("completed_at_utc") or utc_now()),
                str(run.get("current_stage") or "COMPLETE"),
                str(run.get("collection_status") or ""),
                str(run.get("export_status") or ""),
                "SYNCED",
                run.get("final_disposition"),
                _canonical(run.get("reason_codes") or []),
                _canonical(dict(result)),
                str(run["run_id"]),
            ),
        )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=30, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    @contextmanager
    def _connection(self):
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()


def _nested(value: Mapping[str, Any], *path: str) -> Any:
    current: Any = value
    for part in path:
        if not isinstance(current, Mapping):
            return ""
        current = current.get(part)
    return _json_cell(current)


def _json_cell(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return value
