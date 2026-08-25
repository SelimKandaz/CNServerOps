"""Local authoritative store-and-forward queue with idempotent retry semantics."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Mapping, Protocol

from .models import utc_now


class SyncQueueError(RuntimeError):
    pass


class CollectorClient(Protocol):
    def ingest_event(self, event: Mapping[str, Any]) -> Mapping[str, Any]: ...


class StoreForwardQueue:
    def __init__(self, database: Path) -> None:
        self.database = database

    def initialize(self) -> None:
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS queue (
                    event_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    authoritative_record TEXT NOT NULL,
                    authoritative_sha256 TEXT NOT NULL,
                    status TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT NOT NULL DEFAULT '',
                    created_at_utc TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL
                )
                """
            )
            # A process interrupted during upload leaves IN_FLIGHT; make it retryable on next open.
            connection.execute(
                "UPDATE queue SET status='PENDING_UPLOAD',last_error='previous upload interrupted' WHERE status='IN_FLIGHT'"
            )

    def enqueue(self, event: Mapping[str, Any], *, authoritative_record: Path) -> dict[str, Any]:
        self.initialize()
        try:
            resolved_record = authoritative_record.resolve(strict=True)
        except FileNotFoundError as exc:
            raise SyncQueueError("Local authoritative run record must exist before central enqueue") from exc
        if authoritative_record.is_symlink() or not resolved_record.is_file():
            raise SyncQueueError("Local authoritative run record must exist before central enqueue")
        event_id = str(event.get("event_id") or "")
        event_type = str(event.get("event_type") or "")
        run = event.get("run")
        if not event_id or not event_type or not isinstance(run, Mapping) or not run.get("run_id"):
            raise SyncQueueError("Queue event requires event_id, event_type, and run_id")
        payload = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        record_digest = _sha256(resolved_record)
        now = utc_now()
        with self._connection() as connection:
            existing = connection.execute(
                "SELECT payload_sha256 FROM queue WHERE event_id=?", (event_id,)
            ).fetchone()
            if existing:
                if existing[0] != digest:
                    raise SyncQueueError("Event ID is already queued with different content")
                return {"status": "ALREADY_QUEUED", "event_id": event_id}
            connection.execute(
                """
                INSERT INTO queue(event_id,run_id,event_type,payload_json,payload_sha256,authoritative_record,
                    authoritative_sha256,status,created_at_utc,updated_at_utc)
                VALUES(?,?,?,?,?,?,?,'PENDING_UPLOAD',?,?)
                """,
                (
                    event_id,
                    str(run["run_id"]),
                    event_type,
                    payload,
                    digest,
                    str(resolved_record),
                    record_digest,
                    now,
                    now,
                ),
            )
        return {"status": "PENDING_UPLOAD", "event_id": event_id}

    def drain(self, client: CollectorClient, *, limit: int = 100) -> dict[str, Any]:
        self.initialize()
        attempted = synced = pending = 0
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT event_id,payload_json FROM queue WHERE status='PENDING_UPLOAD' ORDER BY created_at_utc LIMIT ?",
                (limit,),
            ).fetchall()
        for event_id, payload_json in rows:
            attempted += 1
            with self._connection() as connection:
                connection.execute(
                    "UPDATE queue SET status='IN_FLIGHT',attempts=attempts+1,updated_at_utc=? WHERE event_id=?",
                    (utc_now(), event_id),
                )
            try:
                response = client.ingest_event(json.loads(payload_json))
                status = str(response.get("status") or "")
                if status not in {"ACCEPTED", "DUPLICATE_ACCEPTED"}:
                    raise SyncQueueError(f"Collector rejected event: {status or 'unknown response'}")
            except Exception as exc:  # queue containment boundary; error text is sanitized by type/message only
                pending += 1
                error = f"{type(exc).__name__}: {exc}"[:500]
                with self._connection() as connection:
                    connection.execute(
                        "UPDATE queue SET status='PENDING_UPLOAD',last_error=?,updated_at_utc=? WHERE event_id=?",
                        (error, utc_now(), event_id),
                    )
            else:
                with self._connection() as connection:
                    connection.execute(
                        "UPDATE queue SET status='SYNCED',last_error='',updated_at_utc=? WHERE event_id=?",
                        (utc_now(), event_id),
                    )
                try:
                    self._mark_authoritative_synced(json.loads(payload_json)["run"]["run_id"])
                except Exception as exc:
                    pending += 1
                    error = f"local sync receipt update failed: {type(exc).__name__}: {exc}"[:500]
                    with self._connection() as connection:
                        connection.execute(
                            "UPDATE queue SET status='PENDING_UPLOAD',last_error=?,updated_at_utc=? WHERE event_id=?",
                            (error, utc_now(), event_id),
                        )
                else:
                    synced += 1
        return {"attempted": attempted, "synced": synced, "pending": pending}

    def quarantine(self, event_id: str, *, reason_code: str) -> dict[str, Any]:
        """Retain a locally invalid event without retrying or deleting its evidence."""
        normalized = str(reason_code or "").strip().upper()
        if not normalized or not normalized.replace("_", "").isalnum():
            raise SyncQueueError("Quarantine requires a machine-readable reason code")
        self.initialize()
        with self._connection() as connection:
            present = connection.execute(
                "SELECT run_id FROM queue WHERE event_id=?", (event_id,)
            ).fetchone()
            if not present:
                raise SyncQueueError("Queue event does not exist")
            connection.execute(
                "UPDATE queue SET status='QUARANTINED',last_error=?,updated_at_utc=? WHERE event_id=?",
                (normalized, utc_now(), event_id),
            )
        return {"status": "QUARANTINED", "event_id": event_id, "run_id": present[0], "reason_code": normalized}

    def status_for_run(self, run_id: str) -> str:
        self.initialize()
        with self._connection() as connection:
            rows = connection.execute("SELECT status FROM queue WHERE run_id=?", (run_id,)).fetchall()
        if not rows:
            return "NOT_QUEUED"
        statuses = {row[0] for row in rows}
        if statuses == {"SYNCED"}:
            return "SYNCED"
        if statuses <= {"SYNCED", "QUARANTINED"} and "QUARANTINED" in statuses:
            return "SYNCED_WITH_QUARANTINED"
        return "PENDING_UPLOAD"

    def counts(self) -> dict[str, int]:
        self.initialize()
        with self._connection() as connection:
            rows = connection.execute("SELECT status,COUNT(*) FROM queue GROUP BY status").fetchall()
        return {str(status): int(count) for status, count in rows}

    def _mark_authoritative_synced(self, run_id: str) -> None:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT status,authoritative_record FROM queue WHERE run_id=? ORDER BY created_at_utc", (run_id,)
            ).fetchall()
        if not rows or any(status != "SYNCED" for status, _ in rows):
            return
        path = Path(rows[-1][1])
        payload = json.loads(path.read_text(encoding="utf-8"))
        run = payload.get("run") if isinstance(payload, dict) and isinstance(payload.get("run"), dict) else payload
        if not isinstance(run, dict) or str(run.get("run_id") or "") != run_id:
            raise SyncQueueError("Authoritative run record does not match queued RUN_ID")
        run["central_sync_status"] = "SYNCED"
        _atomic_json(path, payload)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=30)
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


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        Path(temporary_name).replace(path)
    finally:
        temporary = Path(temporary_name)
        if temporary.exists():
            temporary.unlink()
