"""Independent store-and-forward queue for human report artifacts."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Mapping, Protocol

from .models import utc_now


class ArtifactSyncError(RuntimeError):
    pass


class ArtifactClient(Protocol):
    def upload_artifact(
        self,
        run_id: str,
        path: Path,
        *,
        artifact_type: str,
        sha256: str,
    ) -> Mapping[str, Any]: ...


_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$")
_SENSITIVE_NAME = re.compile(r"password|passwd|credential|secret|token|private.?key|authorization", re.IGNORECASE)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _validate_source(path: Path) -> tuple[Path, str, int]:
    if path.is_symlink():
        raise ArtifactSyncError("artifact symlinks are not accepted")
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ArtifactSyncError("artifact source does not exist") from exc
    if not resolved.is_file():
        raise ArtifactSyncError("artifact source must be a regular file")
    if not _SAFE_NAME.fullmatch(resolved.name) or _SENSITIVE_NAME.search(resolved.name):
        raise ArtifactSyncError("artifact filename is unsafe or credential-sensitive")
    return resolved, sha256_file(resolved), resolved.stat().st_size


class ArtifactStoreForwardQueue:
    """Durable binary-delivery state; local report success remains independent."""

    def __init__(self, database: Path) -> None:
        self.database = database

    def initialize(self) -> None:
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS artifact_queue (
                    artifact_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    artifact_type TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    source_path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    last_delivery_state TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT NOT NULL DEFAULT '',
                    last_response_json TEXT NOT NULL DEFAULT '',
                    created_at_utc TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL
                )
                """
            )
            columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(artifact_queue)").fetchall()}
            if "last_response_json" not in columns:
                connection.execute("ALTER TABLE artifact_queue ADD COLUMN last_response_json TEXT NOT NULL DEFAULT ''")
            connection.execute(
                "UPDATE artifact_queue SET status='PENDING_UPLOAD',last_delivery_state='UPLOAD_FAILED',last_error='previous upload interrupted' WHERE status='IN_FLIGHT'"
            )
            # A Central HTTP 409 means the same run/filename already contains
            # different immutable bytes.  Repeating the identical request can
            # never heal that conflict, so migrate rows left by older runtimes
            # out of the retry set.  The evidence is retained as a terminal
            # failure (or may later be explicitly superseded by a verified,
            # uniquely named successor); it is never deleted or called synced.
            connection.execute(
                """
                UPDATE artifact_queue
                   SET status='UPLOAD_FAILED', last_delivery_state='IDEMPOTENCY_CONFLICT',
                       updated_at_utc=?
                 WHERE status='PENDING_UPLOAD'
                   AND (last_error LIKE '%HTTP 409%' OR last_error LIKE '%IDEMPOTENCY_CONFLICT%')
                """,
                (utc_now(),),
            )

    def enqueue(self, run_id: str, path: Path, *, artifact_type: str) -> dict[str, Any]:
        self.initialize()
        normalized_run = str(run_id or "").strip()
        normalized_type = re.sub(r"[^A-Z0-9._-]+", "_", str(artifact_type or "UNKNOWN").upper()).strip("_")
        if not re.fullmatch(r"RUN-[A-Z0-9-]{8,96}", normalized_run):
            raise ArtifactSyncError("artifact RUN_ID is invalid")
        if not normalized_type:
            raise ArtifactSyncError("artifact type is invalid")
        resolved, digest, size = _validate_source(path)
        artifact_id = hashlib.sha256(f"{normalized_run}\0{normalized_type}\0{digest}\0{resolved.name}".encode("utf-8")).hexdigest()
        now = utc_now()
        with self._connection() as connection:
            existing = connection.execute(
                "SELECT sha256,size_bytes,source_path,status FROM artifact_queue WHERE artifact_id=?", (artifact_id,)
            ).fetchone()
            if existing:
                if existing[0] != digest or int(existing[1]) != size or Path(existing[2]) != resolved:
                    raise ArtifactSyncError("artifact identity already exists with different local content")
                return {"status": str(existing[3]), "artifact_id": artifact_id, "sha256": digest}
            connection.execute(
                """
                INSERT INTO artifact_queue(artifact_id,run_id,artifact_type,filename,source_path,sha256,size_bytes,
                    status,last_delivery_state,created_at_utc,updated_at_utc)
                VALUES(?,?,?,?,?,?,?,'PENDING_UPLOAD','LOCAL_COMPLETE',?,?)
                """,
                (artifact_id, normalized_run, normalized_type, resolved.name, str(resolved), digest, size, now, now),
            )
        return {"status": "PENDING_UPLOAD", "local_state": "LOCAL_COMPLETE", "artifact_id": artifact_id, "sha256": digest}

    def drain(self, client: ArtifactClient, *, limit: int = 20) -> dict[str, Any]:
        self.initialize()
        attempted = synced = pending = failed = duplicates = 0
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT artifact_id,run_id,artifact_type,source_path,sha256,size_bytes
                FROM artifact_queue WHERE status='PENDING_UPLOAD' ORDER BY created_at_utc LIMIT ?
                """,
                (max(1, min(int(limit), 100)),),
            ).fetchall()
        for artifact_id, run_id, artifact_type, source_path, expected_hash, expected_size in rows:
            attempted += 1
            with self._connection() as connection:
                connection.execute(
                    "UPDATE artifact_queue SET status='IN_FLIGHT',attempts=attempts+1,updated_at_utc=? WHERE artifact_id=?",
                    (utc_now(), artifact_id),
                )
            path = Path(source_path)
            try:
                resolved, current_hash, current_size = _validate_source(path)
                if current_hash != expected_hash or current_size != int(expected_size):
                    raise ArtifactSyncError("local artifact changed after queueing")
                response = client.upload_artifact(
                    str(run_id), resolved, artifact_type=str(artifact_type), sha256=str(expected_hash)
                )
                status = str(response.get("status") or "")
                if status not in {"ACCEPTED", "DUPLICATE_ACCEPTED", "REGISTERED"}:
                    raise ArtifactSyncError(f"Central rejected artifact: {status or 'unknown response'}")
                # A production Central response includes a binary-copy proof
                # for the mandatory primary Windows archive.  HTTP acceptance
                # alone is not enough: retain the local immutable bytes for a
                # retry if Central could store them but could not create the
                # serial/run archive.  Older/test-only collectors do not emit
                # this field and remain compatible.
                primary = response.get("primary_archive")
                if isinstance(primary, Mapping) and str(primary.get("status") or "") != "SYNCED":
                    raise ArtifactSyncError("Central primary archive is not hash-verified")
            except ArtifactSyncError as exc:
                failed += 1
                terminal = "changed after queueing" in str(exc) or "credential-sensitive" in str(exc)
                new_status = "UPLOAD_FAILED" if terminal else "PENDING_UPLOAD"
                with self._connection() as connection:
                    connection.execute(
                        "UPDATE artifact_queue SET status=?,last_delivery_state='UPLOAD_FAILED',last_error=?,updated_at_utc=? WHERE artifact_id=?",
                        (new_status, f"{type(exc).__name__}: {exc}"[:500], utc_now(), artifact_id),
                    )
                pending += 0 if terminal else 1
            except Exception as exc:  # retry boundary; credential values are never part of queue records
                failed += 1
                # An immutable Central artifact conflict is deterministic: the
                # same run/filename has already been accepted with different
                # bytes.  Preserve it as terminal evidence instead of retrying
                # forever.  Other HTTP/transport failures remain retryable.
                terminal_conflict = int(getattr(exc, "http_status", 0) or 0) == 409
                pending += 0 if terminal_conflict else 1
                with self._connection() as connection:
                    connection.execute(
                        "UPDATE artifact_queue SET status=?,last_delivery_state=?,last_error=?,updated_at_utc=? WHERE artifact_id=?",
                        (
                            "UPLOAD_FAILED" if terminal_conflict else "PENDING_UPLOAD",
                            "IDEMPOTENCY_CONFLICT" if terminal_conflict else "UPLOAD_FAILED",
                            f"{type(exc).__name__}: {exc}"[:500],
                            utc_now(),
                            artifact_id,
                        ),
                    )
            else:
                if status == "DUPLICATE_ACCEPTED":
                    duplicates += 1
                synced += 1
                with self._connection() as connection:
                    connection.execute(
                        "UPDATE artifact_queue SET status='SYNCED',last_delivery_state=?,last_error='',last_response_json=?,updated_at_utc=? WHERE artifact_id=?",
                        (status, json.dumps(dict(response), sort_keys=True, separators=(",", ":")), utc_now(), artifact_id),
                    )
        return {
            "attempted": attempted,
            "synced": synced,
            "duplicates": duplicates,
            "pending": pending,
            "failed": failed,
        }

    def status_for_run(self, run_id: str) -> str:
        self.initialize()
        with self._connection() as connection:
            rows = connection.execute("SELECT status FROM artifact_queue WHERE run_id=?", (run_id,)).fetchall()
        if not rows:
            return "LOCAL_COMPLETE"
        # A later immutable handoff/report proof may intentionally replace a
        # queued file with a unique filename after Central has already
        # accepted the original.  Superseded local rows remain audit history,
        # but must not keep the run permanently pending.
        statuses = {str(row[0]) for row in rows if str(row[0]) != "SUPERSEDED"}
        if not statuses:
            return "LOCAL_COMPLETE"
        if statuses == {"SYNCED"}:
            return "SYNCED"
        if "UPLOAD_FAILED" in statuses:
            return "UPLOAD_FAILED"
        return "PENDING_UPLOAD"

    def supersede_for_run(self, run_id: str, *, filename: str, reason: str) -> int:
        """Retire queued versions of a file after a unique replacement is ready.

        Central intentionally rejects a changed payload under an already-used
        filename (HTTP 409).  Handoff retries publish a new immutable proof
        filename instead of overwriting the accepted historical bytes; this
        method keeps the old local queue row from blocking the run forever.
        """
        self.initialize()
        with self._connection() as connection:
            cursor = connection.execute(
                """
                UPDATE artifact_queue
                   SET status='SUPERSEDED', last_delivery_state='SUPERSEDED',
                       last_error=?, updated_at_utc=?
                 WHERE run_id=? AND filename=? AND status IN ('PENDING_UPLOAD','IN_FLIGHT','UPLOAD_FAILED')
                """,
                (str(reason or "replaced by immutable successor")[:500], utc_now(), str(run_id), str(filename)),
            )
            return int(cursor.rowcount)

    def counts(self) -> dict[str, int]:
        """Return durable queue counts for offline status/reporting."""
        self.initialize()
        with self._connection() as connection:
            rows = connection.execute("SELECT status,COUNT(*) FROM artifact_queue GROUP BY status").fetchall()
        return {str(status): int(count) for status, count in rows}

    def records_for_run(self, run_id: str) -> list[dict[str, Any]]:
        self.initialize()
        with self._connection() as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """
                SELECT artifact_id,artifact_type,filename,sha256,size_bytes,status,last_delivery_state,
                       attempts,last_error,last_response_json,created_at_utc,updated_at_utc
                FROM artifact_queue WHERE run_id=? ORDER BY filename
                """,
                (run_id,),
            ).fetchall()
        records = []
        for row in rows:
            item = dict(row)
            raw_response = item.pop("last_response_json", "")
            try:
                item["central_response"] = json.loads(raw_response) if raw_response else {}
            except json.JSONDecodeError:
                item["central_response"] = {}
            records.append(item)
        return records

    @contextmanager
    def _connection(self):
        connection = sqlite3.connect(self.database, timeout=30)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=30000")
        try:
            with connection:
                yield connection
        finally:
            connection.close()
