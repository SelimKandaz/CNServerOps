"""Minimal authenticated Central Collector HTTP boundary and HTTPS client."""

from __future__ import annotations

import hmac
import hashlib
import http.client
import json
import os
import re
import shutil
import sqlite3
import ssl
import stat
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlparse
from urllib.request import Request, urlopen

from .collector import CentralCollector, CollectorError, IdempotencyConflict
from .secrets import SensitiveEvidenceError


class CentralApiError(RuntimeError):
    """Central transport failure with an optional sanitized HTTP status.

    Queue consumers must be able to distinguish a transient transport outage
    from an immutable-artifact name/hash conflict.  Keep the response body out
    of this exception (it may be untrusted), but retain the numeric status so
    the durable queue can apply a bounded retry policy without parsing error
    text.
    """

    def __init__(self, message: str, *, http_status: int | None = None) -> None:
        super().__init__(message)
        self.http_status = int(http_status) if http_status is not None else None


@dataclass(frozen=True)
class CentralApiCredential:
    bearer_token: str = field(repr=False)
    source: str = "runtime"


def central_credential_from_env(name: str = "CNSERVEROPS_CENTRAL_TOKEN") -> CentralApiCredential:
    token = os.environ.get(name, "")
    if not token:
        raise CentralApiError(f"Central API credential is unavailable in runtime environment variable {name}")
    return CentralApiCredential(token, source=f"environment:{name}")


def central_credential_from_file(path: Path) -> CentralApiCredential:
    """Load a root-owned, non-symlink runner credential without serializing it."""
    if path.is_symlink():
        raise CentralApiError("Central API access file must not be a symlink")
    try:
        metadata = path.stat()
    except OSError as exc:
        raise CentralApiError("Central API access file is unavailable") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise CentralApiError("Central API access file must be a regular file")
    if os.name != "nt" and metadata.st_mode & 0o077:
        raise CentralApiError("Central API access file permissions must be 0600 or stricter")
    if hasattr(os, "geteuid") and metadata.st_uid not in {0, os.geteuid()}:
        raise CentralApiError("Central API access file owner is not trusted")
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise CentralApiError("Central API access file could not be read") from exc
    if not value or any(character.isspace() for character in value):
        raise CentralApiError("Central API access file is empty or malformed")
    return CentralApiCredential(value, source="protected runner access file")


class CentralApiApp:
    """WSGI application intended to run behind production TLS termination."""

    def __init__(
        self,
        collector: CentralCollector,
        *,
        credential: CentralApiCredential,
        artifact_root: Path | None = None,
        fleet_archive_root: Path | None = None,
        secondary_archive_root: Path | None = None,
        max_body_bytes: int = 8 * 1024 * 1024,
        max_artifact_bytes: int = 256 * 1024 * 1024,
    ) -> None:
        if not credential.bearer_token:
            raise ValueError("Central API bearer token is required")
        self.collector = collector
        self._credential = credential
        self.artifact_root = artifact_root
        self.fleet_archive_root = fleet_archive_root
        self.secondary_archive_root = secondary_archive_root
        self.max_body_bytes = max_body_bytes
        self.max_artifact_bytes = max_artifact_bytes
        self._secondary_retry = (
            SecondaryArchiveRetryQueue(Path(artifact_root) / ".secondary-archive-retry.sqlite3")
            if artifact_root is not None
            else None
        )

    def __call__(self, environ: Mapping[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
        method = str(environ.get("REQUEST_METHOD") or "").upper()
        path = str(environ.get("PATH_INFO") or "")
        if method == "GET" and path == "/healthz":
            return self._respond(start_response, "200 OK", {"status": "OK"})
        if not ((method == "POST" and path == "/v1/events") or (method == "PUT" and path.startswith("/v1/artifacts/"))):
            return self._respond(start_response, "404 Not Found", {"error": "NOT_FOUND"})
        supplied = str(environ.get("HTTP_AUTHORIZATION") or "")
        expected = f"Bearer {self._credential.bearer_token}"
        if not hmac.compare_digest(supplied, expected):
            return self._respond(start_response, "401 Unauthorized", {"error": "UNAUTHORIZED"})
        if method == "PUT":
            return self._receive_artifact(environ, start_response, path)
        try:
            content_length = int(environ.get("CONTENT_LENGTH") or "0")
        except ValueError:
            return self._respond(start_response, "400 Bad Request", {"error": "INVALID_CONTENT_LENGTH"})
        if content_length <= 0 or content_length > self.max_body_bytes:
            return self._respond(start_response, "413 Payload Too Large", {"error": "PAYLOAD_SIZE_REJECTED"})
        body = environ["wsgi.input"].read(content_length)
        try:
            event = json.loads(body.decode("utf-8"))
            if not isinstance(event, dict):
                raise ValueError
            result = self.collector.ingest_event(event)
        except IdempotencyConflict:
            return self._respond(start_response, "409 Conflict", {"error": "IDEMPOTENCY_CONFLICT"})
        except (CollectorError, SensitiveEvidenceError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            return self._respond(start_response, "400 Bad Request", {"error": "INVALID_EVENT"})
        return self._respond(start_response, "200 OK", result)

    def _receive_artifact(self, environ: Mapping[str, Any], start_response: Callable[..., Any], path: str) -> Iterable[bytes]:
        if self.artifact_root is None:
            return self._respond(start_response, "404 Not Found", {"error": "ARTIFACT_STORAGE_DISABLED"})
        parts = path.split("/", 5)
        if len(parts) != 6:
            return self._respond(start_response, "400 Bad Request", {"error": "INVALID_ARTIFACT_PATH"})
        run_id, expected_hash, filename = (unquote(parts[3]), unquote(parts[4]).lower(), unquote(parts[5]))
        artifact_type = str(environ.get("HTTP_X_CNSERVEROPS_ARTIFACT_TYPE") or "UNKNOWN").upper()
        if not re.fullmatch(r"RUN-[A-Z0-9-]{8,96}", run_id):
            return self._respond(start_response, "400 Bad Request", {"error": "INVALID_RUN_ID"})
        if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
            return self._respond(start_response, "400 Bad Request", {"error": "INVALID_SHA256"})
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,159}", filename):
            return self._respond(start_response, "400 Bad Request", {"error": "INVALID_FILENAME"})
        if re.search(r"password|passwd|credential|secret|token|private.?key|authorization", filename, re.IGNORECASE):
            return self._respond(start_response, "400 Bad Request", {"error": "SENSITIVE_FILENAME_REJECTED"})
        if not re.fullmatch(r"[A-Z0-9._-]{1,96}", artifact_type):
            return self._respond(start_response, "400 Bad Request", {"error": "INVALID_ARTIFACT_TYPE"})
        try:
            content_length = int(environ.get("CONTENT_LENGTH") or "0")
        except ValueError:
            return self._respond(start_response, "400 Bad Request", {"error": "INVALID_CONTENT_LENGTH"})
        if content_length <= 0 or content_length > self.max_artifact_bytes:
            return self._respond(start_response, "413 Payload Too Large", {"error": "ARTIFACT_SIZE_REJECTED"})
        try:
            context = self.collector.artifact_context(run_id)
            serial = re.sub(r"[^A-Za-z0-9._-]+", "-", context["system_serial"]).strip("-._") or context["server_id"]
            destination_root = self.artifact_root.resolve()
            destination = (destination_root / serial / run_id / filename).resolve()
            if destination_root != destination and destination_root not in destination.parents:
                raise CollectorError("artifact destination escaped Central storage root")
            destination.parent.mkdir(parents=True, exist_ok=True)
            descriptor, temporary_name = tempfile.mkstemp(prefix=filename + ".", suffix=".upload", dir=destination.parent)
            digest = hashlib.sha256()
            remaining = content_length
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    while remaining:
                        block = environ["wsgi.input"].read(min(1024 * 1024, remaining))
                        if not block:
                            raise CollectorError("artifact body ended before Content-Length")
                        stream.write(block)
                        digest.update(block)
                        remaining -= len(block)
                    stream.flush()
                    os.fsync(stream.fileno())
                if digest.hexdigest() != expected_hash:
                    raise CollectorError("artifact SHA256 does not match request identity")
                duplicate = destination.exists()
                if duplicate:
                    existing_digest = _file_sha256(destination)
                    if existing_digest != expected_hash:
                        raise IdempotencyConflict("artifact filename already contains different content")
                else:
                    Path(temporary_name).replace(destination)
                archive = self._archive_fleet_artifact(
                    destination,
                    serial=serial,
                    run_id=run_id,
                    artifact_type=artifact_type,
                    context=context,
                )
                primary_archive = archive.get("primary") if isinstance(archive, Mapping) else {}
                secondary_archive = archive.get("secondary") if isinstance(archive, Mapping) else {}
                archive_path = str(primary_archive.get("path") or "")
                archive_hash = str(primary_archive.get("sha256") or "")
                record = self.collector.register_artifact(
                    run_id,
                    {
                        "sha256": expected_hash,
                        "type": artifact_type,
                        "uri": str(destination.relative_to(destination_root)).replace("\\", "/"),
                        "size_bytes": content_length,
                        "metadata": {
                            "filename": filename,
                            "server_id": context["server_id"],
                            "fleet_archive_uri": archive_path,
                            "fleet_archive_sha256": archive_hash,
                            "primary_archive_status": str(primary_archive.get("status") or "NOT_CONFIGURED"),
                            "secondary_archive_status": str(secondary_archive.get("status") or "NOT_CONFIGURED"),
                            "secondary_archive_uri": str(secondary_archive.get("path") or ""),
                            "secondary_archive_sha256": str(secondary_archive.get("sha256") or ""),
                        },
                    },
                )
                status = "DUPLICATE_ACCEPTED" if duplicate or record.get("status") == "DUPLICATE_ACCEPTED" else "ACCEPTED"
                return self._respond(
                    start_response,
                    "200 OK",
                    {
                        "status": status,
                        "run_id": run_id,
                        "sha256": expected_hash,
                        "filename": filename,
                        "fleet_archive_path": archive_path,
                        "fleet_archive_sha256": archive_hash,
                        "primary_archive": primary_archive,
                        "secondary_archive": secondary_archive,
                    },
                )
            finally:
                temporary = Path(temporary_name)
                if temporary.exists():
                    temporary.unlink()
        except IdempotencyConflict:
            return self._respond(start_response, "409 Conflict", {"error": "IDEMPOTENCY_CONFLICT"})
        except (CollectorError, OSError, ValueError):
            return self._respond(start_response, "400 Bad Request", {"error": "INVALID_ARTIFACT"})

    def _archive_fleet_artifact(
        self,
        source: Path,
        *,
        serial: str,
        run_id: str,
        artifact_type: str,
        context: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Archive every accepted run artifact on Central's Windows host.

        The Linux runner only uploads immutable bytes.  Central creates the
        serial/timestamp folder and mirrors the same verified bytes to the
        optional UNC secondary without making a mirror outage fail the run.
        """
        result: dict[str, Any] = {
            "run_type": _archive_run_type(context),
            "primary": {"status": "NOT_CONFIGURED", "path": "", "sha256": ""},
            "secondary": {"status": "NOT_CONFIGURED", "path": "", "sha256": ""},
        }
        roots = {
            "primary": self.fleet_archive_root,
            "secondary": self.secondary_archive_root,
        }
        if roots["primary"] is None:
            return result
        started = str(context.get("started_at_utc") or "")
        try:
            parsed = datetime.fromisoformat(started.replace("Z", "+00:00"))
            stamp = parsed.astimezone(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
        except ValueError:
            stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
        run_type = result["run_type"]
        folder_name = f"{stamp}_{run_type}"
        for label, root in roots.items():
            if root is None:
                continue
            try:
                target = _copy_verified_archive_artifact(
                    source,
                    root=Path(root),
                    serial=serial,
                    run_id=run_id,
                    folder_name=folder_name,
                    artifact_type=artifact_type,
                )
                result[label] = {"status": "SYNCED", "path": str(target), "sha256": _file_sha256(target)}
            except (OSError, IdempotencyConflict, CollectorError) as exc:
                result[label] = {
                    "status": "PENDING_RETRY" if label == "secondary" else "FAILED",
                    "path": "",
                    "sha256": "",
                    "error": type(exc).__name__,
                }
        if (
            self._secondary_retry is not None
            and self.secondary_archive_root is not None
            and str(result.get("secondary", {}).get("status") or "") == "PENDING_RETRY"
        ):
            self._secondary_retry.enqueue(
                source,
                serial=serial,
                run_id=run_id,
                folder_name=folder_name,
                artifact_type=artifact_type,
            )
        return result

    def retry_pending_secondary_archives(self, *, limit: int = 100) -> dict[str, Any]:
        """Retry already-accepted Central artifacts to the optional UNC mirror.

        This is deliberately Central-side: the SSD has already delivered and
        hash-verified the immutable bytes over HTTPS, so an unavailable share
        cannot cause duplicate uploads or invalidate a healthy server run.
        """
        if self._secondary_retry is None or self.secondary_archive_root is None:
            return {"status": "NOT_CONFIGURED", "attempted": 0, "synced": 0, "pending": 0}
        result = self._secondary_retry.retry(Path(self.secondary_archive_root), limit=limit)
        for item in result.get("synced_records") or []:
            if not isinstance(item, Mapping):
                continue
            self.collector.update_artifact_delivery_metadata(
                str(item.get("run_id") or ""),
                str(item.get("sha256") or ""),
                str(item.get("artifact_type") or "UNKNOWN"),
                {
                    "secondary_archive_status": "SYNCED",
                    "secondary_archive_uri": str(item.get("path") or ""),
                    "secondary_archive_sha256": str(item.get("sha256") or ""),
                    "secondary_archive_retried_at_utc": datetime.now(timezone.utc).isoformat(),
                },
            )
        return result

    @staticmethod
    def _respond(start_response: Callable[..., Any], status: str, payload: Mapping[str, Any]) -> list[bytes]:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        start_response(
            status,
            [("Content-Type", "application/json"), ("Content-Length", str(len(body))), ("Cache-Control", "no-store")],
        )
        return [body]


class HttpsCollectorClient:
    """Store-and-forward transport; the bearer token is never serialized into an event."""

    def __init__(
        self,
        endpoint: str,
        *,
        credential: CentralApiCredential,
        verify_tls: bool = True,
        ca_file: str | None = None,
        timeout_seconds: int = 30,
    ) -> None:
        parsed = urlparse(endpoint)
        if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Central endpoint must be an HTTPS URL without embedded credentials")
        self.base_endpoint = endpoint.rstrip("/")
        self.endpoint = self.base_endpoint + "/v1/events"
        self._credential = credential
        self.timeout_seconds = timeout_seconds
        if verify_tls:
            self.ssl_context = ssl.create_default_context(cafile=ca_file)
        else:
            self.ssl_context = ssl._create_unverified_context()

    def ingest_event(self, event: Mapping[str, Any]) -> Mapping[str, Any]:
        body = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
        request = Request(
            self.endpoint,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self._credential.bearer_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds, context=self.ssl_context) as response:
                result = json.loads(response.read().decode("utf-8"))
                if not isinstance(result, dict):
                    raise CentralApiError("Central API returned a malformed response")
                return result
        except HTTPError as exc:
            raise CentralApiError(f"Central API HTTP {exc.code}") from exc
        except (URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise CentralApiError(f"Central API transport failure: {type(exc).__name__}") from exc

    def upload_artifact(
        self,
        run_id: str,
        path: Path,
        *,
        artifact_type: str,
        sha256: str,
    ) -> Mapping[str, Any]:
        if path.is_symlink() or not path.resolve(strict=True).is_file():
            raise CentralApiError("Artifact source must be a regular non-symlink file")
        parsed = urlparse(self.base_endpoint)
        route = "/v1/artifacts/{}/{}/{}".format(
            quote(str(run_id), safe=""), quote(str(sha256).lower(), safe=""), quote(path.name, safe="")
        )
        connection = http.client.HTTPSConnection(
            parsed.hostname,
            parsed.port or 443,
            timeout=self.timeout_seconds,
            context=self.ssl_context,
        )
        try:
            size = path.stat().st_size
            connection.putrequest("PUT", route)
            connection.putheader("Authorization", f"Bearer {self._credential.bearer_token}")
            connection.putheader("Content-Type", "application/octet-stream")
            connection.putheader("Content-Length", str(size))
            connection.putheader("X-CNServerOps-Artifact-Type", str(artifact_type).upper())
            connection.putheader("Accept", "application/json")
            connection.endheaders()
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    connection.send(block)
            response = connection.getresponse()
            payload = json.loads(response.read().decode("utf-8"))
            if response.status != 200:
                raise CentralApiError(
                    f"Central artifact upload returned HTTP {response.status}",
                    http_status=response.status,
                )
            if not isinstance(payload, dict):
                raise CentralApiError("Central artifact response was malformed")
            return payload
        except CentralApiError:
            raise
        except (OSError, TimeoutError, ssl.SSLError, http.client.HTTPException, json.JSONDecodeError) as exc:
            raise CentralApiError(f"Central artifact upload failed: {type(exc).__name__}") from exc
        finally:
            connection.close()


class SecondaryArchiveRetryQueue:
    """Durable, hash-bound retry queue for the optional Windows UNC mirror."""

    def __init__(self, database: Path) -> None:
        self.database = Path(database)

    def initialize(self) -> None:
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS secondary_archive_retry (
                    retry_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    artifact_type TEXT NOT NULL,
                    source_path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    serial TEXT NOT NULL,
                    folder_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT NOT NULL DEFAULT '',
                    destination_path TEXT NOT NULL DEFAULT '',
                    created_at_utc TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "UPDATE secondary_archive_retry SET status='PENDING_RETRY',last_error='previous retry interrupted' WHERE status='IN_FLIGHT'"
            )

    def enqueue(
        self,
        source: Path,
        *,
        serial: str,
        run_id: str,
        folder_name: str,
        artifact_type: str,
    ) -> dict[str, Any]:
        self.initialize()
        resolved = source.resolve(strict=True)
        if source.is_symlink() or not resolved.is_file():
            raise CollectorError("secondary retry source must be a regular artifact")
        digest = _file_sha256(resolved)
        retry_id = hashlib.sha256(
            f"{run_id}\0{artifact_type}\0{digest}\0{resolved.name}\0{folder_name}".encode("utf-8")
        ).hexdigest()
        now = datetime.now(timezone.utc).isoformat()
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO secondary_archive_retry(
                    retry_id,run_id,artifact_type,source_path,sha256,serial,folder_name,status,created_at_utc,updated_at_utc
                ) VALUES(?,?,?,?,?,?,?,'PENDING_RETRY',?,?)
                ON CONFLICT(retry_id) DO UPDATE SET
                    source_path=excluded.source_path,
                    status=CASE WHEN secondary_archive_retry.status='SYNCED' THEN 'SYNCED' ELSE 'PENDING_RETRY' END,
                    updated_at_utc=excluded.updated_at_utc
                """,
                (retry_id, run_id, str(artifact_type).upper(), str(resolved), digest, serial, folder_name, now, now),
            )
        return {"status": "PENDING_RETRY", "retry_id": retry_id, "sha256": digest}

    def retry(self, root: Path, *, limit: int = 100) -> dict[str, Any]:
        self.initialize()
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT retry_id,run_id,artifact_type,source_path,sha256,serial,folder_name
                FROM secondary_archive_retry WHERE status='PENDING_RETRY'
                ORDER BY created_at_utc LIMIT ?
                """,
                (max(1, min(int(limit), 1000)),),
            ).fetchall()
        synced: list[dict[str, Any]] = []
        failed = 0
        for retry_id, run_id, artifact_type, source_path, expected_hash, serial, folder_name in rows:
            with self._connection() as connection:
                connection.execute(
                    "UPDATE secondary_archive_retry SET status='IN_FLIGHT',attempts=attempts+1,updated_at_utc=? WHERE retry_id=?",
                    (datetime.now(timezone.utc).isoformat(), retry_id),
                )
            try:
                source = Path(str(source_path))
                if source.is_symlink() or not source.resolve(strict=True).is_file():
                    raise CollectorError("secondary retry artifact unavailable")
                if _file_sha256(source) != str(expected_hash):
                    raise CollectorError("secondary retry artifact hash changed")
                target = _copy_verified_archive_artifact(
                    source,
                    root=Path(root),
                    serial=str(serial),
                    run_id=str(run_id),
                    folder_name=str(folder_name),
                    artifact_type=str(artifact_type),
                )
                target_hash = _file_sha256(target)
                if target_hash != str(expected_hash):
                    raise CollectorError("secondary retry final hash mismatch")
            except (OSError, CollectorError, IdempotencyConflict) as exc:
                failed += 1
                with self._connection() as connection:
                    connection.execute(
                        "UPDATE secondary_archive_retry SET status='PENDING_RETRY',last_error=?,updated_at_utc=? WHERE retry_id=?",
                        (type(exc).__name__, datetime.now(timezone.utc).isoformat(), retry_id),
                    )
            else:
                record = {
                    "run_id": str(run_id),
                    "artifact_type": str(artifact_type),
                    "sha256": target_hash,
                    "path": str(target),
                }
                synced.append(record)
                with self._connection() as connection:
                    connection.execute(
                        "UPDATE secondary_archive_retry SET status='SYNCED',last_error='',destination_path=?,updated_at_utc=? WHERE retry_id=?",
                        (str(target), datetime.now(timezone.utc).isoformat(), retry_id),
                    )
        return {
            "status": "PASS" if not failed else "PARTIAL",
            "attempted": len(rows),
            "synced": len(synced),
            "pending": max(0, len(rows) - len(synced)),
            "failed": failed,
            "synced_records": synced,
        }

    def counts(self) -> dict[str, int]:
        self.initialize()
        with self._connection() as connection:
            rows = connection.execute("SELECT status,COUNT(*) FROM secondary_archive_retry GROUP BY status").fetchall()
        return {str(status): int(count) for status, count in rows}

    def _connection(self):
        connection = sqlite3.connect(self.database, timeout=30)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=30000")
        return _SqliteContext(connection)


class _SqliteContext:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def __enter__(self) -> sqlite3.Connection:
        return self.connection

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        try:
            if exc_type is None:
                self.connection.commit()
            else:
                self.connection.rollback()
        finally:
            self.connection.close()


def _copy_verified_archive_artifact(
    source: Path,
    *,
    root: Path,
    serial: str,
    run_id: str,
    folder_name: str,
    artifact_type: str,
) -> Path:
    """Copy immutable Central bytes to an idempotent serial/run archive path."""
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    server_root = root / str(serial)
    server_root.mkdir(parents=True, exist_ok=True)
    destination = server_root / str(folder_name)
    suffix = 2
    while destination.exists():
        marker = destination / ".run_id"
        if marker.is_file() and marker.read_text(encoding="utf-8").strip() == str(run_id):
            break
        destination = server_root / f"{folder_name}_{suffix:02d}"
        suffix += 1
    destination.mkdir(parents=True, exist_ok=True)
    marker = destination / ".run_id"
    if not marker.exists():
        marker.write_text(str(run_id) + "\n", encoding="utf-8")
    kind = str(artifact_type).upper()
    subdir = "logs" if kind == "SEL_LOG" else "raw" if kind.startswith("RAW") else ""
    target_dir = destination / subdir
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / source.name
    source_hash = _file_sha256(source)
    if target.exists() and _file_sha256(target) != source_hash:
        raise IdempotencyConflict("archive filename already contains different content")
    if not target.exists():
        temporary = target.with_suffix(target.suffix + ".upload")
        shutil.copyfile(source, temporary)
        if _file_sha256(temporary) != source_hash:
            temporary.unlink(missing_ok=True)
            raise CollectorError("archive SHA256 verification failed")
        temporary.replace(target)
    if _file_sha256(target) != source_hash:
        raise CollectorError("archive final SHA256 verification failed")
    return target


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _archive_run_type(context: Mapping[str, Any]) -> str:
    mode = str(context.get("workflow_mode") or "PRODUCTION").upper()
    return {
        "FLEET_INTAKE": "FLEET_INTAKE",
        "PRODUCTION": "FULL_PRODUCTION",
        "FULL_PRODUCTION": "FULL_PRODUCTION",
        "PRODUCTION_EXTENDED": "FULL_PRODUCTION_EXTENDED",
        "FULL_PRODUCTION_EXTENDED": "FULL_PRODUCTION_EXTENDED",
        "DRY_RUN": "DRY_RUN",
        "INVENTORY_ONLY": "INVENTORY_ONLY",
        "SERIAL_COLLECTION": "SERIAL_COLLECTION",
    }.get(mode, re.sub(r"[^A-Z0-9_-]+", "_", mode).strip("_") or "PRODUCTION")
