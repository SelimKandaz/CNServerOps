"""Capability-driven ASUS ASMB12 System Diagnostics integration.

ASMB12 exposes System Diagnostics through its authenticated WebUI API on
some firmware/SKU combinations, rather than through a standard Redfish
diagnostic action.  This module follows the WebUI's documented API contract
without guessing undocumented endpoints.  It never persists credentials or
prints response bodies that could contain sensitive material.
"""

from __future__ import annotations

import hashlib
import http.cookiejar
import json
import os
import re
import ssl
import tempfile
import time
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin
from urllib.request import HTTPSHandler, HTTPCookieProcessor, Request, build_opener


DIAGNOSTIC_STATUSES = frozenset(
    {"PASS", "UNSUPPORTED", "AUTH_BLOCKED", "EXECUTION_FAILED", "HARDWARE_FAILURE"}
)


@dataclass(frozen=True)
class DiagnosticCredentials:
    """Runtime-only credentials; never serialized or repr'ed with the secret."""

    username: str
    password: str


class Asmb12WebError(RuntimeError):
    def __init__(self, path: str, status: str, *, http_status: int | None = None) -> None:
        self.path = path
        self.status = status
        self.http_status = http_status
        suffix = f" HTTP {http_status}" if http_status is not None else ""
        super().__init__(f"{path}: {status}{suffix}")


class Asmb12WebClient:
    """Small authenticated ASMB12 WebUI client restricted to diagnostics GETs."""

    def __init__(self, host: str, credentials: DiagnosticCredentials, *, verify_tls: bool = False, timeout_seconds: int = 30) -> None:
        value = str(host or "").strip()
        if not value:
            raise ValueError("BMC host is required")
        self.base_url = value if value.startswith("https://") else f"https://{value}"
        self.base_url = self.base_url.rstrip("/") + "/"
        self.credentials = credentials
        self.timeout_seconds = max(1, min(int(timeout_seconds), 300))
        self.context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
        self.cookies = http.cookiejar.CookieJar()
        self.opener = build_opener(HTTPSHandler(context=self.context), HTTPCookieProcessor(self.cookies))
        self.csrf_token = ""
        self.authenticated = False

    def login(self) -> dict[str, Any]:
        # Form fields are sent only to the BMC session endpoint; they are never
        # included in exceptions, evidence or returned records.
        body = urlencode({"username": self.credentials.username, "password": self.credentials.password}).encode()
        request = Request(urljoin(self.base_url, "/api/session"), data=body, method="POST")
        request.add_header("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
        try:
            with self.opener.open(request, timeout=self.timeout_seconds) as response:
                payload = _json_response(response.read())
        except HTTPError as exc:
            raise Asmb12WebError("/api/session", "AUTH_BLOCKED", http_status=exc.code) from exc
        except (OSError, URLError, ssl.SSLError, TimeoutError) as exc:
            raise Asmb12WebError("/api/session", "TRANSPORT_ERROR") from exc
        # The AMI/ASMB12 API uses ``ok: 0`` for a successful session (the
        # inverse of many conventional JSON APIs). Treat only an explicit
        # non-zero value as authentication failure.
        if not isinstance(payload, dict) or payload.get("ok") not in {0, "0", False}:
            raise Asmb12WebError("/api/session", "AUTH_BLOCKED")
        self.csrf_token = str(payload.get("CSRFToken") or "")
        self.authenticated = True
        return {
            "status": "AUTHENTICATED",
            "privilege": str(payload.get("privilege") or ""),
            "user_id": payload.get("user_id"),
            "csrf_present": bool(self.csrf_token),
        }

    def get_json(self, path: str) -> tuple[int, Any]:
        return self._request("GET", path, accept="application/json")

    def get_bytes(self, path: str, *, query: Mapping[str, Any] | None = None) -> tuple[int, bytes, str]:
        query_string = urlencode({str(k): str(v) for k, v in (query or {}).items()})
        normalized = path + (f"?{query_string}" if query_string else "")
        request = Request(urljoin(self.base_url, normalized), method="GET")
        request.add_header("Accept", "application/zip, application/octet-stream, */*")
        if self.csrf_token:
            request.add_header("X-CSRFTOKEN", self.csrf_token)
        try:
            with self.opener.open(request, timeout=self.timeout_seconds) as response:
                return int(response.status), response.read(), str(response.headers.get("Content-Type") or "")
        except HTTPError as exc:
            if exc.code in {401, 403}:
                raise Asmb12WebError(path, "AUTH_BLOCKED", http_status=exc.code) from exc
            if exc.code == 404:
                raise Asmb12WebError(path, "UNSUPPORTED", http_status=exc.code) from exc
            raise Asmb12WebError(path, "EXECUTION_FAILED", http_status=exc.code) from exc
        except (OSError, URLError, ssl.SSLError, TimeoutError) as exc:
            raise Asmb12WebError(path, "TRANSPORT_ERROR") from exc

    def _request(self, method: str, path: str, *, accept: str) -> tuple[int, Any]:
        request = Request(urljoin(self.base_url, path), method=method)
        request.add_header("Accept", accept)
        if self.csrf_token:
            request.add_header("X-CSRFTOKEN", self.csrf_token)
        try:
            # The HTTPS context is bound to the opener's HTTPSHandler.  Passing
            # ``context`` to OpenerDirector.open is unsupported on Python 3 and
            # would turn every otherwise valid discovery into EXECUTION_FAILED.
            with self.opener.open(request, timeout=self.timeout_seconds) as response:
                return int(response.status), _json_response(response.read())
        except HTTPError as exc:
            if exc.code in {401, 403}:
                raise Asmb12WebError(path, "AUTH_BLOCKED", http_status=exc.code) from exc
            if exc.code == 404:
                raise Asmb12WebError(path, "UNSUPPORTED", http_status=exc.code) from exc
            raise Asmb12WebError(path, "EXECUTION_FAILED", http_status=exc.code) from exc
        except (OSError, URLError, ssl.SSLError, TimeoutError) as exc:
            raise Asmb12WebError(path, "TRANSPORT_ERROR") from exc


def discover_asmb12_diagnostics(
    host: str,
    *,
    credentials: DiagnosticCredentials | None,
    verify_tls: bool = False,
) -> dict[str, Any]:
    """Discover the official ASMB12 WebUI capability without mutation."""
    result: dict[str, Any] = {
        "schema_version": 1,
        "vendor": "ASUS",
        "adapter": "ASMB12_WEBUI_SYSTEM_DIAGNOSTICS",
        "discovery_started_at_utc": _now(),
        "status": "AUTH_BLOCKED" if credentials is None else "UNSUPPORTED",
        "transport": "ASMB12_WEBUI_API",
        "feature_catalog_endpoint": "/api/configuration/project",
        "log_endpoint": "/api/system_diagnostics/log",
        "generate_endpoint": "/api/system_diagnostics/generate_system_diagnostics_logs",
        "download_endpoint": "/api/system_diagnostics/download_system_diagnostics_log",
        "feature_advertised": False,
        "endpoint_status": {},
        "errors": [],
        "discovery_completed_at_utc": "",
    }
    if credentials is None:
        result["reason"] = "NO_APPROVED_AUTHENTICATED_BMC_CREDENTIAL"
        result["discovery_completed_at_utc"] = _now()
        return result
    client = Asmb12WebClient(host, credentials, verify_tls=verify_tls)
    try:
        login = client.login()
        result["authentication"] = login
        status, catalog = client.get_json("/api/configuration/project")
        result["endpoint_status"]["feature_catalog"] = status
        features = sorted(
            str(item.get("feature") or "")
            for item in (catalog if isinstance(catalog, list) else [])
            if isinstance(item, Mapping) and item.get("feature")
        )
        result["features"] = features
        result["feature_advertised"] = "SYSTEM_DIAGNOSTICS" in {item.upper() for item in features}
        try:
            log_status, logs = client.get_json("/api/system_diagnostics/log")
            result["endpoint_status"]["log"] = log_status
            result["existing_logs"] = _public_log_list(logs)
        except Asmb12WebError as exc:
            result["endpoint_status"]["log"] = exc.http_status or exc.status
            result["errors"].append(exc.status)
            if exc.status == "AUTH_BLOCKED":
                result["status"] = "AUTH_BLOCKED"
            elif exc.status == "UNSUPPORTED":
                result["status"] = "UNSUPPORTED"
            else:
                result["status"] = "EXECUTION_FAILED"
        if result["feature_advertised"] and result.get("endpoint_status", {}).get("log") == 200:
            result["status"] = "AVAILABLE"
        elif result["status"] not in {"AUTH_BLOCKED", "EXECUTION_FAILED"}:
            result["status"] = "UNSUPPORTED"
    except Asmb12WebError as exc:
        result["status"] = "AUTH_BLOCKED" if exc.status == "AUTH_BLOCKED" else "EXECUTION_FAILED"
        result["errors"].append(exc.status)
    finally:
        result["discovery_completed_at_utc"] = _now()
    return result


def execute_asmb12_diagnostics(
    host: str,
    *,
    credentials: DiagnosticCredentials | None,
    output_dir: Path,
    verify_tls: bool = False,
    poll_seconds: int = 5,
    max_polls: int = 24,
) -> dict[str, Any]:
    """Run, poll, download and hash an official ASMB12 diagnostic ZIP."""
    started = _now()
    discovery = discover_asmb12_diagnostics(host, credentials=credentials, verify_tls=verify_tls)
    result: dict[str, Any] = {
        **discovery,
        "execution_started_at_utc": started,
        "execution_completed_at_utc": "",
        "duration_seconds": 0,
        "artifact": None,
        "findings": [],
    }
    if discovery.get("status") != "AVAILABLE":
        result["status"] = str(discovery.get("status") or "UNSUPPORTED")
        result["reason"] = "DIAGNOSTIC_CAPABILITY_NOT_AVAILABLE"
        result["execution_completed_at_utc"] = _now()
        result["duration_seconds"] = _duration(started, result["execution_completed_at_utc"])
        return result
    if credentials is None:
        result["status"] = "AUTH_BLOCKED"
        result["reason"] = "NO_APPROVED_AUTHENTICATED_BMC_CREDENTIAL"
        result["execution_completed_at_utc"] = _now()
        result["duration_seconds"] = _duration(started, result["execution_completed_at_utc"])
        return result
    client = Asmb12WebClient(host, credentials, verify_tls=verify_tls)
    try:
        result["authentication"] = client.login()
        generate_status, generate_payload = client.get_json("/api/system_diagnostics/generate_system_diagnostics_logs")
        result["generate_http_status"] = generate_status
        result["generate_response"] = _safe_payload(generate_payload)
        if generate_status != 200:
            raise Asmb12WebError("/api/system_diagnostics/generate_system_diagnostics_logs", "EXECUTION_FAILED", http_status=generate_status)
        previous = {str(item.get("file_name")) for item in discovery.get("existing_logs") or [] if item.get("file_name")}
        selected: dict[str, Any] | None = None
        for attempt in range(max(1, int(max_polls))):
            status, payload = client.get_json("/api/system_diagnostics/log")
            result["poll_count"] = attempt + 1
            entries = _public_log_list(payload)
            candidates = [item for item in entries if item.get("file_name") not in previous]
            if candidates:
                selected = candidates[-1]
                break
            if attempt + 1 < max(1, int(max_polls)):
                time.sleep(max(0, int(poll_seconds)))
        if selected is None:
            raise Asmb12WebError("/api/system_diagnostics/log", "EXECUTION_FAILED")
        filename = _safe_filename(str(selected.get("file_name") or "ASUS_System_Diagnostics.zip"))
        status, data, content_type = client.get_bytes(
            "/api/system_diagnostics/download_system_diagnostics_log",
            query={"file": str(selected.get("file_name") or filename)},
        )
        if status != 200 or not data:
            raise Asmb12WebError("/api/system_diagnostics/download_system_diagnostics_log", "EXECUTION_FAILED", http_status=status)
        output_dir.mkdir(parents=True, exist_ok=True)
        destination = output_dir / f"ASUS_System_Diagnostics_{filename}"
        _atomic_bytes(destination, data)
        valid_zip = zipfile.is_zipfile(destination)
        if not valid_zip:
            raise Asmb12WebError("/api/system_diagnostics/download_system_diagnostics_log", "EXECUTION_FAILED")
        digest = _sha256(destination)
        findings = _scan_vendor_findings(destination)
        result["artifact"] = {
            "filename": destination.name,
            "path": str(destination),
            "size_bytes": destination.stat().st_size,
            "sha256": digest,
            "content_type": content_type,
            "format": "ZIP",
            "zip_valid": True,
            "source": "ASUS ASMB12 WebUI System Diagnostics",
        }
        result["findings"] = findings
        result["status"] = "HARDWARE_FAILURE" if findings else "PASS"
    except Asmb12WebError as exc:
        result["status"] = exc.status if exc.status in DIAGNOSTIC_STATUSES else "EXECUTION_FAILED"
        result["errors"].append(exc.status)
        result["reason"] = str(exc)
    finally:
        result["execution_completed_at_utc"] = _now()
        result["duration_seconds"] = _duration(started, result["execution_completed_at_utc"])
    return result


def _public_log_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    rows: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            continue
        row = {"file_name": str(item.get("file_name") or "")}
        if item.get("fileinfo") is not None:
            row["fileinfo"] = str(item.get("fileinfo"))[:500]
        rows.append(row)
    return rows


def _scan_vendor_findings(path: Path) -> list[str]:
    findings: list[str] = []
    try:
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                if not name.lower().endswith((".txt", ".log", ".json", ".csv", ".xml")):
                    continue
                data = archive.read(name)[:2_000_000].decode("utf-8", errors="replace")
                for line in data.splitlines():
                    if re.search(r"\b(fail(?:ed|ure)?|critical|error|abnormal|bad)\b", line, re.I):
                        findings.append(f"{name}: {line.strip()[:240]}")
                        if len(findings) >= 100:
                            return findings
    except (OSError, zipfile.BadZipFile, KeyError):
        return ["VENDOR_ARTIFACT_READ_FAILED"]
    return findings


def _json_response(value: bytes) -> Any:
    try:
        return json.loads(value.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise Asmb12WebError("response", "EXECUTION_FAILED") from exc


def _safe_payload(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _safe_payload(v) for k, v in value.items() if not re.search(r"password|token|secret|credential", str(k), re.I)}
    if isinstance(value, list):
        return [_safe_payload(v) for v in value]
    return value


def _safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", Path(value).name).strip("._-") or "diagnostic.zip"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _duration(start: str, end: str) -> int:
    try:
        return max(0, int((datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds()))
    except ValueError:
        return 0


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        Path(temporary_name).replace(path)
    finally:
        temporary = Path(temporary_name)
        if temporary.exists():
            temporary.unlink()
