"""Credential-safe, authenticated Redfish client restricted to HTTPS GET."""

from __future__ import annotations

import base64
import getpass
import hashlib
import json
import os
import re
import socket
import ssl
import uuid
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


class RedfishFailureKind(str, Enum):
    BLOCKED_BY_AUTH = "BLOCKED_BY_AUTH"
    PASSWORD_CHANGE_REQUIRED = "PASSWORD_CHANGE_REQUIRED"
    BLOCKED_BY_MISSING_ENDPOINT = "BLOCKED_BY_MISSING_ENDPOINT"
    TIMEOUT = "TIMEOUT"
    TRANSPORT_ERROR = "TRANSPORT_ERROR"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
    HTTP_ERROR = "HTTP_ERROR"


class RedfishRequestError(RuntimeError):
    """A sanitized GET failure; response bodies and credentials are never retained."""

    def __init__(
        self,
        path: str,
        kind: RedfishFailureKind = RedfishFailureKind.HTTP_ERROR,
        *,
        http_status: int | None = None,
        response_sha256: str = "",
        response_length: int | None = None,
        response_hint: str = "",
    ) -> None:
        self.path = path
        self.kind = kind
        self.http_status = http_status
        # Error bodies can contain vendor diagnostics, but must never be
        # persisted because an implementation or proxy could echo secrets.
        # Keep only a digest and bounded byte count so failed update requests
        # remain auditable without retaining response content.
        self.response_sha256 = str(response_sha256 or "")
        self.response_length = response_length
        self.response_hint = str(response_hint or "")[:240]
        status = f" HTTP {http_status}" if http_status is not None else ""
        super().__init__(f"{path}: {kind.value}{status}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "status": self.kind.value,
            "http_status": self.http_status,
            "response_sha256": self.response_sha256,
            "response_length": self.response_length,
            "response_hint": self.response_hint,
        }


@dataclass(frozen=True)
class RedfishCredentials:
    username: str = ""
    password: str = field(default="", repr=False)
    token: str = field(default="", repr=False)
    source: str = "NONE"

    @property
    def available(self) -> bool:
        return bool(self.token or (self.username and self.password))

    def public_status(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "mode": "TOKEN" if self.token else "USERNAME_PASSWORD" if self.available else "NONE",
            "source": self.source,
            "secret_persisted": False,
        }


def credentials_from_runtime(
    *,
    username: str = "",
    password_env: str = "CN_ASUS_BMC_PASSWORD",
    token_env: str = "CN_ASUS_BMC_TOKEN",
    interactive: bool = False,
) -> RedfishCredentials:
    """Resolve a secret at runtime without putting it in command arguments or output."""
    token = os.environ.get(token_env, "")
    if token:
        return RedfishCredentials(token=token, source=f"environment:{token_env}")
    password = os.environ.get(password_env, "")
    if password:
        return RedfishCredentials(username=username, password=password, source=f"environment:{password_env}")
    if interactive:
        if not username:
            username = input("BMC username: ").strip()
        password = getpass.getpass("BMC password: ")
        if password:
            return RedfishCredentials(username=username, password=password, source="interactive")
    return RedfishCredentials(username=username, source="NONE")


@dataclass(frozen=True)
class RedfishResponse:
    path: str
    status: int
    payload: dict[str, Any]


class ReadOnlyRedfishClient:
    """HTTPS Redfish reader. The public API deliberately exposes only GET."""

    def __init__(
        self,
        host: str,
        username: str | None = None,
        password: str | None = None,
        *,
        credentials: RedfishCredentials | None = None,
        verify_tls: bool = True,
        timeout_seconds: int = 20,
    ) -> None:
        self.base_url = _normalize_base_url(host)
        if timeout_seconds <= 0 or timeout_seconds > 300:
            raise ValueError("Redfish timeout must be between 1 and 300 seconds")
        if credentials is not None and (username is not None or password is not None):
            raise ValueError("Supply credentials or username/password, not both")
        self._credentials = credentials or RedfishCredentials(
            username=username or "",
            password=password or "",
            source="direct-runtime" if username is not None or password is not None else "NONE",
        )
        self.timeout_seconds = timeout_seconds
        self.verify_tls = bool(verify_tls)
        self.ssl_context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()

    @property
    def authentication_status(self) -> dict[str, Any]:
        return self._credentials.public_status()

    def get_json(self, path: str) -> RedfishResponse:
        """Fetch one JSON endpoint. Only GET is ever issued by this client."""
        path = _normalize_path(path)
        request = Request(urljoin(self.base_url, path), headers={"Accept": "application/json"}, method="GET")
        if self._credentials.token:
            request.add_header("X-Auth-Token", self._credentials.token)
        elif self._credentials.username and self._credentials.password:
            token = base64.b64encode(
                f"{self._credentials.username}:{self._credentials.password}".encode("utf-8")
            ).decode("ascii")
            request.add_header("Authorization", f"Basic {token}")
        try:
            with urlopen(request, timeout=self.timeout_seconds, context=self.ssl_context) as response:
                body = response.read().decode("utf-8", errors="replace")
                try:
                    payload = json.loads(body)
                except json.JSONDecodeError as exc:
                    raise RedfishRequestError(path, RedfishFailureKind.MALFORMED_RESPONSE) from exc
                if not isinstance(payload, dict):
                    raise RedfishRequestError(path, RedfishFailureKind.MALFORMED_RESPONSE)
                return RedfishResponse(path=path, status=response.status, payload=payload)
        except HTTPError as exc:
            if (exc.code == 401 or exc.code == 403) and _password_change_marker(exc):
                kind = RedfishFailureKind.PASSWORD_CHANGE_REQUIRED
            elif exc.code == 401 or exc.code == 403:
                kind = RedfishFailureKind.BLOCKED_BY_AUTH
            elif exc.code == 404:
                kind = RedfishFailureKind.BLOCKED_BY_MISSING_ENDPOINT
            else:
                kind = RedfishFailureKind.HTTP_ERROR
            raise RedfishRequestError(path, kind, http_status=exc.code) from exc
        except (TimeoutError, socket.timeout) as exc:
            raise RedfishRequestError(path, RedfishFailureKind.TIMEOUT) from exc
        except (URLError, ssl.SSLError, OSError) as exc:
            raise RedfishRequestError(path, RedfishFailureKind.TRANSPORT_ERROR) from exc


@dataclass(frozen=True)
class RedfishMutationResponse:
    """Sanitized response for an explicitly authorized Redfish mutation."""

    path: str
    status: int
    payload: dict[str, Any]
    headers: dict[str, str]
    location: str = ""


class AuthenticatedRedfishClient(ReadOnlyRedfishClient):
    """Authenticated Redfish client with narrowly-scoped update primitives.

    The read-only client remains the default used by discovery.  This class is
    instantiated only by the firmware executor after the normal mutation gate
    has approved a component, exact package and run identity.
    """

    def request_json(self, method: str, path: str, payload: dict[str, Any] | None = None) -> RedfishMutationResponse:
        if method.upper() not in {"POST", "PATCH", "PUT"}:
            raise ValueError("Redfish mutation method is not permitted")
        body = json.dumps(payload or {}, separators=(",", ":")).encode("utf-8")
        return self._request_bytes(method.upper(), path, body, "application/json")

    def post_multipart(
        self,
        path: str,
        package: Path,
        *,
        update_parameters: Mapping[str, Any] | None = None,
        oem_parameters: Mapping[str, Any] | None = None,
        file_field: str = "UpdateFile",
    ) -> RedfishMutationResponse:
        if package.is_symlink() or not package.is_file():
            raise ValueError("Firmware package must be a regular file")
        if package.stat().st_size > 512 * 1024 * 1024:
            raise ValueError("Firmware package exceeds configured limit")
        boundary = "----CNServerOps-" + uuid.uuid4().hex
        parameters = json.dumps(dict(update_parameters or {}), separators=(",", ":"))
        prefix = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="UpdateParameters"\r\n'
            "Content-Type: application/json\r\n\r\n"
            f"{parameters}\r\n"
        ).encode("utf-8")
        oem_part = b""
        if oem_parameters is not None:
            oem_payload = json.dumps(dict(oem_parameters), separators=(",", ":"))
            oem_part = (
                f"--{boundary}\r\n"
                'Content-Disposition: form-data; name="OemParameters"\r\n'
                "Content-Type: application/json\r\n\r\n"
                f"{oem_payload}\r\n"
            ).encode("utf-8")
        file_part = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{file_field}"; filename="{package.name}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode("utf-8")
        suffix = f"\r\n--{boundary}--\r\n".encode("utf-8")
        body = prefix + oem_part + file_part + package.read_bytes() + suffix
        if len(body) > 512 * 1024 * 1024:
            raise ValueError("Firmware multipart payload exceeds configured limit")
        return self._request_bytes("POST", path, body, f"multipart/form-data; boundary={boundary}")

    def _request_bytes(self, method: str, path: str, body: bytes, content_type: str) -> RedfishMutationResponse:
        normalized = _normalize_path(path)
        request = Request(urljoin(self.base_url, normalized), data=body, method=method)
        request.add_header("Accept", "application/json")
        request.add_header("Content-Type", content_type)
        # ASUS AMI UpdateService rejects an implicit 100-continue handshake on
        # some ASMB generations; the vendor's documented curl examples send
        # an explicit empty Expect header.
        request.add_header("Expect", "")
        if self._credentials.token:
            request.add_header("X-Auth-Token", self._credentials.token)
        elif self._credentials.username and self._credentials.password:
            token = base64.b64encode(
                f"{self._credentials.username}:{self._credentials.password}".encode("utf-8")
            ).decode("ascii")
            request.add_header("Authorization", f"Basic {token}")
        try:
            with urlopen(request, timeout=self.timeout_seconds, context=self.ssl_context) as response:
                raw_headers = {str(key).lower(): str(value) for key, value in response.headers.items()}
                body_text = response.read().decode("utf-8", errors="replace")
                try:
                    payload = json.loads(body_text) if body_text.strip() else {}
                except json.JSONDecodeError:
                    payload = {}
                if not isinstance(payload, dict):
                    payload = {}
                location = raw_headers.get("location", "") or str(payload.get("@odata.id") or "")
                return RedfishMutationResponse(normalized, int(response.status), payload, raw_headers, location)
        except HTTPError as exc:
            if exc.code in {401, 403}:
                kind = RedfishFailureKind.BLOCKED_BY_AUTH
            elif exc.code == 404:
                kind = RedfishFailureKind.BLOCKED_BY_MISSING_ENDPOINT
            else:
                kind = RedfishFailureKind.HTTP_ERROR
            response_sha256, response_length, response_hint = _bounded_error_digest(exc)
            raise RedfishRequestError(
                normalized,
                kind,
                http_status=exc.code,
                response_sha256=response_sha256,
                response_length=response_length,
                response_hint=response_hint,
            ) from exc
        except (TimeoutError, socket.timeout) as exc:
            raise RedfishRequestError(normalized, RedfishFailureKind.TIMEOUT) from exc
        except (URLError, ssl.SSLError, OSError) as exc:
            raise RedfishRequestError(normalized, RedfishFailureKind.TRANSPORT_ERROR) from exc


def _normalize_base_url(host: str) -> str:
    value = str(host or "").strip()
    if not value:
        raise ValueError("BMC host is required")
    candidate = value if "://" in value else f"https://{value}"
    parsed = urlparse(candidate)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError("BMC endpoint must be an HTTPS hostname or IP address")
    if parsed.username or parsed.password:
        raise ValueError("Credentials must not be embedded in the BMC URL")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("BMC endpoint must not contain a path, query, or fragment")
    port = f":{parsed.port}" if parsed.port else ""
    return f"https://{parsed.hostname}{port}/"


def _normalize_path(path: str) -> str:
    value = "/" + str(path or "").lstrip("/")
    parsed = urlparse(value)
    if parsed.scheme or parsed.netloc:
        raise ValueError("Redfish GET path must be relative to the configured BMC")
    return value


_PASSWORD_CHANGE_MARKER = re.compile(
    r"(?i)(password\s*(change|reset|required|expired)|must\s+change|force(d)?\s+change|initial\s+password)"
)


def _password_change_marker(error: HTTPError) -> bool:
    """Inspect only bounded response metadata; never retain the response body."""
    fragments: list[str] = []
    try:
        headers = error.headers
        if headers:
            fragments.extend(str(value) for key, value in headers.items() if "auth" in str(key).lower() or "password" in str(key).lower())
    except Exception:
        pass
    try:
        body = error.read(4096).decode("utf-8", errors="ignore")
        fragments.append(body)
    except Exception:
        pass
    return bool(_PASSWORD_CHANGE_MARKER.search(" ".join(fragments)))


def _bounded_error_digest(error: HTTPError, *, limit: int = 64 * 1024) -> tuple[str, int, str]:
    """Read a bounded HTTP error body only to calculate non-sensitive evidence.

    The body is intentionally not returned, logged, or stored.  ``HTTPError``
    streams are one-shot; callers that need password-change detection must do
    that before invoking this helper (the mutation path has no such marker
    requirement).
    """
    try:
        raw = error.read(limit)
    except Exception:
        raw = b""
    digest = hashlib.sha256(raw).hexdigest()
    hint = ""
    try:
        payload = json.loads(raw.decode("utf-8", errors="replace"))
        values: list[str] = []

        def collect(value: Any, key: str = "") -> None:
            if isinstance(value, Mapping):
                for child_key, child in value.items():
                    lowered = str(child_key).casefold()
                    if any(token in lowered for token in ("password", "passwd", "secret", "token", "authorization", "credential")):
                        continue
                    collect(child, lowered)
            elif isinstance(value, list):
                for child in value[:8]:
                    collect(child, key)
            elif key in {"message", "messageid", "code", "error", "resolution", "severity"}:
                text = re.sub(r"\s+", " ", str(value)).strip()
                if text:
                    values.append(text[:120])

        collect(payload)
        hint = "|".join(dict.fromkeys(values))[:240]
    except Exception:
        hint = ""
    return digest, len(raw), hint
