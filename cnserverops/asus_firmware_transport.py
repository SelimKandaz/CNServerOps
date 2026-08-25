"""Concrete generic ASUS Redfish firmware transport.

It consumes a descriptor produced by :mod:`cnserverops.asus_firmware` and
never invents an endpoint.  Only UpdateService actions advertised by the live
server are used; exact package matching and the normal MutationGate remain
outside this transport.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import re
import socket
import ssl
import subprocess
import threading
import time
import uuid
import struct
from dataclasses import dataclass
from pathlib import Path
import tempfile
import zipfile
from typing import Any, Callable, Mapping
from http.cookiejar import CookieJar
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlparse
from urllib.request import HTTPCookieProcessor, HTTPSHandler, Request, build_opener

from cndellops_asus.redfish import (
    AuthenticatedRedfishClient,
    RedfishFailureKind,
    RedfishRequestError,
)

from .asus_firmware import AsusPlatformFingerprint, AsusTransportDescriptor, match_asus_package
from .firmware import FirmwarePackageMetadata
from .firmware_executor import FirmwareExecutionError, FirmwarePreview, UpdateTask, UpdateTaskState


class AsusWebHpmError(RuntimeError):
    """Credential-safe ASMB web API error.

    Only status, path and a bounded response digest/hint are retained.  In
    particular, response bodies and credentials are never included in the
    exception text or persisted task evidence.
    """

    def __init__(self, path: str, reason: str, *, status: int | None = None, digest: str = "", length: int | None = None, hint: str = "") -> None:
        self.path = str(path)
        self.reason = str(reason)
        self.status = status
        self.digest = str(digest or "")
        self.length = length
        self.hint = str(hint or "")[:240]
        suffix = f":HTTP_{status}" if status is not None else ""
        super().__init__(f"ASUS_WEB_HPM_{reason}{suffix}")


@dataclass(frozen=True)
class AsusWebResponse:
    status: int
    payload: dict[str, Any]
    headers: Mapping[str, str]


class AsusAsmbWebSession:
    """Small cookie/CSRF session for the official ASMB web API.

    ASUS ASMB12 firmware exposes the HPM workflow through this authenticated
    web API even when its Redfish BIOS action is incomplete.  The session is
    deliberately isolated from the read-only Redfish client and accepts a
    secret only in memory.
    """

    def __init__(self, host: str, username: str, password: str, *, verify_tls: bool = True, timeout_seconds: int = 45) -> None:
        self.base_url = _web_base_url(host)
        if not username or not password:
            raise ValueError("ASUS web credentials are required")
        if timeout_seconds <= 0 or timeout_seconds > 300:
            raise ValueError("ASUS web timeout is outside the supported range")
        self.username = str(username)
        self._password = str(password)
        self.timeout_seconds = int(timeout_seconds)
        self.ssl_context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
        self._cookies = CookieJar()
        self._opener = build_opener(HTTPSHandler(context=self.ssl_context), HTTPCookieProcessor(self._cookies))
        self._csrf = ""

    def login(self) -> AsusWebResponse:
        response = self._request(
            "POST",
            "/api/session",
            urlencode({"username": self.username, "password": self._password}).encode("utf-8"),
            "application/x-www-form-urlencoded",
            include_csrf=False,
        )
        self._csrf = _csrf_from_response(response)
        if response.status not in {200, 201, 204}:
            raise AsusWebHpmError("/api/session", "LOGIN_REJECTED", status=response.status)
        return response

    def get_json(self, path: str) -> AsusWebResponse:
        return self._request("GET", path, None, "application/json")

    def put_json(self, path: str, payload: Mapping[str, Any]) -> AsusWebResponse:
        return self._request("PUT", path, _json_bytes(payload), "application/json")

    def post_json(self, path: str, payload: Mapping[str, Any]) -> AsusWebResponse:
        return self._request("POST", path, _json_bytes(payload), "application/json")

    def post_empty(self, path: str) -> AsusWebResponse:
        """POST with the same empty body/content-type semantics as ASUS UI."""
        return self._request("POST", path, None, "")

    def post_multipart(self, path: str, field: str, filename: str, payload: bytes) -> AsusWebResponse:
        if len(payload) > 512 * 1024 * 1024:
            raise ValueError("ASUS HPM payload exceeds configured limit")
        boundary = "----CNServerOps-ASUS-" + uuid.uuid4().hex
        safe_field = re.sub(r"[^A-Za-z0-9_-]", "", str(field)) or "oemimage"
        safe_name = Path(str(filename)).name.replace('"', "_")
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{safe_field}"; filename="{safe_name}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode("utf-8") + payload + f"\r\n--{boundary}--\r\n".encode("utf-8")
        return self._request("POST", path, body, f"multipart/form-data; boundary={boundary}")

    def _request(self, method: str, path: str, body: bytes | None, content_type: str, *, include_csrf: bool = True) -> AsusWebResponse:
        normalized = _web_path(path)
        request = Request(urljoin(self.base_url, normalized), data=body, method=method.upper())
        request.add_header("Accept", "application/json")
        request.add_header("Expect", "")
        if content_type:
            request.add_header("Content-Type", content_type)
        if include_csrf and self._csrf:
            request.add_header("X-CSRFTOKEN", self._csrf)
            request.add_header("X-Requested-With", "XMLHttpRequest")
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                raw = response.read()
                payload = _json_object(raw)
                headers = {str(key).lower(): str(value) for key, value in response.headers.items()}
                result = AsusWebResponse(int(response.status), payload, headers)
                if not self._csrf:
                    self._csrf = _csrf_from_response(result)
                return result
        except HTTPError as exc:
            digest, length, hint = _web_error_digest(exc)
            raise AsusWebHpmError(normalized, "HTTP_ERROR", status=exc.code, digest=digest, length=length, hint=hint) from exc
        except (TimeoutError, OSError, URLError, ssl.SSLError) as exc:
            raise AsusWebHpmError(normalized, type(exc).__name__) from exc


@dataclass(frozen=True)
class AsusHpmImage:
    component_hpm_id: int
    component_id: int
    image_type: int
    section_flash: int
    data_start: int
    data_length: int
    data_end: int
    name: str
    version: str
    version_major: int | None
    version_minor: int | None


def parse_asus_hpm_image(raw: bytes) -> AsusHpmImage:
    """Parse the bounded ASMB HPM wrapper without executing it."""
    if len(raw) < 165 or raw[:8] != b"PICMGFWU":
        raise FirmwareExecutionError("ASUS_HPM_HEADER_INVALID")
    component_hpm_id = int(f"{raw[36]:02x}", 10) if raw[36] < 100 else -1
    component_map = {1: 1, 4: 2, 10: 4}
    component_id = component_map.get(component_hpm_id)
    if component_id is None:
        raise FirmwareExecutionError("ASUS_HPM_COMPONENT_ID_UNSUPPORTED")
    data_start = 69
    data_length = int.from_bytes(raw[65:69], "little")
    data_end = data_start + data_length
    if data_length <= 0 or data_end > len(raw):
        raise FirmwareExecutionError("ASUS_HPM_COMPONENT_LENGTH_INVALID")
    section_flash = int.from_bytes(raw[73:77], "little")
    image_type = int.from_bytes(raw[110:112], "little")
    name = raw[44:76].split(b"\0", 1)[0].decode("ascii", errors="replace").strip()
    version_field = raw[112:144].split(b"\0", 1)[0]
    version_text = version_field.decode("ascii", errors="ignore").strip("\x00 \t")
    if version_text.startswith("\x01"):
        version_text = version_text[1:]
    version_match = re.search(r"(\d+)(?:\.(\d+))?", version_text)
    version_major = int(version_match.group(1)) if version_match else None
    version_minor = int(version_match.group(2)) if version_match and version_match.group(2) else None
    if version_match and not version_match.group(2) and version_match.group(1).isdigit() and len(version_match.group(1)) == 4:
        compact = version_match.group(1)
        version_major, version_minor = int(compact[:2]), int(compact[2:])
    return AsusHpmImage(
        component_hpm_id=component_hpm_id,
        component_id=component_id,
        image_type=image_type,
        section_flash=section_flash,
        data_start=data_start,
        data_length=data_length,
        data_end=data_end,
        name=name,
        version=version_text,
        version_major=version_major,
        version_minor=version_minor,
    )


def _hpm_payload(package: Path, metadata: FirmwarePackageMetadata) -> tuple[str, bytes, AsusHpmImage]:
    if package.is_symlink() or not package.is_file():
        raise FirmwareExecutionError("ASUS_PACKAGE_NOT_REGULAR_FILE")
    candidates: list[tuple[str, bytes]] = []
    if zipfile.is_zipfile(package):
        with zipfile.ZipFile(package) as archive:
            for item in archive.infolist():
                if item.is_dir():
                    continue
                member = Path(item.filename)
                if member.is_absolute() or ".." in member.parts:
                    raise FirmwareExecutionError("ASUS_PACKAGE_MEMBER_PATH_UNSAFE")
                suffix = member.suffix.casefold()
                if suffix in {".hpm", ".cap", ".bin", ".ima"}:
                    candidates.append((member.name, archive.read(item)))
    else:
        candidates.append((package.name, package.read_bytes()))
    for name, raw in sorted(candidates, key=lambda item: (0 if Path(item[0]).suffix.casefold() == ".hpm" else 1, item[0])):
        try:
            parsed = parse_asus_hpm_image(raw)
        except FirmwareExecutionError:
            continue
        if parsed.component_id == (4 if metadata.component.upper() == "BIOS" else 1 if metadata.component.upper() == "BMC" else parsed.component_id):
            return name, raw[parsed.data_start:parsed.data_end], parsed
    raise FirmwareExecutionError(f"ASUS_HPM_{metadata.component.upper()}_PAYLOAD_NOT_FOUND")


class AsusAsmbWebHpmFirmwareAdapter:
    """Official ASMB HPM update lifecycle (staged BIOS or direct component)."""

    name = "asus_asmb_web_hpm"

    def __init__(self, session: AsusAsmbWebSession, descriptor: AsusTransportDescriptor, *, version_reader: Callable[[str], str]) -> None:
        if not descriptor.selectable or descriptor.package_delivery != "ASUS_HPM_WRAPPED_IMAGE":
            raise ValueError("ASUS ASMB web-HPM descriptor is not selectable")
        self.session = session
        self.descriptor = descriptor
        self.version_reader = version_reader
        self._active_component = ""
        self._active_target_version = ""

    def preview(self, package: Path, metadata: FirmwarePackageMetadata) -> FirmwarePreview:
        if not package.is_file() or package.is_symlink() or not self.descriptor.supports(metadata.component):
            return FirmwarePreview(False, self.name, metadata.component, "", metadata.version, True, {"reason": "PACKAGE_OR_COMPONENT_NOT_SUPPORTED"})
        try:
            name, payload, parsed = _hpm_payload(package, metadata)
        except FirmwareExecutionError as exc:
            return FirmwarePreview(False, self.name, metadata.component, "", metadata.version, True, {"reason": str(exc)})
        expected_type = self.descriptor.web_component_image_types.get(metadata.component.upper())
        expected_id = self.descriptor.web_component_ids.get(metadata.component.upper())
        if expected_id is not None and int(expected_id) != parsed.component_id:
            return FirmwarePreview(False, self.name, metadata.component, "", metadata.version, True, {"reason": "HPM_COMPONENT_ID_CONFLICT", "parsed_component_id": parsed.component_id})
        if expected_type is not None and int(expected_type) != parsed.image_type:
            return FirmwarePreview(False, self.name, metadata.component, "", metadata.version, True, {"reason": "HPM_IMAGE_TYPE_CONFLICT", "parsed_image_type": parsed.image_type})
        return FirmwarePreview(
            True,
            self.name,
            metadata.component,
            self.version_reader(metadata.component),
            metadata.version,
            True,
            {
                "descriptor": self.descriptor.to_dict(),
                "selected_image": name,
                "payload_size_bytes": len(payload),
                "hpm_component_id": parsed.component_id,
                "hpm_image_type": parsed.image_type,
                "hpm_section_flash": parsed.section_flash,
                "hpm_version_header": parsed.version,
                "update_method": self.descriptor.web_update_method or "STAGED",
            },
        )

    def start(self, package: Path, metadata: FirmwarePackageMetadata) -> UpdateTask:
        self._active_component = metadata.component.upper()
        self._active_target_version = metadata.version
        try:
            selected_name, payload, parsed = _hpm_payload(package, metadata)
            component = parsed.component_id
            component_len = parsed.data_length
            prefix = self.descriptor.web_endpoint_prefix.rstrip("/") or "/api/maintenance/hpm"
            method = (self.descriptor.web_update_method or "STAGED").upper()
            oob = "/api/maintenance/oob"
            if method != "DIRECT":
                # The ASMB OOB flag must be armed before entering HPM update
                # mode; doing this after upload leaves the image staged but
                # not associated with the next host boot.
                self.session.post_empty(f"{oob}/start-lmedia")
            update_mode = self.session.put_json(f"{prefix}/updatemode", {})
            # The ASMB UI forwards unique_id without stringifying it.  On
            # ASMB12 this is an integer and the endpoint rejects a quoted
            # value with HTTP 400 "Invalid Variable Type Received".
            update_id = update_mode.payload.get("unique_id")
            if update_id in (None, ""):
                update_id = update_mode.payload.get("FWUPDATEID")
            if update_id in (None, ""):
                raise FirmwareExecutionError("ASUS_HPM_UPDATE_ID_NOT_RETURNED")
            prepare = {
                "FWUPDATEID": update_id,
                "COMPONENT_ID": component,
                "PRODUCT_ID": 0,
                "MANAFACTURE_ID": 0,
                # The ASMB12 UI sets HPM_IMAGE_FLAG=1 for a parsed HPM
                # package (the default 0 is reserved for raw/PFR paths).
                "HPM_FLAG": 1,
                "COMPONENT_DATA_LEN": component_len,
                "GLOBAL_COMPONENT_LENGTH": component_len,
                "IS_MMC": 0,
            }
            self.session.put_json(f"{prefix}/preparecomponents", prepare)
            upload_path = f"{prefix}/oemfw"
            self.session.post_multipart(upload_path, "oemimage", selected_name, payload)
            if method == "DIRECT":
                self.session.put_json(f"{prefix}/flash", {"COMPONENT_ID": component, "COMPONENT_DATA_LEN": component_len, "FWUPDATEID": update_id, "SECTION_FLASH": parsed.section_flash})
                self.session.put_json(f"{prefix}/verifyimage", {"COMPONENT_ID": component, "COMPONENT_DATA_LEN": component_len, "FWUPDATEID": update_id})
                self.session.put_json(f"{prefix}/activatecomponents", {"COMPONENT_ID": component})
                self.session.put_json(f"{prefix}/exitupdatemode", {"FWUPDATEID": update_id})
                return UpdateTask(f"ASUS-HPM-DIRECT-{uuid.uuid4().hex}", UpdateTaskState.REBOOT_REQUIRED, f"MUTATION_STARTED:BIOS_DIRECT_STAGED:{selected_name}")
            # Staged BIOS/OOB path: upload and verify now; activation is
            # intentionally deferred to the next controlled host reboot.
            self.session.post_json(f"{oob}/verifyoob", {"COMPONENT_ID": component})
            self.session.post_json(f"{oob}/modifyoob", {})
            major = parsed.version_major
            minor = parsed.version_minor
            if major is not None and minor is not None:
                self.session.post_json(f"{oob}/setoobflag", {"OOBENABLE": 1, "OOBSTATUS": 1, "FORMAT": 0, "OOBMAJOR": major, "OOBMINOR": minor})
            else:
                self.session.post_json(f"{oob}/setoobflag", {"OOBENABLE": 1, "OOBSTATUS": 1, "FORMAT": 1, "OEMSTRING": metadata.version})
            self.session.put_json(f"{prefix}/exitupdatemode", {"FWUPDATEID": update_id})
            return UpdateTask(f"ASUS-HPM-OOB-{uuid.uuid4().hex}", UpdateTaskState.REBOOT_REQUIRED, f"MUTATION_STARTED:BIOS_OOB_STAGED:{selected_name}")
        except (AsusWebHpmError, FirmwareExecutionError, OSError, ValueError) as exc:
            return UpdateTask("ASUS-HPM-ERROR", UpdateTaskState.FAILED, _safe_hpm_reason(exc))

    def poll(self, task_id: str) -> UpdateTask:
        # The web HPM API has no durable task resource for staged BIOS.  The
        # explicit reboot-required state is the lifecycle checkpoint; version
        # verification is resumed by CNServerOps after the host returns.
        if str(task_id).startswith("ASUS-HPM-"):
            return UpdateTask(task_id, UpdateTaskState.REBOOT_REQUIRED, "HOST_REBOOT_REQUIRED_FOR_ASUS_HPM_ACTIVATION")
        return UpdateTask(task_id, UpdateTaskState.UNKNOWN, "ASUS_HPM_TASK_STATE_UNAVAILABLE")

    def read_installed_version(self, component: str) -> str:
        return str(self.version_reader(component) or "")


def discover_asus_web_hpm_capability(host: str, username: str, password: str, *, verify_tls: bool = True) -> dict[str, Any]:
    """Read-only capability probe for official ASMB HPM/OOB endpoints."""
    try:
        session = AsusAsmbWebSession(host, username, password, verify_tls=verify_tls)
        session.login()
        freemem = session.get_json("/api/maintenance/hpm/freemem")
        oob = session.get_json("/api/maintenance/oob/getoobflag")
        supported = freemem.status == 200 and oob.status == 200
        return {
            "schema_version": 1,
            "supported": supported,
            "auth_available": True,
            "components": ["BIOS"] if supported else [],
            "update_method": "STAGED" if supported else "",
            "reboot_behavior": "HOST_REBOOT_REQUIRED" if supported else "UNKNOWN",
            "task_tracking": False,
            "endpoint_prefix": "/api/maintenance/hpm",
            # These are protocol identifiers, not model substitutions; the
            # adapter still parses and cross-checks every package header.
            "component_ids": {"BIOS": 4},
            "image_types": {"BIOS": 42, "BMC": 1},
            "section_flash": {},
            "capability_evidence": {
                "freemem_status": freemem.status,
                "oob_flag_status": oob.status,
                "source": "AUTHENTICATED_ASUS_ASMB_WEB_CAPABILITY",
            },
        }
    except (AsusWebHpmError, ValueError, OSError) as exc:
        return {"schema_version": 1, "supported": False, "auth_available": False, "reason": _safe_hpm_reason(exc)}


def _web_base_url(host: str) -> str:
    value = str(host or "").strip()
    candidate = value if "://" in value else f"https://{value}"
    parsed = urlparse(candidate)
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("ASUS web endpoint must be an HTTPS host without embedded credentials")
    port = f":{parsed.port}" if parsed.port else ""
    return f"https://{parsed.hostname}{port}/"


def _web_path(path: str) -> str:
    value = "/" + str(path or "").lstrip("/")
    parsed = urlparse(value)
    if parsed.scheme or parsed.netloc:
        raise ValueError("ASUS web path must be relative")
    return value


def _json_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(dict(payload), separators=(",", ":")).encode("utf-8")


def _json_object(raw: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(raw.decode("utf-8", errors="replace")) if raw.strip() else {}
    except json.JSONDecodeError:
        return {}
    return dict(payload) if isinstance(payload, Mapping) else {}


def _csrf_from_response(response: AsusWebResponse) -> str:
    for key, value in response.headers.items():
        if "csrf" in str(key).casefold() and str(value).strip():
            return str(value).strip()
    def find(value: Any) -> str:
        if isinstance(value, Mapping):
            for key, child in value.items():
                if "csrf" in str(key).casefold() and isinstance(child, (str, int)) and str(child).strip():
                    return str(child).strip()
                found = find(child)
                if found:
                    return found
        elif isinstance(value, list):
            for child in value[:8]:
                found = find(child)
                if found:
                    return found
        return ""
    return find(response.payload)


def _web_error_digest(error: HTTPError, *, limit: int = 64 * 1024) -> tuple[str, int, str]:
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
                    if any(token in lowered for token in ("password", "passwd", "secret", "token", "credential", "cookie")):
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
        pass
    return digest, len(raw), hint


def _safe_hpm_reason(error: BaseException) -> str:
    if isinstance(error, AsusWebHpmError):
        value = f"{error.path}:{error.reason}"
        if error.status is not None:
            value += f":HTTP_{error.status}"
        if error.digest:
            value += f":RESPONSE_SHA256={error.digest}:RESPONSE_BYTES={error.length}"
        if error.hint:
            value += f":RESPONSE_HINT={error.hint}"
        return value
    return type(error).__name__


class AsusLocalFirmwareUtilityAdapter:
    """Execute an explicitly approved ASUS Linux utility without a BMC login.

    ASUS does not publish one universal local updater across ASMB generations,
    so this adapter is deliberately configuration-driven.  A candidate must
    be rooted in an immutable deployment record with an exact executable
    SHA-256, official-source proof, exact-platform proof and a command template
    containing ``{package}``.  Discovered filenames and arbitrary scripts never
    become executable transports.
    """

    name = "asus_local_official_utility"

    def __init__(self, descriptor: AsusTransportDescriptor, *, version_reader: Callable[[str], str]) -> None:
        if not descriptor.selectable or descriptor.name != "ASUS_LOCAL_OFFICIAL_UTILITY":
            raise ValueError("Local ASUS utility descriptor is not selectable")
        self.descriptor = descriptor
        self.version_reader = version_reader
        self._tasks: dict[str, UpdateTask] = {}

    def _validated_tool(self) -> Path:
        target = Path(str(self.descriptor.target or ""))
        expected = str(self.descriptor.local_tool_sha256 or "").lower()
        if not target.is_absolute() or not target.is_file() or target.is_symlink() or not os.access(target, os.X_OK):
            raise FirmwareExecutionError("LOCAL_ASUS_UTILITY_NOT_EXECUTABLE")
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise FirmwareExecutionError("LOCAL_ASUS_UTILITY_HASH_NOT_PINNED")
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        if digest != expected:
            raise FirmwareExecutionError("LOCAL_ASUS_UTILITY_HASH_MISMATCH")
        command = tuple(str(item) for item in self.descriptor.local_command if str(item).strip())
        if not command or "{package}" not in command:
            raise FirmwareExecutionError("LOCAL_ASUS_UTILITY_PACKAGE_ARGUMENT_NOT_EXPLICIT")
        return target

    @staticmethod
    def _render_arguments(
        command: tuple[str, ...],
        *,
        package: Path,
        metadata: FirmwarePackageMetadata,
        descriptor: AsusTransportDescriptor,
    ) -> list[str]:
        replacements = {
            "{package}": str(package),
            "{component}": metadata.component.upper(),
            "{version}": metadata.version,
            "{model}": " ".join(str(metadata.compatible_models[0]).split()) if metadata.compatible_models else "",
            "{board}": " ".join(str(metadata.compatible_boards[0]).split()) if metadata.compatible_boards else "",
        }
        rendered: list[str] = []
        for value in command:
            text = str(value)
            for token, replacement in replacements.items():
                text = text.replace(token, replacement)
            if "{" in text or "}" in text:
                raise FirmwareExecutionError("LOCAL_ASUS_UTILITY_ARGUMENT_TOKEN_UNSUPPORTED")
            rendered.append(text)
        return rendered

    def preview(self, package: Path, metadata: FirmwarePackageMetadata) -> FirmwarePreview:
        if not package.is_file() or package.is_symlink():
            return FirmwarePreview(False, self.name, metadata.component, "", metadata.version, True, {"reason": "PACKAGE_NOT_REGULAR_FILE"})
        if not self.descriptor.supports(metadata.component):
            return FirmwarePreview(False, self.name, metadata.component, "", metadata.version, True, {"reason": "COMPONENT_NOT_SUPPORTED_BY_DESCRIPTOR"})
        try:
            tool = self._validated_tool()
            self._render_arguments(self.descriptor.local_command, package=package, metadata=metadata, descriptor=self.descriptor)
        except FirmwareExecutionError as exc:
            return FirmwarePreview(False, self.name, metadata.component, "", metadata.version, True, {"reason": str(exc)})
        return FirmwarePreview(
            True,
            self.name,
            metadata.component,
            str(self.version_reader(metadata.component) or ""),
            metadata.version,
            str(self.descriptor.reboot_behavior or "UNKNOWN").upper() != "NO_REBOOT",
            {
                "tool": str(tool),
                "tool_sha256": self.descriptor.local_tool_sha256,
                "command_template": list(self.descriptor.local_command),
                "package_delivery": self.descriptor.package_delivery,
                "requires_authenticated_bmc": False,
            },
        )

    def start(self, package: Path, metadata: FirmwarePackageMetadata) -> UpdateTask:
        task_id = f"LOCAL-{uuid.uuid4().hex.upper()}"
        try:
            self._validated_tool()
            with tempfile.TemporaryDirectory(prefix="cnserverops-asus-local-") as staging:
                staged = Path(staging) / (Path(metadata.package_filename or "firmware.bin").name or "firmware.bin")
                staged.write_bytes(package.read_bytes())
                arguments = self._render_arguments(
                    self.descriptor.local_command,
                    package=staged,
                    metadata=metadata,
                    descriptor=self.descriptor,
                )
                completed = subprocess.run(
                    [str(self.descriptor.target), *arguments],
                    capture_output=True,
                    text=True,
                    timeout=max(60, min(7200, int(self.descriptor.local_timeout_seconds or 7200))),
                    check=False,
                    cwd="/",
                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
                )
            if completed.returncode != 0:
                task = UpdateTask(task_id, UpdateTaskState.FAILED, f"LOCAL_EXIT_{completed.returncode}")
            elif str(self.descriptor.reboot_behavior or "UNKNOWN").upper() != "NO_REBOOT":
                task = UpdateTask(task_id, UpdateTaskState.REBOOT_REQUIRED, "LOCAL_UPDATE_ACCEPTED_REBOOT_REQUIRED")
            else:
                task = UpdateTask(task_id, UpdateTaskState.COMPLETED, "LOCAL_UPDATE_COMPLETED")
        except subprocess.TimeoutExpired:
            task = UpdateTask(task_id, UpdateTaskState.TIMED_OUT, "LOCAL_UTILITY_TIMEOUT")
        except (FirmwareExecutionError, OSError, ValueError) as exc:
            task = UpdateTask(task_id, UpdateTaskState.FAILED, str(exc))
        self._tasks[task_id] = task
        return task

    def poll(self, task_id: str) -> UpdateTask:
        return self._tasks.get(str(task_id), UpdateTask(str(task_id), UpdateTaskState.UNKNOWN, "LOCAL_TASK_NOT_FOUND"))

    def read_installed_version(self, component: str) -> str:
        return str(self.version_reader(component) or "")


class AsusAsmbLinuxBmcFirmwareAdapter:
    """Run ASUS' official ASMB11/ASMB12 Linux BMC updater from its ZIP.

    ASUS distributes ``Linux/Yafuflash`` and the matching ``Image/*.ima``
    inside each exact-platform BMC package.  The package is already fetched,
    exact-matched and SHA-256 pinned by :class:`AsusFirmwareEngine`; this
    adapter only performs bounded, non-shell extraction and execution of that
    package-owned binary.  The updater's documented ``-local`` mode talks to
    the BMC USB-LAN address ``169.254.0.17`` and preserves BMC configuration.
    Credentials are accepted in memory only and are never included in task
    evidence or captured command output.
    """

    name = "asus_asmb_linux_official"
    _BMC_USB_IP = "169.254.0.17"
    _HOST_USB_IP = "169.254.0.18/16"

    def __init__(
        self,
        descriptor: AsusTransportDescriptor,
        *,
        username: str,
        password: str,
        version_reader: Callable[[str], str],
        interface_resolver: Callable[[], str] | None = None,
        command_runner: Callable[[list[str], int], int] | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
        version_wait_seconds: int = 180,
    ) -> None:
        if not descriptor.selectable or descriptor.name != "ASUS_ASMB_LINUX_OFFICIAL":
            raise ValueError("ASUS ASMB Linux descriptor is not selectable")
        if not str(username or "").strip() or not str(password or ""):
            raise ValueError("ASUS ASMB updater requires approved credentials")
        self.descriptor = descriptor
        self.username = str(username)
        self._password = str(password)
        self.version_reader = version_reader
        self.interface_resolver = interface_resolver or self._default_interface
        self.command_runner = command_runner or self._run_command
        self.sleep_fn = sleep_fn
        self.version_wait_seconds = max(5, min(900, int(version_wait_seconds)))
        self._tasks: dict[str, UpdateTask] = {}
        self._address_added = False

    @staticmethod
    def _default_interface() -> str:
        # The ASUS local mode is exposed by the BMC USB-LAN NIC.  Prefer the
        # stable kernel naming used for USB NICs and never choose a server NIC
        # merely because it is the first interface returned by ``ip``.
        candidates = sorted(
            path.name
            for path in Path("/sys/class/net").glob("enx*")
            if path.is_dir() and path.name != "lo"
        )
        if len(candidates) == 1:
            return candidates[0]
        if candidates:
            # A USB NIC is the only supported local-ASMB transport.  When
            # several exist, require an explicit operator/runtime binding
            # instead of mutating an arbitrary interface.
            raise FirmwareExecutionError("ASUS_ASMB_USB_LAN_INTERFACE_AMBIGUOUS")
        raise FirmwareExecutionError("ASUS_ASMB_USB_LAN_INTERFACE_NOT_FOUND")

    @staticmethod
    def _run_command(argv: list[str], timeout_seconds: int) -> int:
        # ASUS' official Yafuflash binary asks an interactive ``Y/N``
        # confirmation even when all update arguments are supplied.  Older
        # ASMB11 builds read that answer from a controlling TTY rather than a
        # pipe; a closed/non-TTY stdin either loops forever or exits 1 before
        # starting the update.  Allocate a private pseudo-terminal, feed one
        # affirmative answer, discard all child output, and enforce a hard
        # timeout.  The password remains an in-memory argument required by
        # the vendor binary and is never logged or captured by CNServerOps.
        try:
            # Network setup/cleanup commands are non-interactive. Running
            # iproute2 through the updater's PTY path can leave ``ip``
            # attached to a controlling terminal after the operation has
            # completed, making the PTY drain loop hit its timeout even when
            # the address change succeeded. Keep only the vendor updater on
            # the private PTY; execute the narrowly scoped ``ip`` commands
            # directly with all output discarded.
            if argv and Path(str(argv[0])).name == "ip":
                completed = subprocess.run(
                    argv,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=max(1, int(timeout_seconds)),
                    check=False,
                    cwd="/",
                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
                )
                return int(completed.returncode)
            try:
                import pty
                import select
            except ImportError:
                # Unit-test/非-Linux fallback.  Production Linux always has
                # pty; retaining a bounded pipe path keeps the adapter
                # importable on the Windows development workstation.
                completed = subprocess.run(
                    argv,
                    input=b"Y\n",
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=max(1, int(timeout_seconds)),
                    check=False,
                    cwd="/",
                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
                )
                return int(completed.returncode)
            master, slave = pty.openpty()
            process = subprocess.Popen(
                argv,
                stdin=slave,
                stdout=slave,
                stderr=slave,
                cwd="/",
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
                close_fds=True,
            )
            os.close(slave)
            deadline = time.monotonic() + max(1, int(timeout_seconds))
            try:
                os.write(master, b"Y\n")
                while process.poll() is None and time.monotonic() < deadline:
                    readable, _, _ = select.select([master], [], [], 0.5)
                    if readable:
                        try:
                            os.read(master, 4096)
                        except OSError:
                            break
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                    return 124
                # Drain/discard any final PTY bytes without retaining vendor
                # output (which may contain sensitive or platform-specific
                # details).
                while True:
                    readable, _, _ = select.select([master], [], [], 0)
                    if not readable:
                        break
                    try:
                        if not os.read(master, 4096):
                            break
                    except OSError:
                        break
                return int(process.returncode)
            finally:
                try:
                    os.close(master)
                except OSError:
                    pass
        except subprocess.TimeoutExpired:
            return 124
        except OSError:
            return 127


    @staticmethod
    def _version_tuple(value: str) -> tuple[int, ...]:
        """Return the numeric version tuple used for YAFU image evidence.

        ASMB11 exposes the full component revision in YAFU (for example
        ``1.2.370000``) while the IPMI ``Firmware Revision`` field is limited
        to two components (``1.02``).  Comparing integer components keeps
        leading-zero formatting from changing the meaning of the proof.
        """
        parts: list[int] = []
        for index, token in enumerate(re.findall(r"\d+", str(value or ""))):
            # YAFU pads the ASMB patch component to six digits (``37`` is
            # rendered as ``370000``).  Trim that padding only after the
            # major/minor pair; two-part IPMI revisions such as ``1.02``
            # remain untouched and therefore cannot become false proof.
            if index >= 2:
                token = token.rstrip("0") or "0"
            parts.append(int(token))
        return tuple(parts)

    @classmethod
    def _parse_yafu_existing_version(cls, output: str) -> str:
        """Extract the exact existing ASMB image revision from ``-info``."""
        # YAFU writes ANSI cursor/colour escapes even when redirected.  Strip
        # only terminal control sequences; never persist or expose the raw
        # vendor output in CNServerOps evidence.
        clean = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", str(output or ""))
        match = re.search(
            r"(?im)\bast2600e\s+([0-9]+(?:\.[0-9]+)+)\s+([0-9]+(?:\.[0-9]+)+)",
            clean,
        )
        return match.group(2) if match else ""

    def _read_yafu_existing_version(self, updater_path: Path, image_path: Path) -> str:
        """Read the BMC's exact ASMB image revision without flashing.

        This is intentionally a separate, bounded ``-info`` invocation.  We
        stream at most 256 KiB to a temporary file to avoid the multi-gigabyte
        output/RAM failure seen when YAFU is attached to a pipe.  The output is
        parsed in memory and discarded; no vendor text or credential is
        written to reports, logs, or Central.
        """
        try:
            with tempfile.TemporaryFile(mode="w+b") as output:
                process = subprocess.Popen(
                    [
                        str(updater_path),
                        "-nw",
                        "-ip",
                        self._BMC_USB_IP,
                        "-U",
                        self.username,
                        "-P",
                        self._password,
                        str(image_path),
                        "-info",
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    cwd="/",
                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
                    close_fds=True,
                )
                try:
                    process.wait(timeout=120)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                    return ""
                output.seek(0)
                raw = output.read(256 * 1024)
            return self._parse_yafu_existing_version(raw.decode("latin-1", errors="ignore"))
        except (OSError, ValueError, subprocess.SubprocessError):
            return ""

    @staticmethod
    def _safe_member(name: str) -> Path:
        member = Path(str(name).replace("\\", "/"))
        if member.is_absolute() or ".." in member.parts:
            raise FirmwareExecutionError("ASUS_ASMB_PACKAGE_MEMBER_PATH_UNSAFE")
        return member

    @classmethod
    def _package_files(cls, package: Path) -> tuple[bytes, bytes, str]:
        if not package.is_file() or package.is_symlink() or not zipfile.is_zipfile(package):
            raise FirmwareExecutionError("ASUS_ASMB_BMC_PACKAGE_NOT_ZIP")
        updater: bytes | None = None
        image: bytes | None = None
        image_name = ""
        image_md5 = ""
        with zipfile.ZipFile(package) as archive:
            for item in archive.infolist():
                if item.is_dir():
                    continue
                member = cls._safe_member(item.filename)
                lowered = member.as_posix().casefold()
                if lowered.endswith("/linux/yafuflash") or lowered == "linux/yafuflash":
                    updater = archive.read(item)
                elif (lowered.startswith("image/") or "/image/" in lowered) and member.suffix.casefold() == ".ima":
                    if image is not None:
                        raise FirmwareExecutionError("ASUS_ASMB_PACKAGE_MULTIPLE_IMAGES")
                    image = archive.read(item)
                    image_name = member.name
                elif (lowered.startswith("image/") or "/image/" in lowered) and member.suffix.casefold() == ".md5":
                    raw = archive.read(item).decode("ascii", errors="ignore")
                    match = re.search(r"\b([0-9a-fA-F]{32})\b", raw)
                    image_md5 = match.group(1).lower() if match else ""
        if not updater or not image or not image_name:
            raise FirmwareExecutionError("ASUS_ASMB_LINUX_PACKAGE_CONTENT_MISSING")
        if updater[:4] != b"\x7fELF":
            raise FirmwareExecutionError("ASUS_ASMB_YAFUFLASH_NOT_ELF")
        # Require a 64-bit little-endian x86_64 utility, matching the supported
        # CNServerOps Linux runtime.  The package hash remains the immutable
        # provenance anchor; this check only prevents an incompatible binary.
        if len(updater) < 20 or updater[4] != 2 or updater[5] != 1 or struct.unpack_from("<H", updater, 18)[0] != 0x3E:
            raise FirmwareExecutionError("ASUS_ASMB_YAFUFLASH_ARCH_UNSUPPORTED")
        if image_md5 and hashlib.md5(image).hexdigest().lower() != image_md5:
            raise FirmwareExecutionError("ASUS_ASMB_IMAGE_MD5_MISMATCH")
        return updater, image, image_name

    @staticmethod
    def _reported_version_aliases(image: bytes, official_target: str) -> tuple[str, ...]:
        """Extract ASMB-reported aliases from the verified image trailer."""
        target_numbers = [int(value) for value in re.findall(r"\d+", str(official_target or ""))]
        if len(target_numbers) < 2:
            return ()
        text = bytes(image[-2_000_000:]).decode("latin-1", errors="ignore")
        aliases: list[str] = []
        for match in re.finditer(r"(?<![A-Za-z0-9])(\d+\.\d+(?:\.\d+)?)(?![A-Za-z0-9])", text):
            value = match.group(1)
            numbers = [int(item) for item in value.split(".")]
            # A two-part value such as ASMB11's ``1.02`` is the pre-update
            # controller revision, not proof of the three-part target
            # ``1.2.37``.  Only accept an image-bound value that contains the
            # complete target component tuple; never synthesize a shortened
            # alias which could make an older BMC appear current.
            if len(numbers) < len(target_numbers) or numbers[: len(target_numbers)] != target_numbers:
                continue
            if value not in aliases:
                aliases.append(value)
        return tuple(aliases)

    def _configure_usb_lan(self, interface: str) -> bool:
        # Link-up and address assignment are strictly scoped to the BMC USB
        # NIC and are reverted in ``finally``.  We do not touch the server LAN
        # interfaces or persistent network configuration.
        self._address_added = False
        if self.command_runner(["/usr/bin/ip", "link", "set", "dev", interface, "up"], 20) != 0:
            return False
        probe = subprocess.run(
            ["/usr/bin/ip", "-4", "addr", "show", "dev", interface],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if re.search(r"\b169\.254\.0\.18/", str(probe.stdout or "")):
            self._address_added = False
            return True
        self._address_added = self.command_runner(["/usr/bin/ip", "addr", "add", self._HOST_USB_IP, "dev", interface], 20) == 0
        return self._address_added

    def _remove_usb_lan(self, interface: str) -> None:
        self.command_runner(["/usr/bin/ip", "addr", "del", self._HOST_USB_IP, "dev", interface], 20)

    def preview(self, package: Path, metadata: FirmwarePackageMetadata) -> FirmwarePreview:
        if metadata.component.upper() != "BMC" or not self.descriptor.supports("BMC"):
            return FirmwarePreview(False, self.name, metadata.component, "", metadata.version, True, {"reason": "BMC_COMPONENT_REQUIRED"})
        try:
            updater, image, image_name = self._package_files(package)
        except FirmwareExecutionError as exc:
            return FirmwarePreview(False, self.name, metadata.component, "", metadata.version, True, {"reason": str(exc)})
        return FirmwarePreview(
            True,
            self.name,
            "BMC",
            str(self.version_reader("BMC") or ""),
            metadata.version,
            False,
            {
                "package_delivery": self.descriptor.package_delivery,
                "image_member": image_name,
                "image_size_bytes": len(image),
                "yafuflash_sha256": hashlib.sha256(updater).hexdigest(),
                "local_mode": "USB_LAN_169.254.0.17",
                "preserve_configuration": True,
                "credential_material_exposed": False,
                "reported_version_aliases": list(self._reported_version_aliases(image, metadata.version)),
            },
        )

    def start(self, package: Path, metadata: FirmwarePackageMetadata) -> UpdateTask:
        task_id = f"ASMB-LINUX-{uuid.uuid4().hex.upper()}"
        interface = ""
        configured = False
        try:
            updater, image, image_name = self._package_files(package)
            reported_aliases = self._reported_version_aliases(image, metadata.version)
            interface = self.interface_resolver()
            with tempfile.TemporaryDirectory(prefix="cnserverops-asmb-linux-") as staging:
                root = Path(staging)
                updater_path = root / "Yafuflash"
                image_path = root / image_name
                updater_path.write_bytes(updater)
                image_path.write_bytes(image)
                os.chmod(updater_path, 0o700)
                os.chmod(image_path, 0o600)
                configured = self._configure_usb_lan(interface)
                if not configured:
                    return self._store(task_id, UpdateTaskState.FAILED, "ASUS_ASMB_USB_LAN_CONFIGURATION_FAILED")
                # The official utility requires username/password arguments.
                # Keep them in memory, suppress all child output, and never
                # persist the rendered command or process result.
                return_code = self.command_runner(
                    [
                        str(updater_path),
                        "-nw",
                        "-ip",
                        self._BMC_USB_IP,
                        "-U",
                        self.username,
                        "-P",
                        self._password,
                        str(image_path),
                        "-preserve-config",
                        # The official ASMB11 tool otherwise asks whether a
                        # same-image package should be flashed.  In a
                        # technician workflow that prompt is not a useful
                        # decision: the package is already exact-platform and
                        # hash-verified.  -isi is the vendor-supported way to
                        # continue without the prompt while retaining the
                        # configuration-preserving mode.
                        "-ignore-same-image",
                    ],
                    max(60, min(7200, int(self.descriptor.local_timeout_seconds or 7200))),
                )
                # Keep the staging directory alive through post-flash image
                # verification.  ASMB11's local IPMI revision is truncated
                # (for example, ``1.02``), so Yafuflash's own image table is
                # sometimes the only exact, target-bound AFTER proof.  It
                # must not be queried after TemporaryDirectory has deleted
                # the official updater/image pair.
                if return_code != 0:
                    return self._store(task_id, UpdateTaskState.FAILED, f"ASUS_ASMB_YAFUFLASH_EXIT_{return_code}")
                deadline = time.monotonic() + self.version_wait_seconds
                next_yafu_probe = 0.0
                while time.monotonic() < deadline:
                    try:
                        observed = str(self.version_reader("BMC") or "")
                        if observed == str(metadata.version) or observed in reported_aliases:
                            return self._store(task_id, UpdateTaskState.COMPLETED, "ASUS_ASMB_BMC_VERSION_VERIFIED")
                        # ASMB11's IPMI field cannot represent the third version
                        # component.  The official YAFU image table is the
                        # stronger, exact-module evidence and is safe to use
                        # after the updater has returned.  This prevents a real
                        # 1.2.37 image from being reported as failed merely
                        # because IPMI says 1.02.
                        now = time.monotonic()
                        if now >= next_yafu_probe:
                            yafu_observed = self._read_yafu_existing_version(updater_path, image_path)
                            next_yafu_probe = now + 5.0
                            if (
                                yafu_observed
                                and self._version_tuple(yafu_observed)[: len(self._version_tuple(metadata.version))]
                                == self._version_tuple(metadata.version)
                            ):
                                return self._store(task_id, UpdateTaskState.COMPLETED, "ASUS_ASMB_YAFU_IMAGE_VERSION_VERIFIED")
                    except Exception:
                        pass
                    self.sleep_fn(2.0)
                return self._store(task_id, UpdateTaskState.FAILED, "ASUS_ASMB_BMC_VERSION_NOT_VERIFIED_AFTER_UPDATE")
        except (FirmwareExecutionError, OSError, ValueError) as exc:
            return self._store(task_id, UpdateTaskState.FAILED, str(exc))
        finally:
            if configured and interface and self._address_added:
                self._remove_usb_lan(interface)

    def _store(self, task_id: str, state: UpdateTaskState, detail: str) -> UpdateTask:
        task = UpdateTask(task_id, state, detail)
        self._tasks[task_id] = task
        return task

    def poll(self, task_id: str) -> UpdateTask:
        return self._tasks.get(str(task_id), UpdateTask(str(task_id), UpdateTaskState.UNKNOWN, "ASUS_ASMB_LOCAL_TASK_NOT_FOUND"))

    def read_installed_version(self, component: str) -> str:
        return str(self.version_reader(component) or "")


class AsusAsmb11KcsBmcFirmwareAdapter(AsusAsmbLinuxBmcFirmwareAdapter):
    """Credential-free ASMB11 BMC update through the package-owned KCS mode.

    The exact ASUS ASMB11 BMC ZIP carries ``Linux/Yafuflash``.  That vendor
    binary documents ``Yafuflash -kcs rom.ima`` and does not need a BMC user
    name or password in KCS mode.  This adapter intentionally does *not* call
    the Linux package wrapper, whose documented USB-LAN mode takes ``-U`` and
    ``-P`` command-line arguments.

    This is a generation capability adapter, not a model shortcut.  It
    requires an exact ASMB11 package/platform match, current local KCS
    evidence, and then a non-mutating package-owned ``-kcs ... -info`` probe
    before it sends the actual flash command.  No secret is accepted by this
    class or included in any child process arguments.
    """

    name = "asus_asmb11_kcs_yafuflash"
    _INFO_TIMEOUT_SECONDS = 120
    _INFO_OUTPUT_MAX_BYTES = 256 * 1024

    def __init__(
        self,
        descriptor: AsusTransportDescriptor,
        *,
        fingerprint: AsusPlatformFingerprint,
        version_reader: Callable[[str], str],
        kcs_probe: Callable[[], bool | Mapping[str, Any]] | None = None,
        command_runner: Callable[[list[str], int], int] | None = None,
        info_runner: Callable[[list[str], int], tuple[int, str]] | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
        version_wait_seconds: int = 180,
    ) -> None:
        if not descriptor.selectable or descriptor.name != "ASUS_ASMB11_KCS_YAFUFLASH":
            raise ValueError("ASUS ASMB11 KCS descriptor is not selectable")
        if descriptor.requires_authenticated_bmc:
            raise ValueError("ASUS ASMB11 KCS descriptor must not require BMC authentication")
        if str(fingerprint.bmc_generation or "").replace(" ", "").upper() != "ASMB11":
            raise ValueError("ASUS_ASMB11_KCS_GENERATION_REQUIRED")
        self.descriptor = descriptor
        self.fingerprint = fingerprint
        self.version_reader = version_reader
        self.kcs_probe = kcs_probe or self._default_kcs_probe
        self.command_runner = command_runner or self._run_command
        self.info_runner = info_runner or self._run_info_command
        self.sleep_fn = sleep_fn
        self.version_wait_seconds = max(5, min(900, int(version_wait_seconds)))
        self._tasks: dict[str, UpdateTask] = {}
        self._verified_version = ""
        self._preview_existing_version = ""

    @staticmethod
    def _default_kcs_probe() -> bool:
        """Check local KCS with a read-only IPMI command, without credentials."""
        # Do not treat a stale /dev node as proof.  The ``mc info`` request
        # exercises the local KCS medium and writes neither BMC state nor host
        # configuration.  All output is discarded.
        if not any(Path(path).exists() for path in ("/dev/ipmi0", "/dev/ipmi/0")):
            return False
        try:
            completed = subprocess.run(
                ["/usr/bin/ipmitool", "mc", "info"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
                cwd="/",
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
            )
            return int(completed.returncode) == 0
        except (OSError, subprocess.SubprocessError):
            return False

    @staticmethod
    def _run_info_command(argv: list[str], timeout_seconds: int) -> tuple[int, str]:
        """Run a bounded, non-mutating YAFU ``-info`` probe.

        The command has no credential arguments.  Vendor output is kept only
        in a temporary, size-bounded file long enough to parse the installed
        firmware revision and is never written to evidence or reports.
        """
        try:
            with tempfile.TemporaryFile(mode="w+b") as output:
                process = subprocess.Popen(
                    argv,
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    cwd="/",
                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
                    close_fds=True,
                )
                deadline = time.monotonic() + max(1, int(timeout_seconds))
                while process.poll() is None and time.monotonic() < deadline:
                    try:
                        output.flush()
                        if os.fstat(output.fileno()).st_size > AsusAsmb11KcsBmcFirmwareAdapter._INFO_OUTPUT_MAX_BYTES:
                            process.kill()
                            process.wait(timeout=5)
                            return 125, ""
                    except OSError:
                        process.kill()
                        process.wait(timeout=5)
                        return 127, ""
                    time.sleep(0.1)
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                    return 124, ""
                output.flush()
                if os.fstat(output.fileno()).st_size > AsusAsmb11KcsBmcFirmwareAdapter._INFO_OUTPUT_MAX_BYTES:
                    return 125, ""
                output.seek(0)
                raw = output.read(AsusAsmb11KcsBmcFirmwareAdapter._INFO_OUTPUT_MAX_BYTES)
            return int(process.returncode), raw.decode("latin-1", errors="ignore")
        except (OSError, ValueError, subprocess.SubprocessError):
            return 127, ""

    @staticmethod
    def _kcs_probe_available(value: bool | Mapping[str, Any]) -> bool:
        if isinstance(value, Mapping):
            state = str(value.get("status") or "").upper()
            return bool(value.get("available")) and state in {"", "PASS", "AVAILABLE", "VERIFIED"}
        return bool(value)

    def _package_platform_reason(self, metadata: FirmwarePackageMetadata) -> str:
        if metadata.component.upper() != "BMC" or not self.descriptor.supports("BMC"):
            return "BMC_COMPONENT_REQUIRED"
        generations = {str(value).replace(" ", "").upper() for value in metadata.compatible_bmc_generations}
        if generations != {"ASMB11"}:
            # A package without a specific ASMB11 applicability declaration
            # cannot use the KCS adapter, even if it has a similar filename.
            return "ASUS_ASMB11_EXACT_PACKAGE_GENERATION_REQUIRED"
        decision = match_asus_package(metadata, self.fingerprint)
        if not decision.exact_match:
            return "ASUS_ASMB11_KCS_EXACT_PLATFORM_REQUIRED"
        return ""

    def _stage_package(self, package: Path) -> tuple[tempfile.TemporaryDirectory[str], Path, Path, bytes, bytes, str]:
        updater, image, image_name = self._package_files(package)
        staging = tempfile.TemporaryDirectory(prefix="cnserverops-asmb11-kcs-")
        root = Path(staging.name)
        updater_path = root / "Yafuflash"
        image_path = root / image_name
        updater_path.write_bytes(updater)
        image_path.write_bytes(image)
        os.chmod(updater_path, 0o700)
        os.chmod(image_path, 0o600)
        return staging, updater_path, image_path, updater, image, image_name

    def _kcs_info(self, updater_path: Path, image_path: Path) -> tuple[int, str]:
        argv = [str(updater_path), "-kcs", str(image_path), "-info"]
        try:
            result = self.info_runner(argv, self._INFO_TIMEOUT_SECONDS)
            return_code, output = result
            return int(return_code), self._parse_yafu_existing_version(str(output or ""))
        except (TypeError, ValueError, OSError):
            return 127, ""

    def _preflight(self, updater_path: Path, image_path: Path, metadata: FirmwarePackageMetadata) -> tuple[bool, str, str]:
        reason = self._package_platform_reason(metadata)
        if reason:
            return False, reason, ""
        try:
            if not self._kcs_probe_available(self.kcs_probe()):
                return False, "ASUS_ASMB11_LOCAL_KCS_UNAVAILABLE", ""
        except Exception:
            return False, "ASUS_ASMB11_LOCAL_KCS_PROBE_FAILED", ""
        return_code, existing = self._kcs_info(updater_path, image_path)
        if return_code != 0:
            return False, f"ASUS_ASMB11_YAFU_KCS_INFO_EXIT_{return_code}", ""
        return True, "ASUS_ASMB11_YAFU_KCS_INFO_PASS", existing

    @classmethod
    def _version_matches_target(cls, observed: str, target: str) -> bool:
        expected = cls._version_tuple(target)
        actual = cls._version_tuple(observed)
        return bool(expected and actual and actual[: len(expected)] == expected)

    def preview(self, package: Path, metadata: FirmwarePackageMetadata) -> FirmwarePreview:
        try:
            staging, updater_path, image_path, updater, image, image_name = self._stage_package(package)
        except FirmwareExecutionError as exc:
            return FirmwarePreview(False, self.name, metadata.component, "", metadata.version, True, {"reason": str(exc)})
        try:
            accepted, reason, existing = self._preflight(updater_path, image_path, metadata)
            self._preview_existing_version = existing if accepted else ""
            return FirmwarePreview(
                accepted,
                self.name,
                "BMC",
                existing or str(self.version_reader("BMC") or ""),
                metadata.version,
                False,
                {
                    "reason": reason,
                    "package_delivery": self.descriptor.package_delivery,
                    "image_member": image_name,
                    "yafuflash_sha256": hashlib.sha256(updater).hexdigest(),
                    "local_mode": "KCS",
                    "kcs_preflight": "YAFU_KCS_INFO",
                    "preflight_mutating": False,
                    "preserve_configuration": True,
                    "credential_material_exposed": False,
                    "argv_contains_bmc_credentials": False,
                    "reported_version_aliases": list(self._reported_version_aliases(image, metadata.version)),
                },
            )
        finally:
            staging.cleanup()

    def start(self, package: Path, metadata: FirmwarePackageMetadata) -> UpdateTask:
        task_id = f"ASMB-KCS-{uuid.uuid4().hex.upper()}"
        try:
            staging, updater_path, image_path, _updater, _image, _image_name = self._stage_package(package)
        except FirmwareExecutionError as exc:
            return self._store(f"ASUS-KCS-PREFLIGHT-{uuid.uuid4().hex.upper()}", UpdateTaskState.FAILED, str(exc))
        try:
            accepted, reason, existing = self._preflight(updater_path, image_path, metadata)
            if not accepted:
                return self._store(f"ASUS-KCS-PREFLIGHT-{uuid.uuid4().hex.upper()}", UpdateTaskState.FAILED, reason)
            if self._version_matches_target(existing, metadata.version):
                self._verified_version = metadata.version
                return self._store(
                    f"ASUS-KCS-NO-MUTATION-{uuid.uuid4().hex.upper()}",
                    UpdateTaskState.COMPLETED,
                    "NO_MUTATION_KCS_IMAGE_VERSION_CURRENT",
                )
            # This command is intentionally direct to the package-owned
            # binary.  There is no wrapper, network address, user name or
            # password in the argument vector.
            return_code = self.command_runner(
                [
                    str(updater_path),
                    "-kcs",
                    str(image_path),
                    "-preserve-config",
                    "-ignore-same-image",
                ],
                max(60, min(7200, int(self.descriptor.local_timeout_seconds or 7200))),
            )
            if return_code != 0:
                return self._store(
                    f"ASUS-KCS-ERROR-{uuid.uuid4().hex.upper()}",
                    UpdateTaskState.FAILED,
                    f"ASUS_ASMB11_YAFU_KCS_EXIT_{return_code}",
                )
            deadline = time.monotonic() + self.version_wait_seconds
            while time.monotonic() < deadline:
                return_code, observed = self._kcs_info(updater_path, image_path)
                if return_code == 0 and self._version_matches_target(observed, metadata.version):
                    self._verified_version = metadata.version
                    return self._store(task_id, UpdateTaskState.COMPLETED, "MUTATION_STARTED:ASUS_ASMB11_KCS_VERSION_VERIFIED")
                self.sleep_fn(2.0)
            return self._store(task_id, UpdateTaskState.FAILED, "ASUS_ASMB11_KCS_VERSION_NOT_VERIFIED_AFTER_UPDATE")
        except (FirmwareExecutionError, OSError, ValueError) as exc:
            return self._store(f"ASUS-KCS-ERROR-{uuid.uuid4().hex.upper()}", UpdateTaskState.FAILED, str(exc))
        finally:
            staging.cleanup()

    def read_installed_version(self, component: str) -> str:
        if str(component).upper() == "BMC" and self._verified_version:
            return self._verified_version
        return str(self.version_reader(component) or "")


class _QuietFirmwareHandler(http.server.BaseHTTPRequestHandler):
    """Serve one verified image to the BMC without logging request contents."""

    server_version = "CNServerOpsFirmware/1"

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        owner = self.server  # type: ignore[assignment]
        token = getattr(owner, "token", "")
        expected = "/" + str(token)
        if self.path.split("?", 1)[0] != expected:
            self.send_error(404)
            return
        payload = getattr(owner, "payload", b"")
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *_args: Any) -> None:
        return


class _LocalFirmwareServer:
    """Ephemeral HTTP origin for a BMC ImageURI update contract.

    The server is bound only for the duration of one update task and exposes
    one random path containing one already verified package member. It never
    writes request logs and never accepts credentials in the URL.
    """

    def __init__(self, payload: bytes, filename: str, bmc_host: str) -> None:
        self.payload = bytes(payload)
        self.filename = Path(filename).name
        self.token = f"cn-fw-{uuid.uuid4().hex}"
        self.bmc_host = str(bmc_host or "")
        self.httpd: http.server.ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None
        self.address = ""

    def _source_address(self) -> str:
        # Ask the kernel which local address routes to the BMC. This avoids
        # cloning/development-IP assumptions and works with renamed NICs.
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect((self.bmc_host, 80))
            value = sock.getsockname()[0]
        finally:
            sock.close()
        if not value or value.startswith("127."):
            raise FirmwareExecutionError("ASUS_BIOS_OOB_NO_ROUTABLE_HOST_ADDRESS")
        return value

    def start(self) -> str:
        bind_host = self._source_address()
        self.httpd = http.server.ThreadingHTTPServer((bind_host, 0), _QuietFirmwareHandler)
        self.httpd.daemon_threads = True
        self.httpd.token = self.token  # type: ignore[attr-defined]
        self.httpd.payload = self.payload  # type: ignore[attr-defined]
        self.address = bind_host
        self.thread = threading.Thread(target=self.httpd.serve_forever, name="cnserverops-fw-oob", daemon=True)
        self.thread.start()
        port = int(self.httpd.server_address[1])
        return f"http://{bind_host}:{port}/{self.token}"

    def close(self) -> None:
        if self.httpd is not None:
            try:
                self.httpd.shutdown()
                self.httpd.server_close()
            except OSError:
                pass
            self.httpd = None
        if self.thread is not None and self.thread.is_alive():
            self.thread.join(timeout=2.0)
        self.thread = None


class AsusRedfishFirmwareAdapter:
    """Adapter for Redfish MultipartHttpPushUri, HttpPushUri and SimpleUpdate."""

    name = "asus_redfish_advertised_update_service"

    def __init__(
        self,
        client: AuthenticatedRedfishClient,
        descriptor: AsusTransportDescriptor,
        *,
        version_reader: Callable[[str], str],
        task_path: str = "/redfish/v1/TaskService",
        simple_update_targets: Mapping[str, list[str]] | None = None,
    ) -> None:
        if not descriptor.selectable:
            raise ValueError("Redfish transport descriptor is not selectable")
        if not descriptor.target:
            raise ValueError("Redfish transport descriptor has no advertised target")
        self.client = client
        self.descriptor = descriptor
        self.version_reader = version_reader
        self.task_path = task_path
        self.simple_update_targets = dict(simple_update_targets or {})
        self._active_component = ""
        self._active_target_version = ""
        self._oob_server: _LocalFirmwareServer | None = None

    def _targets_for(self, component: str) -> list[str]:
        """Return explicit targets, or discover the component inventory member.

        ASUS models do not use one stable BMC inventory URI (ASMB11/12 and
        later generations have used ``BMC``, ``BMCImage1`` and other names).
        The caller may pin a target captured during capability discovery; when
        it does not, consult the live UpdateService inventory and only select
        an updateable member whose name identifies the requested component.
        No endpoint is guessed and an ambiguous inventory remains empty.
        """
        explicit = [str(item) for item in self.simple_update_targets.get(component, []) if str(item).startswith("/")]
        if explicit:
            return explicit
        try:
            inventory = self.client.get_json("/redfish/v1/UpdateService/FirmwareInventory").payload
            members = inventory.get("Members", []) if isinstance(inventory, Mapping) else []
            candidates: list[str] = []
            for item in members if isinstance(members, list) else []:
                if not isinstance(item, Mapping):
                    continue
                uri = str(item.get("@odata.id") or "")
                if not uri.startswith("/"):
                    continue
                try:
                    detail = self.client.get_json(uri).payload
                except Exception:
                    detail = item
                ident = " ".join(str(detail.get(key) or "") for key in ("Id", "Name", "Description", "@odata.id")).casefold()
                updateable = detail.get("Updateable", True)
                if not updateable:
                    continue
                if component.upper() == "BMC" and any(token in ident for token in ("bmc", "asmb", "management")):
                    candidates.append(uri)
                elif component.upper() == "BIOS" and any(token in ident for token in ("bios", "uefi")):
                    candidates.append(uri)
            return candidates if len(candidates) == 1 else []
        except Exception:
            return []

    def preview(self, package: Path, metadata: FirmwarePackageMetadata) -> FirmwarePreview:
        if not package.is_file() or package.is_symlink():
            return FirmwarePreview(False, self.name, metadata.component, "", metadata.version, True, {"reason": "PACKAGE_NOT_REGULAR_FILE"})
        if not self.descriptor.supports(metadata.component):
            return FirmwarePreview(False, self.name, metadata.component, "", metadata.version, True, {"reason": "COMPONENT_NOT_SUPPORTED_BY_DESCRIPTOR"})
        if self.descriptor.package_delivery == "REMOTE_URI" and not metadata.source_url.startswith("https://"):
            return FirmwarePreview(False, self.name, metadata.component, "", metadata.version, True, {"reason": "REMOTE_URI_REQUIRED"})
        return FirmwarePreview(
            True,
            self.name,
            metadata.component,
            self.version_reader(metadata.component),
            metadata.version,
            self.descriptor.reboot_behavior != "NO_REBOOT",
            {
                "descriptor": self.descriptor.to_dict(),
                "package_filename": package.name,
                "package_size_bytes": package.stat().st_size,
                "update_service_target_advertised": True,
            },
        )

    def start(self, package: Path, metadata: FirmwarePackageMetadata) -> UpdateTask:
        self._active_component = metadata.component.upper()
        self._active_target_version = metadata.version
        payload_evidence: dict[str, Any] = {}
        try:
            if self.descriptor.package_delivery == "REDFISH_BIOS_OOB":
                if self._active_component != "BIOS":
                    raise FirmwareExecutionError("ASUS_BIOS_OOB_COMPONENT_UNSUPPORTED")
                image_name = ""
                image_payload = b""
                if zipfile.is_zipfile(package):
                    with zipfile.ZipFile(package) as archive:
                        for item in archive.infolist():
                            if item.is_dir():
                                continue
                            member = Path(item.filename)
                            if member.is_absolute() or ".." in member.parts:
                                raise FirmwareExecutionError("ASUS_PACKAGE_MEMBER_PATH_UNSAFE")
                            if member.suffix.casefold() == ".cap":
                                image_name = member.name
                                image_payload = archive.read(item)
                                break
                else:
                    image_name = package.name
                    image_payload = package.read_bytes()
                if not image_payload:
                    raise FirmwareExecutionError("ASUS_BIOS_OOB_CAP_NOT_FOUND")
                # ASMB11 exposes BIOS OOB through the advertised multipart
                # upload contract.  The OEM BIOSFwUpdate action is a remote
                # URL fetch and does not stage a local OOB capsule; posting a
                # local URI there yields the opaque vendor error
                # ``ImageURI not exist`` even when the URI is reachable.  Use
                # the exact MultipartHttpPushUri advertised by UpdateService
                # and the documented BIOSOOB multipart fields instead.
                update_service = self.client.get_json("/redfish/v1/UpdateService").payload
                multipart_target = str(update_service.get("MultipartHttpPushUri") or "")
                if not multipart_target.startswith("/"):
                    raise FirmwareExecutionError("ASUS_BIOS_OOB_MULTIPART_URI_NOT_ADVERTISED")
                with tempfile.TemporaryDirectory(prefix="cnserverops-asus-bios-oob-") as staging:
                    staged = Path(staging) / Path(image_name).name
                    staged.write_bytes(image_payload)
                    response = self.client.post_multipart(
                        multipart_target,
                        staged,
                        update_parameters={
                            "Targets": ["/redfish/v1/UpdateService/FirmwareInventory/BIOS"],
                        },
                        oem_parameters={
                            "ImageType": "BIOSOOB",
                            "BIOSOOBEnable": 1,
                        },
                    )
                payload_evidence = {
                    "transport": "ASUS_REDFISH_BIOS_OOB",
                    "selected_image": image_name,
                    "selected_suffix": "cap",
                    "image_type": "BIOSOOB",
                    "oob_enabled": True,
                    "multipart_target": multipart_target,
                }
            elif self.descriptor.package_delivery == "MULTIPART_FILE":
                # Content-addressed cache objects intentionally have digest
                # filenames.  ASUS update handlers use the original suffix to
                # select ZIP/HPM/CAP parsing, so present a regular temporary
                # file with the verified package filename while preserving the
                # immutable cache object.
                with tempfile.TemporaryDirectory(prefix="cnserverops-asus-fw-") as staging:
                    component = metadata.component.upper()
                    targets = self._targets_for(component)
                    if not targets:
                        return UpdateTask(
                            "ASUS-TARGET-ERROR",
                            UpdateTaskState.FAILED,
                            "EXACT_UPDATE_TARGET_NOT_RESOLVED",
                        )
                    image_types = self._image_type_candidates(component)
                    image_bytes: dict[str, tuple[str, bytes]] = {}
                    if zipfile.is_zipfile(package):
                        # ASUS download pages publish a ZIP wrapper; Redfish
                        # AMI endpoints consume the signed inner HPM/CAP image.
                        with zipfile.ZipFile(package) as archive:
                            for item in archive.infolist():
                                if item.is_dir():
                                    continue
                                member_path = Path(item.filename)
                                if member_path.is_absolute() or ".." in member_path.parts:
                                    raise FirmwareExecutionError("ASUS_PACKAGE_MEMBER_PATH_UNSAFE")
                                suffix = member_path.suffix.casefold().lstrip(".")
                                if suffix in {"hpm", "cap", "bin", "ima"} and suffix not in image_bytes:
                                    image_bytes[suffix] = (member_path.name, archive.read(item))
                    else:
                        # A content-addressed object may retain a ZIP-like
                        # metadata filename even when the fixture is a raw
                        # image. Treat it as a generic binary candidate; the
                        # component/image-type gate still controls its use.
                        image_bytes["bin"] = (metadata.package_filename, package.read_bytes())

                    response = None
                    last_contract_error: RedfishRequestError | None = None
                    for image_type in image_types:
                        suffixes = self._suffix_preferences(component, image_type)
                        selected = next((image_bytes[suffix] for suffix in suffixes if suffix in image_bytes), None)
                        if selected is None:
                            continue
                        selected_name, selected_bytes = selected
                        staged = Path(staging) / Path(selected_name).name
                        staged.write_bytes(selected_bytes)
                        payload_evidence = {
                            "outer_package": package.name,
                            "selected_image": staged.name,
                            "selected_suffix": staged.suffix.casefold().lstrip("."),
                            "image_type": image_type,
                            "targets": targets,
                        }
                        try:
                            response = self.client.post_multipart(
                                self.descriptor.target,
                                staged,
                                update_parameters={"Targets": targets},
                                oem_parameters={"ImageType": image_type},
                            )
                            break
                        except RedfishRequestError as exc:
                            last_contract_error = exc
                            # A rejected ImageType is a non-mutating contract
                            # response. Try the next explicitly supported ASUS
                            # container/image type only for that exact error.
                            if not _invalid_image_type_error(exc):
                                raise
                    if response is None:
                        if last_contract_error is not None:
                            raise last_contract_error
                        raise FirmwareExecutionError(
                            f"ASUS_PACKAGE_CONTAINS_NO_{component}_COMPATIBLE_IMAGE"
                        )
            elif self.descriptor.package_delivery == "REMOTE_URI":
                response = self.client.request_json(
                    "POST",
                    self.descriptor.target,
                    {"ImageURI": metadata.source_url, "Targets": self._targets_for(metadata.component)},
                )
            else:
                raise FirmwareExecutionError("ASUS OEM Redfish payload is not configured for this platform")
        except FirmwareExecutionError as exc:
            if self._oob_server is not None:
                self._oob_server.close()
                self._oob_server = None
            return UpdateTask("ASUS-PAYLOAD-ERROR", UpdateTaskState.FAILED, str(exc))
        except RedfishRequestError as exc:
            if self._oob_server is not None:
                self._oob_server.close()
                self._oob_server = None
            detail = exc.kind.value
            if exc.http_status:
                detail = f"{detail}:HTTP_{exc.http_status}"
            if exc.response_sha256:
                detail += f":RESPONSE_SHA256={exc.response_sha256}"
            if exc.response_length is not None:
                detail += f":RESPONSE_BYTES={exc.response_length}"
            if exc.response_hint:
                detail += f":RESPONSE_HINT={exc.response_hint}"
            return UpdateTask("REDFISH-ERROR", UpdateTaskState.FAILED, detail)
        task_id = _task_id(response.location, response.payload)
        if not task_id:
            # A 200/204 with no task is not proof that a firmware write was
            # accepted.  Keep the run explicitly unverified.
            self._close_oob_server()
            return UpdateTask("REDFISH-NO-TASK", UpdateTaskState.UNKNOWN, "Mutation response contained no task identity")
        initial = _task_state(response.payload)
        if response.status in {200, 201, 202, 204} and initial == UpdateTaskState.UNKNOWN:
            initial = UpdateTaskState.QUEUED
        detail = f"HTTP {response.status}"
        if payload_evidence:
            detail += ":" + ",".join(
                f"{key}={value}" for key, value in payload_evidence.items()
            )
        return UpdateTask(task_id, initial, detail)

    def _image_type_candidates(self, component: str) -> tuple[str, ...]:
        configured = self.descriptor.component_image_type_candidates.get(component, ())
        values = [str(item).upper() for item in configured if str(item).strip()]
        if not values:
            values = [str(self.descriptor.component_image_types.get(component) or component).upper()]
            # ASMB generations have used HPM for both BIOS and BMC local
            # uploads. It is a fallback only after the initial advertised
            # contract rejects ImageType, never a cross-model substitution.
            if component == "BIOS":
                values.append("HPM")
        return tuple(dict.fromkeys(values))

    def _suffix_preferences(self, component: str, image_type: str) -> tuple[str, ...]:
        configured = tuple(
            str(item).casefold().lstrip(".")
            for item in self.descriptor.component_payload_preferences.get(component, ())
            if str(item).strip()
        )
        defaults = {
            "BIOS": ("cap", "bin", "ima"),
            "BMC": ("hpm", "bin", "ima"),
        }
        preferences = configured or defaults.get(component, ())
        if image_type.upper() == "HPM":
            return tuple(dict.fromkeys(("hpm", *preferences)))
        if component == "BIOS":
            return tuple(item for item in preferences if item != "hpm")
        return preferences

    def poll(self, task_id: str) -> UpdateTask:
        try:
            response = self.client.get_json(task_id)
        except RedfishRequestError as exc:
            if exc.kind in {RedfishFailureKind.TIMEOUT, RedfishFailureKind.TRANSPORT_ERROR, RedfishFailureKind.BLOCKED_BY_MISSING_ENDPOINT}:
                # ASUS BMCs commonly restart during activation and may drop the
                # task resource. Once the live inventory reports the exact
                # target version, that restart is a successful terminal proof;
                # otherwise keep polling after a bounded reconnect delay.
                time.sleep(2.0)
                if self._active_component and self._active_target_version:
                    try:
                        if self.read_installed_version(self._active_component) == self._active_target_version:
                            return UpdateTask(task_id, UpdateTaskState.COMPLETED, "BMC_RESTART_VERSION_VERIFIED")
                    except Exception:
                        pass
                return UpdateTask(task_id, UpdateTaskState.BMC_RESTARTING, exc.kind.value)
            self._close_oob_server()
            return UpdateTask(task_id, UpdateTaskState.FAILED, exc.kind.value)
        state = _task_state(response.payload)
        if (
            self.descriptor.package_delivery == "REDFISH_BIOS_OOB"
            and state in {UpdateTaskState.COMPLETED, UpdateTaskState.COMPLETED_WITH_WARNING}
        ):
            # ASMB11 reports the staging task as Completed while the capsule
            # is merely armed for the next host boot.  Treat that terminal
            # task as a durable reboot checkpoint until the BMC clears its
            # BIOSOOB flag; otherwise the executor would immediately compare
            # the pre-reboot BIOS and report a false version mismatch.
            try:
                service = self.client.get_json("/redfish/v1/UpdateService").payload
                oem = service.get("Oem") if isinstance(service, Mapping) else {}
                bmc = oem.get("BMC") if isinstance(oem, Mapping) else {}
                oob = bmc.get("BIOSOOB") if isinstance(bmc, Mapping) else {}
                enabled = str(oob.get("BIOSOOBEnable") or "").strip().casefold()
                status_text = str(oob.get("BIOSOOBStatus") or "").strip().casefold()
                if enabled in {"1", "true", "yes"} or "ready" in status_text:
                    return UpdateTask(task_id, UpdateTaskState.REBOOT_REQUIRED, "ASUS_BIOS_OOB_STAGED_REBOOT_REQUIRED")
            except Exception:
                # If the status endpoint is temporarily unavailable, retain
                # the normal task state and let post-version verification make
                # the conservative decision.
                pass
        # Do not busy-loop against an AMI task resource.  BMC flash tasks can
        # legitimately remain ``Running`` while the image is staged or while
        # the management controller prepares its restart.
        if state in {UpdateTaskState.NEW, UpdateTaskState.QUEUED, UpdateTaskState.RUNNING}:
            time.sleep(5.0)
        if state not in {UpdateTaskState.NEW, UpdateTaskState.QUEUED, UpdateTaskState.RUNNING, UpdateTaskState.BMC_RESTARTING}:
            self._close_oob_server()
        return UpdateTask(task_id, state, str(response.payload.get("Message") or response.payload.get("PercentComplete") or ""))

    def _close_oob_server(self) -> None:
        if self._oob_server is not None:
            self._oob_server.close()
            self._oob_server = None

    def read_installed_version(self, component: str) -> str:
        return str(self.version_reader(component) or "")


def _task_id(location: str, payload: Mapping[str, Any]) -> str:
    value = str(location or payload.get("@odata.id") or payload.get("Task") or payload.get("TaskId") or "").strip()
    if value.startswith("https://"):
        from urllib.parse import urlparse

        parsed = urlparse(value)
        value = parsed.path or "/"
    return value if value.startswith("/") else f"/{value}" if value else ""


def _invalid_image_type_error(error: RedfishRequestError) -> bool:
    hint = str(error.response_hint or "").casefold()
    return "invalidvariablevalue" in hint and "imagetype" in hint


def _task_state(payload: Mapping[str, Any]) -> UpdateTaskState:
    status = str(payload.get("TaskState") or payload.get("TaskStatus") or payload.get("Status") or "").casefold()
    if status in {"completed", "complete", "success", "succeeded"}:
        return UpdateTaskState.COMPLETED
    if status in {"warning", "completedwithwarning", "completed_with_warning"}:
        return UpdateTaskState.COMPLETED_WITH_WARNING
    if status in {"exception", "failed", "killed", "cancelled", "canceled"}:
        return UpdateTaskState.CANCELLED if "cancel" in status else UpdateTaskState.FAILED
    if status in {"rebootrequired", "reboot_required"}:
        return UpdateTaskState.REBOOT_REQUIRED
    if status in {"running", "processing", "starting", "new"}:
        return UpdateTaskState.RUNNING
    if status in {"pending", "queued"}:
        return UpdateTaskState.QUEUED
    return UpdateTaskState.UNKNOWN
