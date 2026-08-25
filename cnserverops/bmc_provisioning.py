"""Bounded ASUS BMC first-login password provisioning.

This module intentionally exposes one narrowly-scoped mutation: PATCHing the
Password property of the account URI advertised by the ASUS first-login
response.  It never changes roles, enables accounts, resets the BMC, powers a
host, or accepts an arbitrary Redfish mutation path.  Secrets are supplied at
runtime and are never returned in a result or exception message.
"""

from __future__ import annotations

import base64
import json
import re
import ssl
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import urlparse


class BmcProvisioningError(RuntimeError):
    """Sanitized provisioning failure; never includes credentials or bodies."""

    def __init__(self, stage: str, *, http_status: int | None = None) -> None:
        self.stage = str(stage or "UNKNOWN")
        self.http_status = http_status
        suffix = f" HTTP {http_status}" if http_status is not None else ""
        super().__init__(f"BMC password provisioning failed at {self.stage}{suffix}")


@dataclass(frozen=True)
class BmcProvisioningResult:
    status: str
    account_path: str
    get_http_status: int | None = None
    patch_http_status: int | None = None
    patch_precondition: str = ""
    verify_http_status: int | None = None
    mutation_performed: bool = False
    password_change_required_before: bool = False
    password_change_required_after: bool = False
    patch_authentication: str = "BASIC"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "account_path": self.account_path,
            "get_http_status": self.get_http_status,
            "patch_http_status": self.patch_http_status,
            "patch_precondition": self.patch_precondition,
            "verify_http_status": self.verify_http_status,
            "mutation_performed": self.mutation_performed,
            "first_login_change_required_before": self.password_change_required_before,
            "first_login_change_required_after": self.password_change_required_after,
            "patch_authentication": self.patch_authentication,
            "sensitive_material_persisted": False,
        }


_ACCOUNT_PATH = re.compile(r"^/redfish/v1/AccountService/Accounts/4/?$")


def provision_bmc_password(
    host: str,
    username: str,
    current_password: str,
    new_password: str,
    *,
    verify_tls: bool = True,
    account_path: str = "/redfish/v1/AccountService/Accounts/4",
    timeout_seconds: int = 30,
) -> BmcProvisioningResult:
    """Change only the ASUS first-login account password and verify access.

    ASUS/AMI ASMB firmware documents the account-password PATCH with the
    ``If-None-Match: *`` requester header.  Older releases accepted an
    ``If-Match`` ETag instead, so the adapter tries the documented form first
    and falls back to the ETag form only when the BMC rejects the first
    precondition.  The follow-up GET proves the new credential can access
    protected Systems data.
    """
    path = "/" + str(account_path or "").lstrip("/")
    if not _ACCOUNT_PATH.fullmatch(path):
        raise BmcProvisioningError("ACCOUNT_PATH_NOT_ALLOWED")
    if not str(username or "").strip() or not current_password or not new_password:
        raise BmcProvisioningError("CREDENTIAL_INPUT_MISSING")
    if len(str(new_password)) < 8:
        raise BmcProvisioningError("NEW_PASSWORD_TOO_SHORT")
    if timeout_seconds <= 0 or timeout_seconds > 300:
        raise BmcProvisioningError("TIMEOUT_INVALID")
    base = _base_url(host)
    context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    current_auth = _basic_auth(username, current_password)
    target = base + path
    get_request = Request(target, headers={"Accept": "application/json", "Authorization": current_auth}, method="GET")
    try:
        with urlopen(get_request, timeout=timeout_seconds, context=context) as response:
            get_status = int(response.status)
            etag = str(response.headers.get("ETag") or "").strip()
            payload = _json_payload(response.read(8192))
    except HTTPError as exc:
        raise BmcProvisioningError("ACCOUNT_GET", http_status=exc.code) from exc
    except (URLError, ssl.SSLError, OSError, TimeoutError) as exc:
        raise BmcProvisioningError("ACCOUNT_GET_TRANSPORT") from exc
    required_before = bool(payload.get("PasswordChangeRequired"))

    patch_body = json.dumps({"Password": str(new_password)}, separators=(",", ":")).encode("utf-8")
    # AMI's documented first-login path uses If-None-Match: *.  Retain the
    # ETag variant for older ASMB firmware that implemented the earlier
    # Redfish conditional-write behaviour.  Never send both headers: their
    # semantics conflict when the resource already exists.
    preconditions: list[tuple[str, str, str]] = [("If-None-Match", "*", "IF_NONE_MATCH")]
    if etag:
        preconditions.append(("If-Match", etag, "IF_MATCH_ETAG"))
    patch_status: int | None = None
    patch_precondition = ""
    patch_authentication = "BASIC"
    last_error: BmcProvisioningError | None = None
    def _patch(headers: dict[str, str], label: str, authentication: str) -> bool:
        nonlocal patch_status, patch_precondition, patch_authentication, last_error
        patch_request = Request(target, data=patch_body, headers=headers, method="PATCH")
        try:
            with urlopen(patch_request, timeout=timeout_seconds, context=context) as response:
                patch_status = int(response.status)
                response.read(4096)
        except HTTPError as exc:
            last_error = BmcProvisioningError(f"ACCOUNT_PATCH_{label}", http_status=exc.code)
            return False
        except (URLError, ssl.SSLError, OSError, TimeoutError) as exc:
            raise BmcProvisioningError(f"ACCOUNT_PATCH_{label}_TRANSPORT") from exc
        if patch_status in {200, 202, 204}:
            patch_precondition = label
            patch_authentication = authentication
            return True
        last_error = BmcProvisioningError(f"ACCOUNT_PATCH_{label}_STATUS", http_status=patch_status)
        return False

    for header_name, header_value, label in preconditions:
        if _patch(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": current_auth,
                header_name: header_value,
            },
            label,
            "BASIC",
        ):
            break
    else:
        # Redfish PasswordChangeRequired is a restricted-authentication
        # state.  DMTF requires a session POST to be accepted (often HTTP
        # 400 with a usable X-Auth-Token), followed by the password PATCH
        # using that token.  AMI MegaRAC/ASMB11 enforces this even though the
        # account GET and ordinary Basic-auth PATCH endpoint are visible.
        # Only attempt this path after the normal documented Basic path has
        # been rejected with 403; this preserves compatibility with older
        # ASMB firmware and keeps the mutation narrowly scoped.
        session = _create_password_change_session(
            base,
            username,
            current_password,
            verify_tls=verify_tls,
            timeout_seconds=timeout_seconds,
        ) if required_before and getattr(last_error, "http_status", None) == 403 else None
        if session:
            session_token, session_location = session
            try:
                for header_name, header_value, label in preconditions:
                    if _patch(
                        {
                            "Accept": "application/json",
                            "Content-Type": "application/json",
                            "X-Auth-Token": session_token,
                            header_name: header_value,
                        },
                        f"SESSION_{label}",
                        "REDFISH_PASSWORD_CHANGE_SESSION",
                    ):
                        break
                else:
                    if last_error is not None:
                        raise last_error
                    raise BmcProvisioningError("ACCOUNT_PATCH_SESSION_UNAVAILABLE")
            finally:
                _delete_password_change_session(
                    base,
                    session_location,
                    session_token,
                    verify_tls=verify_tls,
                    timeout_seconds=timeout_seconds,
                )
        elif last_error is not None:
            raise last_error
        else:
            raise BmcProvisioningError("ACCOUNT_PATCH_UNAVAILABLE")

    new_auth = _basic_auth(username, new_password)
    verify_request = Request(
        base + "/redfish/v1/Systems",
        headers={"Accept": "application/json", "Authorization": new_auth},
        method="GET",
    )
    try:
        with urlopen(verify_request, timeout=timeout_seconds, context=context) as response:
            verify_status = int(response.status)
            response.read(8192)
    except HTTPError as exc:
        raise BmcProvisioningError("POST_PROVISION_SYSTEMS_GET", http_status=exc.code) from exc
    except (URLError, ssl.SSLError, OSError, TimeoutError) as exc:
        raise BmcProvisioningError("POST_PROVISION_SYSTEMS_TRANSPORT") from exc
    if not 200 <= verify_status < 300:
        raise BmcProvisioningError("POST_PROVISION_SYSTEMS_STATUS", http_status=verify_status)
    return BmcProvisioningResult(
        status="PROVISIONED",
        account_path=path,
        get_http_status=get_status,
        patch_http_status=patch_status,
        verify_http_status=verify_status,
        patch_precondition=patch_precondition,
        mutation_performed=True,
        password_change_required_before=required_before,
        password_change_required_after=False,
        patch_authentication=patch_authentication,
    )


def _create_password_change_session(
    base: str,
    username: str,
    password: str,
    *,
    verify_tls: bool,
    timeout_seconds: int,
) -> tuple[str, str] | None:
    """Create the restricted Redfish session allowed during first login.

    AMI returns HTTP 400 together with ``X-Auth-Token`` and ``Location``
    while reporting Base.1.5.PasswordChangeRequired.  Treat that exact
    response as a usable restricted session; never log the token or body.
    """
    context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    payload = json.dumps({"UserName": str(username), "Password": str(password)}, separators=(",", ":")).encode("utf-8")
    request = Request(
        base + "/redfish/v1/SessionService/Sessions",
        data=payload,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        method="POST",
    )
    token = ""
    location = ""
    status: int | None = None
    response_body = b""
    try:
        with urlopen(request, timeout=timeout_seconds, context=context) as response:
            status = int(response.status)
            token = str(response.headers.get("X-Auth-Token") or "").strip()
            location = str(response.headers.get("Location") or "").strip()
            response_body = response.read(4096)
    except HTTPError as exc:
        status = int(exc.code)
        token = str(exc.headers.get("X-Auth-Token") or "").strip()
        location = str(exc.headers.get("Location") or "").strip()
        response_body = exc.read(4096)
    except (URLError, ssl.SSLError, OSError, TimeoutError) as exc:
        raise BmcProvisioningError("SESSION_CREATE_TRANSPORT") from exc
    if not token or not location:
        return None
    # A restricted first-login session is normally 400; accept successful
    # session creation too, but reject unrelated error responses that happen
    # to include stale headers.
    try:
        document = _json_payload(response_body)
    except Exception:
        document = {}
    message_ids = {
        str(item.get("MessageId") or "")
        for item in ((document.get("error") or {}).get("@Message.ExtendedInfo") or [])
        if isinstance(item, dict)
    }
    if status not in {200, 201, 202, 204, 400} and "Base.1.5.PasswordChangeRequired" not in message_ids:
        return None
    return token, location


def _delete_password_change_session(
    base: str,
    location: str,
    token: str,
    *,
    verify_tls: bool,
    timeout_seconds: int,
) -> None:
    """Best-effort cleanup; session expiry must never mask a successful patch."""
    if not token or not location:
        return
    target = location if location.startswith("http") else base + "/" + location.lstrip("/")
    request = Request(target, headers={"X-Auth-Token": token}, method="DELETE")
    context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    try:
        with urlopen(request, timeout=timeout_seconds, context=context) as response:
            response.read(1024)
    except Exception:
        return


def _base_url(host: str) -> str:
    value = str(host or "").strip()
    candidate = value if "://" in value else f"https://{value}"
    parsed = urlparse(candidate)
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise BmcProvisioningError("HOST_INVALID")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise BmcProvisioningError("HOST_PATH_INVALID")
    port = f":{parsed.port}" if parsed.port else ""
    return f"https://{parsed.hostname}{port}"


def _basic_auth(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def _json_payload(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8", errors="replace"))
    except (ValueError, UnicodeDecodeError):
        return {}
    return value if isinstance(value, dict) else {}
