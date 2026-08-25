"""Controlled, credential-safe ASUS BMC authentication discovery.

This module intentionally performs at most one approved credential probe per
candidate account and only issues Redfish GET requests during discovery. It
never stores or prints a password, never tries arbitrary password lists, and
only changes the documented first-login account when the explicitly enabled
provisioning path is authorized by the caller. Local KCS/IPMI collection
remains independent of this path.
"""

from __future__ import annotations

import os
import json
import re
import secrets
import stat
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

from .evidence import BmcAuthState, bmc_auth_is_usable, classify_bmc_auth_state
from .bmc_provisioning import BmcProvisioningError, provision_bmc_password


class BmcAuthPolicyError(ValueError):
    pass


_POST_RECOVERY_REDFISH_READY_TIMEOUT_SECONDS = 180.0
_POST_RECOVERY_REDFISH_RETRY_DELAY_SECONDS = 5.0


@dataclass(frozen=True)
class BmcAuthPolicy:
    """Configuration references secrets; it never contains the secret value."""

    mode: str = "AUTO_NEW_SERVER"
    default_probe_enabled: bool = True
    default_username: str = "admin"
    default_password_env: str = "CN_ASUS_BMC_DEFAULT_PASSWORD"
    default_password_file: Path = Path("/etc/cnserverops/secrets/asus-default-bmc-password")
    provisioned_username: str = ""
    provisioned_username_env: str = "CN_ASUS_BMC_USERNAME"
    provisioned_password_env: str = "CN_ASUS_BMC_PASSWORD"
    provisioned_password_file: Path = Path("/etc/cnserverops/secrets/asus-bmc-password")
    # Optional approved first-login password target. The supported ASUS path
    # changes the documented default account password (normally ``admin``);
    # this reference is never serialized or packaged with its value.
    first_login_password_env: str = "CN_ASUS_BMC_FIRST_LOGIN_PASSWORD"
    first_login_password_file: Path = Path("/etc/cnserverops/secrets/asus-first-login-bmc-password")
    # This file deliberately contains only the physical server identity that
    # owns the temporary operational account.  It never contains a password,
    # token, or username.  Keeping it beside the root-only secret by default
    # makes cloning and final-handoff cleanup deterministic.
    provisioned_account_binding_file: Path | None = None
    provision_on_password_change: bool = True
    provision_account_path: str = "/redfish/v1/AccountService/Accounts/4"
    verify_tls: bool = True
    password_change_required_statuses: tuple[int, ...] = ()
    collect_authenticated_get_only: bool = True

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> "BmcAuthPolicy":
        payload = dict(value or {})
        mode = str(payload.get("mode") or cls.mode).strip().upper()
        if mode not in {"DISABLED", "PROVISIONED_ONLY", "AUTO_NEW_SERVER", "NEW_SERVER_ONLY"}:
            raise BmcAuthPolicyError("unsupported BMC authentication policy mode")
        default_username = str(payload.get("default_username") or cls.default_username).strip()
        if not default_username or len(default_username) > 64:
            raise BmcAuthPolicyError("default BMC username is invalid")
        statuses = payload.get("password_change_required_statuses", cls.password_change_required_statuses)
        if not isinstance(statuses, (list, tuple)):
            raise BmcAuthPolicyError("password_change_required_statuses must be a list")
        parsed_statuses = tuple(int(item) for item in statuses)
        if any(item < 100 or item > 599 for item in parsed_statuses):
            raise BmcAuthPolicyError("password-change HTTP statuses are invalid")
        return cls(
            mode=mode,
            default_probe_enabled=bool(payload.get("default_probe_enabled", cls.default_probe_enabled)),
            default_username=default_username,
            default_password_env=str(payload.get("default_password_env") or cls.default_password_env),
            default_password_file=Path(str(payload.get("default_password_file") or cls.default_password_file)),
            provisioned_username=str(payload.get("provisioned_username") or "").strip(),
            provisioned_username_env=str(payload.get("provisioned_username_env") or cls.provisioned_username_env),
            provisioned_password_env=str(payload.get("provisioned_password_env") or cls.provisioned_password_env),
            provisioned_password_file=Path(str(payload.get("provisioned_password_file") or cls.provisioned_password_file)),
            first_login_password_env=str(payload.get("first_login_password_env") or cls.first_login_password_env),
            first_login_password_file=Path(
                str(payload.get("first_login_password_file") or cls.first_login_password_file)
            ),
            provisioned_account_binding_file=(
                Path(str(payload["provisioned_account_binding_file"]))
                if payload.get("provisioned_account_binding_file")
                else None
            ),
            provision_on_password_change=bool(payload.get("provision_on_password_change", cls.provision_on_password_change)),
            provision_account_path=str(payload.get("provision_account_path") or cls.provision_account_path),
            verify_tls=bool(payload.get("verify_tls", cls.verify_tls)),
            password_change_required_statuses=parsed_statuses,
            collect_authenticated_get_only=bool(payload.get("collect_authenticated_get_only", cls.collect_authenticated_get_only)),
        )

    def public_record(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "default_probe_enabled": self.default_probe_enabled,
            "default_username": self.default_username,
            "default_account_reference": {
                "source": "runtime-environment-or-root-only-file",
                "root_only_file_configured": bool(str(self.default_password_file)),
            },
            "provisioned_username_source": "configured_or_environment",
            "provisioned_account_reference": {
                "source": "runtime-environment-or-root-only-file",
                "root_only_file_configured": bool(str(self.provisioned_password_file)),
            },
            "provisioned_account_binding": {
                "required_for_reuse": True,
                "server_identity_bound": True,
                "root_only_file_configured": bool(str(self.provisioned_account_binding_path)),
                "sensitive_material_persisted": False,
            },
            "first_login_target_reference": {
                "account_username": self.default_username,
                "source": "runtime-environment-or-root-only-file",
                "root_only_file_configured": bool(str(self.first_login_password_file)),
                "sensitive_material_persisted": False,
            },
            "first_login_provisioning_enabled": self.provision_on_password_change,
            "first_login_account_path": self.provision_account_path,
            "verify_tls": self.verify_tls,
            "first_login_change_statuses": list(self.password_change_required_statuses),
            "collect_authenticated_get_only": self.collect_authenticated_get_only,
            "sensitive_material_persisted": False,
            "mutation_enabled": False,
        }

    @property
    def provisioned_account_binding_path(self) -> Path:
        """Return the root-only, secret-free owner record for this account.

        Existing deployments which customize the secret path automatically get
        a colocated binding path.  This avoids a shared global binding record
        accidentally authorizing a secret stored in a different location.
        """
        if self.provisioned_account_binding_file is not None:
            return Path(self.provisioned_account_binding_file)
        secret_path = Path(self.provisioned_password_file)
        return secret_path.with_name(secret_path.name + ".binding.json")


@dataclass(frozen=True)
class _CredentialCandidate:
    kind: str
    username: str
    password: str = field(repr=False, default="")
    source: str = "NONE"

    def public(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "username": self.username,
            "source": self.source.split(":", 1)[0],
            "sensitive_material_supplied": bool(self.password),
            "sensitive_material_persisted": False,
        }


def discover_bmc_auth(
    host: str,
    *,
    policy: BmcAuthPolicy,
    primary_root: Path,
    server_id: str,
    exclude_run_id: str = "",
    allow_password_provisioning: bool = True,
    allow_default_probe_after_recovery: bool = False,
    allow_default_probe_after_observed_first_login: bool = False,
    ignore_provisioned_candidates: bool = False,
    redfish_factory: Callable[..., Any] | None = None,
    discovery_factory: Callable[[Any], Mapping[str, Any]] | None = None,
    post_recovery_readiness_timeout_seconds: float = _POST_RECOVERY_REDFISH_READY_TIMEOUT_SECONDS,
    post_recovery_readiness_retry_delay_seconds: float = _POST_RECOVERY_REDFISH_RETRY_DELAY_SECONDS,
) -> dict[str, Any]:
    """Probe provisioned credentials and, for a new candidate, one default.

    The output is safe to persist.  ``host`` is the discovered BMC endpoint,
    while username/source metadata explains provenance without exposing a
    password or token.
    """
    result: dict[str, Any] = {
        "schema_version": 1,
        "host": str(host or ""),
        "server_id": str(server_id or ""),
        "policy": policy.public_record(),
        "server_seen_before": server_seen_before(primary_root, server_id, exclude_run_id=exclude_run_id),
        "attempts": [],
        "state": BmcAuthState.BMC_AUTH_UNAVAILABLE.value,
        "usable_for_authenticated_get": False,
        "authenticated_discovery": {},
        "mutation_authorized": False,
    }
    if not host:
        result["reason"] = "BMC_IP_UNAVAILABLE"
        return result
    if policy.mode == "DISABLED":
        result["reason"] = "POLICY_DISABLED"
        return result

    # A server being present in local history normally suppresses the ASUS
    # factory credential probe.  A bounded, exact-platform factory recovery
    # is the one deliberate exception: recovery has just replaced the BMC
    # account state, so the documented first-login credential is now the
    # authoritative next step even when this physical server was seen before.
    candidates = _candidates(
        policy,
        result["server_seen_before"],
        server_id=str(server_id or ""),
        allow_default_probe_after_recovery=allow_default_probe_after_recovery,
        allow_default_probe_after_observed_first_login=allow_default_probe_after_observed_first_login,
        ignore_provisioned_candidates=ignore_provisioned_candidates,
    )
    if not candidates:
        result["reason"] = "NO_APPROVED_SECRET_REFERENCE_AVAILABLE"
        return result
    factory = redfish_factory or _default_redfish_factory
    for candidate in candidates:
        # ServiceRoot is intentionally readable on many BMCs even when the
        # account is still in first-login/password-change state.  Probe a
        # protected inventory collection as part of the *same* approved
        # read-only attempt so a public ServiceRoot cannot be mistaken for
        # authenticated capability.
        attempt: dict[str, Any] = {
            "account": candidate.public(),
            "endpoint": "/redfish/v1/Systems",
            "service_root_endpoint": "/redfish/v1/",
            "method": "GET",
        }
        # KCS can return before HTTPS/Redfish is ready after the exact ASUS
        # factory-default recovery.  Retry only this one documented DEFAULT
        # credential and only for sanitized transport/timeout failures which
        # have no HTTP response.  An explicit 401/403 or any other HTTP reply
        # is terminal: it is never converted into password enumeration.
        readiness_retry_enabled = bool(
            allow_default_probe_after_recovery and candidate.kind == "DEFAULT"
        )
        readiness_started = time.monotonic()
        readiness_attempt_count = 0
        readiness_retry_count = 0
        readiness_last_retry_reason = ""
        terminal_exc: Exception | None = None
        readiness_timeout = max(
            0.0,
            min(
                float(post_recovery_readiness_timeout_seconds),
                _POST_RECOVERY_REDFISH_READY_TIMEOUT_SECONDS,
            ),
        )
        readiness_delay = max(
            0.0,
            min(float(post_recovery_readiness_retry_delay_seconds), 10.0),
        )
        while True:
            readiness_attempt_count += 1
            try:
                client = factory(host, candidate, policy)
                service_root = client.get_json("/redfish/v1/")
                response = client.get_json("/redfish/v1/Systems")
                state = classify_bmc_auth_state(
                    credential_supplied=True,
                    http_status=int(getattr(response, "status", 200)),
                    credential_kind=candidate.kind,
                )
                if readiness_retry_enabled:
                    receipt = _post_recovery_readiness_receipt(
                        status="READY",
                        reason=(
                            "TRANSIENT_REDFISH_UNAVAILABLE_THEN_READY"
                            if readiness_retry_count
                            else "READY_ON_FIRST_ATTEMPT"
                        ),
                        started=readiness_started,
                        attempt_count=readiness_attempt_count,
                        retry_count=readiness_retry_count,
                        last_retry_reason=readiness_last_retry_reason,
                        timeout_seconds=readiness_timeout,
                    )
                    attempt["post_recovery_readiness"] = receipt
                    result["post_recovery_redfish_readiness"] = receipt
                attempt.update(
                    {
                        "status": "PASS",
                        "http_status": int(getattr(response, "status", 200)),
                        "service_root_http_status": int(getattr(service_root, "status", 200)),
                        "state": state.value,
                    }
                )
                result["attempts"].append(attempt)
                result["state"] = state.value
                result["usable_for_authenticated_get"] = bmc_auth_is_usable(state)
                if result["usable_for_authenticated_get"] and policy.collect_authenticated_get_only:
                    try:
                        discovery = (discovery_factory or _default_discovery_factory)(client)
                        result["authenticated_discovery"] = _drop_sensitive_keys(discovery or {})
                    except Exception as exc:  # discovery is corroborating; auth remains valid
                        result["authenticated_discovery"] = {"status": "FAILED", "error": type(exc).__name__}
                return result
            except Exception as exc:
                retryable_readiness = bool(
                    readiness_retry_enabled
                    and _retryable_post_recovery_readiness_error(exc)
                )
                elapsed = max(0.0, time.monotonic() - readiness_started)
                if retryable_readiness and elapsed < readiness_timeout:
                    readiness_retry_count += 1
                    readiness_last_retry_reason = _post_recovery_readiness_error_reason(exc)
                    remaining = max(0.0, readiness_timeout - elapsed)
                    time.sleep(min(readiness_delay, remaining))
                    continue

                if readiness_retry_enabled:
                    http_status = getattr(exc, "http_status", None)
                    kind = getattr(getattr(exc, "kind", None), "value", str(getattr(exc, "kind", "")))
                    if retryable_readiness:
                        readiness_status = "TIMEOUT"
                        readiness_reason = "BOUNDED_REDFISH_READINESS_TIMEOUT"
                    elif str(kind).upper() == "PASSWORD_CHANGE_REQUIRED":
                        readiness_status = "READY_FOR_FIRST_LOGIN"
                        readiness_reason = (
                            "TRANSIENT_REDFISH_UNAVAILABLE_THEN_PASSWORD_CHANGE_REQUIRED"
                            if readiness_retry_count
                            else "PASSWORD_CHANGE_REQUIRED_ON_FIRST_ATTEMPT"
                        )
                    elif http_status in {401, 403} or str(kind).upper() == "BLOCKED_BY_AUTH":
                        readiness_status = "TERMINAL_RESPONSE"
                        readiness_reason = "EXPLICIT_AUTHENTICATION_REJECTION"
                    else:
                        readiness_status = "TERMINAL_RESPONSE"
                        readiness_reason = (
                            "TRANSIENT_REDFISH_UNAVAILABLE_THEN_RESPONSE"
                            if readiness_retry_count
                            else "NON_RETRYABLE_REDFISH_FAILURE"
                        )
                    receipt = _post_recovery_readiness_receipt(
                        status=readiness_status,
                        reason=readiness_reason,
                        started=readiness_started,
                        attempt_count=readiness_attempt_count,
                        retry_count=readiness_retry_count,
                        last_retry_reason=readiness_last_retry_reason,
                        timeout_seconds=readiness_timeout,
                        terminal_error=exc,
                    )
                    attempt["post_recovery_readiness"] = receipt
                    result["post_recovery_redfish_readiness"] = receipt

                terminal_exc = exc

            # The exception target of an ``except`` clause is cleared by
            # Python after the clause exits.  Retain only the exception object
            # in-process long enough to derive sanitized public evidence.
            assert terminal_exc is not None
            exc = terminal_exc
            http_status = getattr(exc, "http_status", None)
            kind = getattr(getattr(exc, "kind", None), "value", str(getattr(exc, "kind", "")))
            password_change = (
                http_status in policy.password_change_required_statuses
                or str(kind).upper() == "PASSWORD_CHANGE_REQUIRED"
            )
            state = classify_bmc_auth_state(
                credential_supplied=True,
                http_status=http_status,
                password_change_required=password_change,
                credential_kind=candidate.kind,
            )
            attempt.update(
                {
                    "status": "PASSWORD_CHANGE_REQUIRED" if password_change else "UNAVAILABLE",
                    "http_status": http_status,
                    "state": state.value,
                    "error": type(exc).__name__,
                }
            )
            result["attempts"].append(attempt)
            if password_change:
                result["state"] = state.value
                result["usable_for_authenticated_get"] = False
                result["reason"] = "BMC_PASSWORD_CHANGE_REQUIRED"
                if allow_password_provisioning:
                    provisioning = _attempt_password_provisioning(
                        host,
                        candidate,
                        policy,
                        server_id=str(server_id or ""),
                        factory=factory,
                        discovery_factory=discovery_factory or _default_discovery_factory,
                        result=result,
                    )
                    if provisioning:
                        return provisioning
                return result
            break
    result["reason"] = "APPROVED_AUTHENTICATION_UNAVAILABLE"
    return result


def _retryable_post_recovery_readiness_error(exc: Exception) -> bool:
    """Return true only for a credential-independent Redfish readiness gap."""
    if getattr(exc, "http_status", None) is not None:
        return False
    kind = getattr(getattr(exc, "kind", None), "value", str(getattr(exc, "kind", "")))
    return str(kind).upper() in {"TIMEOUT", "TRANSPORT_ERROR"}


def _post_recovery_readiness_error_reason(exc: Exception) -> str:
    kind = getattr(getattr(exc, "kind", None), "value", str(getattr(exc, "kind", "")))
    normalized = str(kind).upper()
    if normalized == "TIMEOUT":
        return "REDFISH_TIMEOUT_WITHOUT_HTTP_STATUS"
    return "REDFISH_TRANSPORT_UNAVAILABLE_WITHOUT_HTTP_STATUS"


def _post_recovery_readiness_receipt(
    *,
    status: str,
    reason: str,
    started: float,
    attempt_count: int,
    retry_count: int,
    last_retry_reason: str,
    timeout_seconds: float,
    terminal_error: Exception | None = None,
) -> dict[str, Any]:
    """Build a secret-free receipt for the bounded post-reset readiness wait."""
    kind = ""
    http_status: int | None = None
    error_name = ""
    if terminal_error is not None:
        kind = str(
            getattr(
                getattr(terminal_error, "kind", None),
                "value",
                str(getattr(terminal_error, "kind", "")),
            )
        ).upper()
        http_status = getattr(terminal_error, "http_status", None)
        error_name = type(terminal_error).__name__
    return {
        "status": str(status),
        "reason": str(reason),
        "attempt_count": max(1, int(attempt_count)),
        "retry_count": max(0, int(retry_count)),
        "elapsed_seconds": round(max(0.0, time.monotonic() - started), 3),
        "timeout_seconds": round(max(0.0, float(timeout_seconds)), 3),
        "retry_policy": "SAME_DEFAULT_ACCOUNT_TRANSPORT_OR_TIMEOUT_WITHOUT_HTTP_STATUS_ONLY",
        "last_retry_reason": str(last_retry_reason or "NONE"),
        "terminal_failure_kind": kind or "NONE",
        "terminal_http_status": http_status,
        "terminal_error": error_name or "NONE",
        "sensitive_material_persisted": False,
    }


def _attempt_password_provisioning(
    host: str,
    candidate: _CredentialCandidate,
    policy: BmcAuthPolicy,
    *,
    server_id: str,
    factory: Callable[..., Any],
    discovery_factory: Callable[[Any], Mapping[str, Any]],
    result: dict[str, Any],
) -> dict[str, Any] | None:
    """Provision a first-login default account when a target secret exists."""
    if not policy.provision_on_password_change or candidate.kind != "DEFAULT":
        return None
    # An operational secret belonging to another server must never become the
    # new password for this BMC.  If there is no exact owner binding, generate
    # a fresh per-server secret only after the documented first-login state is
    # positively identified.
    new_password, new_source = _bound_operational_secret(policy, server_id)
    generated_secret = False
    configured_first_login_secret = False
    if not new_password:
        # A site-approved first-login target is considered only after the
        # documented DEFAULT/password-change response. It is never a general
        # credential candidate. On success it is copied to the bound,
        # per-server operational secret for resume/task polling.
        new_password, new_source = _secret(
            policy.first_login_password_env,
            policy.first_login_password_file,
        )
        configured_first_login_secret = bool(new_password)
    if not new_password:
        # A fresh ASUS BMC may require the first-login password change while
        # the cloned SSD has no pre-seeded operational secret. Generate a
        # per-run secret into the existing root-only secret path so the
        # authenticated lifecycle can continue without exposing a shared
        # password. The final factory/default handoff removes it again.
        try:
            new_password = _generate_operational_secret(policy.provisioned_password_file)
            new_source = "generated:root-only-file"
            generated_secret = True
        except OSError:
            result["provisioning"] = {
                "status": "NOT_ATTEMPTED",
                "reason": "OPERATIONAL_SECRET_UNAVAILABLE",
                "account_path": policy.provision_account_path,
                "sensitive_material_persisted": False,
            }
            return None
    if new_password == candidate.password:
        result["provisioning"] = {
            "status": "NOT_ATTEMPTED",
            "reason": "NO_DISTINCT_TARGET_SECRET",
            "account_path": policy.provision_account_path,
            "sensitive_material_persisted": False,
        }
        return None
    public = {
        "status": "ATTEMPTED",
        "account_path": policy.provision_account_path,
        "source": new_source.split(":", 1)[0],
        "sensitive_material_persisted": False,
        "mutation_scope": "ACCOUNT_4_PASSWORD_ONLY",
    }
    try:
        provisioned = _provision_with_bounded_retry(
            host,
            candidate.username,
            candidate.password,
            new_password,
            verify_tls=policy.verify_tls,
            account_path=policy.provision_account_path,
        )
        public.update(provisioned.to_dict())
        public["status"] = "PROVISIONED"
    except (BmcProvisioningError, ValueError) as exc:
        if generated_secret:
            try:
                policy.provisioned_password_file.unlink(missing_ok=True)
            except OSError:
                pass
        # Keep the failure actionable without ever persisting exception text,
        # response bodies, or credential material.  The provisioning adapter
        # exposes only a bounded stage and HTTP status.
        public.update(
            {
                "status": "FAILED",
                "error": type(exc).__name__,
                "stage": str(getattr(exc, "stage", "UNKNOWN")),
                "http_status": getattr(exc, "http_status", None),
            }
        )
        result["provisioning"] = public
        return None
    # Re-authenticate through the normal GET-only adapter and collect the
    # complete corroborating discovery using the newly provisioned secret.
    replacement = _CredentialCandidate("PROVISIONED", candidate.username, new_password, new_source)
    try:
        client = factory(host, replacement, policy)
        service_root = client.get_json("/redfish/v1/")
        systems = client.get_json("/redfish/v1/Systems")
        state = classify_bmc_auth_state(
            credential_supplied=True,
            http_status=int(getattr(systems, "status", 200)),
            credential_kind="PROVISIONED",
        )
        attempt = {
            "account": replacement.public(),
            "endpoint": "/redfish/v1/Systems",
            "service_root_endpoint": "/redfish/v1/",
            "method": "GET",
            "status": "PASS",
            "http_status": int(getattr(systems, "status", 200)),
            "service_root_http_status": int(getattr(service_root, "status", 200)),
            "state": state.value,
        }
        result["attempts"].append(attempt)
        result["state"] = state.value
        result["reason"] = "BMC_PASSWORD_PROVISIONED"
        result["usable_for_authenticated_get"] = bmc_auth_is_usable(state)
        if result["usable_for_authenticated_get"] and policy.collect_authenticated_get_only:
            try:
                discovery = discovery_factory(client)
                result["authenticated_discovery"] = _drop_sensitive_keys(discovery or {})
            except Exception as exc:
                result["authenticated_discovery"] = {"status": "FAILED", "error": type(exc).__name__}
        if not result["usable_for_authenticated_get"]:
            public["status"] = "FAILED"
            public["reason"] = "POST_PROVISION_AUTHENTICATION_UNUSABLE"
            result["provisioning"] = public
            return result
        if configured_first_login_secret and not _write_secret_atomic(policy.provisioned_password_file, new_password):
            public["status"] = "PROVISIONED_SECRET_PERSISTENCE_FAILED"
            public["reason"] = "OPERATIONAL_SECRET_UNAVAILABLE"
            result["provisioning"] = public
            result["state"] = BmcAuthState.BMC_AUTH_UNAVAILABLE.value
            result["usable_for_authenticated_get"] = False
            return result
        if not write_provisioned_account_binding(policy, server_id):
            # The password mutation may already have succeeded, so preserve
            # that fact for the mandatory final handoff.  The unbound secret
            # is intentionally unusable on any subsequent path, including a
            # post-reboot resume, rather than being tried against a different
            # physical server.
            public["status"] = "PROVISIONED_BINDING_FAILED"
            public["operational_account_binding"] = {
                "status": "FAILED",
                "server_identity_bound": False,
                "sensitive_material_persisted": False,
            }
            result["provisioning"] = public
            result["state"] = BmcAuthState.BMC_AUTH_UNAVAILABLE.value
            result["usable_for_authenticated_get"] = False
            result["reason"] = "BMC_OPERATIONAL_ACCOUNT_BINDING_FAILED"
            return result
        public["operational_account_binding"] = {
            "status": "PASS",
            "server_identity_bound": True,
            "sensitive_material_persisted": False,
        }
        result["provisioning"] = public
        return result
    except Exception as exc:
        result["provisioning"] = public
        result["provisioning"]["post_provision_authentication"] = "FAILED"
        result["provisioning"]["post_provision_error"] = type(exc).__name__
        return result


def _generate_operational_secret(path: Path) -> str:
    """Create a temporary root-only secret without returning it publicly."""
    # ASMB11/ASMB12 firmware generations commonly enforce the IPMI account
    # password ceiling (20 characters) even though Redfish does not advertise
    # that limit consistently.  A URL-safe 32-byte token is 43 characters and
    # is therefore rejected by some first-login implementations.  ASMB11 also
    # rejects otherwise-valid Redfish passwords containing punctuation on the
    # first-login path, so use the conservative cross-generation alphanumeric
    # subset.  The secret remains per-run and is removed by the final BMC
    # factory/default handoff.
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    required = [
        secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ"),
        secrets.choice("abcdefghijkmnopqrstuvwxyz"),
        secrets.choice("23456789"),
    ]
    required.extend(secrets.choice(alphabet) for _ in range(13))
    secrets.SystemRandom().shuffle(required)
    value = "".join(required)
    if not _write_secret_atomic(path, value):
        raise OSError("unable to persist operational secret")
    return value


def _write_secret_atomic(path: Path, value: str) -> bool:
    """Persist a secret with root-only permissions and atomic publication."""
    parent = Path(path).parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(parent, 0o700)
    except OSError:
        pass
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=Path(path).name + ".", suffix=".tmp", dir=parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(str(value).strip() + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, path)
        return True
    except (OSError, ValueError):
        try:
            Path(temporary_name).unlink(missing_ok=True)
        except OSError:
            pass
        return False


def _provision_with_bounded_retry(
    host: str,
    username: str,
    current_password: str,
    new_password: str,
    *,
    verify_tls: bool,
    account_path: str,
    attempts: int = 5,
    retry_delay_seconds: float = 2.0,
) -> Any:
    """Retry only the same approved first-login PATCH while Redfish restarts.

    ASUS ASMB11/ASMB12 can expose KCS immediately after factory recovery while
    the HTTPS account service is still restarting.  A bounded retry avoids
    misclassifying that readiness window as an authentication failure.  No
    alternate credential, account, endpoint or password is attempted.
    """
    last_error: BmcProvisioningError | None = None
    for index in range(max(1, int(attempts))):
        try:
            return provision_bmc_password(
                host,
                username,
                current_password,
                new_password,
                verify_tls=verify_tls,
                account_path=account_path,
            )
        except BmcProvisioningError as exc:
            last_error = exc
            status = getattr(exc, "http_status", None)
            transient_stage = str(getattr(exc, "stage", "")).startswith((
                "ACCOUNT_GET", "ACCOUNT_PATCH", "POST_PROVISION_SYSTEMS"
            ))
            transient_status = status is None or status in {400, 401, 403, 404, 409, 412, 429, 500, 502, 503, 504}
            if index + 1 >= max(1, int(attempts)) or not (transient_stage and transient_status):
                raise
            time.sleep(max(0.2, min(float(retry_delay_seconds), 5.0)))
    if last_error is not None:
        raise last_error
    raise BmcProvisioningError("ACCOUNT_PROVISION_RETRY_EXHAUSTED")


def server_seen_before(primary_root: Path, server_id: str, *, exclude_run_id: str = "") -> bool:
    """Treat a server as known only from local authoritative run records."""
    needle = str(server_id or "")
    if not needle:
        return False
    runs_root = Path(primary_root) / "runs"
    try:
        for path in runs_root.glob("RUN-*/run.json"):
            if exclude_run_id and path.parent.name == str(exclude_run_id):
                continue
            try:
                import json

                payload = json.loads(path.read_text(encoding="utf-8"))
                server = payload.get("server") if isinstance(payload, dict) else None
                if isinstance(server, dict) and str(server.get("server_id") or "") == needle:
                    return True
                run = payload.get("run") if isinstance(payload, dict) else None
                if isinstance(run, dict) and str(run.get("server_id") or "") == needle:
                    return True
            except (OSError, ValueError, TypeError):
                continue
    except OSError:
        return False
    return False


def _candidates(
    policy: BmcAuthPolicy,
    seen_before: bool,
    *,
    server_id: str = "",
    allow_default_probe_after_recovery: bool = False,
    allow_default_probe_after_observed_first_login: bool = False,
    ignore_provisioned_candidates: bool = False,
) -> list[_CredentialCandidate]:
    values: list[_CredentialCandidate] = []
    provisioned_username = ""
    provisioned_password = ""
    provisioned_source = ""
    if not ignore_provisioned_candidates:
        provisioned_username = policy.provisioned_username or os.environ.get(policy.provisioned_username_env, "").strip()
        provisioned_password, provisioned_source = _bound_operational_secret(policy, server_id)
    # A generated first-login secret is intentionally stored without a
    # username-bearing file.  The only account that the bounded provisioning
    # path can mutate is the documented default account, so use the policy's
    # default username when a root-only operational secret exists but no
    # explicit username was configured.  This keeps post-provision Redfish,
    # task polling, and resume on the same in-process credential instead of
    # silently losing access after the first boot.
    if provisioned_password and not provisioned_username:
        provisioned_username = policy.default_username
    if provisioned_username and provisioned_password:
        values.append(_CredentialCandidate("PROVISIONED", provisioned_username, provisioned_password, provisioned_source))
        # ASUS BMC generations vary the administrator account spelling
        # (``admin`` versus ``Administrator``), including after a firmware
        # lifecycle. Try at most one deterministic alias with the *same
        # approved provisioned secret*. This is not password enumeration and
        # keeps the existing bounded, credential-safe policy intact.
        if provisioned_username.casefold() in {"admin", "administrator"}:
            alias = "Administrator" if provisioned_username.casefold() == "admin" else "admin"
            if alias.casefold() != provisioned_username.casefold():
                values.append(
                    _CredentialCandidate(
                        "PROVISIONED_ADMIN_ALIAS",
                        alias,
                        provisioned_password,
                        provisioned_source,
                    )
                )
    allow_default = policy.default_probe_enabled and policy.mode in {"AUTO_NEW_SERVER", "NEW_SERVER_ONLY"}
    if allow_default and (
        not seen_before
        or allow_default_probe_after_recovery
        # This override is deliberately narrower than a history bypass: the
        # caller has just observed the documented factory account's
        # PasswordChangeRequired response from this current BMC endpoint.
        # It permits one continuation of that exact first-login exchange,
        # never a credential list or a blind default-password probe.
        or allow_default_probe_after_observed_first_login
    ):
        default_password, default_source = _secret(policy.default_password_env, policy.default_password_file)
        if default_password:
            values.append(_CredentialCandidate("DEFAULT", policy.default_username, default_password, default_source))
    # Normal discovery is limited to the provisioned credential plus one
    # deterministic administrator alias.  The recovery override may append
    # the single documented factory credential as a third bounded candidate;
    # it is still not password enumeration.
    return values[:3]


def runtime_credential_candidates(
    policy: BmcAuthPolicy,
    *,
    server_id: str = "",
    allow_default_if_discovered: bool = False,
) -> tuple[tuple[str, str, str], ...]:
    """Return approved runtime credential tuples for an authenticated GET.

    The secret is returned only to an in-process capability adapter and is
    never serialized, logged, or included in a public result.  The bounded
    candidate set is exactly the same provisioned/default policy used by
    :func:`discover_bmc_auth`; no password enumeration is introduced.  The
    documented factory credential is included only when the caller has just
    recorded a successful bounded ``DEFAULT`` discovery for this same run.
    A
    provisioned candidate is available only when its root-only, secret-free
    server binding exactly matches ``server_id``.  An omitted or mismatched
    ID fails closed instead of reusing a credential from another server.
    """
    return tuple(
        (item.username, item.password, item.kind)
        for item in _candidates(
            policy,
            seen_before=True,
            server_id=server_id,
            allow_default_probe_after_recovery=allow_default_if_discovered,
        )
    )


def write_provisioned_account_binding(policy: BmcAuthPolicy, server_id: str) -> bool:
    """Atomically bind a temporary operational BMC account to one server.

    This record authorizes *use* of a separately stored secret; it never
    contains or derives that secret.  Call it only after an authenticated
    first-login provisioning has completed successfully.
    """
    owner = str(server_id or "").strip()
    if not owner:
        return False
    path = policy.provisioned_account_binding_path
    parent = path.parent
    descriptor: int | None = None
    temporary_name = ""
    try:
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(parent, 0o700)
        except OSError:
            pass
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=path.name + ".", suffix=".tmp", dir=parent
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = None
            json.dump(
                {
                    "schema_version": 1,
                    "scope": "CN_SERVEROPS_TEMPORARY_BMC_OPERATIONAL_ACCOUNT",
                    "server_id": owner,
                    "sensitive_material_persisted": False,
                },
                stream,
                sort_keys=True,
                separators=(",", ":"),
            )
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, path)
        return _provisioned_account_bound_to_server(policy, owner)
    except (OSError, TypeError, ValueError):
        return False
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temporary_name:
            temporary = Path(temporary_name)
            try:
                if temporary.exists():
                    temporary.unlink()
            except OSError:
                pass


def clear_provisioned_account_binding(policy: BmcAuthPolicy) -> None:
    """Remove only the secret-free operational-account ownership record."""
    try:
        policy.provisioned_account_binding_path.unlink(missing_ok=True)
    except OSError:
        pass


def provisioned_account_binding_matches(policy: BmcAuthPolicy, server_id: str) -> bool:
    """Public, credential-free binding check for lifecycle guards/tests."""
    return _provisioned_account_bound_to_server(policy, server_id)


def _bound_operational_secret(policy: BmcAuthPolicy, server_id: str) -> tuple[str, str]:
    """Read a temporary secret only after its owner binding validates."""
    if not _provisioned_account_bound_to_server(policy, server_id):
        # In particular, a legacy secret with no binding must never be tried
        # against a freshly detected server.
        return "", "UNBOUND_OR_MISMATCHED_SERVER"
    return _secret(policy.provisioned_password_env, policy.provisioned_password_file)


def _provisioned_account_bound_to_server(policy: BmcAuthPolicy, server_id: str) -> bool:
    owner = str(server_id or "").strip()
    if not owner:
        return False
    path = policy.provisioned_account_binding_path
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        # Windows ACLs do not map reliably to POSIX mode bits.  The production
        # SSD is Linux and enforces 0600; test/development Windows hosts still
        # need to be able to exercise the binding logic without treating an
        # ACL-managed file as world-readable.
        if os.name != "nt" and mode & 0o077:
            return False
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return False
    if not isinstance(payload, Mapping):
        return False
    return (
        int(payload.get("schema_version") or 0) == 1
        and str(payload.get("scope") or "") == "CN_SERVEROPS_TEMPORARY_BMC_OPERATIONAL_ACCOUNT"
        and str(payload.get("server_id") or "").strip() == owner
        and payload.get("sensitive_material_persisted") is False
    )


def _secret(env_name: str, file_path: Path) -> tuple[str, str]:
    value = os.environ.get(str(env_name or ""), "") if env_name else ""
    if value:
        return value, f"environment:{env_name}"
    try:
        mode = stat.S_IMODE(file_path.stat().st_mode)
        # Windows ACLs do not map to POSIX mode bits. The production SSD is
        # Linux and enforces 0600; Windows unit fixtures rely on ACLs instead.
        if os.name != "nt" and mode & 0o077:
            return "", "REJECTED_INSECURE_FILE_PERMISSIONS"
        value = file_path.read_text(encoding="utf-8").strip()
    except OSError:
        return "", "NONE"
    return (value, f"root-only-file:{file_path}") if value else ("", "NONE")


def _default_redfish_factory(host: str, candidate: _CredentialCandidate, policy: BmcAuthPolicy) -> Any:
    from cndellops_asus.redfish import ReadOnlyRedfishClient, RedfishCredentials

    return ReadOnlyRedfishClient(
        host,
        credentials=RedfishCredentials(username=candidate.username, password=candidate.password, source=candidate.source),
        verify_tls=policy.verify_tls,
        timeout_seconds=20,
    )


def _default_discovery_factory(client: Any) -> Mapping[str, Any]:
    from cndellops_asus.asus import AsusDiscoveryAdapter

    discovery = AsusDiscoveryAdapter(client).discover()
    # Keep the full sanitized discovery useful for capability evidence while
    # making the mutation boundary explicit in the persisted record.
    discovery["safety"] = {**dict(discovery.get("safety") or {}), "mutation_authorized": False}
    return discovery


_SENSITIVE_NAME = re.compile(
    r"(^|[_ .-])(password|passwd|credential|secret|token|authorization|cookie|private[_ -]?key|api[_ -]?key|community[_ -]?string)($|[_ .-])",
    re.IGNORECASE,
)


def _drop_sensitive_keys(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _drop_sensitive_keys(item) for key, item in value.items() if not _SENSITIVE_NAME.search(str(key))}
    if isinstance(value, list):
        return [_drop_sensitive_keys(item) for item in value]
    return value
