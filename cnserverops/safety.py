"""Explicit mutation authorization shared by update, cleanup, and reset engines."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping


class MutationBlockedError(RuntimeError):
    """A state-changing operation was not explicitly and safely authorized."""


@dataclass(frozen=True)
class MutationGate:
    authorized: bool = False
    lab_mode: bool = False
    approval_id: str = ""
    machine_fingerprint_sha256: str = ""
    vendor: str = ""
    model: str = ""
    system_serial: str = ""
    run_id: str = ""
    component: str = ""
    target_version: str = ""
    package_sha256: str = ""
    allowed_actions: frozenset[str] = field(default_factory=frozenset)
    expires_at_utc: str = ""

    def require(
        self,
        action: str,
        identity: Mapping[str, Any],
        *,
        context: Mapping[str, Any] | None = None,
    ) -> None:
        if not self.authorized or not self.lab_mode:
            raise MutationBlockedError("Mutation gate is closed; explicit lab authorization is required.")
        if not self.approval_id:
            raise MutationBlockedError("Mutation approval identifier is missing.")
        if action not in self.allowed_actions:
            raise MutationBlockedError(f"Mutation action is outside the approved scope: {action}")
        fingerprint = str(identity.get("fingerprint_sha256") or "")
        if not fingerprint or fingerprint != self.machine_fingerprint_sha256:
            raise MutationBlockedError("Mutation gate is bound to a different or weak machine identity.")
        if not bool(identity.get("mutation_eligible")):
            raise MutationBlockedError("Platform identity is not mutation-eligible.")
        bindings = {
            "vendor": (self.vendor, str(identity.get("vendor") or "")),
            "model": (self.model, str(identity.get("model") or "")),
            "system serial": (
                self.system_serial,
                str(identity.get("primary_serial") or identity.get("system_serial") or ""),
            ),
        }
        supplied_context = dict(context or {})
        bindings.update(
            {
                "RUN_ID": (self.run_id, str(supplied_context.get("run_id") or "")),
                "component": (self.component, str(supplied_context.get("component") or "")),
                "target version": (self.target_version, str(supplied_context.get("target_version") or "")),
                "package SHA256": (self.package_sha256, str(supplied_context.get("package_sha256") or "")),
            }
        )
        for label, (expected, observed) in bindings.items():
            if expected and expected.upper() != observed.upper():
                raise MutationBlockedError(f"Mutation gate {label} binding does not match the live operation.")
        if self.expires_at_utc:
            try:
                expiry = datetime.fromisoformat(self.expires_at_utc.replace("Z", "+00:00"))
            except ValueError as exc:
                raise MutationBlockedError("Mutation gate expiry is invalid.") from exc
            if expiry <= datetime.now(timezone.utc):
                raise MutationBlockedError("Mutation gate has expired.")

    def public_record(self) -> dict[str, Any]:
        """Return non-secret approval metadata suitable for evidence."""
        return {
            "authorized": self.authorized,
            "lab_mode": self.lab_mode,
            "approval_id": self.approval_id,
            "machine_fingerprint_sha256": self.machine_fingerprint_sha256,
            "vendor": self.vendor,
            "model": self.model,
            "system_serial": self.system_serial,
            "run_id": self.run_id,
            "component": self.component,
            "target_version": self.target_version,
            "package_sha256": self.package_sha256,
            "allowed_actions": sorted(self.allowed_actions),
            "expires_at_utc": self.expires_at_utc,
        }


CLOSED_MUTATION_GATE = MutationGate()
