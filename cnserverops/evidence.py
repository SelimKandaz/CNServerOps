"""Provenance-, freshness-, and capability-aware evidence fusion."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable


class EvidenceFreshness(str, Enum):
    CURRENT_BOOT = "CURRENT_BOOT"
    LIVE_SENSOR = "LIVE_SENSOR"
    STATIC_FRU = "STATIC_FRU"
    BMC_CURRENT_CONFIRMED = "BMC_CURRENT_CONFIRMED"
    BMC_FRESHNESS_UNKNOWN = "BMC_FRESHNESS_UNKNOWN"
    STALE_SUSPECTED = "STALE_SUSPECTED"
    CONFLICTING = "CONFLICTING"


class EvidenceConfidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class BmcAuthState(str, Enum):
    BMC_AUTH_AVAILABLE = "BMC_AUTH_AVAILABLE"
    # A successful GET with the documented factory/default account is useful
    # evidence, but it is deliberately distinct from a provisioned account.
    BMC_AUTH_DEFAULT_AVAILABLE = "BMC_AUTH_DEFAULT_AVAILABLE"
    # A first-login policy may allow authentication only after the operator
    # changes the password.  This is not a global run blocker.
    BMC_PASSWORD_CHANGE_REQUIRED = "BMC_PASSWORD_CHANGE_REQUIRED"
    # Backward-compatible member name retained for existing evidence/tests.
    BMC_AUTH_REQUIRES_PASSWORD_CHANGE = "BMC_PASSWORD_CHANGE_REQUIRED"
    BMC_AUTH_PROVISIONED = "BMC_AUTH_PROVISIONED"
    BMC_AUTH_UNAVAILABLE = "BMC_AUTH_UNAVAILABLE"


class CapabilityAccess(str, Enum):
    AVAILABLE_LOCAL = "AVAILABLE_LOCAL"
    AVAILABLE_BMC = "AVAILABLE_BMC"
    AVAILABLE_LOCAL_WITH_BMC_CORROBORATION = "AVAILABLE_LOCAL_WITH_BMC_CORROBORATION"
    BLOCKED_BY_AUTH = "BLOCKED_BY_AUTH"
    NOT_SUPPORTED = "NOT_SUPPORTED"


def classify_bmc_auth_state(
    *,
    credential_supplied: bool,
    http_status: int | None = None,
    password_change_required: bool = False,
    credential_kind: str = "PROVISIONED",
) -> BmcAuthState:
    """Normalize an auth probe without treating credential failure as server failure."""
    if password_change_required:
        return BmcAuthState.BMC_PASSWORD_CHANGE_REQUIRED
    if credential_supplied and http_status is not None and 200 <= http_status < 300:
        if str(credential_kind or "").strip().upper() == "DEFAULT":
            return BmcAuthState.BMC_AUTH_DEFAULT_AVAILABLE
        return BmcAuthState.BMC_AUTH_PROVISIONED
    return BmcAuthState.BMC_AUTH_UNAVAILABLE


def bmc_auth_is_usable(state: BmcAuthState | str) -> bool:
    """Return whether authenticated BMC GET-only capabilities may be used."""
    value = state.value if isinstance(state, BmcAuthState) else str(state or "")
    return value in {
        BmcAuthState.BMC_AUTH_AVAILABLE.value,
        BmcAuthState.BMC_AUTH_DEFAULT_AVAILABLE.value,
        BmcAuthState.BMC_AUTH_PROVISIONED.value,
    }


@dataclass(frozen=True)
class FieldObservation:
    value: str
    source: str
    freshness: EvidenceFreshness
    confidence: EvidenceConfidence
    current_local: bool = False
    bmc_derived: bool = False

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["freshness"] = self.freshness.value
        payload["confidence"] = self.confidence.value
        return payload


def read_linux_boot_id(path: Path = Path("/proc/sys/kernel/random/boot_id")) -> str:
    """Read the current Linux boot ID without treating it as machine identity."""
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""
    return value if len(value) == 36 else ""


def fuse_field(field: str, observations: Iterable[FieldObservation]) -> dict[str, Any]:
    """Prefer current/local evidence and preserve disagreements instead of overwriting it."""
    usable = [item for item in observations if str(item.value or "").strip()]
    current = [item for item in usable if item.current_local]
    static = [item for item in usable if not item.current_local and not item.bmc_derived]
    bmc = [item for item in usable if item.bmc_derived]
    preferred = current or static or bmc
    selected = preferred[0] if preferred else None

    trusted_values = {_key(item.value) for item in current + static}
    bmc_values = {_key(item.value) for item in bmc}
    local_conflict = len(trusted_values) > 1
    bmc_conflict = bool(trusted_values and bmc_values and trusted_values.isdisjoint(bmc_values))
    reason_codes: list[str] = []
    if local_conflict:
        reason_codes.append("LOCAL_EVIDENCE_CONFLICT")
    if bmc_conflict:
        reason_codes.extend(["BMC_INVENTORY_CONFLICT", "POSSIBLE_STALE_BMC_DATA"])

    confidence = selected.confidence.value if selected else EvidenceConfidence.UNKNOWN.value
    freshness = selected.freshness.value if selected else EvidenceFreshness.CONFLICTING.value
    if local_conflict:
        confidence = EvidenceConfidence.LOW.value
        freshness = EvidenceFreshness.CONFLICTING.value

    return {
        "field": field,
        "value": selected.value if selected else "",
        "source": selected.source if selected else "NONE",
        "freshness": freshness,
        "confidence": confidence,
        "observations": [item.to_dict() for item in usable],
        "local_conflict": local_conflict,
        "bmc_conflict": bmc_conflict,
        "reason_codes": reason_codes,
        "bmc_value_authoritative_for_mutation": bool(bmc and not bmc_conflict and not trusted_values),
    }


def resolve_capability_access(
    capability: str,
    *,
    bmc_auth_state: BmcAuthState,
    verified_local_mechanism: str = "",
    verified_bmc_mechanism: str = "",
    bmc_corroboration_available: bool = False,
) -> dict[str, Any]:
    """Resolve one capability without making BMC authentication a global gate."""
    if verified_local_mechanism:
        access = (
            CapabilityAccess.AVAILABLE_LOCAL_WITH_BMC_CORROBORATION
            if bmc_auth_is_usable(bmc_auth_state) and bmc_corroboration_available
            else CapabilityAccess.AVAILABLE_LOCAL
        )
        mechanism = verified_local_mechanism
        blocked_by_auth = False
    elif verified_bmc_mechanism and bmc_auth_is_usable(bmc_auth_state):
        access = CapabilityAccess.AVAILABLE_BMC
        mechanism = verified_bmc_mechanism
        blocked_by_auth = False
    elif verified_bmc_mechanism:
        access = CapabilityAccess.BLOCKED_BY_AUTH
        mechanism = ""
        blocked_by_auth = True
    else:
        access = CapabilityAccess.NOT_SUPPORTED
        mechanism = ""
        blocked_by_auth = False
    return {
        "capability": capability,
        "status": access.value,
        "selected_mechanism": mechanism,
        "bmc_auth_state": bmc_auth_state.value,
        "blocked_by_auth": blocked_by_auth,
        "overall_run_blocked": False,
    }


def _key(value: str) -> str:
    return " ".join(str(value).strip().upper().split())
