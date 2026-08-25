"""Explicit overall-result and handoff-policy evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


PASS_STATES = frozenset(
    {"PASS", "SUCCESS", "CURRENT", "UPDATED_VERIFIED", "NOT_PRESENT", "NOT_REQUIRED", "ONLINE", "SYNCED", "LOCAL_COMPLETE"}
)
FAIL_STATES = frozenset({"FAIL", "FAILED", "BLOCKED", "NOT_READY", "HARDWARE_FAILURE", "UPDATE_REQUIRED"})
REVIEW_STATES = frozenset(
    {
        "REVIEW",
        "BLOCKED_BY_AUTH",
        "UNVERIFIED",
        "NOT_SUPPORTED",
        "UNSUPPORTED",
        "EXECUTION_FAILED",
        "NOT_TESTED",
        "PARTIAL",
        "PENDING_UPLOAD",
        "UPLOAD_FAILED",
    }
)

# These fields are outputs of this evaluator rather than independently
# measured capabilities.  A final evaluation routinely receives the result
# object from an earlier provisional evaluation after reports and artifact
# delivery have been added.  Re-evaluating a stale ``REVIEW`` in one of these
# fields would otherwise make the earlier aggregate decision self-fulfilling.
_DERIVED_STATUS_FIELDS = frozenset({"overall", "handoff_status", "readiness"})


def normalized_status(value: Any) -> str:
    return str(value or "UNKNOWN").strip().upper().replace(" ", "_")


@dataclass(frozen=True)
class HandoffPolicy:
    required_pass: tuple[str, ...] = (
        "collection",
        "serial_inventory",
        "identity",
        "storage",
        "nic",
        "sensors",
    )
    required_for_production: tuple[str, ...] = ("cpu", "ram")
    optional_review_states: Mapping[str, tuple[str, ...]] = field(
        default_factory=lambda: {
            "firmware_update": ("BLOCKED_BY_AUTH", "UNVERIFIED", "NOT_SUPPORTED", "NOT_PRESENT", "CURRENT"),
            "system_diagnostics": (
                "BLOCKED_BY_AUTH",
                "UNVERIFIED",
                "NOT_SUPPORTED",
                "UNSUPPORTED",
                "PLATFORM_UNSUPPORTED",
                "EXECUTION_FAILED",
            ),
            "bmc_soft_reset": ("UNVERIFIED", "NOT_SUPPORTED", "NOT_PERFORMED"),
            "bmc_access_state": (
                "BMC_AUTH_AVAILABLE",
                "BMC_AUTH_PROVISIONED",
                "BMC_AUTH_UNAVAILABLE",
                "BMC_AUTH_REQUIRES_PASSWORD_CHANGE",
            ),
            "runner_storage_smart": ("UNAVAILABLE", "UNKNOWN_USB_BRIDGE", "NOT_PERFORMED"),
            "central_link": ("OFFLINE", "PENDING_UPLOAD", "UPLOAD_FAILED"),
        }
    )
    allow_optional_review_for_ready: bool = False

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> "HandoffPolicy":
        payload = dict(value or {})
        defaults = cls()
        optional = payload.get("optional_review_states")
        return cls(
            required_pass=tuple(str(item) for item in payload.get("required_pass", defaults.required_pass)),
            required_for_production=tuple(
                str(item) for item in payload.get("required_for_production", defaults.required_for_production)
            ),
            optional_review_states={
                str(key): tuple(normalized_status(item) for item in values)
                for key, values in (optional.items() if isinstance(optional, Mapping) else defaults.optional_review_states.items())
            },
            allow_optional_review_for_ready=bool(payload.get("allow_optional_review_for_ready", False)),
        )


def evaluate_handoff(
    component_statuses: Mapping[str, Any],
    *,
    workflow_mode: str,
    policy: HandoffPolicy | None = None,
    bmc_auth_changed: bool = False,
    bmc_handoff_status: str = "NOT_REQUIRED",
) -> dict[str, Any]:
    policy = policy or HandoffPolicy()
    # Counters, booleans, and nested evidence are report data, not capability
    # states.  Treating values such as ``sel_entries: 0`` as UNKNOWN would
    # manufacture a handoff review unrelated to the actual SEL status.
    statuses = {
        str(key): normalized_status(value)
        for key, value in component_statuses.items()
        if isinstance(value, str) and str(key).strip().lower() not in _DERIVED_STATUS_FIELDS
    }
    required = list(policy.required_pass)
    if normalized_status(workflow_mode) not in {"DRY_RUN", "SERIAL_COLLECTION", "INVENTORY_ONLY"}:
        required.extend(policy.required_for_production)

    failures: list[dict[str, str]] = []
    reviews: list[dict[str, str]] = []
    for capability, status in statuses.items():
        if status in FAIL_STATES:
            failures.append({"capability": capability, "status": status})
        elif status in REVIEW_STATES or status not in PASS_STATES:
            reviews.append({"capability": capability, "status": status})
    # A CNServerOps-owned BMC authentication change is never an optional capability.  It
    # must be removed through the official factory/default handoff before a
    # server can be released, regardless of otherwise healthy hardware.
    if bmc_auth_changed:
        handoff_status = normalized_status(bmc_handoff_status)
        # Keep the public capability name free of secret-bearing field names.
        # This is metadata about the handoff state, not the credential itself.
        statuses["bmc_auth_handoff"] = handoff_status
        if handoff_status not in PASS_STATES:
            if handoff_status in FAIL_STATES:
                failures.append({"capability": "bmc_auth_handoff", "status": handoff_status})
            else:
                reviews.append({"capability": "bmc_auth_handoff", "status": handoff_status})
        elif "bmc_auth_handoff" in {item["capability"] for item in reviews}:
            reviews = [item for item in reviews if item["capability"] != "bmc_auth_handoff"]
    missing_or_unready = [
        {"capability": name, "status": statuses.get(name, "MISSING")}
        for name in required
        if statuses.get(name) not in PASS_STATES
    ]
    for item in missing_or_unready:
        if item not in failures and item not in reviews:
            reviews.append(item)

    if failures:
        overall = "FAIL"
    elif reviews:
        overall = "REVIEW"
    else:
        overall = "PASS"

    optional_only = bool(reviews) and not missing_or_unready and all(
        item["capability"] in policy.optional_review_states
        and item["status"] in policy.optional_review_states[item["capability"]]
        for item in reviews
    )
    if failures or missing_or_unready:
        handoff = "NOT_READY" if failures else "REVIEW_REQUIRED"
    elif not reviews:
        handoff = "READY_FOR_HANDOFF"
    elif optional_only and policy.allow_optional_review_for_ready:
        handoff = "READY_FOR_HANDOFF"
    else:
        handoff = "REVIEW_REQUIRED"
    if optional_only and policy.allow_optional_review_for_ready and not failures and not missing_or_unready:
        # Capability metadata (BMC auth, unused firmware transport, optional
        # diagnostics, runner SMART) remains visible in ``reviews`` but does
        # not downgrade a physically healthy production server.
        overall = "PASS"
    return {
        "schema_version": 1,
        "workflow_mode": normalized_status(workflow_mode),
        "overall": overall,
        "handoff_status": handoff,
        "component_statuses": statuses,
        "failures": failures,
        "reviews": reviews,
        "required_capabilities": required,
        "policy": {
            "allow_optional_review_for_ready": policy.allow_optional_review_for_ready,
            "optional_review_states": {key: list(values) for key, values in policy.optional_review_states.items()},
            "bmc_auth_changed": bool(bmc_auth_changed),
            "bmc_handoff_status": normalized_status(bmc_handoff_status),
        },
    }
