"""Normalized capability records with explicit validation maturity."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Mapping

from .evidence import BmcAuthState, resolve_capability_access


class ValidationLevel(str, Enum):
    DISCOVERED = "DISCOVERED"
    DETECTED = "DETECTED"
    IMPLEMENTED = "IMPLEMENTED"
    SIMULATED = "SIMULATED"
    PARTIALLY_LAB_VERIFIED = "PARTIALLY_LAB_VERIFIED"
    LAB_VERIFIED = "LAB_VERIFIED"
    PRODUCTION_VERIFIED = "PRODUCTION_VERIFIED"
    BLOCKED_BY_AUTH = "BLOCKED_BY_AUTH"
    BLOCKED_BY_MISSING_ENDPOINT = "BLOCKED_BY_MISSING_ENDPOINT"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class CapabilityRecord:
    capability: str
    mechanism_used: str
    raw_command_api: str
    raw_evidence: str
    normalized_result: Any
    supported_model: str
    failure_behavior: str
    timeout_behavior: str
    fallback: str
    validation_level: ValidationLevel
    safe_for_production: bool

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["validation_level"] = self.validation_level.value
        return payload


@dataclass(frozen=True)
class CapabilitySourcePolicy:
    capability: str
    preferred_sources: tuple[str, ...]
    authenticated_bmc_may_be_required: bool
    freshness_rule: str


ASUS_CAPABILITY_SOURCE_POLICIES = (
    CapabilitySourcePolicy("identity", ("DMI_SMBIOS", "IPMI_FRU_LOCAL_KCS", "REDFISH_SYSTEM"), False, "Prefer matching current-boot DMI and static local FRU; never replace them with conflicting BMC data."),
    CapabilitySourcePolicy("firmware_inventory", ("DMI_BIOS", "IPMI_MC", "REDFISH_FIRMWARE_INVENTORY"), False, "Record per-component provenance; require a fresh verified source before mutation."),
    CapabilitySourcePolicy("bios_update", ("VERIFIED_LOCAL_ASUS_UTILITY", "REDFISH_UPDATE_SERVICE", "VERIFIED_OEM_ACTION"), True, "Select only a physically verified transport for the exact platform/package."),
    CapabilitySourcePolicy("bmc_update", ("VERIFIED_LOCAL_ASUS_UTILITY", "REDFISH_UPDATE_SERVICE", "VERIFIED_OEM_ACTION"), True, "Select only a physically verified transport and tolerate expected BMC restart."),
    CapabilitySourcePolicy("task_completion", ("VERIFIED_LOCAL_TASK_STATUS", "REDFISH_TASK_SERVICE", "VERIFIED_OEM_JOB"), True, "HTTP acceptance is not completion; require terminal task state and post-version verification."),
    CapabilitySourcePolicy("hardware_inventory", ("LINUX_SYSFS", "DMIDECODE", "LSCPU", "LSPCI", "LSBLK", "IPMI_FRU_LOCAL_KCS", "REDFISH_INVENTORY"), False, "Prefer current-boot Linux observations over BMC cached inventory."),
    CapabilitySourcePolicy("sensors", ("IPMI_SDR_LOCAL_KCS", "REDFISH_SENSORS"), False, "Prefer live sensor reads and preserve timestamp/freshness."),
    CapabilitySourcePolicy("sel", ("IPMI_SEL_LOCAL_KCS", "REDFISH_LOG_SERVICES"), False, "Local KCS collection is sufficient; clearing remains separately mutation-gated."),
    CapabilitySourcePolicy("system_diagnostics", ("VERIFIED_LOCAL_ASUS_DIAGNOSTIC", "REDFISH_OR_OEM_DIAGNOSTIC"), True, "Auth blocks only this capability when no verified local equivalent exists."),
)


def classify_asus_system_diagnostics_platform(
    *,
    normalized_inventory: Mapping[str, Any] | None = None,
    platform: Mapping[str, Any] | None = None,
    firmware_plan: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Classify only the platform precondition for ASUS diagnostics.

    The ASMB12 WebUI diagnostics API is not a generic BMC capability.  In
    particular, an ASMB11 controller is known not to advertise that API, so
    an unavailable password must not turn an unsupported platform into an
    authentication block.  Conversely, discovering ASMB12 only establishes
    that authenticated endpoint discovery is meaningful; it does *not* claim
    that the diagnostics implementation is present on that firmware/SKU.

    Firmware planning may know the generation even when the normalized
    inventory stores it only in a MANAGEMENT_MODULE component.  Accept both
    representations, retain public provenance, and refuse to make the
    ASMB11-only conclusion if current evidence conflicts.
    """
    normalized = normalized_inventory if isinstance(normalized_inventory, Mapping) else {}
    platform_payload = platform if isinstance(platform, Mapping) else {}
    plan = firmware_plan if isinstance(firmware_plan, Mapping) else {}
    observations: list[dict[str, str]] = []

    def observe(value: Any, source: str) -> None:
        match = re.search(r"(?i)\b(ASMB\s*\d+)\b", str(value or ""))
        if not match:
            return
        generation = re.sub(r"\s+", "", match.group(1)).upper()
        observation = {"value": generation, "source": source}
        if observation not in observations:
            observations.append(observation)

    # The planner's platform descriptor is generated from current local BMC
    # evidence or exact ASUS metadata and is the most complete representation
    # available at the diagnostics stage.
    generic = plan.get("generic_asus_firmware_engine")
    generic = generic if isinstance(generic, Mapping) else {}
    descriptor = generic.get("platform")
    descriptor = descriptor if isinstance(descriptor, Mapping) else {}
    observe(descriptor.get("bmc_generation"), "ASUS_EXACT_FIRMWARE_PLATFORM_DESCRIPTOR")
    observe(descriptor.get("bmc_model"), "ASUS_EXACT_FIRMWARE_PLATFORM_DESCRIPTOR")

    for key in ("bmc_generation", "management_bmc_generation", "management_model", "bmc_model"):
        observe(normalized.get(key), f"NORMALIZED_INVENTORY:{key}")

    components = normalized.get("components")
    for component in components if isinstance(components, list) else ():
        if not isinstance(component, Mapping):
            continue
        category = str(component.get("category") or "").upper()
        if category not in {"MANAGEMENT_MODULE", "BMC"}:
            continue
        observe(component.get("model"), f"NORMALIZED_COMPONENT:{category}:model")
        metadata = component.get("metadata")
        if isinstance(metadata, Mapping):
            observe(metadata.get("bmc_generation"), f"NORMALIZED_COMPONENT:{category}:metadata")

    for key in ("bmc_generation", "management_bmc_generation", "management_model", "bmc_model"):
        observe(platform_payload.get(key), f"PLATFORM:{key}")

    observed_generations = {item["value"] for item in observations}
    # The exact planner descriptor is preferred for the public provenance, but
    # conflicting ASMB generation evidence must never be silently collapsed
    # into an unsupported decision.
    preferred = next(
        (
            item
            for item in observations
            if item["source"] == "ASUS_EXACT_FIRMWARE_PLATFORM_DESCRIPTOR"
        ),
        observations[0] if observations else {"value": "", "source": ""},
    )
    result: dict[str, Any] = {
        "schema_version": 1,
        "capability": "system_diagnostics",
        "bmc_generation": preferred["value"],
        "bmc_generation_source": preferred["source"],
        "generation_observations": observations,
    }
    if len(observed_generations) > 1:
        return result | {
            "status": "PLATFORM_UNVERIFIED",
            "reason": "BMC_GENERATION_EVIDENCE_CONFLICT",
        }
    if preferred["value"] == "ASMB11":
        return result | {
            "status": "PLATFORM_UNSUPPORTED",
            "reason": "ASMB11_SYSTEM_DIAGNOSTICS_ENDPOINT_NOT_ADVERTISED",
        }
    if preferred["value"] == "ASMB12":
        return result | {
            "status": "CANDIDATE_REQUIRES_AUTHENTICATED_DISCOVERY",
            "reason": "ASMB12_SYSTEM_DIAGNOSTICS_CAPABILITY_UNVERIFIED",
        }
    return result | {
        "status": "PLATFORM_UNVERIFIED",
        "reason": "NO_EXPLICIT_ASMB12_SYSTEM_DIAGNOSTICS_CAPABILITY",
    }


def build_asus_capability_path_matrix(
    *,
    bmc_auth_state: BmcAuthState,
    verified_local_mechanisms: Mapping[str, str] | None = None,
    verified_bmc_mechanisms: Mapping[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Resolve every major ASUS function independently from the BMC auth state."""
    local = dict(verified_local_mechanisms or {})
    bmc = dict(verified_bmc_mechanisms or {})
    rows: list[dict[str, Any]] = []
    for policy in ASUS_CAPABILITY_SOURCE_POLICIES:
        row = resolve_capability_access(
            policy.capability,
            bmc_auth_state=bmc_auth_state,
            verified_local_mechanism=local.get(policy.capability, ""),
            verified_bmc_mechanism=bmc.get(policy.capability, ""),
            bmc_corroboration_available=bool(bmc.get(policy.capability)),
        )
        row.update(
            {
                "preferred_sources": list(policy.preferred_sources),
                "authenticated_bmc_may_be_required": policy.authenticated_bmc_may_be_required,
                "freshness_rule": policy.freshness_rule,
            }
        )
        rows.append(row)
    return rows


def apply_firmware_transport_paths(
    rows: list[dict[str, Any]],
    firmware_plan: Mapping[str, Any] | None,
) -> list[dict[str, Any]]:
    """Overlay the exact transport selected by the shared firmware planner.

    The initial capability matrix is intentionally conservative because the
    firmware planner has not run yet.  Once the exact platform/package plan is
    available, report the selected local or authenticated path per component.
    This keeps capability provenance truthful without making a current
    firmware run depend on an unused mutation transport.
    """
    payload = firmware_plan if isinstance(firmware_plan, Mapping) else {}
    generic = payload.get("generic_asus_firmware_engine")
    generic = generic if isinstance(generic, Mapping) else {}
    components = generic.get("components")
    components = components if isinstance(components, Mapping) else {}
    by_capability = {str(row.get("capability") or ""): row for row in rows if isinstance(row, Mapping)}
    for component, capability in (("BIOS", "bios_update"), ("BMC", "bmc_update")):
        row = by_capability.get(capability)
        component_plan = components.get(component)
        if not isinstance(row, dict) or not isinstance(component_plan, Mapping):
            continue
        selected = component_plan.get("selected_transport")
        selected = selected if isinstance(selected, Mapping) else {}
        selected_name = str(selected.get("name") or "")
        status = str(component_plan.get("status") or "")
        row["firmware_component"] = component
        row["firmware_status"] = status or "UNVERIFIED"
        row["selected_transport"] = selected_name or ""
        row["transport_provenance"] = {
            "source": str(selected.get("source") or ""),
            "target": str(selected.get("target") or ""),
            "requires_authenticated_bmc": bool(selected.get("requires_authenticated_bmc", True)) if selected else None,
        }
        if selected_name == "ASUS_LOCAL_OFFICIAL_UTILITY":
            row.update(
                {
                    "status": "AVAILABLE_LOCAL",
                    "selected_mechanism": "ASUS_LOCAL_OFFICIAL_UTILITY",
                    "blocked_by_auth": False,
                    "overall_run_blocked": False,
                }
            )
        elif selected_name and bool(selected.get("requires_authenticated_bmc", True)):
            # Preserve the auth-specific status generated by the initial
            # matrix; the exact transport is still useful provenance.
            row["selected_mechanism"] = selected_name
        elif status in {"NO_SUPPORTED_TRANSPORT", "NO_EXACT_OFFICIAL_PACKAGE"}:
            row.update(
                {
                    "status": "NOT_SUPPORTED",
                    "selected_mechanism": "",
                    "blocked_by_auth": False,
                    "overall_run_blocked": False,
                }
            )
    return rows
