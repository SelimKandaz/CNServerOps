"""Vendor-neutral requirements for an ASUS TSR-equivalent evidence outcome."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Iterable, Mapping


@dataclass(frozen=True)
class DiagnosticRequirement:
    category: str
    required: bool
    preferred_sources: tuple[str, ...]


ASUS_DIAGNOSTIC_REQUIREMENTS = (
    DiagnosticRequirement("identity_manifest", True, ("DMI", "FRU", "Redfish")),
    DiagnosticRequirement("dmi", True, ("Linux sysfs", "dmidecode")),
    DiagnosticRequirement("fru", True, ("IPMI FRU", "Redfish Chassis/Fru")),
    DiagnosticRequirement("firmware_inventory", True, ("Redfish FirmwareInventory", "DMI/IPMI fallback")),
    DiagnosticRequirement("sensors", True, ("Redfish Sensors/Thermal/Power", "IPMI SDR")),
    DiagnosticRequirement("preclean_sel", True, ("IPMI SEL", "Redfish LogServices")),
    DiagnosticRequirement("bmc_logs", False, ("Redfish LogServices", "ASUS/AMI OEM")),
    DiagnosticRequirement("linux_hardware", True, ("Linux local inventory",)),
    DiagnosticRequirement("storage_health", False, ("SMART", "NVMe", "RAID/HBA")),
    DiagnosticRequirement("test_results", True, ("CNServerOps test engine",)),
    DiagnosticRequirement("firmware_task_evidence", False, ("Redfish TaskService", "ASUS/AMI OEM")),
    DiagnosticRequirement("system_diagnostics_artifact", False, ("ASUS documented API/export",)),
    DiagnosticRequirement("checksum_manifest", True, ("CNServerOps SHA256 manifest",)),
)


def evaluate_diagnostic_coverage(
    artifacts: Iterable[Mapping[str, Any]],
    requirements: Iterable[DiagnosticRequirement] = ASUS_DIAGNOSTIC_REQUIREMENTS,
) -> dict[str, Any]:
    items = list(artifacts)
    categories = {str(item.get("category") or "") for item in items if item.get("sha256")}
    rows: list[dict[str, Any]] = []
    missing_required: list[str] = []
    missing_optional: list[str] = []
    for requirement in requirements:
        present = requirement.category in categories
        rows.append(asdict(requirement) | {"present": present})
        if not present:
            (missing_required if requirement.required else missing_optional).append(requirement.category)
    return {
        "schema_version": 1,
        "status": "COMPLETE" if not missing_required else "INCOMPLETE",
        "requirements": rows,
        "missing_required": missing_required,
        "missing_optional": missing_optional,
        "system_diagnostics_equivalent_not_format_equivalent_to_dell_tsr": True,
    }
