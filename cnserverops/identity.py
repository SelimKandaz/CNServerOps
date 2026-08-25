"""Stable cross-vendor identity derived from fused local and BMC evidence."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Mapping

from .evidence import (
    EvidenceConfidence,
    EvidenceFreshness,
    FieldObservation,
    fuse_field,
    read_linux_boot_id,
)
from .platform import PlatformProbe


_PLACEHOLDERS = {
    "",
    "0",
    "NONE",
    "N A",
    "NA",
    "NOT APPLICABLE",
    "NOT SPECIFIED",
    "SYSTEM SERIAL NUMBER",
    "TO BE FILLED BY O E M",
    "TO BE FILLED BY OEM",
    "UNKNOWN",
}


def _clean(value: Any) -> str:
    return " ".join(str(value or "").strip().split())


def _serial(value: Any) -> str:
    cleaned = _clean(value)
    key = re.sub(r"[^A-Z0-9]+", " ", cleaned.upper()).strip()
    return "" if key in _PLACEHOLDERS else cleaned


def _nested(mapping: Mapping[str, Any] | None, *keys: str) -> Any:
    value: Any = mapping or {}
    for key in keys:
        if not isinstance(value, Mapping):
            return ""
        value = value.get(key, "")
    return value


def _observation(
    value: Any,
    source: str,
    freshness: EvidenceFreshness,
    confidence: EvidenceConfidence,
    *,
    current_local: bool = False,
    bmc_derived: bool = False,
) -> FieldObservation:
    return FieldObservation(
        value=_serial(value),
        source=source,
        freshness=freshness,
        confidence=confidence,
        current_local=current_local,
        bmc_derived=bmc_derived,
    )


def derive_machine_identity(
    platform: Mapping[str, Any],
    local_dmi: PlatformProbe,
    *,
    redfish_system: Mapping[str, Any] | None = None,
    chassis_fru: Mapping[str, Any] | None = None,
    manager: Mapping[str, Any] | None = None,
    boot_id: str | None = None,
) -> dict[str, Any]:
    """Build stable SERVER_ID while retaining per-field provenance and freshness.

    Current-boot DMI/SMBIOS and local KCS FRU are the identity authorities. Redfish
    is corroborating evidence unless its freshness has been independently proven.
    A Redfish disagreement is recorded and cannot replace or invalidate matching
    local evidence; a disagreement between DMI and local FRU remains fail-safe.
    """
    fru = _nested(chassis_fru, "FruInfo")
    if not isinstance(fru, Mapping):
        fru = {}
    product = fru.get("Product", {}) if isinstance(fru.get("Product"), Mapping) else {}
    chassis = fru.get("Chassis", {}) if isinstance(fru.get("Chassis"), Mapping) else {}
    board = fru.get("Board", {}) if isinstance(fru.get("Board"), Mapping) else {}
    board_product = _clean(board.get("BoardProduct"))
    board_manufacturer = _clean(board.get("BoardMfg"))
    # ASUS ASMB/SCM FRU is a management module, not the DMI Type-2
    # motherboard.  Keep it as a separate component and do not make a
    # legitimate DMI-board/FRU-board serial difference an identity conflict.
    management_module = bool(re.search(r"\bASMB\d*\b|\bSCM\b", f"{board_product} {board_manufacturer}", re.IGNORECASE))

    fields = {
        "model": fuse_field(
            "model",
            [
                _observation(local_dmi.product_name, "DMI_SMBIOS", EvidenceFreshness.CURRENT_BOOT, EvidenceConfidence.HIGH, current_local=True),
                _observation((redfish_system or {}).get("Model"), "REDFISH_SYSTEM", EvidenceFreshness.BMC_FRESHNESS_UNKNOWN, EvidenceConfidence.MEDIUM, bmc_derived=True),
            ],
        ),
        "system_uuid": fuse_field(
            "system_uuid",
            [
                _observation(local_dmi.product_uuid, "DMI_SMBIOS", EvidenceFreshness.CURRENT_BOOT, EvidenceConfidence.HIGH, current_local=True),
                _observation((redfish_system or {}).get("UUID"), "REDFISH_SYSTEM", EvidenceFreshness.BMC_FRESHNESS_UNKNOWN, EvidenceConfidence.MEDIUM, bmc_derived=True),
            ],
        ),
        "system_serial": fuse_field(
            "system_serial",
            [
                _observation(local_dmi.system_serial, "DMI_SMBIOS", EvidenceFreshness.CURRENT_BOOT, EvidenceConfidence.HIGH, current_local=True),
                _observation(product.get("ProductSerial"), "IPMI_FRU_LOCAL_KCS", EvidenceFreshness.STATIC_FRU, EvidenceConfidence.HIGH),
                _observation((redfish_system or {}).get("SerialNumber"), "REDFISH_SYSTEM", EvidenceFreshness.BMC_FRESHNESS_UNKNOWN, EvidenceConfidence.MEDIUM, bmc_derived=True),
            ],
        ),
        "chassis_serial": fuse_field(
            "chassis_serial",
            [
                _observation(local_dmi.chassis_serial, "DMI_SMBIOS", EvidenceFreshness.CURRENT_BOOT, EvidenceConfidence.HIGH, current_local=True),
                _observation(chassis.get("ChassisSerial"), "IPMI_FRU_LOCAL_KCS", EvidenceFreshness.STATIC_FRU, EvidenceConfidence.HIGH),
            ],
        ),
        "board_serial": fuse_field(
            "board_serial",
            [
                _observation(local_dmi.board_serial, "DMI_SMBIOS", EvidenceFreshness.CURRENT_BOOT, EvidenceConfidence.HIGH, current_local=True),
                *([] if management_module else [_observation(board.get("BoardSerial"), "IPMI_FRU_LOCAL_KCS", EvidenceFreshness.STATIC_FRU, EvidenceConfidence.HIGH)]),
            ],
        ),
        "management_module_serial": fuse_field(
            "management_module_serial",
            [
                _observation(board.get("BoardSerial"), "IPMI_FRU_LOCAL_KCS", EvidenceFreshness.STATIC_FRU, EvidenceConfidence.HIGH)
                if management_module else _observation("", "IPMI_FRU_LOCAL_KCS", EvidenceFreshness.STATIC_FRU, EvidenceConfidence.LOW),
            ],
        ),
        "bmc_serial": fuse_field(
            "bmc_serial",
            [
                _observation((manager or {}).get("SerialNumber"), "REDFISH_MANAGER", EvidenceFreshness.BMC_FRESHNESS_UNKNOWN, EvidenceConfidence.MEDIUM, bmc_derived=True),
            ],
        ),
    }

    anchors = {
        "dmi_system_uuid": _serial(local_dmi.product_uuid),
        "redfish_system_uuid": _serial((redfish_system or {}).get("UUID")),
        "dmi_system_serial": _serial(local_dmi.system_serial),
        "redfish_system_serial": _serial((redfish_system or {}).get("SerialNumber")),
        "fru_product_serial": _serial(product.get("ProductSerial")),
        "dmi_chassis_serial": _serial(local_dmi.chassis_serial),
        "fru_chassis_serial": _serial(chassis.get("ChassisSerial")),
        "dmi_board_serial": _serial(local_dmi.board_serial),
        "fru_board_serial": _serial(board.get("BoardSerial")),
        "fru_board_product": board_product,
        "fru_board_manufacturer": board_manufacturer,
        "fru_management_module_serial": _serial(board.get("BoardSerial")) if management_module else "",
        "fru_management_module_model": board_product if management_module else "",
        "bmc_serial": _serial((manager or {}).get("SerialNumber")),
    }
    source_groups = {
        "system serial": ("dmi_system_serial", "fru_product_serial"),
        "chassis serial": ("dmi_chassis_serial", "fru_chassis_serial"),
        **({} if management_module else {"board serial": ("dmi_board_serial", "fru_board_serial")}),
    }
    conflicts: list[str] = []
    for label, keys in source_groups.items():
        values = {anchors[key].upper() for key in keys if anchors[key]}
        if len(values) > 1:
            conflicts.append(f"{label} sources disagree")

    bmc_conflicts = [name for name, field in fields.items() if field["bmc_conflict"]]
    warning_codes = sorted(
        {code for name in bmc_conflicts for code in fields[name]["reason_codes"]}
    )
    primary_serial = str(fields["system_serial"]["value"])
    vendor = _clean(platform.get("vendor")).upper() or "UNKNOWN"
    platform_id = _clean(platform.get("platform_id")).upper() or "UNSUPPORTED_PLATFORM"
    model = _clean(fields["model"]["value"])

    trusted_serial_present = bool(anchors["dmi_system_serial"] or anchors["fru_product_serial"])
    basis: list[tuple[str, str]] = []
    if primary_serial and trusted_serial_present:
        basis = [("vendor", vendor), ("model", model.upper()), ("system_serial", primary_serial.upper())]
    elif anchors["dmi_chassis_serial"] and anchors["dmi_board_serial"]:
        basis = [
            ("vendor", vendor),
            ("model", model.upper()),
            ("chassis_serial", anchors["dmi_chassis_serial"].upper()),
            ("board_serial", anchors["dmi_board_serial"].upper()),
        ]

    fingerprint = ""
    if basis and not conflicts and vendor != "UNKNOWN":
        canonical = "|".join(f"{key}={value}" for key, value in basis)
        fingerprint = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    usable_anchor_count = sum(1 for value in anchors.values() if value)
    corroborated = bool(
        anchors["dmi_system_serial"]
        and anchors["fru_product_serial"]
        and anchors["dmi_system_serial"].upper() == anchors["fru_product_serial"].upper()
    )
    confidence = "high" if primary_serial and corroborated and not conflicts else "medium" if basis and not conflicts else "low"
    resumable = bool(fingerprint) and not conflicts and bool(platform.get("discovery_supported", platform.get("supported")))
    # This flag describes identity quality only. Route, capability, operation,
    # package, RUN, and expiry gates independently decide whether a mutation is allowed.
    mutation_eligible = resumable
    current_boot_id = str(boot_id if boot_id is not None else read_linux_boot_id()).strip()

    return {
        "schema_version": 2,
        "server_id": f"SERVER-{fingerprint.upper()}" if fingerprint else "",
        "boot_id": current_boot_id,
        "vendor": vendor,
        "platform_id": platform_id,
        "model": model,
        "dmi_uuid": anchors["dmi_system_uuid"],
        "primary_serial": primary_serial,
        "anchors": anchors,
        "component_identities": {
            "SYSTEM": {
                "model": _clean(local_dmi.product_name),
                "serial": anchors["dmi_system_serial"] or anchors["fru_product_serial"],
                "sources": ["DMI_SMBIOS", "IPMI_FRU_LOCAL_KCS"],
                "freshness": "CURRENT_BOOT",
                "confidence": "HIGH" if corroborated else "MEDIUM",
            },
            "CHASSIS": {
                "serial": anchors["dmi_chassis_serial"] or anchors["fru_chassis_serial"],
                "sources": ["DMI_SMBIOS", "IPMI_FRU_LOCAL_KCS"],
                "freshness": "CURRENT_BOOT",
                "confidence": "HIGH" if anchors["dmi_chassis_serial"] and anchors["dmi_chassis_serial"].upper() == anchors["fru_chassis_serial"].upper() else "MEDIUM",
            },
            "MOTHERBOARD": {
                "model": _clean(local_dmi.board_name),
                "serial": anchors["dmi_board_serial"],
                "source": "DMI_SMBIOS",
                "freshness": "CURRENT_BOOT",
                "confidence": "HIGH" if anchors["dmi_board_serial"] else "LOW",
            },
            "MANAGEMENT_MODULE": {
                "model": anchors["fru_management_module_model"],
                "serial": anchors["fru_management_module_serial"],
                "source": "IPMI_FRU_LOCAL_KCS" if management_module else "NOT_PRESENT",
                "freshness": "STATIC_FRU",
                "confidence": "HIGH" if management_module and anchors["fru_management_module_serial"] else "NOT_PRESENT",
            },
            "BMC": {"serial": anchors["bmc_serial"], "source": "REDFISH_MANAGER", "freshness": "BMC_FRESHNESS_UNKNOWN", "confidence": "MEDIUM" if anchors["bmc_serial"] else "UNKNOWN"},
        },
        "management_module": management_module,
        "identity_state": "TRUSTED_CURRENT" if resumable else "UNTRUSTED",
        "field_evidence": fields,
        "anchor_count": usable_anchor_count,
        "confidence": confidence,
        "conflicts": conflicts,
        "bmc_conflicts": bmc_conflicts,
        "warning_codes": warning_codes,
        "fingerprint_basis_fields": [key for key, _ in basis],
        "fingerprint_sha256": fingerprint,
        "resumable": resumable,
        "mutation_eligible": mutation_eligible,
        "platform_production_supported": bool(platform.get("production_supported", platform.get("supported"))),
        "bmc_values_authoritative_for_identity": False,
        "bmc_conflicting_values_authoritative_for_mutation": False,
        "resume_block_reason": "" if resumable else _resume_block_reason(platform, basis, conflicts),
    }


def _resume_block_reason(platform: Mapping[str, Any], basis: list[tuple[str, str]], conflicts: list[str]) -> str:
    if not platform.get("discovery_supported", platform.get("supported")):
        return "platform discovery is not supported"
    if conflicts:
        return "; ".join(conflicts)
    if not basis:
        return "stable current/local system serial or chassis-plus-board identity is unavailable"
    return "identity fingerprint could not be established"
