"""Pure platform classification plus a read-only Linux DMI probe."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping


def _clean(value: Any) -> str:
    return " ".join(str(value or "").strip().split())


def _key(value: Any) -> str:
    return re.sub(r"[^A-Z0-9]+", " ", _clean(value).upper()).strip()


@dataclass(frozen=True)
class PlatformProbe:
    manufacturer: str = ""
    product_name: str = ""
    system_serial: str = ""
    board_serial: str = ""
    chassis_serial: str = ""
    product_uuid: str = ""
    bios_version: str = ""
    board_name: str = ""

    @classmethod
    def from_mapping(cls, values: Mapping[str, Any]) -> "PlatformProbe":
        return cls(
            manufacturer=_clean(values.get("manufacturer") or values.get("sys_vendor") or values.get("Manufacturer")),
            product_name=_clean(values.get("product_name") or values.get("product") or values.get("Model")),
            system_serial=_clean(values.get("system_serial") or values.get("product_serial") or values.get("SerialNumber")),
            board_serial=_clean(values.get("board_serial")),
            chassis_serial=_clean(values.get("chassis_serial")),
            product_uuid=_clean(values.get("product_uuid") or values.get("UUID")),
            bios_version=_clean(values.get("bios_version") or values.get("BiosVersion")),
            board_name=_clean(values.get("board_name") or values.get("BaseboardProduct") or values.get("BoardProduct")),
        )

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


_DMI_FILES = {
    "manufacturer": "sys_vendor",
    "product_name": "product_name",
    "system_serial": "product_serial",
    "board_serial": "board_serial",
    "chassis_serial": "chassis_serial",
    "product_uuid": "product_uuid",
    "bios_version": "bios_version",
    "board_name": "board_name",
}


def read_linux_dmi(root: Path = Path("/sys/class/dmi/id")) -> PlatformProbe:
    """Read Linux sysfs only; this function executes no external command."""
    values: dict[str, str] = {}
    for field, filename in _DMI_FILES.items():
        try:
            values[field] = (root / filename).read_text(encoding="utf-8", errors="replace").strip()
        except (FileNotFoundError, PermissionError, OSError):
            values[field] = ""
    return PlatformProbe.from_mapping(values)


def detect_platform(probe: PlatformProbe) -> dict[str, Any]:
    """Classify a platform without granting permission for a mutating action."""
    manufacturer = _key(probe.manufacturer)
    product = _key(probe.product_name)
    combined = f"{manufacturer} {product}"

    if "DELL" in manufacturer or "DELL" in combined:
        if "POWEREDGE R640" in product:
            return _decision(
                probe,
                vendor="DELL",
                platform_id="DELL_POWEREDGE_R640",
                discovery_supported=True,
                production_supported=True,
                production_flow="EXISTING_DELL_PRODUCTION",
                adapter="dell_existing",
                firmware_policy="EXISTING_DSU_PREVIEW_AND_APPLY_GATES_REQUIRED",
                reason="Dell PowerEdge R640 matches the currently verified production path.",
            )
        return _decision(
            probe,
            vendor="DELL",
            platform_id="DELL_UNSUPPORTED_MODEL",
            discovery_supported=True,
            production_supported=False,
            production_flow="SAFE_INVENTORY_ONLY",
            adapter="none",
            firmware_policy="BLOCKED_UNSUPPORTED_PLATFORM",
            reason="Dell manufacturer detected, but the model is outside the verified R640 path.",
        )

    if "ASUSTEK" in manufacturer or manufacturer == "ASUS" or " ASUS " in f" {combined} ":
        return _decision(
            probe,
            vendor="ASUS",
            platform_id="ASUS_SERVER",
            discovery_supported=True,
            production_supported=False,
            production_flow="ASUS_CAPABILITY_DISCOVERY",
            adapter="asus_common",
            firmware_policy="BLOCKED_PENDING_CAPABILITY_AND_MODEL_VALIDATION",
            reason="ASUS server detected; use common capability discovery before selecting any generation/model behavior.",
        )

    return _decision(
        probe,
        vendor="UNKNOWN",
        platform_id="UNSUPPORTED_PLATFORM",
        discovery_supported=True,
        production_supported=False,
        production_flow="SAFE_INVENTORY_ONLY",
        adapter="none",
        firmware_policy="BLOCKED_UNSUPPORTED_PLATFORM",
        reason="No supported Dell or ASUS platform signature matched.",
    )


def _decision(
    probe: PlatformProbe,
    *,
    vendor: str,
    platform_id: str,
    discovery_supported: bool,
    production_supported: bool,
    production_flow: str,
    adapter: str,
    firmware_policy: str,
    reason: str,
) -> dict[str, Any]:
    return {
        "schema_version": 2,
        "probe": probe.to_dict(),
        "vendor": vendor,
        "platform_id": platform_id,
        "discovery_supported": discovery_supported,
        "production_supported": production_supported,
        "supported": production_supported,
        "production_flow": production_flow,
        "adapter": adapter,
        "firmware_policy": firmware_policy,
        "mutating_operations_authorized": False,
        "decision": "PRODUCTION_SUPPORTED" if production_supported else "DISCOVERY_SUPPORTED" if discovery_supported else "UNSUPPORTED_PLATFORM",
        "reason": reason,
    }
