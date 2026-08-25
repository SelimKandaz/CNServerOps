"""Identity normalization and stale-state protection."""

from __future__ import annotations

import hashlib
from typing import Any


def _clean(value: Any) -> str:
    return " ".join(str(value or "").strip().split())


def derive_identity(system: dict[str, Any], chassis_fru: dict[str, Any], manager: dict[str, Any]) -> dict[str, Any]:
    """Create a durable multi-source machine identity without retaining credentials."""
    fru = chassis_fru.get("FruInfo", {}) if isinstance(chassis_fru, dict) else {}
    board = fru.get("Board", {}) if isinstance(fru, dict) else {}
    chassis = fru.get("Chassis", {}) if isinstance(fru, dict) else {}
    product = fru.get("Product", {}) if isinstance(fru, dict) else {}
    identity = {
        "manufacturer": _clean(system.get("Manufacturer") or product.get("ProductManufacturer")),
        "model": _clean(system.get("Model") or product.get("ProductName")),
        "system_serial": _clean(system.get("SerialNumber") or product.get("ProductSerial")),
        "chassis_serial": _clean(chassis.get("ChassisSerial")),
        "baseboard_serial": _clean(board.get("BoardSerial")),
        "bmc_serial": _clean(manager.get("SerialNumber")),
        "bmc_firmware": _clean(manager.get("FirmwareVersion")),
    }
    anchors = [identity[key] for key in ("system_serial", "chassis_serial", "baseboard_serial", "bmc_serial") if identity[key]]
    identity["anchor_count"] = len(anchors)
    identity["confidence"] = "high" if identity["system_serial"] and len(anchors) >= 2 else "medium" if anchors else "low"
    canonical = "|".join(
        _clean(identity[key]).upper()
        for key in ("manufacturer", "model", "system_serial", "chassis_serial", "baseboard_serial", "bmc_serial")
    )
    identity["fingerprint_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return identity
