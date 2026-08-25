"""Read-only local evidence adapters used when BMC authentication is unavailable."""

from __future__ import annotations

import subprocess
from typing import Any


def read_local_ipmi_fru(*, timeout_seconds: int = 20) -> dict[str, Any]:
    """Read the primary FRU through local KCS using a fixed, non-mutating command."""
    if timeout_seconds <= 0 or timeout_seconds > 120:
        raise ValueError("FRU read timeout must be between 1 and 120 seconds")
    try:
        completed = subprocess.run(
            ["ipmitool", "fru", "print"],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return {
            "status": "UNAVAILABLE",
            "mechanism": "LOCAL_KCS_IPMITOOL_FRU_READ",
            "error": type(exc).__name__,
            "fru": {},
        }
    if completed.returncode != 0:
        return {
            "status": "UNAVAILABLE",
            "mechanism": "LOCAL_KCS_IPMITOOL_FRU_READ",
            "error": f"EXIT_{completed.returncode}",
            "fru": {},
        }
    values: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        if ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        if key and value and key not in values:
            values[key] = value
    fru = {
        "FruInfo": {
            "Product": {
                "ProductName": values.get("Product Name", ""),
                "ProductSerial": values.get("Product Serial", ""),
                "ProductManufacturer": values.get("Product Manufacturer", ""),
            },
            "Board": {
                "BoardProduct": values.get("Board Product", ""),
                "BoardSerial": values.get("Board Serial", ""),
                "BoardMfg": values.get("Board Mfg", ""),
            },
            "Chassis": {"ChassisSerial": values.get("Chassis Serial", "")},
        }
    }
    return {
        "status": "PASS",
        "mechanism": "LOCAL_KCS_IPMITOOL_FRU_READ",
        "error": "",
        "fru": fru,
    }
