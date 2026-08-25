"""Safe finalization capability model; BMC reset remains closed until verified."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


class FinalizationError(RuntimeError):
    pass


@dataclass(frozen=True)
class BmcSoftResetCapability:
    validation: str = "UNVERIFIED"
    mechanism: str = ""
    host_power_impact_verified: bool = False
    configuration_preservation_verified: bool = False

    @property
    def enabled(self) -> bool:
        return (
            self.validation == "PHYSICALLY_VERIFIED"
            and bool(self.mechanism)
            and self.host_power_impact_verified
            and self.configuration_preservation_verified
        )

    def public_record(self) -> dict[str, Any]:
        return {
            "status": "AVAILABLE" if self.enabled else "UNVERIFIED",
            "validation": self.validation,
            "mechanism": self.mechanism,
            "host_power_impact_verified": self.host_power_impact_verified,
            "configuration_preservation_verified": self.configuration_preservation_verified,
            "factory_reset": False,
        }

    def require(self) -> None:
        if not self.enabled:
            raise FinalizationError("BMC soft reset is UNVERIFIED and cannot be executed")


def build_finalization_status(
    *,
    sel_cleanup: str,
    final_sanity: str,
    bmc_soft_reset: BmcSoftResetCapability | None = None,
    evidence_saved: bool = True,
    identity_reverified: bool = True,
    firmware_reverified: bool = True,
) -> dict[str, Any]:
    capability = bmc_soft_reset or BmcSoftResetCapability()
    return {
        "schema_version": 1,
        "evidence_saved": bool(evidence_saved),
        "sel_cleanup": str(sel_cleanup or "NOT_PERFORMED").upper(),
        "final_sanity": str(final_sanity or "NOT_TESTED").upper(),
        "bmc_soft_reset": "NOT_PERFORMED" if not capability.enabled else "PENDING_OPERATOR_CONFIRMATION",
        "bmc_soft_reset_capability": capability.public_record(),
        "identity_reverified": bool(identity_reverified),
        "firmware_reverified": bool(firmware_reverified),
        "factory_reset_performed": False,
        "host_reboot_performed": False,
        "power_cycle_performed": False,
    }
