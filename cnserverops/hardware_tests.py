"""Capability-driven hardware test planning and normalization."""

from __future__ import annotations

import shutil
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping


class TestStatus(str, Enum):
    PASS = "PASS"
    PASS_WITH_WARNINGS = "PASS_WITH_WARNINGS"
    FAIL = "FAIL"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    BLOCKED = "BLOCKED"
    NOT_RUN = "NOT_RUN"


@dataclass(frozen=True)
class HardwareTestSpec:
    test_id: str
    category: str
    required_tools: tuple[str, ...] = ()
    required_capabilities: tuple[str, ...] = ()
    workload: bool = False
    destructive: bool = False
    timeout_seconds: int = 300
    validation_profile: str = "generic"


@dataclass(frozen=True)
class HardwareValidationProfile:
    profile_id: str
    expected_fan_sensors: tuple[str, ...] = ()
    minimum_psu_count: int | None = None
    require_nvme: bool = False
    require_gpu: bool = False
    maximum_temperature_c: Mapping[str, float] = field(default_factory=dict)
    source: str = "operator-approved platform profile"


@dataclass(frozen=True)
class HardwareTestResult:
    test_id: str
    status: TestStatus
    reason_codes: tuple[str, ...]
    source: str
    evidence: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["status"] = self.status.value
        return payload


GENERIC_TEST_SPECS = (
    HardwareTestSpec("cpu.inventory", "CPU", ("lscpu",)),
    HardwareTestSpec("cpu.stress", "CPU", ("stress-ng",), workload=True, timeout_seconds=3600),
    HardwareTestSpec("memory.inventory", "MEMORY", ("dmidecode",)),
    HardwareTestSpec("memory.stress", "MEMORY", ("stress-ng",), workload=True, timeout_seconds=3600),
    HardwareTestSpec("storage.inventory", "STORAGE", ("lsblk",)),
    HardwareTestSpec("storage.smart", "STORAGE", ("smartctl",), ("sata_or_scsi_disk",)),
    HardwareTestSpec("storage.nvme", "STORAGE", ("nvme",), ("nvme_device",)),
    HardwareTestSpec("storage.raid_sas", "STORAGE", (), ("raid_or_sas_controller",)),
    HardwareTestSpec("network.inventory", "NETWORK", ("ip", "ethtool")),
    HardwareTestSpec("pcie.inventory", "PCIE", ("lspci",)),
    HardwareTestSpec("gpu.inventory", "GPU", (), ("accelerator_gpu",)),
    HardwareTestSpec("bmc.sensors", "BMC", ("ipmitool",), ("ipmi_sdr",)),
    HardwareTestSpec("bmc.sensor_trend", "BMC", ("ipmitool",), ("ipmi_sdr",), workload=True),
)


class HardwareTestPlanner:
    def __init__(self, specs: Iterable[HardwareTestSpec] = GENERIC_TEST_SPECS) -> None:
        self.specs = tuple(specs)

    def plan(
        self,
        *,
        capabilities: Mapping[str, bool],
        available_tools: Mapping[str, str] | None = None,
        allow_workloads: bool = False,
    ) -> list[dict[str, Any]]:
        tools = dict(available_tools or {name: shutil.which(name) or "" for spec in self.specs for name in spec.required_tools})
        plan: list[dict[str, Any]] = []
        for spec in self.specs:
            missing_tools = [name for name in spec.required_tools if not tools.get(name)]
            missing_capabilities = [name for name in spec.required_capabilities if not capabilities.get(name, False)]
            if spec.destructive:
                status, reasons = TestStatus.BLOCKED, ["DESTRUCTIVE_TEST_PROHIBITED"]
            elif missing_tools:
                status, reasons = TestStatus.NOT_SUPPORTED, [f"MISSING_TOOL:{name}" for name in missing_tools]
            elif missing_capabilities:
                status, reasons = TestStatus.NOT_SUPPORTED, [f"CAPABILITY_NOT_DETECTED:{name}" for name in missing_capabilities]
            elif spec.workload and not allow_workloads:
                status, reasons = TestStatus.BLOCKED, ["WORKLOAD_GATE_CLOSED"]
            else:
                status, reasons = TestStatus.NOT_RUN, ["READY"]
            plan.append(
                {
                    "spec": asdict(spec),
                    "plan_status": status.value,
                    "reason_codes": reasons,
                    "hardcoded_device_count_assumptions": False,
                }
            )
        return plan


def assess_sensor_snapshot(
    rows: Iterable[Mapping[str, Any]],
    *,
    profile: HardwareValidationProfile | None = None,
) -> HardwareTestResult:
    values = list(rows)
    critical = [row for row in values if str(row.get("status") or "").lower() not in {"ok", "ns", "na", "unavailable"}]
    reasons = ["SENSOR_NON_OK"] if critical else []
    warnings: list[str] = []
    if profile and profile.expected_fan_sensors:
        observed = {str(row.get("sensor") or "").upper() for row in values}
        missing = [fan for fan in profile.expected_fan_sensors if fan.upper() not in observed]
        if missing:
            reasons.append("PROFILE_EXPECTED_FAN_MISSING")
    elif any("FAN" in str(row.get("sensor") or "").upper() for row in values):
        warnings.append("FAN_POPULATION_PROFILE_UNAVAILABLE")
    if critical or reasons:
        status = TestStatus.FAIL
    elif warnings:
        status = TestStatus.PASS_WITH_WARNINGS
    else:
        status = TestStatus.PASS
    return HardwareTestResult(
        test_id="bmc.sensors",
        status=status,
        reason_codes=tuple(reasons + warnings),
        source="normalized IPMI/Redfish sensor snapshot",
        evidence={"row_count": len(values), "critical_rows": critical, "profile_id": profile.profile_id if profile else ""},
    )
