"""Normalized final production disposition with explicit reason severity."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable

from .models import FinalDisposition


class ReasonSeverity(str, Enum):
    WARNING = "WARNING"
    REVIEW = "REVIEW"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"


class ReasonCode(str, Enum):
    FIRMWARE_UPDATE_FAILED = "FIRMWARE_UPDATE_FAILED"
    DIMM_TEST_FAILED = "DIMM_TEST_FAILED"
    STORAGE_HEALTH_FAILED = "STORAGE_HEALTH_FAILED"
    SENSOR_CRITICAL = "SENSOR_CRITICAL"
    IDENTITY_CONFLICT = "IDENTITY_CONFLICT"
    DIAGNOSTIC_COLLECTION_FAILED = "DIAGNOSTIC_COLLECTION_FAILED"
    LOG_CLEAR_FAILED = "LOG_CLEAR_FAILED"
    CENTRAL_SYNC_PENDING = "CENTRAL_SYNC_PENDING"
    EXPORT_FAILED = "EXPORT_FAILED"
    UNSUPPORTED_PLATFORM = "UNSUPPORTED_PLATFORM"
    BLOCKED_BY_AUTH = "BLOCKED_BY_AUTH"


@dataclass(frozen=True)
class Reason:
    code: str
    severity: ReasonSeverity
    detail: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "severity": self.severity.value, "detail": self.detail}


def decide_final_disposition(reasons: Iterable[Reason]) -> dict[str, Any]:
    items = list(reasons)
    severities = {item.severity for item in items}
    if ReasonSeverity.BLOCKED in severities:
        disposition = FinalDisposition.BLOCKED
    elif ReasonSeverity.FAIL in severities:
        disposition = FinalDisposition.FAIL
    elif ReasonSeverity.REVIEW in severities:
        disposition = FinalDisposition.REVIEW
    elif ReasonSeverity.WARNING in severities:
        disposition = FinalDisposition.PASS_WITH_WARNINGS
    else:
        disposition = FinalDisposition.PASS
    return {
        "schema_version": 1,
        "disposition": disposition.value,
        "reasons": [item.to_dict() for item in items],
        "central_sync_is_non_blocking": all(item.code != "CENTRAL_SYNC_REQUIRED_BY_POLICY" for item in items),
    }
