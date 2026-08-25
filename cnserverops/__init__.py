"""Vendor-neutral building blocks for the universal Dell + ASUS production SSD."""

__version__ = "3.8.120-pass3-stress-recovery"

from .capabilities import CapabilityRecord, ValidationLevel
from .asus_firmware import AsusFirmwareEngine, AsusPlatformFingerprint, AsusOfficialCatalogSource
from .evidence import BmcAuthState, EvidenceConfidence, EvidenceFreshness
from .identity import derive_machine_identity
from .models import FinalDisposition, RunRecord, ServerRecord
from .orchestrator import ProductionOrchestrator, WorkflowStage
from .platform import PlatformProbe, detect_platform
from .safety import MutationBlockedError, MutationGate
from .state import (
    FirmwareTaskContinuityError,
    StateMismatchError,
    UnsafeIdentityError,
    assert_firmware_task_continuity,
    assert_resume_allowed,
    assert_workflow_resume_allowed,
)

__all__ = [
    "CapabilityRecord",
    "AsusFirmwareEngine",
    "AsusPlatformFingerprint",
    "AsusOfficialCatalogSource",
    "BmcAuthState",
    "EvidenceConfidence",
    "EvidenceFreshness",
    "FinalDisposition",
    "FirmwareTaskContinuityError",
    "MutationBlockedError",
    "MutationGate",
    "PlatformProbe",
    "ProductionOrchestrator",
    "RunRecord",
    "ServerRecord",
    "StateMismatchError",
    "UnsafeIdentityError",
    "ValidationLevel",
    "WorkflowStage",
    "assert_resume_allowed",
    "assert_firmware_task_continuity",
    "assert_workflow_resume_allowed",
    "derive_machine_identity",
    "detect_platform",
]
