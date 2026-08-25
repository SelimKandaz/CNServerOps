"""Physical, operator-started CNServerOps production workflow.

The module deliberately contains no boot-time trigger.  The console launcher calls
it only after an operator selects the production option.  Every external command
is a fixed, shell-free local read or an explicitly gated workload/log operation.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import ssl
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from .artifact_sync import ArtifactStoreForwardQueue
from .asus_firmware import (
    ASUS_VALIDATED_PACKAGE_STATUSES,
    AsusFirmwareEngine,
    AsusFirmwarePlan,
    AsusOfficialCatalogSource,
    AsusPlatformFingerprint,
    AsusTransportDescriptor,
    discover_asus_transports,
    select_asus_transport_for_package,
)
from .asus_firmware_transport import (
    AsusAsmb11KcsBmcFirmwareAdapter,
    AsusAsmbWebHpmFirmwareAdapter,
    AsusAsmbLinuxBmcFirmwareAdapter,
    AsusLocalFirmwareUtilityAdapter,
    AsusAsmbWebSession,
    AsusRedfishFirmwareAdapter,
    discover_asus_web_hpm_capability,
)
from .asus_diagnostics import DiagnosticCredentials, execute_asmb12_diagnostics
from .bmc_auth import (
    BmcAuthPolicy,
    clear_provisioned_account_binding,
    discover_bmc_auth,
    runtime_credential_candidates,
)
from .bmc_handoff import bmc_auth_change_required, perform_asus_factory_handoff
from .bmc_recovery import (
    asmb12_recovery_capability,
    asus_bmc_recovery_capability,
    discover_local_bmc_endpoint,
    recover_asmb12_bmc,
    recover_asus_bmc,
    restore_local_ipmi_kcs,
)
from .bmc_version import parse_ipmi_mc_firmware_version
from .capabilities import (
    apply_firmware_transport_paths,
    build_asus_capability_path_matrix,
    classify_asus_system_diagnostics_platform,
)
from .central_api import (
    CentralApiError,
    HttpsCollectorClient,
    central_credential_from_file,
)
from .firmware import FirmwarePackageMetadata, FirmwareRepository, HttpsPackageDownloader
from .firmware_executor import FirmwareUpdateExecutor
from .firmware_lifecycle import (
    FirmwareLifecycleError,
    build_pending as build_firmware_pending,
    clear_pending as clear_firmware_pending,
    load_pending as load_firmware_pending,
    request_controlled_reboot,
    save_pending as save_firmware_pending,
    validate_pending_for_resume,
)
from cndellops_asus.redfish import AuthenticatedRedfishClient, RedfishCredentials
from .diagnostics import build_universal_bundle, inspect_asmb12_system_diagnostics
from .disposition import Reason, ReasonSeverity, decide_final_disposition
from .evidence import BmcAuthState, bmc_auth_is_usable, read_linux_boot_id
from .enrollment import reconcile_server_enrollment
from .finalization import BmcSoftResetCapability, build_finalization_status
from .handoff import HandoffPolicy, evaluate_handoff, normalized_status
from .identity import derive_machine_identity
from .inventory_model import build_normalized_inventory, physical_nic_rows
from .local_evidence import read_local_ipmi_fru
from .logs import (
    LocalIpmiSelCleanupAdapter,
    execute_log_cleanup,
    preserve_preclean_logs,
)
from .models import (
    FinalDisposition,
    OperationStatus,
    RunRecord,
    ServerRecord,
    run_completed_event,
    run_progress_event,
    run_started_event,
    utc_now,
)
from .orchestrator import ProductionOrchestrator, WorkflowError, WorkflowStage
from .platform import PlatformProbe, detect_platform, read_linux_dmi
from .runner import load_runner
from .reports import generate_human_reports, report_manifest_complete
from .safety import MutationGate
from .secrets import assert_no_sensitive_fields
from .stress_profiles import (
    ExecutorProfileRunner,
    MonitoredStressRunner,
    ProgressCallback,
    StressProfileError,
    resolve_profile,
)
from .sync import StoreForwardQueue


class ProductionWorkflowError(RuntimeError):
    pass


class CommandExecutor(Protocol):
    def run(self, tool: str, arguments: tuple[str, ...], *, timeout_seconds: int) -> dict[str, Any]: ...


_TOOLS = {
    "dmidecode": Path("/usr/sbin/dmidecode"),
    "dmesg": Path("/usr/bin/dmesg"),
    "ethtool": Path("/usr/sbin/ethtool"),
    "findmnt": Path("/usr/bin/findmnt"),
    "ip": Path("/usr/sbin/ip"),
    "ipmitool": Path("/usr/bin/ipmitool"),
    "lsblk": Path("/usr/bin/lsblk"),
    "lscpu": Path("/usr/bin/lscpu"),
    "lspci": Path("/usr/bin/lspci"),
    "modprobe": Path("/usr/sbin/modprobe"),
    "nvme": Path("/usr/sbin/nvme"),
    "smartctl": Path("/usr/sbin/smartctl"),
    "systemctl": Path("/usr/bin/systemctl"),
    # The explicit system path prevents the inherited /usr/local CNGPU shim
    # from ever satisfying the production workload command.
    "stress-ng": Path("/usr/bin/stress-ng"),
}


class FixedCommandExecutor:
    """Execute only allowlisted absolute binaries, never through a shell."""

    def run(self, tool: str, arguments: tuple[str, ...], *, timeout_seconds: int) -> dict[str, Any]:
        binary = _TOOLS.get(tool)
        if binary is None:
            raise ProductionWorkflowError(f"Tool is outside the production allowlist: {tool}")
        if timeout_seconds <= 0 or timeout_seconds > 7200:
            raise ProductionWorkflowError("Command timeout is outside the production safety range")
        command = [str(binary), *arguments]
        if not binary.is_file() or not os.access(binary, os.X_OK):
            return {
                "tool": tool,
                "command": command,
                "status": "UNAVAILABLE",
                "exit_code": None,
                "stdout": "",
                "stderr": "tool not installed at the approved absolute path",
                "started_at_utc": utc_now(),
                "completed_at_utc": utc_now(),
            }
        started = utc_now()
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
            )
        except subprocess.TimeoutExpired as exc:
            return {
                "tool": tool,
                "command": command,
                "status": "TIMED_OUT",
                "exit_code": None,
                "stdout": str(exc.stdout or ""),
                "stderr": str(exc.stderr or ""),
                "started_at_utc": started,
                "completed_at_utc": utc_now(),
            }
        except OSError as exc:
            return {
                "tool": tool,
                "command": command,
                "status": "UNAVAILABLE",
                "exit_code": None,
                "stdout": "",
                "stderr": type(exc).__name__,
                "started_at_utc": started,
                "completed_at_utc": utc_now(),
            }
        return {
            "tool": tool,
            "command": command,
            "status": "PASS" if completed.returncode == 0 else "FAILED",
            "exit_code": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "started_at_utc": started,
            "completed_at_utc": utc_now(),
        }


@dataclass(frozen=True)
class ProductionConfig:
    primary_root: Path = Path("/CN_STRESS_RESULTS")
    runner_config: Path = Path("/etc/cnserverops/runner.json")
    central_config: Path = Path("/etc/cnserverops/central.json")
    queue_database: Path = Path("/var/lib/cnserverops/production/sync.sqlite3")
    artifact_queue_database: Path = Path("/var/lib/cnserverops/production/artifacts.sqlite3")
    # Backwards-compatible custom knobs.  STANDARD execution is selected from
    # stress_profiles.py; these defaults are kept consistent with its 120s
    # CPU and memory phases so configuration receipts do not advertise the
    # old 60s values.
    cpu_seconds: int = 120
    memory_seconds: int = 120
    sel_cleanup_enabled: bool = True
    default_profile: str = "STANDARD"
    reports_enabled: bool = True
    artifact_sync_enabled: bool = True
    handoff_policy: Mapping[str, Any] | None = None
    bmc_auth_policy: Mapping[str, Any] | None = None
    # Windows archiving is performed by Central after binary artifact upload;
    # the Linux runner never assumes a /mnt/host/c mount.
    windows_archive_root: Path | None = None
    firmware_current_proof: Path = Path("/etc/cnserverops/firmware-current-proof.json")
    # Optional immutable-runner pointer to a Central/official catalog snapshot.
    # The snapshot is data, not executable code, and is never treated as a
    # model-specific fallback.  Missing/unreadable data remains UNVERIFIED.
    firmware_catalog_path: Path = Path("/etc/cnserverops/firmware-catalog.json")
    firmware_cache_root: Path = Path("/var/lib/cnserverops/firmware/asus-generic-validation")
    # Optional root-owned record for a verified ASUS Linux updater.  Missing
    # config is normal and leaves local candidates non-selectable.
    local_firmware_tools_path: Path = Path("/etc/cnserverops/asus-local-firmware-tools.json")
    firmware_live_discovery_enabled: bool = True
    firmware_discovery_timeout_seconds: int = 15
    bmc_auth_change_marker: Path = Path("/var/lib/cnserverops/bmc-auth-change-state.json")

    @classmethod
    def load(cls, path: Path | None = None) -> "ProductionConfig":
        if path is None or not path.exists():
            return cls()
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ProductionWorkflowError("Production configuration must be a JSON object")
        cpu_seconds = int(payload.get("cpu_seconds", 120))
        memory_seconds = int(payload.get("memory_seconds", 120))
        if not 10 <= cpu_seconds <= 3600 or not 10 <= memory_seconds <= 3600:
            raise ProductionWorkflowError("Workload duration must be between 10 and 3600 seconds")
        default_profile = str(payload.get("default_profile") or "STANDARD").upper()
        try:
            resolve_profile(default_profile)
        except StressProfileError as exc:
            raise ProductionWorkflowError(str(exc)) from exc
        return cls(
            primary_root=Path(str(payload.get("primary_root") or "/CN_STRESS_RESULTS")),
            runner_config=Path(str(payload.get("runner_config") or "/etc/cnserverops/runner.json")),
            central_config=Path(str(payload.get("central_config") or "/etc/cnserverops/central.json")),
            queue_database=Path(str(payload.get("queue_database") or "/var/lib/cnserverops/production/sync.sqlite3")),
            artifact_queue_database=Path(
                str(payload.get("artifact_queue_database") or "/var/lib/cnserverops/production/artifacts.sqlite3")
            ),
            cpu_seconds=cpu_seconds,
            memory_seconds=memory_seconds,
            sel_cleanup_enabled=bool(payload.get("sel_cleanup_enabled", True)),
            default_profile=default_profile,
            reports_enabled=bool(payload.get("reports_enabled", True)),
            artifact_sync_enabled=bool(payload.get("artifact_sync_enabled", True)),
            handoff_policy=dict(payload.get("handoff_policy") or {}),
            bmc_auth_policy=dict(payload.get("bmc_auth_policy") or {}),
            # Central owns both Windows archive roots.  Older per-SSD
            # configuration may contain ``windows_archive_root``; it is
            # intentionally ignored so delivery never depends on a WSL mount.
            windows_archive_root=None,
            firmware_current_proof=Path(str(payload.get("firmware_current_proof") or "/etc/cnserverops/firmware-current-proof.json")),
            firmware_catalog_path=Path(str(payload.get("firmware_catalog_path") or "/etc/cnserverops/firmware-catalog.json")),
            firmware_cache_root=Path(str(payload.get("firmware_cache_root") or "/var/lib/cnserverops/firmware/asus-generic-validation")),
            local_firmware_tools_path=Path(str(payload.get("local_firmware_tools_path") or "/etc/cnserverops/asus-local-firmware-tools.json")),
            firmware_live_discovery_enabled=bool(payload.get("firmware_live_discovery_enabled", True)),
            firmware_discovery_timeout_seconds=max(5, min(60, int(payload.get("firmware_discovery_timeout_seconds", 15)))),
            bmc_auth_change_marker=Path(str(payload.get("bmc_auth_change_marker") or "/var/lib/cnserverops/bmc-auth-change-state.json")),
        )


def detect_current_platform_and_identity(
    *,
    dmi_root: Path = Path("/sys/class/dmi/id"),
    fru_reader: Callable[..., Mapping[str, Any]] = read_local_ipmi_fru,
) -> tuple[PlatformProbe, dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Vendor detection always precedes route selection or menu exposure."""
    probe = read_linux_dmi(dmi_root)
    platform = detect_platform(probe)
    fru = dict(fru_reader())
    identity = derive_machine_identity(platform, probe, chassis_fru=fru.get("fru") or None)
    return probe, platform, identity, fru


class ProductionWorkflow:
    def __init__(
        self,
        config: ProductionConfig,
        *,
        runtime_version: str,
        executor: CommandExecutor | None = None,
        dmi_root: Path = Path("/sys/class/dmi/id"),
        fru_reader: Callable[..., Mapping[str, Any]] = read_local_ipmi_fru,
        cleanup_adapter_factory: Callable[[], Any] = LocalIpmiSelCleanupAdapter,
        collector_client: Any | None = None,
        stress_runner: Any | None = None,
        progress_callback: ProgressCallback | None = None,
    ) -> None:
        self.config = config
        self.runtime_version = runtime_version
        self.executor = executor or FixedCommandExecutor()
        self.dmi_root = dmi_root
        self.fru_reader = fru_reader
        self.cleanup_adapter_factory = cleanup_adapter_factory
        self._collector_client_override = collector_client
        self.stress_runner = stress_runner or (
            MonitoredStressRunner() if isinstance(self.executor, FixedCommandExecutor) else ExecutorProfileRunner()
        )
        self.progress_callback = progress_callback

    def inventory_only(self, *, allow_bmc_provisioning: bool = False) -> dict[str, Any]:
        """Collect current/local inventory without workload or destructive actions.

        The normal inventory/menu path is read-only with respect to BMC
        authentication. A caller with explicit authorization for firmware or
        diagnostics may opt into the bounded ASUS first-login provisioning
        probe; this keeps ordinary inventory independent of BMC credentials.
        """
        probe, platform, identity, fru = detect_current_platform_and_identity(
            dmi_root=self.dmi_root, fru_reader=self.fru_reader
        )
        try:
            runner = load_runner(self.config.runner_config)
        except Exception:
            runner = {"runner_id": "NOT_CONFIGURED"}
        pending = self._load_pending_firmware()
        pending_quarantine = self._quarantine_foreign_pending(
            pending,
            identity=identity,
            runner_id=str(runner.get("runner_id") or ""),
        )
        enrollment = reconcile_server_enrollment(
            self.config.primary_root,
            identity,
            runner_id=str(runner.get("runner_id") or "NOT_CONFIGURED"),
            server_specific_paths=self._server_specific_enrollment_paths(),
        )
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output = self.config.primary_root / "inventory" / f"INV-{stamp}"
        output.mkdir(parents=True, exist_ok=False)
        inventory = self._collect_inventory(
            output,
            identity=identity,
            platform=platform,
            probe=probe,
            run_id="",
            runner_id=str(runner.get("runner_id") or "NOT_CONFIGURED"),
        )
        bmc_discovery = self._discover_bmc_auth(
            inventory.get("normalized") or {},
            identity,
            exclude_run_id="",
            read_only=not allow_bmc_provisioning,
        )
        if inventory.get("normalized"):
            inventory["normalized"]["bmc_auth_state"] = bmc_discovery["state"]
            _atomic_json(output / "normalized-inventory.json", inventory["normalized"])
        result = {
            "schema_version": 1,
            "mode": "INVENTORY_ONLY",
            "created_at_utc": utc_now(),
            "platform": platform,
            "probe": probe.to_dict(),
            "identity": identity,
            "enrollment": enrollment,
            "foreign_pending_quarantine": pending_quarantine or {"status": "NOT_APPLICABLE"},
            "local_fru_collection": _public_fru_status(fru),
            "bmc_auth_discovery": bmc_discovery,
            "inventory": inventory["summary"],
            "normalized_inventory": inventory.get("normalized", {}),
            "workload_started": False,
            "sel_cleanup_started": False,
            "vendor_specific_workflow_invoked": False,
            "output_directory": str(output),
            "status_summary": {
                "schema_version": 1,
                "overall": "PASS",
                "collection": "PASS",
                "central_sync": "NOT_RUN",
                "reports": "NOT_REQUESTED",
                "reason": [],
                "reason_text": "Safe inventory completed; no workload, cleanup, or mutation was requested.",
                "workflow_mode": "INVENTORY_ONLY",
            },
        }
        assert_no_sensitive_fields(result)
        _atomic_json(output / "inventory-result.json", result)
        return result

    def reset_bmc(self, *, operator_authorized: bool = False) -> dict[str, Any]:
        """Run the explicit ASUS local KCS factory/default BMC recovery.

        This is intentionally a separate technician action rather than a
        side-effect of inventory or firmware status.  It is the validated
        ASMB11/ASMB12 ``raw 0x32 0x66`` recovery path, which can reset BMC
        LAN/account configuration and may therefore change the management IP.
        The method preserves the read-only BMC/SEL/account evidence first,
        binds the mutation gate to the live ASUS identity, and never accepts,
        creates, or prints a password.
        """
        if not operator_authorized:
            raise ProductionWorkflowError("BMC reset requires explicit operator authorization")
        if self._load_pending_firmware():
            raise ProductionWorkflowError(
                "BMC reset is refused while a firmware resume checkpoint is pending"
            )

        probe, platform, identity, _fru = detect_current_platform_and_identity(
            dmi_root=self.dmi_root, fru_reader=self.fru_reader
        )
        if platform.get("platform_id") != "ASUS_SERVER" or platform.get("vendor") != "ASUS":
            raise ProductionWorkflowError("BMC reset is available only on an ASUS server")
        if not identity.get("resumable") or not identity.get("fingerprint_sha256"):
            raise ProductionWorkflowError("BMC reset requires trustworthy current/local identity")

        try:
            runner = load_runner(self.config.runner_config)
            runner_id = str(runner.get("runner_id") or "")
        except Exception:
            runner = {"runner_id": "CNSSD-UNCONFIGURED"}
            runner_id = "CNSSD-UNCONFIGURED"
        if not runner_id:
            runner_id = "CNSSD-UNCONFIGURED"

        server = ServerRecord.from_identity(identity)
        run = RunRecord.start(
            server,
            runner_id=runner_id,
            runtime_version=self.runtime_version,
            boot_id=str(identity.get("boot_id") or read_linux_boot_id()),
            workflow_mode="BMC_FACTORY_RECOVERY",
            test_profile="BMC_RESET",
        )
        run_dir = self.config.primary_root / "runs" / run.run_id
        run_dir.mkdir(parents=True, exist_ok=False)
        _atomic_json(
            run_dir / "operator-launch.json",
            {
                "schema_version": 1,
                "mode": "BMC_FACTORY_RECOVERY",
                "selected_at_utc": utc_now(),
                "vendor_detected_before_selection": True,
                "platform_id": platform.get("platform_id"),
                "runtime_version": self.runtime_version,
                "automatic_action_at_boot": False,
                "operator_authorized": True,
                "firmware_or_power_actions": "BMC_FACTORY_DEFAULT_ONLY",
                "sensitive_material_exposed": False,
            },
        )
        _atomic_json(run_dir / "identity-before.json", identity)

        # Intake-mode collection keeps this action read-only apart from the
        # explicitly gated BMC recovery and avoids SMART/ethtool work.
        inventory = self._collect_inventory(
            run_dir / "evidence-before",
            identity=identity,
            platform=platform,
            probe=probe,
            run_id=run.run_id,
            runner_id=runner_id,
            intake_mode=True,
        )
        normalized = inventory.get("normalized") if isinstance(inventory.get("normalized"), Mapping) else {}
        normalized = dict(normalized)

        # The reset path does not resolve or download firmware.  The recovery
        # capability only needs exact BMC-generation evidence from the live
        # normalized inventory; the empty generic plan deliberately prevents a
        # reset option from becoming an update option.
        capability_plan: dict[str, Any] = {
            "schema_version": 1,
            "policy": "BMC_FACTORY_RECOVERY_ONLY_NO_FIRMWARE_MUTATION",
            "generic_asus_firmware_engine": {"platform": {}},
        }
        capability = asus_bmc_recovery_capability(
            normalized_inventory=normalized,
            firmware_plan=capability_plan,
        )
        _atomic_json(run_dir / "bmc-recovery-capability.json", capability)

        if not bool(capability.get("supported")):
            recovery = {
                "schema_version": 1,
                "status": "UNSUPPORTED",
                "supported": False,
                "method": str(capability.get("method") or "NONE"),
                "reset_requested": False,
                "reason": str(capability.get("reason") or "NO_VALIDATED_LOCAL_RECOVERY_FOR_THIS_BMC_GENERATION"),
                "sensitive_material_exposed": False,
            }
        else:
            gate = MutationGate(
                authorized=True,
                lab_mode=True,
                approval_id=f"OPERATOR-BMC-RESET-{run.run_id}",
                machine_fingerprint_sha256=str(identity.get("fingerprint_sha256") or ""),
                vendor="ASUS",
                model=str(identity.get("model") or ""),
                system_serial=str(identity.get("primary_serial") or ""),
                run_id=run.run_id,
                component="BMC",
                allowed_actions=frozenset({"BMC_FACTORY_RECOVERY"}),
                expires_at_utc=(datetime.now(timezone.utc) + timedelta(minutes=20)).isoformat(),
            )
            generation = str(capability.get("bmc_generation") or "").upper()
            recovery_runner = recover_asmb12_bmc if generation == "ASMB12" else recover_asus_bmc
            recovery = recovery_runner(
                executor=self.executor,
                identity=identity,
                normalized_inventory=normalized,
                firmware_plan=capability_plan,
                mutation_gate=gate,
                run_id=run.run_id,
                evidence_dir=run_dir / "bmc-recovery",
            ).to_dict()
            recovery["mutation_gate"] = gate.public_record()
            _atomic_json(run_dir / "bmc-recovery-gate.json", gate.public_record())

        status = str(recovery.get("status") or "UNVERIFIED")
        result = {
            "schema_version": 1,
            "operation": "BMC_FACTORY_RECOVERY",
            "status": status,
            "mutation_started": bool(recovery.get("reset_requested")),
            "vendor": "ASUS",
            "model": str(identity.get("model") or ""),
            "system_serial": str(identity.get("primary_serial") or ""),
            "bmc_generation": str(capability.get("bmc_generation") or "UNKNOWN"),
            "method": str(recovery.get("method") or capability.get("method") or "NONE"),
            "bmc_ip_before": str(recovery.get("bmc_ip_before") or ""),
            "bmc_ip_after": str(recovery.get("bmc_ip_after") or ""),
            "bmc_endpoint_status": str(recovery.get("bmc_endpoint_status") or "NOT_TESTED"),
            "firmware_before": str(recovery.get("firmware_before") or ""),
            "firmware_after": str(recovery.get("firmware_after") or ""),
            "kcs_before": str(recovery.get("kcs_before") or "NOT_TESTED"),
            "kcs_after": str(recovery.get("kcs_after") or "NOT_TESTED"),
            "reason": str(recovery.get("reason") or ""),
            "sensitive_material_exposed": False,
        }
        _atomic_json(run_dir / "bmc-reset-result.json", result)
        _atomic_json(
            run_dir / "run.json",
            {
                "schema_version": 2,
                "server": server.to_dict(),
                "run": run.to_dict(),
                "platform": platform,
                "identity": identity,
                "inventory_summary": inventory.get("summary") or {},
                "bmc_recovery_capability": capability,
                "bmc_recovery": recovery,
                "result": result,
                "safety": {
                    "bmc_reset_started": bool(recovery.get("reset_requested")),
                    "firmware_mutation_started": False,
                    "host_reboot_started": False,
                    "power_action_started": False,
                    "sel_cleanup_started": False,
                },
                "sensitive_material_exposed": False,
            },
        )
        response = {
            "schema_version": 1,
            "run": run.to_dict(),
            "server": server.to_dict(),
            "platform": platform,
            "identity": identity,
            "inventory": inventory.get("summary") or {},
            "bmc_recovery_capability": capability,
            "recovery": recovery,
            "result": result,
            "run_directory": str(run_dir),
            "central": {"status": "NOT_REQUESTED", "reason": "MAINTENANCE_ACTION_LOCAL_EVIDENCE_ONLY"},
            "sensitive_material_exposed": False,
        }
        assert_no_sensitive_fields(response)
        return response

    def firmware_status_only(self) -> dict[str, Any]:
        """Read-only firmware resolver/status path used by console option 5.

        It intentionally reuses safe inventory and never calls a package
        downloader, executor, mutation gate, reset, reboot, or Redfish write.
        """
        result = self.inventory_only()
        inventory = {"normalized": result.get("normalized_inventory") or {}, "raw": {}}
        plan = self._firmware_plan(inventory, result.get("bmc_auth_discovery") or {})
        return {"inventory": result, "firmware": plan, "mutation_started": False}

    def firmware_update_only(self, *, operator_authorized: bool = False) -> dict[str, Any]:
        """Run Option 5 through the same durable firmware state machine.

        Firmware-only intentionally skips CPU/RAM/SEL work, but it is still a
        real authoritative ``RUN-*`` lifecycle: Central gets RUN_STARTED and
        RUN_COMPLETED events, firmware proof artifacts are uploaded, and a
        temporary BMC account is handed off only after those bytes are
        verified.  A reboot checkpoint is resumed automatically by the same
        systemd service used by Options 1 and 2.
        """
        pending = self._load_pending_firmware()
        if pending:
            # A cloned/moved SSD must not attempt to resume another server's
            # mutation.  Resolve current identity first and quarantine only a
            # positively identified foreign checkpoint; incomplete identity
            # remains fail-closed in the normal resume validator.
            try:
                _probe, _platform, current_identity, _fru = detect_current_platform_and_identity(
                    dmi_root=self.dmi_root, fru_reader=self.fru_reader
                )
                current_runner = load_runner(self.config.runner_config)
            except Exception:
                current_identity, current_runner = {}, {}
            foreign_pending = self._quarantine_foreign_pending(
                pending,
                identity=current_identity,
                runner_id=str(current_runner.get("runner_id") or ""),
            )
            if foreign_pending is not None:
                pending = None
        if pending:
            return self._resume_pending_firmware(pending)
        inventory_result = self.inventory_only()  # always read-only before exact planning
        platform = dict(inventory_result.get("platform") or {})
        identity = dict(inventory_result.get("identity") or {})
        if platform.get("platform_id") != "ASUS_SERVER" or not identity.get("resumable"):
            raise ProductionWorkflowError("Firmware Update requires a trusted currently detected ASUS server")
        runner = load_runner(self.config.runner_config)
        probe = PlatformProbe.from_mapping(inventory_result.get("probe") or {})
        inventory: dict[str, Any] = {"normalized": inventory_result.get("normalized_inventory") or {}, "raw": {}}
        discovery: dict[str, Any] = dict(inventory_result.get("bmc_auth_discovery") or {})
        orchestrator = ProductionOrchestrator(self.config.primary_root, runtime_version=self.runtime_version)
        context = orchestrator.start(
            platform=platform,
            identity=identity,
            runner_id=runner["runner_id"],
            workflow_mode="FIRMWARE_ONLY",
            test_profile="FIRMWARE_ONLY",
        )
        run_id = str(context["run"]["run_id"])
        run_dir = self.config.primary_root / "runs" / run_id
        client, central_runtime = self._collector_client()
        queue = StoreForwardQueue(self.config.queue_database)
        started = run_started_event(
            RunRecord.from_dict(context["run"]),
            ServerRecord.from_identity(identity),
            bmc={"access_state": str(discovery.get("state") or BmcAuthState.BMC_AUTH_UNAVAILABLE.value)},
            runner={
                "runner_id": runner["runner_id"],
                "local_runner_uuid": runner.get("local_runner_uuid", ""),
                "storage_fingerprint_sha256": runner.get("storage_fingerprint_sha256", ""),
            },
        )
        _atomic_json(run_dir / "central-run-started.json", self._enqueue_and_drain(queue, started, run_dir / "run.json", client))
        context = orchestrator.transition(
            context, identity=identity, next_stage=WorkflowStage.CAPABILITY_DISCOVERY,
            details={"bmc_auth_discovery": discovery, "workflow": "FIRMWARE_ONLY"},
        )
        context = orchestrator.transition(
            context, identity=identity, next_stage=WorkflowStage.INVENTORY,
            details={"inventory_only": True, "system_serial": inventory["normalized"].get("system_serial", "")},
        )
        plan = self._firmware_plan(inventory, discovery)
        _atomic_json(run_dir / "firmware-plan.json", plan)
        context = orchestrator.transition(
            context, identity=identity, next_stage=WorkflowStage.FIRMWARE_PLAN, details=plan,
        )
        execution: dict[str, Any]
        readiness = str(plan.get("readiness") or "UNVERIFIED")
        if readiness == "CURRENT_VERIFIED":
            execution = {"status": "CURRENT_VERIFIED", "reason": "NO_UPDATE_REQUIRED", "mutation_started": False}
        elif not operator_authorized:
            execution = {"status": "OPERATOR_CONFIRMATION_REQUIRED", "mutation_started": False}
        elif readiness != "UPDATE_REQUIRED":
            execution = {"status": readiness, "reason": "EXACT_TARGET_NOT_RESOLVED", "mutation_started": False}
        else:
            if _firmware_requires_authenticated_bmc(plan):
                inventory, discovery, recovery = self._ensure_authenticated_firmware_access(
                    run_dir=run_dir,
                    identity=identity,
                    platform=platform,
                    probe=probe,
                    inventory=inventory,
                    firmware=plan,
                    run_id=run_id,
                    runner_id=runner["runner_id"],
                    discovery=discovery,
                )
            else:
                recovery = {
                    "status": "NOT_REQUIRED",
                    "reason": "SELECTED_LOCAL_TRANSPORT_DOES_NOT_REQUIRE_BMC_AUTH",
                    "mutation_started": False,
                    "sensitive_material_exposed": False,
                }
            _atomic_json(run_dir / "bmc-recovery-path.json", recovery)
            _atomic_json(run_dir / "bmc-auth-discovery.json", discovery)
            if _firmware_requires_authenticated_bmc(plan):
                plan = self._firmware_plan(inventory, discovery)
                _atomic_json(run_dir / "firmware-plan.json", plan)
            update_components = [
                item for item in plan.get("components") or []
                if isinstance(item, Mapping) and str(item.get("status") or "") == "UPDATE_REQUIRED"
            ]
            if not update_components:
                execution = {"status": str(plan.get("readiness") or "UNVERIFIED"), "mutation_started": False}
            else:
                selected = update_components[0]
                gate = MutationGate(
                    authorized=True,
                    lab_mode=True,
                    approval_id=f"OPERATOR-FIRMWARE-{run_id}",
                    machine_fingerprint_sha256=str(identity.get("fingerprint_sha256") or ""),
                    vendor="ASUS",
                    model=str(identity.get("model") or ""),
                    system_serial=str(identity.get("primary_serial") or ""),
                    run_id=run_id,
                    component=str(selected.get("component") or "").upper(),
                    target_version=str(selected.get("target") or ""),
                    allowed_actions=frozenset({"FIRMWARE_APPLY"}),
                    expires_at_utc=(datetime.now(timezone.utc) + timedelta(minutes=45)).isoformat(),
                )
                context = orchestrator.transition(
                    context,
                    identity=identity,
                    next_stage=WorkflowStage.FIRMWARE_APPLY,
                    mutation_gate=gate,
                    details={"component": gate.component, "target_version": gate.target_version},
                )
                execution = self._execute_firmware_lifecycle(
                    run_dir=run_dir,
                    identity=identity,
                    platform=platform,
                    probe=probe,
                    runner_id=str(runner["runner_id"]),
                    inventory=inventory,
                    bmc_discovery=discovery,
                    firmware=plan,
                    run_id=run_id,
                )
                if str(execution.get("status") or "") == "REBOOT_REQUIRED":
                    context = orchestrator.transition(
                        context, identity=identity, next_stage=WorkflowStage.REBOOT_PENDING, details=execution,
                        firmware_task_identity=str(execution.get("task_id") or ""),
                    )
                    pending = self._write_pending_firmware(
                        run_dir=run_dir,
                        identity=identity,
                        plan=plan,
                        execution=execution,
                        bmc_auth_changed=bmc_auth_change_required(discovery),
                        runner_id=runner["runner_id"],
                        workflow_mode="FIRMWARE_ONLY",
                        profile_id="FIRMWARE_ONLY",
                    )
                    reboot = request_controlled_reboot(
                        executor=self.executor, primary_root=self.config.primary_root, pending=pending,
                    )
                    execution["reboot"] = reboot
                    _atomic_json(run_dir / "firmware-execution.json", execution)
                    return {
                        "status": reboot["status"], "firmware": plan, "execution": execution,
                        "run": context["run"], "run_directory": str(run_dir),
                        "mutation_started": bool(execution.get("mutation_started")),
                    }
                if str(execution.get("status") or "") == "UPDATED_VERIFIED":
                    context = orchestrator.transition(
                        context, identity=identity, next_stage=WorkflowStage.POST_UPDATE_VERIFY, details=execution,
                    )

        _atomic_json(run_dir / "firmware-execution.json", execution)
        return self._complete_firmware_only_run(
            orchestrator=orchestrator,
            context=context,
            identity=identity,
            inventory=inventory,
            discovery=discovery,
            plan=plan,
            execution=execution,
            run_dir=run_dir,
            client=client,
            central_runtime=central_runtime,
            queue=queue,
            bmc_auth_changed=bmc_auth_change_required(discovery),
            resumed=False,
        )

    def _complete_firmware_only_run(
        self,
        *,
        orchestrator: ProductionOrchestrator,
        context: dict[str, Any],
        identity: Mapping[str, Any],
        inventory: Mapping[str, Any],
        discovery: Mapping[str, Any],
        plan: Mapping[str, Any],
        execution: Mapping[str, Any],
        run_dir: Path,
        client: Any | None,
        central_runtime: Mapping[str, Any],
        queue: StoreForwardQueue,
        bmc_auth_changed: bool,
        resumed: bool,
    ) -> dict[str, Any]:
        """Finalize the single authoritative Option 5 run.

        This is shared by the initial and post-reboot paths.  In particular,
        evidence, report hashes, Central/Windows archive delivery, and the
        final BMC handoff occur in that order for either path.
        """
        run_id = str(context.get("run", {}).get("run_id") or run_dir.name)
        terminal_ok = str(execution.get("status") or "") in {"CURRENT_VERIFIED", "UPDATED_VERIFIED"}
        reasons: list[Reason] = []
        current_stage = str(context.get("run", {}).get("current_stage") or "")
        if not terminal_ok:
            if current_stage != WorkflowStage.BLOCKED.value:
                context = orchestrator.transition(
                    context,
                    identity=identity,
                    next_stage=WorkflowStage.BLOCKED,
                    details={"firmware_execution": dict(execution)},
                )
            reasons.append(
                Reason(
                    "FIRMWARE_LIFECYCLE_INCOMPLETE",
                    ReasonSeverity.FAIL,
                    "Firmware-only lifecycle did not reach a verified terminal state.",
                )
            )
        elif current_stage != WorkflowStage.FINALIZE.value:
            context = orchestrator.transition(
                context,
                identity=identity,
                next_stage=WorkflowStage.FINALIZE,
                details=dict(execution),
            )
        context = orchestrator.finalize(context, reasons, identity=identity)
        final_run = RunRecord.from_dict(context["run"])
        normalized = dict(inventory.get("normalized") or {})
        statuses = self._normalized_result(
            context,
            central_runtime,
            bmc_auth_state=str(discovery.get("state") or BmcAuthState.BMC_AUTH_UNAVAILABLE.value),
            firmware_status=(
                "UPDATED_VERIFIED"
                if str(execution.get("status") or "") == "UPDATED_VERIFIED"
                else "CURRENT"
                if terminal_ok
                else str(execution.get("status") or "UNVERIFIED")
            ),
            system_diagnostics_status="NOT_REQUESTED",
        )
        statuses.update(
            {
                "collection": "PASS" if normalized else "FAIL",
                "serial_inventory": "PASS" if normalized.get("system_serial") else "FAIL",
                "firmware_update": "PASS" if terminal_ok else "FAIL",
                "cpu": "NOT_REQUESTED",
                "ram": "NOT_REQUESTED",
                "combined": "NOT_REQUESTED",
                "system_diagnostics": "NOT_REQUESTED",
                "sel": "NOT_REQUESTED",
                "runner_storage_smart": (inventory.get("summary") or {}).get("runner_storage", {}).get("smart_status", "UNKNOWN"),
            }
        )
        handoff_policy_payload = dict(self.config.handoff_policy or {})
        required_firmware_only = list(
            handoff_policy_payload.get(
                "required_for_firmware_only",
                ("firmware_update", "reports", "artifact_delivery", "primary_archive"),
            )
        )
        for capability in ("firmware_update", "reports", "artifact_delivery", "primary_archive"):
            if capability not in required_firmware_only:
                required_firmware_only.append(capability)
        handoff_policy_payload["required_for_production"] = required_firmware_only
        handoff_policy = HandoffPolicy.from_mapping(handoff_policy_payload)
        handoff = evaluate_handoff(
            statuses,
            workflow_mode="FIRMWARE_ONLY",
            policy=handoff_policy,
            bmc_auth_changed=bmc_auth_changed,
            bmc_handoff_status="PENDING" if bmc_auth_changed else "NOT_REQUIRED",
        )
        statuses.update(
            {
                "overall": handoff["overall"],
                "handoff_status": handoff["handoff_status"],
                "handoff_policy": handoff,
                "readiness": _public_readiness_label(
                    workflow_mode="FIRMWARE_ONLY",
                    overall=handoff["overall"],
                ),
            }
        )
        finalization = build_finalization_status(
            sel_cleanup="NOT_REQUESTED",
            final_sanity="NOT_REQUESTED",
            bmc_soft_reset=BmcSoftResetCapability(),
            evidence_saved=True,
            identity_reverified=True,
            firmware_reverified=terminal_ok,
        )
        evidence_manifest = self._evidence_manifest([path for path in run_dir.rglob("*") if path.is_file()])
        _atomic_json(run_dir / "evidence-manifest.json", evidence_manifest)
        report_manifest = (
            generate_human_reports(
                run_dir,
                inventory=normalized,
                run=final_run.to_dict(),
                result=statuses,
                firmware=plan,
                tests={"status": "NOT_REQUESTED_FIRMWARE_ONLY"},
                finalization=finalization,
                central={"artifact_status": "LOCAL_COMPLETE", **dict(central_runtime)},
                evidence_manifest=evidence_manifest,
            )
            if self.config.reports_enabled and normalized
            else {"artifacts": []}
        )
        artifact_sync = self._sync_artifacts(run_id, report_manifest, client)
        windows_archive = self._central_archive_summary(artifact_sync)
        statuses["reports"] = "PASS" if report_manifest_complete(report_manifest) else "FAIL"
        statuses["artifact_delivery"] = (
            "PASS" if str(artifact_sync.get("status") or "") == "SYNCED" else str(artifact_sync.get("status") or "PENDING_UPLOAD")
        )
        statuses["primary_archive"] = (
            "PASS" if str(windows_archive.get("primary_status") or "") == "SYNCED" else "PENDING_UPLOAD"
        )
        handoff = evaluate_handoff(
            statuses,
            workflow_mode="FIRMWARE_ONLY",
            policy=handoff_policy,
            bmc_auth_changed=bmc_auth_changed,
            bmc_handoff_status="PENDING" if bmc_auth_changed else "NOT_REQUIRED",
        )
        statuses.update(
            {
                "overall": handoff["overall"],
                "handoff_status": handoff["handoff_status"],
                "handoff_policy": handoff,
                "windows_archive": windows_archive,
                # The first evaluation happens before report/archive fields
                # exist.  Keep Option 5's public readiness synchronized with
                # the final delivery-gated evaluation as well.
                "readiness": _public_readiness_label(
                    workflow_mode="FIRMWARE_ONLY",
                    overall=handoff["overall"],
                ),
            }
        )
        # Option 5's complete human-report bundle is an immutable
        # *pre-handoff* deliverable.  The final factory/default BMC action is
        # allowed only after this exact bundle has been uploaded and Central
        # has returned hash-verified primary-archive receipts for every file.
        # The BMC handoff outcome is published later as a small, immutable
        # post-handoff addendum instead of rewriting the report bytes after a
        # credential reset.
        final_report_manifest: dict[str, Any] = {}
        final_report_sync: dict[str, Any] = {"status": "NOT_REQUESTED"}
        if self.config.reports_enabled and normalized:
            final_report_manifest = generate_human_reports(
                run_dir,
                inventory=normalized,
                run=final_run.to_dict(),
                result=statuses,
                firmware=plan,
                tests={"status": "NOT_REQUESTED_FIRMWARE_ONLY"},
                finalization=finalization,
                central={"artifact_status": statuses.get("artifact_status", "LOCAL_COMPLETE"), **dict(central_runtime)},
                evidence_manifest=evidence_manifest,
                report_variant="FINAL_PRE_HANDOFF",
            )
            final_report_sync = self._sync_artifacts(run_id, final_report_manifest, client)
            report_manifest = dict(report_manifest)
            report_manifest["artifacts"] = list(report_manifest.get("artifacts") or []) + list(
                final_report_manifest.get("artifacts") or []
            )
            final_archive = self._central_archive_summary(final_report_sync)
            statuses["artifact_delivery"] = (
                "PASS"
                if str(final_report_sync.get("status") or "").upper() == "SYNCED"
                else str(final_report_sync.get("status") or "PENDING_UPLOAD")
            )
            statuses["primary_archive"] = (
                "PASS" if str(final_archive.get("primary_status") or "").upper() == "SYNCED" else "PENDING_UPLOAD"
            )
            statuses["windows_archive"] = final_archive
        statuses["final_report_delivery"] = final_report_sync
        handoff = evaluate_handoff(
            statuses,
            workflow_mode="FIRMWARE_ONLY",
            policy=handoff_policy,
            bmc_auth_changed=bmc_auth_changed,
            bmc_handoff_status="PENDING" if bmc_auth_changed else "NOT_REQUIRED",
        )
        statuses.update(
            {
                "overall": handoff["overall"],
                "handoff_status": handoff["handoff_status"],
                "handoff_policy": handoff,
                "readiness": _public_readiness_label(
                    workflow_mode="FIRMWARE_ONLY",
                    overall=handoff["overall"],
                ),
            }
        )
        if bmc_auth_changed:
            expected_bmc = next(
                (
                    str(item.get("after") or item.get("target") or item.get("current") or item.get("before") or "")
                    for item in plan.get("components") or []
                    if isinstance(item, Mapping) and str(item.get("component") or "").upper() == "BMC"
                ),
                "",
            )
            # Option 5 must obey the same ordering as Options 1 and 2:
            # reports, Central event/artifact delivery and the primary
            # Windows archive are proven before the final BMC mutation.  A
            # periodic retry service can consume this secret-free record once
            # the external delivery dependency recovers.
            delivery_ready = _bmc_handoff_delivery_ready(
                statuses,
                # _sync_artifacts returns the queue-wide state.  Using the
                # second report pass here proves both the original and the
                # authoritative FINAL_PRE_HANDOFF bundles are archived.
                artifact_sync=final_report_sync,
                event_queue_status=queue.status_for_run(run_id),
            )
            pending_record = {
                "schema_version": 1,
                "status": "PENDING",
                "run_id": run_id,
                "run_directory": str(run_dir),
                "server_id": str(identity.get("server_id") or ""),
                "fingerprint_sha256": str(identity.get("fingerprint_sha256") or ""),
                "system_serial": str(identity.get("primary_serial") or ""),
                "expected_bmc_version": expected_bmc,
                "created_at_utc": utc_now(),
                "sensitive_material_exposed": False,
            }
            handoff_sync: dict[str, Any] = {"status": "NOT_STARTED"}
            if not delivery_ready:
                bmc_handoff = {
                    "schema_version": 1,
                    "status": "PENDING",
                    "required": True,
                    "method": "ASUS_ASMB_KCS_FACTORY_DEFAULT_RAW_32_66",
                    "reset_requested": False,
                    "default_state": "NOT_STARTED",
                    "reason": "HANDOFF_DEFERRED_UNTIL_REPORTS_CENTRAL_AND_PRIMARY_ARCHIVE_SYNC",
                    "sensitive_material_exposed": False,
                }
                _atomic_json(
                    run_dir / "bmc-handoff-pending.json",
                    pending_record | {"reason": bmc_handoff["reason"]},
                )
            else:
                bmc_handoff = self._perform_bmc_handoff(
                    run_dir=run_dir,
                    normalized_inventory=normalized,
                    expected_bmc_version=expected_bmc,
                    firmware_plan=plan,
                )
                handoff_artifact = run_dir / "bmc-handoff.json"
                _atomic_json(handoff_artifact, bmc_handoff)
                receipt_handoff = evaluate_handoff(
                    statuses,
                    workflow_mode="FIRMWARE_ONLY",
                    policy=handoff_policy,
                    bmc_auth_changed=True,
                    bmc_handoff_status=str(bmc_handoff.get("status") or "FAIL"),
                )
                receipt_payload = {
                    "schema_version": 1,
                    "record_type": "CNSERVEROPS_OPTION5_POST_HANDOFF_ADDENDUM",
                    "status": str(bmc_handoff.get("status") or "FAIL").upper(),
                    "run_id": run_id,
                    "server_id": str(identity.get("server_id") or ""),
                    "system_serial": str(identity.get("primary_serial") or ""),
                    "firmware_result": str(execution.get("status") or "UNVERIFIED"),
                    "bmc_handoff_status": str(bmc_handoff.get("status") or "FAIL").upper(),
                    "handoff_disposition": str(receipt_handoff.get("handoff_status") or "NOT_READY"),
                    "overall": str(receipt_handoff.get("overall") or "FAIL"),
                    "pre_handoff_report_delivery": str(final_report_sync.get("status") or "PENDING_UPLOAD"),
                    "pre_handoff_primary_archive": str(
                        (statuses.get("windows_archive") or {}).get("primary_status")
                        if isinstance(statuses.get("windows_archive"), Mapping)
                        else "PENDING_UPLOAD"
                    ),
                    "created_at_utc": utc_now(),
                    "sensitive_material_exposed": False,
                }
                assert_no_sensitive_fields(receipt_payload)
                # Hash the exact finalized bytes, including the host's text
                # newline convention in tests.  Production runs on Linux,
                # but byte verification must be portable and literal.
                receipt_staging_path = run_dir / ".option5-post-handoff-addendum.pending.json"
                _atomic_json(receipt_staging_path, receipt_payload)
                receipt_digest = _sha256(receipt_staging_path)
                receipt_path = run_dir / f"CNServerOps_Option5_Post_Handoff_{receipt_digest[:12].upper()}.json"
                receipt_staging_path.replace(receipt_path)
                if _sha256(receipt_path) != receipt_digest:
                    raise ProductionWorkflowError("Option 5 post-handoff receipt failed local hash verification")
                handoff_sync = self._sync_artifacts(
                    run_id,
                    {
                        "artifacts": [
                            {
                                "path": str(handoff_artifact),
                                "type": "RAW_BMC_HANDOFF",
                                "sha256": _sha256(handoff_artifact),
                            },
                            {
                                "path": str(receipt_path),
                                "type": "OPTION5_POST_HANDOFF_ADDENDUM",
                                "sha256": receipt_digest,
                            },
                        ]
                    },
                    client,
                )
                if (
                    str(bmc_handoff.get("status") or "").upper() != "PASS"
                    or str(handoff_sync.get("status") or "").upper() != "SYNCED"
                ):
                    _atomic_json(
                        run_dir / "bmc-handoff-pending.json",
                        pending_record
                        | {
                            "reason": "HANDOFF_OR_HANDOFF_ARTIFACT_NOT_COMPLETE",
                            "handoff_status": str(bmc_handoff.get("status") or "FAIL"),
                            "handoff_artifact_status": str(handoff_sync.get("status") or "PENDING_UPLOAD"),
                        },
                    )
                else:
                    (run_dir / "bmc-handoff-pending.json").unlink(missing_ok=True)
            statuses["bmc_auth_handoff"] = bmc_handoff
            statuses["bmc_handoff_artifact"] = handoff_sync
            if delivery_ready:
                statuses["post_handoff_addendum"] = receipt_payload
                statuses["post_handoff_addendum_delivery"] = handoff_sync
            effective_handoff_status = str(bmc_handoff.get("status") or "FAIL")
            if effective_handoff_status.upper() == "PASS" and str(handoff_sync.get("status") or "").upper() != "SYNCED":
                effective_handoff_status = "PENDING"
            handoff = evaluate_handoff(
                statuses,
                workflow_mode="FIRMWARE_ONLY",
                policy=handoff_policy,
                bmc_auth_changed=True,
                bmc_handoff_status=effective_handoff_status,
            )
            statuses.update(
                {
                    "overall": handoff["overall"],
                    "handoff_status": handoff["handoff_status"],
                    "handoff_policy": handoff,
                    "readiness": _public_readiness_label(
                        workflow_mode="FIRMWARE_ONLY",
                        overall=handoff["overall"],
                    ),
                }
            )
            finalization["bmc_auth_handoff"] = bmc_handoff
            finalization["factory_reset_performed"] = bool(bmc_handoff.get("reset_requested"))
        final_run.final_disposition = FinalDisposition(handoff["overall"])
        final_run.collection_status = OperationStatus.PASS if normalized else OperationStatus.PARTIAL
        final_run.export_status = (
            OperationStatus.PASS
            if statuses.get("reports") == "PASS"
            and statuses.get("artifact_delivery") == "PASS"
            and statuses.get("primary_archive") == "PASS"
            else OperationStatus.PARTIAL
        )
        context["run"] = final_run.to_dict()
        context["result"] = statuses
        context["finalization"] = finalization
        _atomic_json(run_dir / "run.json", context)
        completion = self._enqueue_and_drain(
            queue,
            run_completed_event(final_run, result=statuses),
            run_dir / "run.json",
            client,
        )
        pending_completion = (
            self._archive_and_clear_pending_firmware(
                run_dir=run_dir,
                run_id=run_id,
                completion_status=str(final_run.final_disposition.value),
            )
            if resumed
            else {"status": "NOT_APPLICABLE", "sensitive_material_exposed": False}
        )
        _atomic_json(run_dir / "firmware-pending-completion.json", pending_completion)
        response = {
            "status": execution.get("status"),
            "run": final_run.to_dict(),
            "firmware": dict(plan),
            "execution": dict(execution),
            "result": statuses,
            "reports": report_manifest,
            "central": {
                "completion": completion,
                "artifact_status": (
                    statuses.get("post_handoff_addendum_delivery", {}).get("status")
                    if isinstance(statuses.get("post_handoff_addendum_delivery"), Mapping)
                    else final_report_sync.get("status")
                ),
            },
            "firmware_resume_completion": pending_completion,
            "run_directory": str(run_dir),
            "mutation_started": bool(execution.get("mutation_started")),
        }
        assert_no_sensitive_fields(response)
        _atomic_json(run_dir / "result-summary.json", response)
        return response

    def resume_pending_firmware_only(self) -> dict[str, Any]:
        """Dispatch a durable checkpoint to its original workflow.

        The systemd unit deliberately has a historical CLI name, but it owns
        continuations for firmware-only, Option 1 and Option 2.  It never
        starts a fresh workflow when no checkpoint exists.
        """
        # Workload execution is deliberately never resumed after a host
        # restart.  A restart while stress-ng is active is a production
        # failure, not evidence that the workload completed.  Close the
        # original identity-bound run first, then let the existing firmware
        # checkpoint dispatcher run only when there was no interrupted
        # workload record.
        workload_recovery = self.recover_interrupted_workload()
        if str(workload_recovery.get("status") or "") != "NO_PENDING_WORKLOAD_RECOVERY":
            return workload_recovery
        pending = self._load_pending_firmware()
        if not pending:
            return {"status": "NO_PENDING_FIRMWARE", "mutation_started": False, "sensitive_material_exposed": False}
        try:
            _probe, _platform, current_identity, _fru = detect_current_platform_and_identity(
                dmi_root=self.dmi_root, fru_reader=self.fru_reader
            )
            current_runner = load_runner(self.config.runner_config)
        except Exception:
            current_identity, current_runner = {}, {}
        foreign_pending = self._quarantine_foreign_pending(
            pending,
            identity=current_identity,
            runner_id=str(current_runner.get("runner_id") or ""),
        )
        if foreign_pending is not None:
            return foreign_pending
        # A post-reboot workflow can finish its authoritative state and then
        # fail while publishing a human report (for example, an evidence
        # boundary rejection).  The durable checkpoint must not make the boot
        # service re-enter a terminal RUN-* record and attempt the forbidden
        # COMPLETE -> CAPABILITY_DISCOVERY transition.  Retire only a
        # checkpoint whose saved workflow state is already COMPLETE; all
        # non-terminal checkpoints continue through the normal identity-bound
        # resume path below.
        run_directory = Path(str(pending.get("run_directory") or ""))
        state_path = run_directory / "workflow-state.json"
        try:
            saved_state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.is_file() else {}
        except (OSError, ValueError, json.JSONDecodeError):
            saved_state = {}
        if str(saved_state.get("current_workflow_stage") or "").upper() == WorkflowStage.COMPLETE.value:
            terminal_receipt = run_directory / "result-summary.json"
            archived = {
                "schema_version": 1,
                "status": "TERMINAL_CHECKPOINT_RETIRED",
                "run_id": str(pending.get("run_id") or run_directory.name),
                "run_directory": str(run_directory),
                "result_summary_present": terminal_receipt.is_file(),
                "reason": "WORKFLOW_STATE_ALREADY_COMPLETE",
                "sensitive_material_exposed": False,
            }
            if run_directory:
                _atomic_json(run_directory / "firmware-pending-terminal-retired.json", archived)
            clear_firmware_pending(self.config.primary_root, run_directory if run_directory else None)
            return archived
        # A non-reboot BMC task can outlive the Python process.  Reattach to
        # that exact durable task before dispatching the owning workflow; a
        # successful reattach changes only the checkpoint state and then lets
        # the normal same-run production/firmware continuation proceed.
        task_resume = self._resume_inflight_firmware_task(pending)
        if task_resume is not None:
            if not bool(task_resume.pop("_continue", False)):
                return task_resume
            pending = self._load_pending_firmware() or pending
        # A oneshot resume service can itself be restarted while the host is
        # still on the pre-reboot boot (for example when systemctl rejected a
        # reboot request or a BMC restart interrupted the handoff).  Re-issue
        # only the already-persisted reboot checkpoint; never re-run an
        # adapter or a mutation on the unchanged boot.
        same_boot_retry = self._retry_same_boot_firmware_reboot(pending)
        if same_boot_retry is not None:
            return same_boot_retry
        mode = str(pending.get("workflow_mode") or "").upper()
        if mode == "PRODUCTION":
            return self.run_asus_production()
        if mode == "PRODUCTION_EXTENDED":
            return self.run_asus_production(extended_diagnostics=True)
        if mode != "FIRMWARE_ONLY":
            return {
                "status": "BLOCKED_FIRMWARE_RESUME_WORKFLOW",
                "pending_workflow_mode": mode,
                "mutation_started": False,
                "sensitive_material_exposed": False,
            }
        return self._resume_pending_firmware(pending)

    def _workload_continuation_path(self) -> Path:
        """Return the one durable, identity-bound workload checkpoint path.

        It is intentionally outside a run directory so it can be found at
        boot without trusting a filename supplied by a prior machine.  The
        payload itself still carries the run, runner, physical identity and
        pre-workload boot binding which are all revalidated before use.
        """
        return self.config.primary_root / "workload-continuation.json"

    def _write_workload_continuation(
        self,
        *,
        run_id: str,
        run_dir: Path,
        identity: Mapping[str, Any],
        runner_id: str,
        workflow_mode: str,
        profile_id: str,
    ) -> dict[str, Any]:
        payload = {
            "schema_version": 1,
            "state": "WORKLOAD_ACTIVE",
            "run_id": str(run_id),
            "run_directory": str(run_dir),
            "server_id": str(identity.get("server_id") or ""),
            "fingerprint_sha256": str(identity.get("fingerprint_sha256") or ""),
            "system_serial": str(identity.get("primary_serial") or ""),
            "vendor": str(identity.get("vendor") or "").upper(),
            "platform_id": str(identity.get("platform_id") or "").upper(),
            "runner_id": str(runner_id or "").upper(),
            "boot_id_before": str(identity.get("boot_id") or read_linux_boot_id()),
            "workflow_mode": str(workflow_mode or "").upper(),
            "profile_id": str(profile_id or "").upper(),
            "created_at_utc": utc_now(),
            "sensitive_material_exposed": False,
        }
        if not all(
            payload[key]
            for key in ("run_id", "server_id", "fingerprint_sha256", "runner_id", "boot_id_before")
        ):
            raise ProductionWorkflowError("Workload checkpoint requires trusted run, runner, identity, and boot bindings")
        assert_no_sensitive_fields(payload)
        _atomic_json(run_dir / "workload-continuation-started.json", payload)
        _atomic_json(self._workload_continuation_path(), payload)
        return payload

    def _clear_workload_continuation(self, *, run_dir: Path, outcome: str) -> None:
        path = self._workload_continuation_path()
        try:
            checkpoint = _load_json_mapping(path)
        except Exception:
            checkpoint = {}
        if str(checkpoint.get("run_id") or "") and str(checkpoint.get("run_id") or "") != run_dir.name:
            # A current run may never erase another run's durable recovery
            # record.  The boot recovery path will quarantine a foreign one.
            return
        receipt = {
            "schema_version": 1,
            "run_id": run_dir.name,
            "outcome": str(outcome),
            "cleared_at_utc": utc_now(),
            "sensitive_material_exposed": False,
        }
        _atomic_json(run_dir / "workload-continuation-completion.json", receipt)
        try:
            path.unlink(missing_ok=True)
        except OSError:
            # The in-run workflow must still be able to finalize a genuine
            # stress result.  A later boot will see the completion receipt and
            # fail closed rather than resume the workload.
            pass

    def recover_interrupted_workload(self) -> dict[str, Any]:
        """Close a workload interrupted by an unexpected Linux reboot.

        This routine is used only by the boot-time continuation service.  It
        never re-runs CPU/RAM stress, firmware, SEL cleanup, or any BMC action.
        If the prior workload's server/runner/boot binding cannot be proven it
        is quarantined rather than applied to the current machine.
        """
        checkpoint_path = self._workload_continuation_path()
        if not checkpoint_path.is_file():
            return {"status": "NO_PENDING_WORKLOAD_RECOVERY", "mutation_started": False, "sensitive_material_exposed": False}
        try:
            checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            checkpoint = {}
        if not isinstance(checkpoint, Mapping) or str(checkpoint.get("state") or "").upper() != "WORKLOAD_ACTIVE":
            return {
                "status": "BLOCKED_WORKLOAD_RECOVERY_INVALID_CHECKPOINT",
                "mutation_started": False,
                "sensitive_material_exposed": False,
            }
        run_id = str(checkpoint.get("run_id") or "")
        run_dir = self.config.primary_root / "runs" / run_id
        if not run_id.startswith("RUN-") or run_dir.name != run_id or not run_dir.is_dir():
            return {
                "status": "BLOCKED_WORKLOAD_RECOVERY_INVALID_RUN",
                "mutation_started": False,
                "sensitive_material_exposed": False,
            }
        try:
            _probe, platform, identity, _fru = detect_current_platform_and_identity(
                dmi_root=self.dmi_root, fru_reader=self.fru_reader
            )
            runner = load_runner(self.config.runner_config)
        except Exception as exc:
            return {
                "status": "WORKLOAD_RECOVERY_WAITING_FOR_LOCAL_IDENTITY",
                "reason": type(exc).__name__,
                "mutation_started": False,
                "sensitive_material_exposed": False,
            }
        expected = {
            "server_id": str(checkpoint.get("server_id") or ""),
            "fingerprint_sha256": str(checkpoint.get("fingerprint_sha256") or ""),
            "runner_id": str(checkpoint.get("runner_id") or "").upper(),
            "vendor": str(checkpoint.get("vendor") or "").upper(),
            "platform_id": str(checkpoint.get("platform_id") or "").upper(),
        }
        observed = {
            "server_id": str(identity.get("server_id") or ""),
            "fingerprint_sha256": str(identity.get("fingerprint_sha256") or ""),
            "runner_id": str(runner.get("runner_id") or "").upper(),
            "vendor": str(identity.get("vendor") or "").upper(),
            "platform_id": str(identity.get("platform_id") or "").upper(),
        }
        if not identity.get("resumable") or any(not expected[key] or expected[key] != observed[key] for key in expected):
            quarantine = run_dir / f"workload-continuation-quarantined-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
            _atomic_json(
                quarantine,
                {
                    "schema_version": 1,
                    "status": "QUARANTINED_FOREIGN_OR_UNTRUSTED_WORKLOAD_CHECKPOINT",
                    "run_id": run_id,
                    "expected": expected,
                    "observed": observed,
                    "quarantined_at_utc": utc_now(),
                    "sensitive_material_exposed": False,
                },
            )
            checkpoint_path.unlink(missing_ok=True)
            return {
                "status": "QUARANTINED_FOREIGN_WORKLOAD_CHECKPOINT",
                "run_id": run_id,
                "mutation_started": False,
                "sensitive_material_exposed": False,
            }
        if str(checkpoint.get("boot_id_before") or "") == str(identity.get("boot_id") or read_linux_boot_id()):
            return {
                "status": "WORKLOAD_RECOVERY_AWAITING_NEW_BOOT",
                "run_id": run_id,
                "mutation_started": False,
                "sensitive_material_exposed": False,
            }
        if platform.get("platform_id") != "ASUS_SERVER" or str(platform.get("vendor") or "") != "ASUS":
            return {
                "status": "BLOCKED_WORKLOAD_RECOVERY_PLATFORM",
                "run_id": run_id,
                "mutation_started": False,
                "sensitive_material_exposed": False,
            }
        try:
            orchestrator = ProductionOrchestrator(self.config.primary_root, runtime_version=self.runtime_version)
            context = orchestrator.resume(run_id, identity=identity, runner_id=str(runner.get("runner_id") or ""))
            current_stage = str((context.get("run") or {}).get("current_stage") or "")
            if current_stage != WorkflowStage.HARDWARE_TESTS.value:
                raise ProductionWorkflowError(f"WORKLOAD_CHECKPOINT_STAGE_MISMATCH:{current_stage or 'MISSING'}")
            evidence_dir = run_dir / "evidence"
            evidence_dir.mkdir(parents=True, exist_ok=True)
            interruption = {
                "schema_version": 1,
                "status": "UNEXPECTED_HOST_REBOOT_DURING_STRESS",
                "run_id": run_id,
                "workflow_mode": str(checkpoint.get("workflow_mode") or ""),
                "profile_id": str(checkpoint.get("profile_id") or ""),
                "boot_id_before": str(checkpoint.get("boot_id_before") or ""),
                "boot_id_after": str(identity.get("boot_id") or read_linux_boot_id()),
                "same_server_verified": True,
                "same_runner_verified": True,
                "recovery_action": "WORKLOAD_NOT_RETRIED; RUN_FINALIZED_FAIL",
                "recovered_at_utc": utc_now(),
                "sensitive_material_exposed": False,
            }
            _atomic_json(evidence_dir / "unexpected-host-reboot-during-stress.json", interruption)
            reasons = [
                Reason(
                    "UNEXPECTED_HOST_REBOOT_DURING_STRESS",
                    ReasonSeverity.FAIL,
                    "Linux rebooted or became unavailable while the authorized hardware stress phase was active; the workload was not retried automatically.",
                )
            ]
            context = orchestrator.transition(
                context,
                identity=identity,
                next_stage=WorkflowStage.BLOCKED,
                details=interruption,
            )
            context = orchestrator.finalize(context, reasons, identity=identity)
            final_run = RunRecord.from_dict(context["run"])
            inventory = _load_json_mapping(run_dir / "normalized-inventory.json")
            firmware = _load_json_mapping(run_dir / "firmware-plan.json")
            tests = {
                "status": "FAIL",
                "cpu": {"status": "NOT_COMPLETED"},
                "memory": {"status": "NOT_COMPLETED"},
                "combined": {"status": "NOT_COMPLETED"},
                "interruption": interruption,
            }
            finalization = {
                "schema_version": 1,
                "overall": "FAIL",
                "handoff_status": "NOT_READY",
                "reason": "UNEXPECTED_HOST_REBOOT_DURING_STRESS",
                "bmc_auth_handoff": "NOT_STARTED_BY_RECOVERY",
            }
            client, central_runtime = self._collector_client()
            normalized_result = self._normalized_result(
                context,
                central_runtime,
                firmware_status="UNVERIFIED",
                system_diagnostics_status="NOT_COMPLETED",
            )
            normalized_result.update(
                {
                    "cpu": "NOT_COMPLETED",
                    "ram": "NOT_COMPLETED",
                    "combined": "NOT_COMPLETED",
                    "firmware_update": "UNVERIFIED",
                    "workload_interruption": "FAIL",
                    "reports": "PENDING",
                    "artifact_delivery": "PENDING_UPLOAD",
                    "primary_archive": "PENDING_UPLOAD",
                    "overall": "FAIL",
                    "handoff_status": "NOT_READY",
                    "readiness": "NOT_READY_FOR_SALE",
                }
            )
            evidence_manifest = self._evidence_manifest([path for path in run_dir.rglob("*") if path.is_file()])
            _atomic_json(run_dir / "evidence-manifest.json", evidence_manifest)
            report_manifest: dict[str, Any] = {"artifacts": []}
            if self.config.reports_enabled and inventory.get("system_serial"):
                report_manifest = generate_human_reports(
                    run_dir,
                    inventory=inventory,
                    run=final_run.to_dict(),
                    result=normalized_result,
                    firmware=firmware,
                    tests=tests,
                    finalization=finalization,
                    central={"artifact_status": "LOCAL_COMPLETE", **central_runtime},
                    evidence_manifest=evidence_manifest,
                    extended_diagnostics=None,
                    report_variant="INTERRUPTED_WORKLOAD",
                )
                normalized_result["reports"] = "PASS" if report_manifest_complete(report_manifest) else "FAIL"
            artifact_sync = self._sync_artifacts(run_id, report_manifest, client)
            normalized_result["artifact_delivery"] = str(artifact_sync.get("status") or "PENDING_UPLOAD")
            normalized_result["central_artifact_delivery"] = artifact_sync
            normalized_result["windows_archive"] = self._central_archive_summary(artifact_sync)
            normalized_result["primary_archive"] = (
                "PASS" if str(normalized_result["windows_archive"].get("primary_status") or "") == "SYNCED" else "PENDING_UPLOAD"
            )
            result = {
                "schema_version": 1,
                "run": final_run.to_dict(),
                "server": context.get("server") or {},
                "normalized_inventory": inventory,
                "normalized_result": normalized_result,
                "firmware": firmware,
                "tests": tests,
                "finalization": finalization,
                "reports": report_manifest,
                "recovery": interruption,
                "sensitive_material_exposed": False,
            }
            assert_no_sensitive_fields(result)
            _atomic_json(run_dir / "result-summary.json", result)
            queue = StoreForwardQueue(self.config.queue_database)
            completion_sync = self._enqueue_and_drain(
                queue,
                run_completed_event(final_run, result=normalized_result),
                run_dir / "run.json",
                client,
            )
            _atomic_json(run_dir / "central-run-completed.json", completion_sync)
            # If this same run had provisioned a temporary BMC account before
            # the host interruption, preserve the production handoff promise.
            # The retry path is delivery-gated and same-server-bound; it will
            # never reset an untouched BMC or an unverified different server.
            marker = self._active_bmc_auth_change_marker(identity)
            handoff_retry: dict[str, Any] = {"status": "NOT_REQUIRED"}
            if marker.get("active"):
                expected_bmc = ""
                for component in firmware.get("components") or []:
                    if isinstance(component, Mapping) and str(component.get("component") or "").upper() == "BMC":
                        expected_bmc = str(
                            component.get("after")
                            or component.get("current")
                            or component.get("before")
                            or component.get("target")
                            or ""
                        )
                        break
                pending_handoff = {
                    "schema_version": 1,
                    "status": "PENDING",
                    "run_id": run_id,
                    "run_directory": str(run_dir),
                    "server_id": str(identity.get("server_id") or ""),
                    "fingerprint_sha256": str(identity.get("fingerprint_sha256") or ""),
                    "system_serial": str(identity.get("primary_serial") or ""),
                    "expected_bmc_version": expected_bmc,
                    "created_at_utc": utc_now(),
                    "reason": "INTERRUPTED_WORKLOAD_AFTER_CNSERVEROPS_BMC_AUTH_CHANGE",
                    "sensitive_material_exposed": False,
                }
                _atomic_json(run_dir / "bmc-handoff-pending.json", pending_handoff)
                handoff_retry = self._retry_pending_bmc_handoffs(client, limit=1)
                normalized_result["bmc_auth_handoff"] = {
                    "status": "PENDING_OR_RETRIED",
                    "retry": handoff_retry,
                    "required": True,
                }
                _atomic_json(run_dir / "result-summary.json", result | {"normalized_result": normalized_result})
            self._clear_workload_continuation(run_dir=run_dir, outcome="RECOVERED_AS_FAIL")
            self._notify({"event": "WORKLOAD_INTERRUPTION_RECOVERED", "run_id": run_id, "status": "FAIL"})
            return {
                "status": "INTERRUPTED_WORKLOAD_FINALIZED_FAIL",
                "run": final_run.to_dict(),
                "central": completion_sync,
                "artifact_status": artifact_sync.get("status"),
                "bmc_handoff_retry": handoff_retry,
                "mutation_started": False,
                "sensitive_material_exposed": False,
            }
        except Exception as exc:
            return {
                "status": "BLOCKED_WORKLOAD_RECOVERY_FINALIZATION",
                "run_id": run_id,
                "reason": type(exc).__name__,
                "mutation_started": False,
                "sensitive_material_exposed": False,
            }

    def _retry_same_boot_firmware_reboot(self, pending: Mapping[str, Any]) -> dict[str, Any] | None:
        """Recover an interrupted reboot checkpoint without repeating flash.

        ``None`` means the live boot is already different and the normal
        identity-bound resume path should continue.  A result object means the
        caller must return it to the boot service; the durable checkpoint has
        either been re-requested or has reached its bounded retry limit.
        """
        before = str(pending.get("boot_id_before") or "")
        if not before or before != read_linux_boot_id():
            return None
        if str(pending.get("state") or "").upper() not in {"REBOOT_PENDING", "REBOOT_REQUESTED"}:
            return None
        try:
            _probe, platform, identity, _fru = detect_current_platform_and_identity(
                dmi_root=self.dmi_root, fru_reader=self.fru_reader
            )
            if platform.get("platform_id") != "ASUS_SERVER" or str(platform.get("vendor") or "") != "ASUS":
                return {
                    "status": "BLOCKED_FIRMWARE_RESUME_PLATFORM",
                    "reason": "CURRENT_PLATFORM_IS_NOT_THE_APPROVED_ASUS_SERVER",
                    "pending": dict(pending),
                    "mutation_started": False,
                    "sensitive_material_exposed": False,
                }
            runner = load_runner(self.config.runner_config)
            validate_pending_for_resume(
                pending,
                identity=identity,
                runner_id=str(runner.get("runner_id") or ""),
                require_new_boot=False,
            )
        except (FirmwareLifecycleError, WorkflowError, OSError) as exc:
            return {
                "status": "BLOCKED_IDENTITY_MISMATCH",
                "reason": str(exc),
                "pending": dict(pending),
                "mutation_started": False,
                "sensitive_material_exposed": False,
            }
        reboot = request_controlled_reboot(
            executor=self.executor,
            primary_root=self.config.primary_root,
            pending=pending,
        )
        return {
            "status": reboot.get("status"),
            "reason": reboot.get("reason") or "SAME_BOOT_REBOOT_CHECKPOINT_RETRIED",
            "pending": reboot.get("pending", dict(pending)),
            "reboot": reboot,
            "mutation_started": bool(pending.get("mutation_started")),
            "sensitive_material_exposed": False,
        }

    def _resume_inflight_firmware_task(self, pending: Mapping[str, Any]) -> dict[str, Any] | None:
        """Reattach to a non-reboot BMC task after a process interruption.

        A Redfish/OEM task can continue while Linux remains up.  The task
        identity and package metadata are persisted before the first poll, so
        the resume service can reopen the exact task without calling
        ``adapter.start`` or resolving a new package.  ``None`` means there
        is no non-reboot task checkpoint and the normal dispatcher should
        continue.
        """
        if str(pending.get("state") or "").upper() != "TASK_IN_PROGRESS":
            return None
        inflight_path = self.config.primary_root / "firmware-inflight.json"
        try:
            raw = json.loads(inflight_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            return {
                "status": "BLOCKED_FIRMWARE_TASK_STATE",
                "reason": "DURABLE_TASK_RECORD_MISSING",
                "pending": dict(pending),
                "mutation_started": bool(pending.get("mutation_started")),
                "sensitive_material_exposed": False,
            }
        if not isinstance(raw, Mapping):
            return {
                "status": "BLOCKED_FIRMWARE_TASK_STATE",
                "reason": "DURABLE_TASK_RECORD_INVALID",
                "pending": dict(pending),
                "mutation_started": bool(pending.get("mutation_started")),
                "sensitive_material_exposed": False,
            }
        record = dict(raw)
        run_id = str(pending.get("run_id") or "")
        if str(record.get("run_id") or "") != run_id:
            return {
                "status": "BLOCKED_FIRMWARE_TASK_BINDING",
                "reason": "DURABLE_TASK_RUN_ID_MISMATCH",
                "pending": dict(pending),
                "mutation_started": bool(pending.get("mutation_started")),
                "sensitive_material_exposed": False,
            }
        task_id = str(record.get("task_id") or pending.get("firmware_task_identity") or "")
        component = str(record.get("component") or pending.get("pending_component") or "").upper()
        metadata_payload = record.get("metadata") if isinstance(record.get("metadata"), Mapping) else {}
        transport_payload = record.get("transport") if isinstance(record.get("transport"), Mapping) else {}
        if not task_id or not component or not metadata_payload:
            return {
                "status": "BLOCKED_FIRMWARE_TASK_STATE",
                "reason": "DURABLE_TASK_ID_OR_METADATA_MISSING",
                "pending": dict(pending),
                "mutation_started": bool(pending.get("mutation_started")),
                "sensitive_material_exposed": False,
            }

        probe, platform, identity, _fru = detect_current_platform_and_identity(
            dmi_root=self.dmi_root, fru_reader=self.fru_reader
        )
        if platform.get("platform_id") != "ASUS_SERVER" or str(platform.get("vendor") or "") != "ASUS":
            return {
                "status": "BLOCKED_FIRMWARE_RESUME_PLATFORM",
                "reason": "CURRENT_PLATFORM_IS_NOT_THE_APPROVED_ASUS_SERVER",
                "pending": dict(pending),
                "mutation_started": bool(pending.get("mutation_started")),
                "sensitive_material_exposed": False,
            }
        try:
            runner = load_runner(self.config.runner_config)
            validate_pending_for_resume(
                pending,
                identity=identity,
                runner_id=str(runner.get("runner_id") or ""),
                require_new_boot=False,
            )
        except (FirmwareLifecycleError, WorkflowError, OSError) as exc:
            return {
                "status": "BLOCKED_IDENTITY_MISMATCH",
                "reason": str(exc),
                "pending": dict(pending),
                "mutation_started": bool(pending.get("mutation_started")),
                "sensitive_material_exposed": False,
            }

        run_dir = self.config.primary_root / "runs" / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        # Recollect current local/BMC address evidence.  This is read-only and
        # avoids trusting a stale pre-interruption Redfish address.
        try:
            inventory = self._collect_inventory(
                run_dir / "evidence-task-resume",
                identity=identity,
                platform=platform,
                probe=probe,
                run_id=run_id,
                runner_id=str(runner.get("runner_id") or ""),
            )
        except Exception as exc:
            return {
                "status": "BLOCKED_FIRMWARE_TASK_INVENTORY",
                "reason": f"TASK_RESUME_INVENTORY_{type(exc).__name__}",
                "pending": dict(pending),
                "mutation_started": bool(pending.get("mutation_started")),
                "sensitive_material_exposed": False,
            }
        normalized = inventory.get("normalized") if isinstance(inventory.get("normalized"), Mapping) else {}
        discovery = self._discover_bmc_auth(
            normalized,
            identity,
            exclude_run_id=run_id,
            read_only=True,
        )
        transport_requires_auth = bool(transport_payload.get("requires_authenticated_bmc", True))
        if transport_requires_auth and not bmc_auth_is_usable(str(discovery.get("state") or "")):
            return {
                "status": "BLOCKED_BY_AUTH",
                "reason": "DURABLE_TASK_REATTACH_REQUIRES_APPROVED_BMC_AUTH",
                "pending": dict(pending),
                "bmc_auth_state": str(discovery.get("state") or BmcAuthState.BMC_AUTH_UNAVAILABLE.value),
                "mutation_started": bool(pending.get("mutation_started")),
                "sensitive_material_exposed": False,
            }

        try:
            metadata = FirmwarePackageMetadata.from_dict(metadata_payload)
            descriptor_keys = {
                "name", "source", "target", "components", "rank",
                "requires_authenticated_bmc", "task_tracking", "package_delivery",
                "reboot_behavior", "component_payload_preferences",
                "component_image_types", "component_image_type_candidates",
                "web_update_method", "web_component_ids", "web_component_image_types",
                "web_section_flash", "web_endpoint_prefix", "local_command",
                "local_tool_sha256", "local_timeout_seconds", "selectable", "reason",
            }
            descriptor = AsusTransportDescriptor(
                **{key: value for key, value in dict(transport_payload).items() if key in descriptor_keys}
            )
            if descriptor.name == "ASUS_LOCAL_OFFICIAL_UTILITY":
                # Approved local tools are synchronous by contract, so a
                # TASK_IN_PROGRESS checkpoint is invalid rather than a reason
                # to execute a second untracked command after a crash.
                raise FirmwareLifecycleError("LOCAL_ASUS_TASK_REATTACH_UNSUPPORTED")
            repository = FirmwareRepository(self.config.firmware_cache_root)
            version_reader = lambda name: self._read_live_firmware_version(name, normalized)
            if descriptor.name == "ASUS_ASMB11_KCS_YAFUFLASH":
                # KCS Yafuflash is deliberately synchronous.  It never
                # creates a durable BMC task identity, so a TASK_IN_PROGRESS
                # record for it is corrupt/stale rather than authority to
                # replay a flash after a process crash.
                raise FirmwareLifecycleError("ASMB11_KCS_TASK_REATTACH_UNSUPPORTED")
            elif descriptor.name == "ASUS_ASMB_WEB_HPM":
                web_client, _web_policy = self._authenticated_asus_web_client(inventory, discovery)
                if web_client is None:
                    raise FirmwareLifecycleError("APPROVED_ASUS_WEB_CREDENTIAL_UNAVAILABLE")
                adapter = AsusAsmbWebHpmFirmwareAdapter(web_client, descriptor, version_reader=version_reader)
            else:
                client, _policy = self._authenticated_firmware_client(inventory, discovery)
                if client is None:
                    raise FirmwareLifecycleError("APPROVED_FIRMWARE_CREDENTIAL_UNAVAILABLE")
                adapter = AsusRedfishFirmwareAdapter(client, descriptor, version_reader=version_reader)

            def persist_resume_progress(payload: Mapping[str, Any]) -> None:
                updated = dict(record)
                updated.update(
                    {
                        "state": str(payload.get("phase") or "TASK_RESUME_PROGRESS"),
                        "updated_at_utc": utc_now(),
                        "task_state": str(payload.get("task_state") or ""),
                        "task_detail": str(payload.get("task_detail") or "")[:240],
                        "task_id": str(payload.get("task_id") or task_id),
                        "sensitive_material_exposed": False,
                    }
                )
                _atomic_json(inflight_path, updated)
                _atomic_json(run_dir / "firmware-inflight.json", updated)

            execution = FirmwareUpdateExecutor(repository).resume_task(
                identity={**dict(identity), "current_version": str(record.get("task_state") or "")},
                metadata=metadata,
                adapter=adapter,
                task_id=task_id,
                run_id=run_id,
                progress_callback=persist_resume_progress,
            )
        except Exception as exc:
            # Never expose exception text from a transport; class-only failure
            # evidence is sufficient and keeps credentials/response bodies out
            # of the durable record.
            return {
                "status": "BLOCKED_FIRMWARE_TASK_REATTACH",
                "reason": f"TASK_REATTACH_{type(exc).__name__}",
                "pending": dict(pending),
                "mutation_started": bool(pending.get("mutation_started")),
                "sensitive_material_exposed": False,
            }

        _atomic_json(run_dir / "firmware-execution-recovered.json", execution)
        status = str(execution.get("status") or "FAILED").upper()
        if status == "REBOOT_REQUIRED":
            next_pending = dict(pending)
            next_pending.update(
                {
                    "state": "REBOOT_PENDING",
                    "updated_at_utc": utc_now(),
                    "execution_status": "REBOOT_REQUIRED",
                    "firmware_task_identity": str(execution.get("task_id") or task_id),
                    "activation_pending_components": sorted(
                        set(str(item).upper() for item in (pending.get("activation_pending_components") or []) if str(item).strip())
                        | {component}
                    ),
                    "reboot": {"requested": False, "requested_at_utc": "", "status": "NOT_REQUESTED", "retry_count": 0},
                    "sensitive_material_exposed": False,
                }
            )
            save_firmware_pending(self.config.primary_root, next_pending)
            _atomic_json(run_dir / "firmware-pending.json", next_pending)
            reboot = request_controlled_reboot(
                executor=self.executor,
                primary_root=self.config.primary_root,
                pending=next_pending,
            )
            execution["reboot"] = reboot
            _atomic_json(run_dir / "firmware-execution-recovered.json", execution)
            return {
                "status": reboot.get("status"),
                "reason": "DURABLE_TASK_REATTACHED_REBOOT_REQUIRED",
                "pending": reboot.get("pending", next_pending),
                "execution": execution,
                "mutation_started": True,
                "sensitive_material_exposed": False,
            }
        if status in {"FAILED", "SUCCESS", "SUCCESS_WITH_WARNING"}:
            if status == "FAILED" and str(execution.get("reason") or "") == "UPDATE_TASK_TIMEOUT":
                # Leave the exact task checkpoint in place so systemd can
                # retry polling later; no new mutation is authorized.
                return {
                    "status": "TASK_RESUME_RETRY",
                    "reason": "DURABLE_TASK_POLL_TIMEOUT",
                    "pending": dict(pending),
                    "execution": execution,
                    "mutation_started": True,
                    "sensitive_material_exposed": False,
                }
            if status == "FAILED":
                clear_firmware_pending(self.config.primary_root, run_dir)
                try:
                    inflight_path.unlink(missing_ok=True)
                except OSError:
                    pass
                return {
                    "status": "FAILED",
                    "reason": str(execution.get("reason") or "DURABLE_TASK_FAILED"),
                    "pending": dict(pending),
                    "execution": execution,
                    "mutation_started": True,
                    "sensitive_material_exposed": False,
                }

            next_pending = dict(pending)
            next_pending.update(
                {
                    "state": "TASK_RESUMED",
                    "updated_at_utc": utc_now(),
                    "execution_status": "TASK_RESUMED",
                    "firmware_task_identity": str(execution.get("task_id") or task_id),
                    "activation_pending_components": sorted(
                        set(str(item).upper() for item in (pending.get("activation_pending_components") or []) if str(item).strip())
                        | {component}
                    ),
                    "remaining_components": [
                        str(item).upper()
                        for item in (pending.get("remaining_components") or [])
                        if str(item).upper() != component
                    ],
                    "reboot": {"requested": False, "requested_at_utc": "", "status": "NOT_REQUESTED", "retry_count": 0},
                    "sensitive_material_exposed": False,
                }
            )
            save_firmware_pending(self.config.primary_root, next_pending)
            _atomic_json(run_dir / "firmware-pending.json", next_pending)
            try:
                inflight_path.unlink(missing_ok=True)
            except OSError:
                pass
            return {
                "_continue": True,
                "status": "TASK_REATTACHED",
                "execution": execution,
                "pending": next_pending,
                "mutation_started": True,
                "sensitive_material_exposed": False,
            }
        return {
            "status": "BLOCKED_FIRMWARE_TASK_REATTACH",
            "reason": "DURABLE_TASK_TERMINAL_STATE_UNKNOWN",
            "pending": dict(pending),
            "execution": execution,
            "mutation_started": True,
            "sensitive_material_exposed": False,
        }

    def retry_pending_sync(self) -> dict[str, Any]:
        """Drain queues and finish only an already-authorized BMC handoff.

        Normal event/artifact retry is read-only.  A same-server pending
        handoff may invoke the official ASUS factory/default action, but only
        after all pre-handoff delivery proof is synchronized and the original
        run's marker is still active.  No new firmware, test, or production
        workflow is started by the timer.
        """
        client, central_runtime = self._collector_client()
        if client is None:
            event_queue = StoreForwardQueue(self.config.queue_database)
            artifact_queue = ArtifactStoreForwardQueue(self.config.artifact_queue_database)
            event_counts = event_queue.counts()
            artifact_counts = artifact_queue.counts()
            return {
                "status": "PENDING_CENTRAL_OFFLINE",
                "central": central_runtime,
                "events": {
                    "attempted": 0,
                    "synced": 0,
                    "pending": sum(event_counts.get(state, 0) for state in ("PENDING_UPLOAD", "IN_FLIGHT")),
                    "counts": event_counts,
                },
                "artifacts": {
                    "attempted": 0,
                    "synced": 0,
                    "pending": sum(artifact_counts.get(state, 0) for state in ("PENDING_UPLOAD", "IN_FLIGHT")),
                    "failed": artifact_counts.get("UPLOAD_FAILED", 0),
                    "counts": artifact_counts,
                },
                "hardware_mutation_started": False,
                "sensitive_material_exposed": False,
            }
        events = StoreForwardQueue(self.config.queue_database).drain(client, limit=100)
        artifact_queue = ArtifactStoreForwardQueue(self.config.artifact_queue_database)
        artifacts = artifact_queue.drain(client, limit=100)
        # Keep the current retry attempt separate from preserved historical
        # terminal evidence.  In particular, an old immutable HTTP 409 must
        # not be presented as a fresh failure of the current run, but it also
        # must not disappear from audit/status output.
        artifact_counts = artifact_queue.counts()
        artifacts["counts"] = artifact_counts
        artifacts["terminal_failed"] = int(artifact_counts.get("UPLOAD_FAILED", 0))
        handoffs = self._retry_pending_bmc_handoffs(client, limit=8)
        return {
            "status": "SYNC_RETRY_COMPLETED",
            "central": central_runtime,
            "events": events,
            "artifacts": artifacts,
            "bmc_handoffs": handoffs,
            "hardware_mutation_started": bool(handoffs.get("mutation_started")),
            "sensitive_material_exposed": False,
        }

    def _retry_pending_bmc_handoffs(self, client: Any, *, limit: int = 8) -> dict[str, Any]:
        """Finish deferred BMC handoffs after Central delivery recovers.

        This is the only retry path that may invoke the official ASUS factory
        handoff.  It is strictly same-server bound, requires all pre-handoff
        artifacts and events to be synchronized, and reuses a successful local
        handoff attestation instead of repeating the reset.  No credentials are
        printed or persisted by this routine.
        """
        root = self.config.primary_root / "runs"
        if not root.is_dir():
            return {"attempted": 0, "completed": 0, "deferred": 0, "failed": 0}
        try:
            _probe, _platform, current_identity, _fru = detect_current_platform_and_identity(
                dmi_root=self.dmi_root, fru_reader=self.fru_reader
            )
        except Exception:
            return {"attempted": 0, "completed": 0, "deferred": 0, "failed": 0, "reason": "CURRENT_IDENTITY_UNAVAILABLE"}
        if not current_identity.get("resumable") or not current_identity.get("fingerprint_sha256"):
            return {"attempted": 0, "completed": 0, "deferred": 0, "failed": 0, "reason": "CURRENT_IDENTITY_UNTRUSTED"}
        attempted = completed = deferred = failed = 0
        errors: list[str] = []
        mutation_started = False
        # Process the newest receipt first; an old lexicographic backlog must
        # not starve the current same-server handoff retry.
        pending_paths = sorted(
            root.glob("RUN-*/bmc-handoff-pending.json"),
            key=lambda path: path.stat().st_mtime if path.exists() else 0,
            reverse=True,
        )[: max(1, min(int(limit), 32))]
        for pending_path in pending_paths:
            try:
                pending = json.loads(pending_path.read_text(encoding="utf-8"))
            except (OSError, ValueError, json.JSONDecodeError):
                failed += 1
                continue
            if not isinstance(pending, Mapping) or str(pending.get("status") or "").upper() != "PENDING":
                continue
            run_dir = pending_path.parent
            run_id = str(pending.get("run_id") or run_dir.name)
            if run_id != run_dir.name:
                failed += 1
                continue
            if str(pending.get("fingerprint_sha256") or "") != str(current_identity.get("fingerprint_sha256") or ""):
                deferred += 1
                continue
            if str(pending.get("server_id") or "") != str(current_identity.get("server_id") or ""):
                deferred += 1
                continue
            artifact_queue = ArtifactStoreForwardQueue(self.config.artifact_queue_database)
            event_queue = StoreForwardQueue(self.config.queue_database)
            # The first attempt may have uploaded bmc-handoff.json while the
            # BMC was still in its pre-reset state.  Once the local receipt is
            # a verified PASS, Central correctly rejects a changed payload
            # under that same filename (HTTP 409).  Retire only that stale
            # queued revision; the immutable bmc-handoff-retry.json successor
            # below carries the authoritative post-reset proof.
            current_handoff_path = run_dir / "bmc-handoff.json"
            try:
                current_handoff = json.loads(current_handoff_path.read_text(encoding="utf-8"))
            except (OSError, ValueError, json.JSONDecodeError):
                current_handoff = {}
            if isinstance(current_handoff, Mapping) and str(current_handoff.get("status") or "").upper() == "PASS":
                handoff_digest = _sha256(current_handoff_path)
                immutable_retry_filename = f"bmc-handoff-retry-{handoff_digest[:12].upper()}.json"
                immutable_report_token = f"HANDOFF_FINAL_{handoff_digest[:12].upper()}"
                for stale_filename in (current_handoff_path.name, "bmc-handoff-retry.json"):
                    artifact_queue.supersede_for_run(
                        run_id,
                        filename=stale_filename,
                        reason="replaced by immutable post-handoff proof",
                    )
                # A previous release used the fixed HANDOFF_FINAL filename.
                # Retire only those old revisions; the hash-qualified successor
                # below remains eligible for normal retry delivery.
                for record in artifact_queue.records_for_run(run_id):
                    filename = str(record.get("filename") or "")
                    status = str(record.get("status") or "")
                    if (
                        "HANDOFF_FINAL" in filename
                        and immutable_report_token not in filename
                        and status in {"PENDING_UPLOAD", "IN_FLIGHT", "UPLOAD_FAILED"}
                    ):
                        artifact_queue.supersede_for_run(
                            run_id,
                            filename=filename,
                            reason="replaced by hash-qualified post-handoff report bundle",
                        )
            if artifact_queue.status_for_run(run_id) != "SYNCED" or event_queue.status_for_run(run_id) not in {"SYNCED", "SYNCED_WITH_QUARANTINED"}:
                deferred += 1
                continue
            attempted += 1
            try:
                # Firmware-only resume deliberately captures fresh inventory
                # under a phase-qualified filename.  Older retry code assumed
                # every workflow also retained the production-mode canonical
                # ``normalized-inventory.json`` and therefore raised
                # FileNotFoundError after an otherwise successful Option 5
                # reboot/resume.  Prefer the current-boot snapshot, then the
                # post-recovery snapshot, and use the canonical snapshot only
                # for workflows that actually wrote it.  Every usable
                # fallback remains bound to this run and the already-verified
                # current physical server; a stale/cross-server snapshot is a
                # hard failure and can never authorize a factory handoff.
                normalized_inventory = self._load_pending_handoff_inventory(
                    run_dir=run_dir,
                    pending=pending,
                    current_identity=current_identity,
                )
                context = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
                summary = json.loads((run_dir / "result-summary.json").read_text(encoding="utf-8"))
                if not isinstance(normalized_inventory, Mapping) or not isinstance(context, Mapping) or not isinstance(summary, Mapping):
                    raise ValueError("HANDOFF_RECORD_INVALID")
                normalized_result = dict(summary.get("normalized_result") or summary.get("result") or {})
                if not normalized_result:
                    raise ValueError("HANDOFF_RESULT_MISSING")
                handoff_path = run_dir / "bmc-handoff.json"
                handoff: dict[str, Any]
                try:
                    existing_handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
                except (OSError, ValueError, json.JSONDecodeError):
                    existing_handoff = {}
                if isinstance(existing_handoff, Mapping) and str(existing_handoff.get("status") or "").upper() == "PASS":
                    handoff = dict(existing_handoff)
                else:
                    handoff = self._perform_bmc_handoff(
                        run_dir=run_dir,
                        normalized_inventory=normalized_inventory,
                        expected_bmc_version=str(pending.get("expected_bmc_version") or ""),
                        firmware_plan=_load_json_mapping(run_dir / "firmware-plan.json"),
                        reset_already_requested=bool(
                            isinstance(existing_handoff, Mapping)
                            and existing_handoff.get("reset_requested")
                        ),
                    )
                    mutation_started = mutation_started or bool(handoff.get("reset_requested"))
                    _atomic_json(handoff_path, handoff)
                normalized_result["bmc_auth_handoff"] = handoff
                workflow_mode = str(
                    (context.get("run") or {}).get("workflow_mode") if isinstance(context.get("run"), Mapping) else "PRODUCTION"
                ).upper() or "PRODUCTION"
                handoff_config = dict(self.config.handoff_policy or {})
                handoff_config["allow_optional_review_for_ready"] = True
                # Extended diagnostics adds its own condition, but it never
                # replaces the normal production delivery/firmware gates.
                # A deferred handoff retry must evaluate the same mandatory
                # production evidence as the original Option 2 run.
                if workflow_mode not in {"FLEET_INTAKE", "DRY_RUN", "SERIAL_COLLECTION", "INVENTORY_ONLY"}:
                    required = list(handoff_config.get("required_for_production", HandoffPolicy().required_for_production))
                    for capability in ("firmware_update", "reports", "artifact_delivery", "primary_archive"):
                        if capability not in required:
                            required.append(capability)
                    handoff_config["required_for_production"] = required
                if workflow_mode == "PRODUCTION_EXTENDED":
                    diagnostic_state = normalized_status(normalized_result.get("system_diagnostics"))
                    if diagnostic_state not in {"UNSUPPORTED", "PLATFORM_UNSUPPORTED"}:
                        required = list(handoff_config.get("required_for_production", HandoffPolicy().required_for_production))
                        if "system_diagnostics" not in required:
                            required.append("system_diagnostics")
                        handoff_config["required_for_production"] = required
                # result-summary.json already contains the previous derived
                # disposition.  Never feed those derived fields back into
                # the policy evaluator: a prior FAIL/NOT_READY value would
                # otherwise be mistaken for a fresh component failure and
                # make a successfully completed handoff permanently fail.
                handoff_input = {
                    key: value
                    for key, value in normalized_result.items()
                    if key
                    not in {
                        "overall",
                        "handoff_status",
                        "handoff_policy",
                        "readiness",
                        "status_summary",
                        "bmc_handoff_artifact",
                        "handoff_final_report_delivery",
                    }
                }
                handoff_eval = evaluate_handoff(
                    handoff_input,
                    workflow_mode=workflow_mode,
                    policy=HandoffPolicy.from_mapping(handoff_config),
                    bmc_auth_changed=True,
                    bmc_handoff_status=str(handoff.get("status") or "FAIL"),
                )
                normalized_result.update(
                    {
                        "overall": handoff_eval["overall"],
                        "handoff_status": handoff_eval["handoff_status"],
                        "handoff_policy": handoff_eval,
                        # The delivery gate is evaluated after the first
                        # report pass.  Recompute the public label here so a
                        # run that was provisionally REVIEW_REQUIRED while
                        # reports were pending can become READY_FOR_SALE
                        # once the final handoff and artifact are complete.
                        "readiness": _public_readiness_label(
                            workflow_mode=workflow_mode,
                            overall=handoff_eval["overall"],
                        ),
                    }
                )
                # The retry receipt is content-addressed.  Central correctly
                # rejects changed bytes under an already-used filename; a
                # handoff proof hash makes retries byte-stable and prevents
                # HTTP 409 collisions after a previous provisional upload.
                handoff_digest = _sha256(handoff_path)
                handoff_retry_path = run_dir / f"bmc-handoff-retry-{handoff_digest[:12].upper()}.json"
                # Keep a successful retry receipt byte-stable.  Rewriting the
                # same Central filename with a new timestamp would correctly
                # produce HTTP 409 and strand an otherwise complete run.
                try:
                    existing_retry = json.loads(handoff_retry_path.read_text(encoding="utf-8"))
                except (OSError, ValueError, json.JSONDecodeError):
                    existing_retry = {}
                if not (isinstance(existing_retry, Mapping) and str(existing_retry.get("status") or "").upper() == "PASS"):
                    _atomic_json(
                        handoff_retry_path,
                        {
                            "schema_version": 1,
                            "status": str(handoff.get("status") or "FAIL"),
                            "attempted_at_utc": utc_now(),
                            "run_id": run_id,
                            "sensitive_material_exposed": False,
                        },
                    )
                handoff_sync = self._sync_artifacts(
                    run_id,
                    {"artifacts": [{"path": str(handoff_retry_path), "type": "RAW_BMC_HANDOFF_RETRY", "sha256": _sha256(handoff_retry_path)}]},
                    client,
                )
                normalized_result["bmc_handoff_artifact"] = handoff_sync
                normalized_result["status_summary"] = human_status_summary(
                    statuses=normalized_result,
                    handoff=handoff_eval,
                    workflow_mode=workflow_mode,
                    central_sync=(
                        "SYNCED"
                        if event_queue.status_for_run(run_id) in {"SYNCED", "SYNCED_WITH_QUARANTINED"}
                        else "PENDING_UPLOAD"
                    ),
                    artifact_status=str(handoff_sync.get("status") or "PENDING_UPLOAD"),
                    reports_status="PASS" if normalized_result.get("reports") == "PASS" else "REVIEW",
                )
                if str(handoff.get("status") or "").upper() != "PASS" or str(handoff_sync.get("status") or "") != "SYNCED":
                    failed += 1
                    continue
                run_payload = dict(context.get("run") or {})
                run_payload["final_disposition"] = handoff_eval["overall"]
                context = dict(context)
                context["run"] = run_payload
                context["result"] = normalized_result
                context["final_decision"] = _final_decision_from_handoff(handoff_eval, workflow_mode=workflow_mode)
                context["finalization"] = dict(context.get("finalization") or {}) | {
                    "bmc_auth_handoff": handoff,
                    "factory_reset_performed": bool(handoff.get("reset_requested")),
                    "overall": handoff_eval["overall"],
                    "handoff_status": handoff_eval["handoff_status"],
                }
                _atomic_json(run_dir / "run.json", context)
                summary_payload = dict(summary)
                summary_payload["normalized_result"] = normalized_result
                summary_payload["bmc_handoff"] = handoff
                _atomic_json(run_dir / "result-summary.json", summary_payload)
                # A deferred handoff changes the authoritative disposition
                # after the original FINAL report was generated.  Publish a
                # second, uniquely named handoff-final bundle so the human
                # PDF/HTML/XLSX carries the same successful handoff state as
                # run.json/result-summary.json.  This is intentionally done
                # only after the factory/default handoff and its raw evidence
                # have been hash-verified; it never triggers another BMC
                # mutation.
                if self.config.reports_enabled:
                    try:
                        firmware_payload: Mapping[str, Any] = {}
                        firmware_path = run_dir / "firmware-plan.json"
                        if firmware_path.is_file():
                            loaded_firmware = json.loads(firmware_path.read_text(encoding="utf-8"))
                            if isinstance(loaded_firmware, Mapping):
                                firmware_payload = loaded_firmware
                        tests_payload: Mapping[str, Any] = {"status": "NOT_REQUESTED"}
                        tests_path = run_dir / "evidence" / "hardware-test-summary.json"
                        if tests_path.is_file():
                            loaded_tests = json.loads(tests_path.read_text(encoding="utf-8"))
                            if isinstance(loaded_tests, Mapping):
                                tests_payload = loaded_tests
                        extended_payload: Mapping[str, Any] | None = None
                        diagnostic_path = run_dir / "diagnostics" / "diagnostic_summary.json"
                        if workflow_mode == "PRODUCTION_EXTENDED" and diagnostic_path.is_file():
                            loaded_diagnostics = json.loads(diagnostic_path.read_text(encoding="utf-8"))
                            if isinstance(loaded_diagnostics, Mapping):
                                extended_payload = loaded_diagnostics
                        handoff_evidence = self._evidence_manifest(
                            [path for path in run_dir.rglob("*") if path.is_file()]
                        )
                        handoff_report = generate_human_reports(
                            run_dir,
                            inventory=normalized_inventory,
                            run=context.get("run") or {},
                            result=normalized_result,
                            firmware=firmware_payload,
                            tests=tests_payload,
                            finalization=context.get("finalization") or {},
                            central={"artifact_status": "SYNCED", "status": "SYNCED"},
                            evidence_manifest=handoff_evidence,
                            extended_diagnostics=extended_payload,
                            report_variant=f"HANDOFF_FINAL_{handoff_digest[:12].upper()}",
                        )
                        handoff_report_sync = self._sync_artifacts(run_id, handoff_report, client)
                        normalized_result["handoff_final_report_delivery"] = handoff_report_sync
                        summary_payload["normalized_result"] = normalized_result
                        summary_payload["handoff_final_report"] = handoff_report
                        _atomic_json(run_dir / "result-summary.json", summary_payload)
                    except Exception as report_error:
                        # The handoff itself remains authoritative, but a
                        # report-generation failure must remain visible and
                        # must never be presented as a successful delivery.
                        normalized_result["handoff_final_report_delivery"] = {
                            "status": "FAILED",
                            "reason": type(report_error).__name__,
                        }
                        summary_payload["normalized_result"] = normalized_result
                        _atomic_json(run_dir / "result-summary.json", summary_payload)
                event = run_completed_event(RunRecord.from_dict(run_payload), result=normalized_result)
                self._enqueue_and_drain(event_queue, event, run_dir / "run.json", client)
                _atomic_json(
                    run_dir / "bmc-handoff-completed.json",
                    {
                        "schema_version": 1,
                        "status": "PASS",
                        "completed_at_utc": utc_now(),
                        "run_id": run_id,
                        "handoff_status": handoff_eval["handoff_status"],
                        "sensitive_material_exposed": False,
                    },
                )
                pending_path.unlink(missing_ok=True)
                # A repeated same-server run can leave older pending receipts
                # behind.  Once this newest receipt proves the factory/default
                # handoff, retain those records as history but prevent them
                # from issuing another BMC reset on a later retry.
                for stale_path in root.glob("RUN-*/bmc-handoff-pending.json"):
                    if stale_path == pending_path:
                        continue
                    try:
                        stale = json.loads(stale_path.read_text(encoding="utf-8"))
                    except (OSError, ValueError, json.JSONDecodeError):
                        continue
                    if not isinstance(stale, Mapping) or str(stale.get("status") or "").upper() != "PENDING":
                        continue
                    if str(stale.get("server_id") or "") != str(current_identity.get("server_id") or ""):
                        continue
                    _atomic_json(
                        stale_path,
                        dict(stale)
                        | {
                            "status": "SUPERSEDED",
                            "superseded_by_run_id": run_id,
                            "reason": "SAME_SERVER_HANDOFF_COMPLETED_BY_NEWER_RUN",
                            "sensitive_material_exposed": False,
                        },
                    )
                completed += 1
            except Exception as exc:
                failed += 1
                # Keep retry diagnostics actionable without serializing the
                # exception text (which could contain paths or credentials).
                errors.append("HANDOFF_RETRY_EXCEPTION:" + type(exc).__name__)
        return {
            "attempted": attempted,
            "completed": completed,
            "deferred": deferred,
            "failed": failed,
            "mutation_started": mutation_started,
            "errors": errors,
        }

    @staticmethod
    def _load_pending_handoff_inventory(
        *,
        run_dir: Path,
        pending: Mapping[str, Any],
        current_identity: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Load the freshest identity-bound inventory for a deferred handoff.

        Option 5's reboot/resume path writes phase-qualified snapshots while
        Options 1/2 normally retain the canonical filename.  Missing files
        may fall back in freshness order, but an existing malformed or
        identity-conflicting snapshot fails closed instead of silently using
        older evidence.
        """
        expected_run_id = str(pending.get("run_id") or run_dir.name)
        expected_server_id = str(
            pending.get("server_id") or current_identity.get("server_id") or ""
        )
        expected_system_serial = str(
            pending.get("system_serial") or current_identity.get("primary_serial") or ""
        )
        for filename in (
            "normalized-inventory-post-reboot.json",
            "normalized-inventory-post-bmc-recovery.json",
            "normalized-inventory.json",
        ):
            path = run_dir / filename
            if not path.is_file():
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                raise ValueError("HANDOFF_INVENTORY_INVALID") from exc
            if not isinstance(payload, Mapping):
                raise ValueError("HANDOFF_INVENTORY_INVALID")
            actual_run_id = str(payload.get("run_id") or "")
            actual_server_id = str(payload.get("server_id") or "")
            actual_system_serial = str(payload.get("system_serial") or "")
            if (
                not actual_run_id
                or actual_run_id != expected_run_id
                or not actual_server_id
                or not expected_server_id
                or actual_server_id != expected_server_id
                or (
                    expected_system_serial
                    and actual_system_serial != expected_system_serial
                )
            ):
                raise ValueError("HANDOFF_INVENTORY_IDENTITY_MISMATCH")
            return dict(payload)
        raise FileNotFoundError("HANDOFF_INVENTORY_NOT_FOUND")

    def _write_pending_firmware(
        self,
        *,
        run_dir: Path,
        identity: Mapping[str, Any],
        plan: Mapping[str, Any],
        execution: Mapping[str, Any],
        bmc_auth_changed: bool,
        runner_id: str,
        workflow_mode: str,
        profile_id: str = "STANDARD",
        profile_total_seconds: int = 0,
        extended_diagnostics: bool = False,
        checkpoint_state: str = "REBOOT_PENDING",
    ) -> dict[str, Any]:
        pending = build_firmware_pending(
            run_id=run_dir.name,
            run_directory=run_dir,
            identity=identity,
            runner_id=runner_id,
            workflow_mode=workflow_mode,
            profile_id=profile_id,
            profile_total_seconds=profile_total_seconds,
            extended_diagnostics=extended_diagnostics,
            plan=plan,
            execution=execution,
            bmc_auth_changed=bmc_auth_changed,
        )
        normalized_state = str(checkpoint_state or "REBOOT_PENDING").upper()
        if normalized_state not in {"REBOOT_PENDING", "TASK_IN_PROGRESS", "TASK_RESUMED"}:
            raise FirmwareLifecycleError("PENDING_FIRMWARE_CHECKPOINT_STATE_INVALID")
        pending["state"] = normalized_state
        if normalized_state in {"TASK_IN_PROGRESS", "TASK_RESUMED"}:
            pending["reboot"] = {
                "requested": False,
                "requested_at_utc": "",
                "status": "NOT_REQUESTED",
                "retry_count": 0,
            }
        save_firmware_pending(self.config.primary_root, pending)
        _atomic_json(run_dir / "firmware-pending.json", pending)
        return pending

    def _load_pending_firmware(self) -> dict[str, Any] | None:
        return load_firmware_pending(self.config.primary_root)

    def _quarantine_foreign_pending(
        self,
        pending: Mapping[str, Any] | None,
        *,
        identity: Mapping[str, Any],
        runner_id: str,
    ) -> dict[str, Any] | None:
        """Move a positively foreign checkpoint out of the active slot.

        A pending checkpoint is mutation authority, not ordinary history.  If
        a technician moves an SSD to another server, leaving it in the global
        slot causes every menu path to stop at a safe-but-unhelpful mismatch.
        Once current identity is trusted and the stored server/fingerprint or
        runner binding differs, preserve the exact checkpoint under a dated,
        secret-free quarantine and let the new server enroll normally.  Missing
        identity is deliberately *not* quarantined; the normal validator then
        fails closed until identity is trustworthy.
        """
        if not isinstance(pending, Mapping):
            return None
        observed_server = str(identity.get("server_id") or "")
        observed_fingerprint = str(identity.get("fingerprint_sha256") or "")
        observed_runner = str(runner_id or "").upper()
        expected_server = str(pending.get("server_id") or "")
        expected_fingerprint = str(pending.get("fingerprint_sha256") or "")
        expected_runner = str(pending.get("runner_id") or "").upper()
        if (
            not bool(identity.get("resumable"))
            or not expected_server
            or not expected_fingerprint
            or not observed_server
            or not observed_fingerprint
        ):
            return None
        mismatches: dict[str, dict[str, str]] = {}
        if expected_server != observed_server:
            mismatches["server_id"] = {"pending": expected_server, "current": observed_server}
        if expected_fingerprint != observed_fingerprint:
            mismatches["fingerprint_sha256"] = {"pending": expected_fingerprint, "current": observed_fingerprint}
        if expected_runner and observed_runner and expected_runner != observed_runner:
            mismatches["runner_id"] = {"pending": expected_runner, "current": observed_runner}
        if not mismatches:
            return None
        source = self.config.primary_root / "firmware-pending.json"
        if not source.exists() and not source.is_symlink():
            return None
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        quarantine = self.config.primary_root / "enrollment-quarantine" / (
            f"FOREIGN-PENDING-{stamp}-{observed_fingerprint[:12].upper()}"
        )
        destination = quarantine / "firmware-pending.json"
        quarantine.mkdir(parents=True, exist_ok=True)
        suffix = 1
        while destination.exists() or destination.is_symlink():
            destination = quarantine / f"firmware-pending.json.{suffix}"
            suffix += 1
        source.replace(destination)
        receipt = {
            "schema_version": 1,
            "status": "FOREIGN_PENDING_QUARANTINED",
            "reason": "PENDING_FIRMWARE_SERVER_OR_RUNNER_BINDING_MISMATCH",
            "quarantined_at_utc": utc_now(),
            "quarantine_path": str(destination),
            "run_id": str(pending.get("run_id") or ""),
            "workflow_mode": str(pending.get("workflow_mode") or ""),
            "mismatches": mismatches,
            "current_server_id": observed_server,
            "current_fingerprint_sha256": observed_fingerprint,
            "current_runner_id": observed_runner,
            "resume_allowed": False,
            "sensitive_material_exposed": False,
        }
        _atomic_json(quarantine / "quarantine-receipt.json", receipt)
        assert_no_sensitive_fields(receipt)
        return receipt

    def _archive_and_clear_pending_firmware(
        self,
        *,
        run_dir: Path,
        run_id: str,
        completion_status: str,
    ) -> dict[str, Any]:
        """Retire a completed reboot checkpoint without erasing its evidence.

        The global checkpoint is an *instruction* for the boot-time resume
        unit, not a historical result.  Leaving it in place would make a later
        boot attempt to resume an already complete RUN.  Before removal, write
        a terminal, secret-free receipt in the original run directory.
        """
        pending = self._load_pending_firmware()
        if not pending or str(pending.get("run_id") or "") != str(run_id):
            return {"status": "NOT_PRESENT", "run_id": str(run_id), "sensitive_material_exposed": False}
        archived = dict(pending)
        archived.update(
            {
                "state": "COMPLETED",
                "completed_at_utc": utc_now(),
                "completion_status": str(completion_status or "UNKNOWN"),
                "resume_instruction_active": False,
                "sensitive_material_exposed": False,
            }
        )
        _atomic_json(run_dir / "firmware-pending-completed.json", archived)
        clear_firmware_pending(self.config.primary_root, run_dir)
        try:
            (self.config.primary_root / "firmware-inflight.json").unlink(missing_ok=True)
        except OSError:
            pass
        return {
            "status": "ARCHIVED_AND_CLEARED",
            "path": str(run_dir / "firmware-pending-completed.json"),
            "run_id": str(run_id),
            "sensitive_material_exposed": False,
        }

    def _verify_pending_components_after_reboot(
        self,
        pending: Mapping[str, Any],
        normalized_inventory: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Attest every component captured by a reboot checkpoint.

        The checkpoint is the authority for *what was approved before the
        reboot*.  A freshly fetched catalog may legitimately change while the
        server is restarting; it must not cause a second, unconfirmed flash.
        Conversely, a single BIOS match must never hide a BMC target that did
        not activate.  All values are obtained from current local DMI/KCS
        evidence and no BMC credential is needed here.
        """
        all_components = [item for item in pending.get("components") or [] if isinstance(item, Mapping)]
        activation_names = {
            str(value or "").upper()
            for value in pending.get("activation_pending_components") or []
            if str(value or "").upper()
        }
        # Backwards compatibility for a checkpoint produced before component
        # progress was persisted: it contained only one staged BIOS target.
        if not activation_names:
            activation_names = {
                str(item.get("component") or "").upper()
                for item in all_components
                if str(item.get("component") or "").upper() == "BIOS"
            }
        completed_pre_reboot_names = {
            str(value or "").upper()
            for value in pending.get("completed_pre_reboot_components") or []
            if str(value or "").upper() in {"BIOS", "BMC"}
        }
        verification_names = activation_names | completed_pre_reboot_names
        checkpoint_targets = {
            str(item.get("component") or "").upper(): str(item.get("target") or "")
            for item in all_components
            if str(item.get("component") or "").upper() in {"BIOS", "BMC"}
            and str(item.get("target") or "")
        }
        missing_targets = sorted(verification_names - set(checkpoint_targets))
        if missing_targets:
            # Never let a partially populated checkpoint turn one matching
            # component into proof for the whole staged lifecycle.  This is
            # especially important when BMC completed before a later BIOS
            # reboot: the exact BMC target must be present and re-attested on
            # the new boot, even when the refreshed plan called it CURRENT.
            return {
                "schema_version": 1,
                "status": "FAIL",
                "reason": "PENDING_FIRMWARE_COMPONENT_TARGET_MISSING",
                "components": [
                    {
                        "component": name,
                        "target": "",
                        "status": "FAIL",
                        "reason": "PENDING_FIRMWARE_COMPONENT_TARGET_MISSING",
                    }
                    for name in missing_targets
                ],
                "activation_pending_components": sorted(activation_names),
                "completed_pre_reboot_components": sorted(completed_pre_reboot_names),
                "remaining_components": [],
                "resume_boot_id": read_linux_boot_id(),
                "sensitive_material_exposed": False,
            }
        components = [
            item for item in all_components
            if str(item.get("component") or "").upper() in verification_names
        ]
        if not components or not verification_names:
            return {
                "status": "FAIL",
                "reason": "PENDING_FIRMWARE_COMPONENTS_MISSING",
                "components": [],
                "sensitive_material_exposed": False,
            }
        results: list[dict[str, Any]] = []
        for component in components:
            name = str(component.get("component") or "").upper()
            target = str(component.get("target") or "")
            if name not in {"BIOS", "BMC"} or not target:
                results.append(
                    {
                        "component": name or "UNKNOWN",
                        "target": target,
                        "status": "FAIL",
                        "reason": "PENDING_FIRMWARE_COMPONENT_INVALID",
                    }
                )
                continue
            current = self._read_live_firmware_version(name, normalized_inventory)
            verified = _firmware_versions_equal(current, target)
            results.append(
                {
                    "component": name,
                    "before": str(component.get("before") or ""),
                    "target": target,
                    "after": current,
                    "status": "UPDATED_VERIFIED" if verified else "REBOOT_REQUIRED",
                    "source": "DMI_CURRENT_BOOT" if name == "BIOS" else "IPMI_MC_LOCAL_KCS",
                }
            )
        verified = bool(results) and all(str(item["status"]) == "UPDATED_VERIFIED" for item in results)
        remaining = [
            str(value or "").upper()
            for value in pending.get("remaining_components") or []
            if str(value or "").upper() in {"BIOS", "BMC"}
        ]
        return {
            "schema_version": 1,
            "status": "UPDATED_VERIFIED" if verified else "REBOOT_REQUIRED",
            "reason": "POST_REBOOT_ALL_PENDING_COMPONENTS_VERIFIED" if verified else "POST_REBOOT_COMPONENT_VERSION_NOT_VERIFIED",
            "components": results,
            "activation_pending_components": sorted(activation_names),
            "completed_pre_reboot_components": sorted(completed_pre_reboot_names),
            "remaining_components": list(dict.fromkeys(remaining)),
            "resume_boot_id": read_linux_boot_id(),
            "sensitive_material_exposed": False,
        }

    def _resume_pending_firmware(self, pending: Mapping[str, Any]) -> dict[str, Any]:
        """Resume Option 5 from the same identity-bound checkpoint.

        A reboot never converts a firmware-only request into a second run or a
        BIOS-only verification shortcut.  The exact checkpointed plan remains
        authoritative, every activation-pending component is attested from
        current DMI/KCS evidence, and any still-approved component continues
        through the shared executor before reports and final BMC handoff.
        """
        if str(pending.get("workflow_mode") or "").upper() != "FIRMWARE_ONLY":
            return {
                "status": "BLOCKED_FIRMWARE_RESUME_WORKFLOW",
                "pending_workflow_mode": str(pending.get("workflow_mode") or ""),
                "mutation_started": False,
                "sensitive_material_exposed": False,
            }
        probe, platform, identity, fru = detect_current_platform_and_identity(
            dmi_root=self.dmi_root,
            fru_reader=self.fru_reader,
        )
        if platform.get("platform_id") != "ASUS_SERVER" or str(platform.get("vendor") or "") != "ASUS":
            return {
                "status": "BLOCKED_FIRMWARE_RESUME_PLATFORM",
                "reason": "CURRENT_PLATFORM_IS_NOT_THE_APPROVED_ASUS_SERVER",
                "pending": dict(pending),
                "mutation_started": False,
                "sensitive_material_exposed": False,
            }
        try:
            runner = load_runner(self.config.runner_config)
            validate_pending_for_resume(
                pending,
                identity=identity,
                runner_id=str(runner.get("runner_id") or ""),
                require_new_boot=str(pending.get("state") or "").upper()
                not in {"TASK_IN_PROGRESS", "TASK_RESUMED"},
            )
            orchestrator = ProductionOrchestrator(self.config.primary_root, runtime_version=self.runtime_version)
            context = orchestrator.resume(
                str(pending.get("run_id") or ""),
                identity=identity,
                runner_id=str(runner.get("runner_id") or ""),
            )
        except (FirmwareLifecycleError, WorkflowError, OSError) as exc:
            return {
                "status": "BLOCKED_IDENTITY_MISMATCH",
                "reason": str(exc),
                "execution": {"status": "BLOCKED_IDENTITY_MISMATCH", "sensitive_material_exposed": False},
                "pending": dict(pending),
            }
        run_id = str(context.get("run", {}).get("run_id") or pending.get("run_id") or "")
        run_dir = self.config.primary_root / "runs" / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        client, central_runtime = self._collector_client()
        queue = StoreForwardQueue(self.config.queue_database)
        resumed_event = run_progress_event(
            RunRecord.from_dict(context["run"]),
            stage_result={
                "stage": "FIRMWARE_ONLY_POST_REBOOT_RESUME",
                "boot_id": str(identity.get("boot_id") or ""),
                "same_run": True,
            },
        )
        _atomic_json(
            run_dir / "central-firmware-resumed.json",
            self._enqueue_and_drain(queue, resumed_event, run_dir / "run.json", client),
        )
        context = orchestrator.transition(
            context,
            identity=identity,
            next_stage=WorkflowStage.CAPABILITY_DISCOVERY,
            details={"resume": True, "local_fru_collection": _public_fru_status(fru)},
        )
        evidence_dir = run_dir / "evidence-post-reboot"
        inventory = self._collect_inventory(
            evidence_dir,
            identity=identity,
            platform=platform,
            probe=probe,
            run_id=run_id,
            runner_id=str(runner.get("runner_id") or ""),
        )
        discovery = self._discover_bmc_auth(
            inventory.get("normalized") or {},
            identity,
            exclude_run_id=run_id,
            read_only=True,
        )
        if inventory.get("normalized"):
            inventory["normalized"]["bmc_auth_state"] = str(
                discovery.get("state") or BmcAuthState.BMC_AUTH_UNAVAILABLE.value
            )
        _atomic_json(run_dir / "normalized-inventory-post-reboot.json", inventory.get("normalized") or {})
        _atomic_json(run_dir / "bmc-auth-discovery-post-reboot.json", discovery)
        context = orchestrator.transition(
            context,
            identity=identity,
            next_stage=WorkflowStage.INVENTORY,
            details=inventory.get("summary") or {},
        )
        post_reboot = self._verify_pending_components_after_reboot(
            pending,
            inventory.get("normalized") or {},
        )
        _atomic_json(run_dir / "firmware-post-reboot-verification.json", post_reboot)
        try:
            saved_plan = json.loads((run_dir / "firmware-plan.json").read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            saved_plan = {}
        plan = dict(saved_plan) if isinstance(saved_plan, Mapping) else {}
        if not plan:
            plan = {"readiness": "UNVERIFIED", "components": []}
        if str(post_reboot.get("status") or "") != "UPDATED_VERIFIED":
            execution = {
                "status": "REBOOT_REQUIRED",
                "reason": str(post_reboot.get("reason") or "POST_REBOOT_VERSION_NOT_VERIFIED"),
                "components": list(post_reboot.get("components") or []),
                "mutation_started": bool(pending.get("mutation_started")),
                "resumed": True,
                "sensitive_material_exposed": False,
            }
            context = orchestrator.transition(
                context,
                identity=identity,
                next_stage=WorkflowStage.FIRMWARE_PLAN,
                details={"resume": True, "post_reboot_verification": post_reboot},
            )
            _atomic_json(run_dir / "firmware-execution-resume.json", execution)
            return self._complete_firmware_only_run(
                orchestrator=orchestrator,
                context=context,
                identity=identity,
                inventory=inventory,
                discovery=discovery,
                plan=plan,
                execution=execution,
                run_dir=run_dir,
                client=client,
                central_runtime=central_runtime,
                queue=queue,
                bmc_auth_changed=bool(pending.get("bmc_auth_changed")) or bmc_auth_change_required(discovery),
                resumed=True,
            )

        activation_names = {
            str(value or "").upper()
            for value in post_reboot.get("activation_pending_components") or []
            if str(value or "").upper()
        }
        completed_pre_reboot_names = {
            str(value or "").upper()
            for value in post_reboot.get("completed_pre_reboot_components") or []
            if str(value or "").upper() in {"BIOS", "BMC"}
        }
        remaining = [
            str(value or "").upper()
            for value in post_reboot.get("remaining_components") or []
            if str(value or "").upper() in {"BIOS", "BMC"}
        ]
        for item in plan.get("components") or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("component") or "").upper()
            match = next(
                (
                    row
                    for row in post_reboot.get("components") or []
                    if isinstance(row, Mapping) and str(row.get("component") or "").upper() == name
                ),
                None,
            )
            if name in (activation_names | completed_pre_reboot_names) and isinstance(match, Mapping):
                item["after"] = str(match.get("after") or "")
                item["status"] = "UPDATED_VERIFIED"
        plan["post_reboot_verification"] = post_reboot
        plan["resume_remaining_components"] = list(dict.fromkeys(remaining))
        plan["readiness"] = "UPDATE_REQUIRED" if remaining else "UPDATED_VERIFIED"
        _atomic_json(run_dir / "firmware-plan-resume-approved.json", plan)
        context = orchestrator.transition(
            context,
            identity=identity,
            next_stage=WorkflowStage.FIRMWARE_PLAN,
            details={"resume": True, "post_reboot_verification": post_reboot, "remaining_components": remaining},
        )

        if remaining:
            if _firmware_requires_authenticated_bmc(plan):
                inventory, discovery, recovery = self._ensure_authenticated_firmware_access(
                    run_dir=run_dir,
                    identity=identity,
                    platform=platform,
                    probe=probe,
                    inventory=inventory,
                    firmware=plan,
                    run_id=run_id,
                    runner_id=str(runner.get("runner_id") or ""),
                    discovery=discovery,
                )
            else:
                recovery = {
                    "status": "NOT_REQUIRED",
                    "reason": "SELECTED_LOCAL_TRANSPORT_DOES_NOT_REQUIRE_BMC_AUTH",
                    "mutation_started": False,
                    "sensitive_material_exposed": False,
                }
            _atomic_json(run_dir / "bmc-recovery-path-resume.json", recovery)
            _atomic_json(run_dir / "bmc-auth-discovery-resume.json", discovery)
            if _firmware_requires_authenticated_bmc(plan) and not bmc_auth_is_usable(str(discovery.get("state") or "")):
                execution = {
                    "status": str(recovery.get("status") or "BLOCKED_BY_AUTH"),
                    "reason": str(recovery.get("reason") or "AUTHENTICATED_BMC_REQUIRED_FOR_REMAINING_FIRMWARE"),
                    "mutation_started": bool(pending.get("mutation_started")),
                    "resumed": True,
                    "sensitive_material_exposed": False,
                }
            else:
                next_component = next(
                    (
                        item
                        for item in plan.get("components") or []
                        if isinstance(item, Mapping)
                        and str(item.get("component") or "").upper() in set(remaining)
                        and str(item.get("status") or "") == "UPDATE_REQUIRED"
                    ),
                    {},
                )
                if not next_component:
                    execution = {
                        "status": "UNVERIFIED",
                        "reason": "PENDING_REMAINING_COMPONENT_NOT_PRESENT_IN_APPROVED_PLAN",
                        "mutation_started": bool(pending.get("mutation_started")),
                        "resumed": True,
                        "sensitive_material_exposed": False,
                    }
                else:
                    context = orchestrator.transition(
                        context,
                        identity=identity,
                        next_stage=WorkflowStage.FIRMWARE_APPLY,
                        mutation_gate=MutationGate(
                            authorized=True,
                            lab_mode=True,
                            approval_id=f"AUTO-FIRMWARE-RESUME-{run_id}",
                            machine_fingerprint_sha256=str(identity.get("fingerprint_sha256") or ""),
                            vendor="ASUS",
                            model=str(identity.get("model") or ""),
                            system_serial=str(identity.get("primary_serial") or ""),
                            run_id=run_id,
                            component=str(next_component.get("component") or "").upper(),
                            target_version=str(next_component.get("target") or ""),
                            allowed_actions=frozenset({"FIRMWARE_APPLY"}),
                            expires_at_utc=(datetime.now(timezone.utc) + timedelta(minutes=45)).isoformat(),
                        ),
                        details={"resume": True, "remaining_components": remaining},
                    )
                    execution = self._execute_firmware_lifecycle(
                        run_dir=run_dir,
                        identity=identity,
                        platform=platform,
                        probe=probe,
                        runner_id=str(runner.get("runner_id") or ""),
                        inventory=inventory,
                        bmc_discovery=discovery,
                        firmware=plan,
                        run_id=run_id,
                    )
                if str(execution.get("status") or "") == "REBOOT_REQUIRED":
                    context = orchestrator.transition(
                        context,
                        identity=identity,
                        next_stage=WorkflowStage.REBOOT_PENDING,
                        details=execution,
                        firmware_task_identity=str(execution.get("task_id") or ""),
                    )
                    next_pending = self._write_pending_firmware(
                        run_dir=run_dir,
                        identity=identity,
                        plan=plan,
                        execution=execution,
                        bmc_auth_changed=bool(pending.get("bmc_auth_changed")) or bmc_auth_change_required(discovery),
                        runner_id=str(runner.get("runner_id") or ""),
                        workflow_mode="FIRMWARE_ONLY",
                        profile_id="FIRMWARE_ONLY",
                    )
                    reboot = request_controlled_reboot(
                        executor=self.executor,
                        primary_root=self.config.primary_root,
                        pending=next_pending,
                    )
                    execution["reboot"] = reboot
                    _atomic_json(run_dir / "firmware-execution-resume.json", execution)
                    return {
                        "status": reboot["status"],
                        "firmware": plan,
                        "execution": execution,
                        "pending": next_pending,
                        "run": context["run"],
                        "run_directory": str(run_dir),
                        "mutation_started": bool(execution.get("mutation_started")),
                        "sensitive_material_exposed": False,
                    }
                if str(execution.get("status") or "") == "UPDATED_VERIFIED":
                    context = orchestrator.transition(
                        context,
                        identity=identity,
                        next_stage=WorkflowStage.POST_UPDATE_VERIFY,
                        details=execution,
                    )
        else:
            execution = {
                "status": "UPDATED_VERIFIED",
                "reason": "POST_REBOOT_VERSION_VERIFIED",
                "components": list(post_reboot.get("components") or []),
                "mutation_started": bool(pending.get("mutation_started")),
                "resumed": True,
                "sensitive_material_exposed": False,
            }
            context = orchestrator.transition(
                context,
                identity=identity,
                next_stage=WorkflowStage.POST_UPDATE_VERIFY,
                details=execution,
            )
        _atomic_json(run_dir / "firmware-execution-resume.json", execution)
        return self._complete_firmware_only_run(
            orchestrator=orchestrator,
            context=context,
            identity=identity,
            inventory=inventory,
            discovery=discovery,
            plan=plan,
            execution=execution,
            run_dir=run_dir,
            client=client,
            central_runtime=central_runtime,
            queue=queue,
            bmc_auth_changed=bool(pending.get("bmc_auth_changed")) or bmc_auth_change_required(discovery),
            resumed=True,
        )

    def _ensure_authenticated_firmware_access(
        self,
        *,
        run_dir: Path,
        identity: Mapping[str, Any],
        platform: Mapping[str, Any],
        probe: PlatformProbe,
        inventory: Mapping[str, Any],
        firmware: Mapping[str, Any],
        run_id: str,
        runner_id: str,
        discovery: Mapping[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        """Establish BMC auth only when an exact firmware update needs it.

        Normal inventory, Fleet Intake, Dry Run, and a firmware-current
        production run retain the server's existing BMC credential state.  If
        the update path needs authenticated transport and an exact ASUS ASMB
        capability is detected, this is the only bounded used-server recovery
        flow: preserve evidence, local KCS factory recovery, rediscover LAN,
        then perform the documented default first-login provisioning.
        """
        current = dict(discovery or {})
        if bmc_auth_is_usable(str(current.get("state") or "")):
            return dict(inventory), current, {"status": "NOT_REQUIRED", "reason": "APPROVED_AUTH_ALREADY_USABLE"}
        normalized = inventory.get("normalized") if isinstance(inventory.get("normalized"), Mapping) else {}
        # A prior boot may have already executed the bounded ASUS factory
        # recovery or first-login password patch.  Never repeat that raw KCS
        # mutation merely because the resumed process cannot authenticate yet:
        # retry the approved credential/provisioning probe, then stop with a
        # capability-specific block if access is still unavailable.  Repeating
        # factory recovery could erase a technician's intervening BMC setup and
        # would violate the one-bounded-recovery contract.
        active_marker = self._active_bmc_auth_change_marker(identity)
        if active_marker:
            # The same-run marker is durable across the BMC/host reboot
            # boundary.  Host-side enumeration can temporarily omit the BMC
            # address after that reboot, so reuse only the marker's own
            # recovery-proven IP (never a previous-server value) for the
            # authenticated probe.
            endpoint_verified = bool(active_marker.get("bmc_endpoint_verified"))
            endpoint_ip = str(active_marker.get("bmc_ip") or "").strip()
            endpoint_source = str(active_marker.get("bmc_endpoint_source") or "")
            endpoint_mac = str(active_marker.get("bmc_mac") or "")
            if not endpoint_verified or not endpoint_ip:
                # Older durable markers did not carry endpoint provenance.
                # Re-establish it locally, bound to KCS LAN/MAC evidence,
                # rather than trusting a historical marker IP.
                endpoint = discover_local_bmc_endpoint(
                    self.executor,
                    normalized_inventory=normalized,
                )
                if endpoint.status == "DISCOVERED":
                    endpoint_verified = True
                    endpoint_ip = endpoint.ip
                    endpoint_source = endpoint.source
                    endpoint_mac = endpoint.mac
            if not endpoint_verified:
                blocked = dict(current)
                blocked.update(
                    {
                        "state": BmcAuthState.BMC_AUTH_UNAVAILABLE.value,
                        "usable_for_authenticated_get": False,
                        "reason": "BMC_ENDPOINT_NOT_DISCOVERABLE_POST_RECOVERY",
                    }
                )
                return dict(inventory), blocked, {
                    "status": "BLOCKED_BY_AUTH",
                    "reason": "BMC_ENDPOINT_NOT_DISCOVERABLE_POST_RECOVERY",
                    "marker_active": True,
                    "sensitive_material_exposed": False,
                }
            normalized = _merge_post_recovery_inventory(
                normalized,
                recovery={
                    "bmc_ip_after": endpoint_ip,
                    "bmc_endpoint_status": "DISCOVERED",
                    "bmc_endpoint_source": endpoint_source,
                    "bmc_mac": endpoint_mac,
                },
                firmware=firmware,
            )
            rediscovered = self._discover_bmc_auth(
                normalized,
                identity,
                exclude_run_id=run_id,
                read_only=False,
                allow_default_probe_after_recovery=True,
                # A raw ASUS factory recovery has invalidated the prior
                # operational account.  Do not submit that now-stale secret
                # before the one documented factory/default probe.
                ignore_provisioned_candidates="FACTORY_DEFAULT_RAW_32_66" in str(active_marker.get("method") or "").upper(),
            )
            rediscovered["bmc_auth_change_started"] = True
            rediscovered["auth_change_provenance"] = "CNServerOps_PERSISTED_MARKER"
            rediscovered["bmc_auth_change_marker"] = {
                "method": str(active_marker.get("method") or "UNKNOWN"),
                "changed_at_utc": str(active_marker.get("changed_at_utc") or ""),
                "active": True,
                "sensitive_material_exposed": False,
            }
            resumed_inventory = dict(inventory)
            resumed_inventory["normalized"] = normalized
            if bmc_auth_is_usable(str(rediscovered.get("state") or "")):
                return resumed_inventory, rediscovered, {
                    "status": "NOT_REQUIRED",
                    "reason": "ACTIVE_AUTH_CHANGE_MARKER_CREDENTIAL_REUSED",
                    "marker_active": True,
                    "sensitive_material_exposed": False,
                }
            return resumed_inventory, rediscovered, {
                "status": "BLOCKED_BY_AUTH",
                "reason": "BMC_AUTH_CHANGE_MARKER_ACTIVE_RECOVERY_NOT_REPEATED",
                "marker_active": True,
                "method": str(active_marker.get("method") or "UNKNOWN"),
                "sensitive_material_exposed": False,
            }

        # A new ASUS BMC may accept the documented factory credential only
        # long enough to require its first password change.  That is positive
        # current-endpoint evidence, not an unknown-used-server credential
        # failure.  Complete this one supported first-login flow before
        # considering the much more disruptive local factory recovery.
        #
        # The host equality check prevents a stale stored discovery record
        # from authorizing a default-account attempt against a different
        # endpoint after DHCP or a server move.  The auth layer then uses only
        # the observed documented default account and deliberately excludes
        # every provisioned credential candidate.
        observed_state = str(current.get("state") or "")
        observed_host = str(current.get("host") or "").strip()
        current_host = str(normalized.get("bmc_ip") or "").strip()
        if (
            observed_state == BmcAuthState.BMC_PASSWORD_CHANGE_REQUIRED.value
            and observed_host
            and observed_host == current_host
        ):
            first_login = self._discover_bmc_auth(
                normalized,
                identity,
                exclude_run_id=run_id,
                read_only=False,
                allow_default_probe_after_observed_first_login=True,
                ignore_provisioned_candidates=True,
            )
            first_login["first_login_provisioning_attempted"] = True
            first_login["first_login_provisioning_provenance"] = (
                "DOCUMENTED_DEFAULT_PASSWORD_CHANGE_REQUIRED_CURRENT_ENDPOINT"
            )
            if bmc_auth_is_usable(str(first_login.get("state") or "")):
                return dict(inventory), first_login, {
                    "status": "NOT_REQUIRED",
                    "reason": "DOCUMENTED_FIRST_LOGIN_PROVISIONED_WITHOUT_FACTORY_RECOVERY",
                    "factory_recovery_started": False,
                    "sensitive_material_exposed": False,
                }
            provisioning = first_login.get("provisioning") if isinstance(first_login, Mapping) else {}
            if isinstance(provisioning, Mapping) and bool(provisioning.get("mutation_performed")):
                # A password patch might have reached the BMC even if its
                # post-patch verification was interrupted.  The marker is
                # already persisted by _discover_bmc_auth; do not erase that
                # evidence with a second raw factory reset in this run.
                return dict(inventory), first_login, {
                    "status": "BLOCKED_BY_AUTH",
                    "reason": "FIRST_LOGIN_PROVISIONING_MUTATION_UNVERIFIED_RECOVERY_NOT_REPEATED",
                    "factory_recovery_started": False,
                    "sensitive_material_exposed": False,
                }
            current["first_login_provisioning"] = {
                "status": str(first_login.get("state") or "UNAVAILABLE"),
                "reason": str(first_login.get("reason") or ""),
                "attempted": True,
                "mutation_performed": False,
                "sensitive_material_exposed": False,
            }
        capability = asus_bmc_recovery_capability(
            normalized_inventory=normalized,
            firmware_plan=firmware,
        )
        if not bool(capability.get("supported")):
            return dict(inventory), current, {
                "status": "BLOCKED_BY_AUTH",
                "reason": "NO_VALIDATED_LOCAL_RECOVERY_FOR_THIS_PLATFORM",
                "capability": capability,
                "sensitive_material_exposed": False,
            }
        gate = MutationGate(
            authorized=True,
            lab_mode=True,
            approval_id=f"OPERATOR-FIRMWARE-BMC-RECOVERY-{run_id}",
            machine_fingerprint_sha256=str(identity.get("fingerprint_sha256") or ""),
            vendor="ASUS",
            model=str(identity.get("model") or ""),
            system_serial=str(identity.get("primary_serial") or ""),
            run_id=run_id,
            component="BMC",
            allowed_actions=frozenset({"BMC_FACTORY_RECOVERY"}),
            expires_at_utc=(datetime.now(timezone.utc) + timedelta(minutes=20)).isoformat(),
        )
        generation = str(capability.get("bmc_generation") or "").upper()
        recovery_runner = recover_asmb12_bmc if generation == "ASMB12" else recover_asus_bmc
        recovery = recovery_runner(
            executor=self.executor,
            identity=identity,
            normalized_inventory=normalized,
            firmware_plan=firmware,
            mutation_gate=gate,
            run_id=run_id,
            evidence_dir=run_dir / "bmc-recovery",
        ).to_dict()
        _atomic_json(run_dir / "bmc-recovery.json", recovery)
        # A factory recovery is itself an authentication-state mutation, even
        # when the subsequent first-login password patch fails or is not
        # needed because the documented default credential works.  Persist a
        # secret-free marker immediately so an interrupted/blocked run cannot
        # release the server while its original BMC account state has been
        # replaced by the ASUS factory state.
        recovery_changed = bool(recovery.get("reset_requested"))
        if recovery_changed:
            endpoint_verified = str(recovery.get("bmc_endpoint_status") or "").upper() == "DISCOVERED"
            marker = self._persist_bmc_auth_change_marker(
                identity=identity,
                bmc_ip=str(recovery.get("bmc_ip_after") or "") if endpoint_verified else "",
                method=str(recovery.get("method") or f"ASUS_{str(capability.get('bmc_generation') or 'ASMB')}_KCS_FACTORY_DEFAULT_RAW_32_66"),
                account_path="",
                bmc_endpoint_verified=endpoint_verified,
                bmc_endpoint_source=str(recovery.get("bmc_endpoint_source") or ""),
                bmc_mac=str(recovery.get("bmc_mac") or ""),
            )
            current["bmc_auth_change_started"] = True
            current["auth_change_provenance"] = f"CNServerOps_{str(capability.get('bmc_generation') or 'ASUS_ASMB')}_FACTORY_RECOVERY"
            current["bmc_auth_change_marker_persisted"] = marker
        if str(recovery.get("status") or "") != "RECOVERED":
            return dict(inventory), current, recovery
        if str(recovery.get("bmc_endpoint_status") or "").upper() != "DISCOVERED" or not str(recovery.get("bmc_ip_after") or "").strip():
            blocked = dict(current)
            blocked.update(
                {
                    "state": BmcAuthState.BMC_AUTH_UNAVAILABLE.value,
                    "usable_for_authenticated_get": False,
                    "reason": "BMC_ENDPOINT_NOT_DISCOVERABLE_POST_RECOVERY",
                }
            )
            return dict(inventory), blocked, recovery | {
                "authentication_continuation": "BLOCKED_BY_AUTH",
                "reason": "BMC_ENDPOINT_NOT_DISCOVERABLE_POST_RECOVERY",
            }
        # The reset can move BMC LAN from static to DHCP. Recollect current
        # local evidence rather than reusing the old BMC IP or cached Redfish
        # inventory. This is read-only and stays bound to the same DMI/FRU
        # identity established before recovery.
        refreshed = self._collect_inventory(
            run_dir / "evidence-post-bmc-recovery",
            identity=identity,
            platform=platform,
            probe=probe,
            run_id=run_id,
            runner_id=runner_id,
        )
        refreshed_normalized = _merge_post_recovery_inventory(
            refreshed.get("normalized") if isinstance(refreshed.get("normalized"), Mapping) else {},
            recovery=recovery,
            firmware=firmware,
        )
        refreshed["normalized"] = refreshed_normalized
        rediscovered = self._discover_bmc_auth(
            refreshed_normalized,
            identity,
            exclude_run_id=run_id,
            read_only=False,
            allow_default_probe_after_recovery=recovery_changed,
            ignore_provisioned_candidates=recovery_changed,
        )
        rediscovered["recovery"] = recovery
        rediscovered["recovery_capability"] = capability
        if recovery_changed:
            rediscovered["bmc_auth_change_started"] = True
            rediscovered["auth_change_provenance"] = f"CNServerOps_{str(capability.get('bmc_generation') or 'ASUS_ASMB')}_FACTORY_RECOVERY"
            rediscovered["bmc_auth_change_marker_persisted"] = True
        if refreshed_normalized:
            refreshed_normalized["bmc_auth_state"] = str(
                rediscovered.get("state") or BmcAuthState.BMC_AUTH_UNAVAILABLE.value
            )
            _atomic_json(run_dir / "normalized-inventory-post-bmc-recovery.json", refreshed_normalized)
        return refreshed, rediscovered, recovery

    def _execute_firmware_lifecycle(
        self,
        *,
        run_dir: Path,
        identity: Mapping[str, Any],
        platform: Mapping[str, Any],
        probe: PlatformProbe,
        runner_id: str,
        inventory: Mapping[str, Any],
        bmc_discovery: Mapping[str, Any],
        firmware: dict[str, Any],
        run_id: str,
    ) -> dict[str, Any]:
        """Shared exact-package executor for Option 1, Option 2 and Option 5."""
        result: dict[str, Any] = {
            "schema_version": 1,
            "status": "UNVERIFIED",
            "mutation_started": False,
            "mutation_attempted": False,
            "components": [],
            "packages": {},
        }
        readiness = str(firmware.get("readiness") or "UNVERIFIED")
        if readiness == "CURRENT_VERIFIED":
            result.update({"status": "CURRENT_VERIFIED", "reason": "NO_UPDATE_REQUIRED"})
            return result
        if readiness != "UPDATE_REQUIRED":
            result.update({"status": readiness, "reason": "EXACT_TARGET_NOT_RESOLVED"})
            return result
        generic = firmware.get("generic_asus_firmware_engine")
        if not isinstance(generic, Mapping):
            result.update({"status": "UNVERIFIED", "reason": "GENERIC_ENGINE_PLAN_MISSING"})
            return result
        platform_payload = generic.get("platform") if isinstance(generic.get("platform"), Mapping) else {}
        fingerprint = AsusPlatformFingerprint(
            vendor=str(platform_payload.get("vendor") or "ASUS"),
            model=str(platform_payload.get("model") or ""),
            board=str(platform_payload.get("board") or ""),
            bmc_model=str(platform_payload.get("bmc_model") or ""),
            bmc_generation=str(platform_payload.get("bmc_generation") or ""),
            platform_id=str(platform_payload.get("platform_id") or ""),
            system_serial=str(platform_payload.get("system_serial") or ""),
        )
        plan_object = AsusFirmwarePlan(
            platform=fingerprint,
            catalog=dict(generic.get("catalog") or {}),
            transports=dict(generic.get("transports") or {}),
            components=dict(generic.get("components") or {}),
        )
        # Do not download a large package when the exact plan has no
        # selectable transport for the component.  Transport discovery is a
        # capability gate, not a post-download detail: an exact ASUS target
        # may be known while the current host has no verified way to apply it.
        # Returning this state before package preparation also prevents an
        # offline technician SSD from hanging while attempting an unusable
        # HTTPS download, and guarantees that a missing transport can never
        # be mistaken for a successful package resolution.
        required_components = [
            str(item.get("component") or "").upper()
            for item in firmware.get("components") or []
            if isinstance(item, Mapping) and str(item.get("status") or "") == "UPDATE_REQUIRED"
        ]
        deferred_components: list[str] = []
        initial_components: list[str] = []
        # Resolve the BMC capability before iterating.  The catalog normally
        # lists BIOS first, but staging must not depend on that presentation
        # order: an ASMB11/12 BMC update can expose the BIOS transport only
        # after the management controller has restarted.
        bmc_plan = plan_object.components.get("BMC") or {}
        bmc_transport = (
            bmc_plan.get("selected_transport")
            if isinstance(bmc_plan, Mapping)
            else None
        )
        bmc_has_initial_transport = (
            "BMC" in required_components
            and isinstance(bmc_transport, Mapping)
            and bool(bmc_transport.get("selectable"))
        )
        for component in required_components:
            component_plan = plan_object.components.get(component) or {}
            selected_transport = (
                component_plan.get("selected_transport")
                if isinstance(component_plan, Mapping)
                else None
            )
            if not isinstance(selected_transport, Mapping) or not bool(selected_transport.get("selectable")):
                # A BMC update can restart the management controller and
                # expose the BIOS UpdateService only after it returns.  Keep
                # that exact BIOS component deferred until the BMC component
                # has completed; do not reject the whole lifecycle before the
                # supported staged path gets a chance to run.
                if component == "BIOS" and "BMC" in required_components and bmc_has_initial_transport:
                    deferred_components.append(component)
                    continue
                result.update({
                    "status": "NO_SUPPORTED_TRANSPORT",
                    "reason": f"NO_SELECTABLE_TRANSPORT_FOR_{component}",
                    "packages": {},
                })
                return result
            initial_components.append(component)
        if not initial_components:
            result.update({"status": "NO_SUPPORTED_TRANSPORT", "reason": "NO_INITIAL_FIRMWARE_TRANSPORT", "packages": {}})
            return result
        repository = FirmwareRepository(self.config.firmware_cache_root)
        prepared = AsusFirmwareEngine.prepare_plan_packages(
            plan_object,
            repository=repository,
            # Firmware bytes must come from the approved HTTPS ASUS host with
            # normal certificate validation.  Own SHA256 pinning remains the
            # final package-integrity check after the download.
            downloader=HttpsPackageDownloader(verify_tls=True),
            components=tuple(initial_components),
        )
        result["packages"] = prepared
        if any(str(item.get("status") or "") != "PACKAGE_READY" for item in prepared.values()):
            result.update({"status": "PACKAGE_RESOLUTION_FAILED", "reason": "EXACT_PACKAGE_NOT_READY"})
            return result
        # ASMB11 IPMI reports only the major/minor portion of some official
        # images (for example 1.02) while the ASUS catalog labels that same
        # exact image 1.2.37.  Re-open the already verified package and use the
        # image-bound trailer aliases to avoid reflashing an actually-current
        # BMC.  Aliases are never guessed and remain local to this run.
        alias_current: set[str] = set()
        for component_name, prepared_item in prepared.items():
            if str(component_name).upper() != "BMC" or not isinstance(prepared_item, Mapping):
                continue
            try:
                package_path = Path(str(prepared_item.get("path") or ""))
                metadata_payload = prepared_item.get("metadata") if isinstance(prepared_item.get("metadata"), Mapping) else {}
                target_version = str(metadata_payload.get("version") or bmc_plan.get("target_version") or "")
                _updater, image, _image_name = AsusAsmbLinuxBmcFirmwareAdapter._package_files(package_path)
                aliases = list(AsusAsmbLinuxBmcFirmwareAdapter._reported_version_aliases(image, target_version))
                if aliases:
                    prepared_item["reported_version_aliases"] = aliases
                    if isinstance(prepared_item.get("metadata"), dict):
                        prepared_item["metadata"]["reported_version_aliases"] = aliases
                    # The component plan carries the target/transport, while
                    # the authoritative live value is stored on the top-level
                    # firmware evidence (IPMI_MC_LOCAL_KCS).  Do not read a
                    # non-existent plan field and accidentally reflash a
                    # BMC that already matches an image-bound alias.
                    live_bmc = firmware.get("bmc") if isinstance(firmware.get("bmc"), Mapping) else {}
                    current_bmc = str(
                        (live_bmc or {}).get("value")
                        or bmc_plan.get("current_version")
                        or ""
                    )
                    if current_bmc in aliases:
                        alias_current.add("BMC")
            except (OSError, ValueError, FirmwareExecutionError):
                pass
        if alias_current:
            required_components = [item for item in required_components if item not in alias_current]
            deferred_components = [item for item in deferred_components if item not in alias_current]
            for item in firmware.get("components") or []:
                if isinstance(item, dict) and str(item.get("component") or "").upper() in alias_current:
                    item["status"] = "CURRENT"
                    item["reason"] = "LIVE_IPMI_VERSION_MATCHES_VERIFIED_ASUS_IMAGE_ALIAS"
            initial_components = [item for item in initial_components if item not in alias_current]
            if not initial_components and deferred_components:
                promotable = []
                for item in deferred_components:
                    selected_transport = (plan_object.components.get(item) or {}).get("selected_transport")
                    if isinstance(selected_transport, Mapping) and bool(selected_transport.get("selectable")):
                        promotable.append(item)
                initial_components.extend(promotable)
                deferred_components = [item for item in deferred_components if item not in promotable]
            if not initial_components:
                result.update({"status": "UPDATED_VERIFIED", "reason": "CURRENT_VERSION_ALIAS_VERIFIED", "components": []})
                return result
        # Keep skipped, image-bound-current packages in the evidence bundle,
        # but never feed them back into the mutation queue below.  The
        # prepared package map is also the audit record, so filtering it out
        # would lose proof even though the component must not be flashed.
        skipped_components = set(alias_current)
        if not alias_current:
            skipped_components = set()
        auth_state = str(bmc_discovery.get("state") or BmcAuthState.BMC_AUTH_UNAVAILABLE.value)
        requires_authenticated_bmc = _firmware_requires_authenticated_bmc(firmware)
        if requires_authenticated_bmc and not bmc_auth_is_usable(auth_state):
            result.update({"status": "BLOCKED_BY_AUTH", "reason": "AUTHENTICATED_BMC_REQUIRED_FOR_FIRMWARE_APPLY"})
            return result
        client, policy = (
            self._authenticated_firmware_client(inventory, bmc_discovery)
            if requires_authenticated_bmc
            else (None, None)
        )
        normalized = inventory.get("normalized") if isinstance(inventory.get("normalized"), Mapping) else {}
        expiry = (datetime.now(timezone.utc) + timedelta(minutes=45)).isoformat()
        normalized_runner = inventory.get("normalized") if isinstance(inventory.get("normalized"), Mapping) else {}
        runner_id = str(normalized_runner.get("runner_id") or "")
        workflow_mode = "FIRMWARE_ONLY"
        profile_id = "FIRMWARE_ONLY"
        profile_total_seconds = 0
        extended_diagnostics = False
        try:
            run_context = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
            run_payload = run_context.get("run") if isinstance(run_context, Mapping) else {}
            if isinstance(run_payload, Mapping):
                workflow_mode = str(run_payload.get("workflow_mode") or workflow_mode).upper()
                profile_id = str(run_payload.get("test_profile") or profile_id).upper()
                profile_total_seconds = int(run_payload.get("profile_total_seconds") or 0)
            extended_diagnostics = workflow_mode == "PRODUCTION_EXTENDED"
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            pass
        inflight_global = self.config.primary_root / "firmware-inflight.json"
        inflight_run = run_dir / "firmware-inflight.json"

        def persist_progress(payload: Mapping[str, Any], *, component: str, metadata: FirmwarePackageMetadata, descriptor_payload: Mapping[str, Any]) -> None:
            """Persist task identity before returning from the adapter call.

            The record is deliberately credential-free.  If the process is
            interrupted while a BMC task is running, the boot service has a
            durable same-server binding and exact task/package identity rather
            than guessing whether a second flash is safe.
            """
            record = {
                "schema_version": 1,
                "state": str(payload.get("phase") or "TASK_PROGRESS"),
                "updated_at_utc": utc_now(),
                "run_id": run_id,
                "run_directory": str(run_dir),
                "workflow_mode": workflow_mode,
                "profile_id": profile_id,
                "profile_total_seconds": profile_total_seconds,
                "extended_diagnostics": extended_diagnostics,
                "server_id": str(identity.get("server_id") or ""),
                "system_serial": str(identity.get("primary_serial") or ""),
                "fingerprint_sha256": str(identity.get("fingerprint_sha256") or ""),
                "runner_id": runner_id,
                "boot_id": str(identity.get("boot_id") or read_linux_boot_id()),
                "bmc_ip": str(normalized.get("bmc_ip") or ""),
                "component": component,
                "metadata": metadata.to_dict(),
                "transport": dict(descriptor_payload),
                "task_id": str(payload.get("task_id") or ""),
                "task_state": str(payload.get("task_state") or ""),
                "task_detail": str(payload.get("task_detail") or "")[:240],
                "package_sha256": metadata.sha256,
                "mutation_started": bool(payload.get("mutation_started")) or str(payload.get("phase") or "") in {"TASK_STARTED", "TASK_POLLED", "TASK_TERMINAL"},
                "sensitive_material_exposed": False,
            }
            _atomic_json(inflight_run, record)
            _atomic_json(inflight_global, record)
            if (
                str(payload.get("phase") or "") == "TASK_STARTED"
            ):
                # The adapter has returned a durable task identity. Publish a
                # same-server continuation before the executor returns so a
                # service crash cannot strand a BMC task behind an in-memory
                # result.  A host-reboot task is upgraded to the normal
                # REBOOT_PENDING state by the caller; non-reboot tasks use
                # TASK_IN_PROGRESS and are reattached by the boot service.
                try:
                    self._write_pending_firmware(
                        run_dir=run_dir,
                        identity=identity,
                        plan=firmware,
                        execution={
                            "status": (
                                "REBOOT_REQUIRED"
                                if str(payload.get("task_state") or "").upper() == "REBOOT_REQUIRED"
                                else "TASK_IN_PROGRESS"
                            ),
                            "pending_component": component,
                            "task_id": str(payload.get("task_id") or ""),
                            "components": [{"component": component, "status": str(payload.get("task_state") or "TASK_IN_PROGRESS").upper()}],
                            "mutation_started": True,
                        },
                        bmc_auth_changed=bmc_auth_change_required(bmc_discovery),
                        runner_id=runner_id,
                        workflow_mode=workflow_mode,
                        profile_id=profile_id,
                        profile_total_seconds=profile_total_seconds,
                        extended_diagnostics=extended_diagnostics,
                        checkpoint_state=(
                            "REBOOT_PENDING"
                            if str(payload.get("task_state") or "").upper() == "REBOOT_REQUIRED"
                            else "TASK_IN_PROGRESS"
                        ),
                    )
                except (FirmwareLifecycleError, OSError, ValueError):
                    # Keep the task marker; the caller will fail closed rather
                    # than silently claiming a reboot-safe continuation.
                    record["pending_checkpoint_status"] = "FAILED"
                    _atomic_json(inflight_run, record)
                    _atomic_json(inflight_global, record)

        # Prefer the BMC component before a BIOS host-reboot activation.  A
        # BMC task can normally complete and verify while Linux is still up;
        # staging BIOS last therefore produces one checkpoint containing only
        # the BIOS activation rather than strand an otherwise executable BMC
        # update behind a host reboot.
        processed_components: set[str] = set()
        while True:
            pending_items = [
                item for item in prepared.items()
                if str(item[0]).upper() not in processed_components
                and str(item[0]).upper() not in skipped_components
            ]
            if not pending_items:
                break
            component, prepared_item = sorted(
                pending_items,
                key=lambda item: (str(item[0]).upper() == "BIOS", str(item[0])),
            )[0]
            component = str(component).upper()
            processed_components.add(component)
            component_plan = plan_object.components.get(component) or {}
            selected = component_plan.get("selected_package") if isinstance(component_plan, Mapping) else {}
            metadata_payload = selected.get("metadata") if isinstance(selected, Mapping) else {}
            if (
                (not isinstance(metadata_payload, Mapping))
                or str(metadata_payload.get("sha256") or "") == "0" * 64
            ):
                prepared_metadata = prepared_item.get("metadata") if isinstance(prepared_item, Mapping) else {}
                if isinstance(prepared_metadata, Mapping):
                    metadata_payload = prepared_metadata
            metadata = FirmwarePackageMetadata.from_dict(metadata_payload or {})
            package_path = Path(str(prepared_item.get("path") or ""))
            transport_payload = select_asus_transport_for_package(
                plan_object.transports,
                component=component,
                package=package_path,
                metadata=metadata,
            )
            if transport_payload is None:
                result.update({
                    "status": "NO_SUPPORTED_TRANSPORT",
                    "reason": f"NO_PACKAGE_COMPATIBLE_TRANSPORT_FOR_{component}",
                })
                return result
            # Preserve the finalized choice in the shared plan/evidence.  All
            # production entrypoints (Options 1, 2 and 5) execute this method,
            # so they cannot diverge on package/transport compatibility.
            if isinstance(component_plan, dict):
                component_plan["selected_transport"] = dict(transport_payload)
            descriptor = AsusTransportDescriptor(**{
                key: value for key, value in dict(transport_payload or {}).items()
                if key in {
                    "name", "source", "target", "components", "rank",
                    "requires_authenticated_bmc", "task_tracking", "package_delivery",
                    "reboot_behavior", "component_payload_preferences",
                    "component_image_types", "component_image_type_candidates",
                    "web_update_method", "web_component_ids", "web_component_image_types",
                    "web_section_flash", "web_endpoint_prefix", "local_command",
                    "local_tool_sha256", "local_timeout_seconds",
                    "selectable", "reason",
                }
            })
            if not descriptor.selectable or not descriptor.name:
                result.update({"status": "NO_SUPPORTED_TRANSPORT", "reason": f"NO_SELECTABLE_TRANSPORT_FOR_{component}"})
                return result
            gate = MutationGate(
                authorized=True,
                lab_mode=True,
                approval_id=f"OPERATOR-MANUAL-FIRMWARE-{run_id}",
                machine_fingerprint_sha256=str(identity.get("fingerprint_sha256") or ""),
                vendor="ASUS",
                model=str(identity.get("model") or ""),
                system_serial=str(identity.get("primary_serial") or ""),
                run_id=run_id,
                component=component,
                target_version=metadata.version,
                package_sha256=metadata.sha256,
                allowed_actions=frozenset({"FIRMWARE_APPLY"}),
                expires_at_utc=expiry,
            )
            if descriptor.name == "ASUS_ASMB11_KCS_YAFUFLASH":
                # The exact ASUS ASMB11 package owns this local KCS path.
                # It deliberately accepts no BMC credential, so do not invoke
                # the USB-LAN wrapper whose ``-U/-P`` arguments would expose
                # an operational secret to the process table.
                try:
                    adapter = AsusAsmb11KcsBmcFirmwareAdapter(
                        descriptor,
                        fingerprint=fingerprint,
                        version_reader=lambda name: self._read_live_firmware_version(name, normalized),
                    )
                except (OSError, ValueError) as exc:
                    result.update({"status": "NO_SUPPORTED_TRANSPORT", "reason": f"ASMB11_KCS_TRANSPORT_{type(exc).__name__}"})
                    return result
            elif descriptor.name == "ASUS_ASMB_WEB_HPM":
                web_client, _web_policy = self._authenticated_asus_web_client(inventory, bmc_discovery)
                if web_client is None:
                    result.update({"status": "BLOCKED_BY_AUTH", "reason": "APPROVED_ASUS_WEB_CREDENTIAL_UNAVAILABLE"})
                    return result
                adapter = AsusAsmbWebHpmFirmwareAdapter(
                    web_client,
                    descriptor,
                    version_reader=lambda name: self._read_live_firmware_version(name, normalized),
                )
            elif descriptor.name == "ASUS_ASMB_LINUX_OFFICIAL":
                selected = self._approved_firmware_credential(inventory, bmc_discovery)
                if selected is None:
                    result.update({"status": "BLOCKED_BY_AUTH", "reason": "APPROVED_ASUS_ASMB_CREDENTIAL_UNAVAILABLE"})
                    return result
                adapter = AsusAsmbLinuxBmcFirmwareAdapter(
                    descriptor,
                    username=selected[0],
                    password=selected[1],
                    version_reader=lambda name: self._read_live_firmware_version(name, normalized),
                )
            elif descriptor.name == "ASUS_LOCAL_OFFICIAL_UTILITY":
                try:
                    adapter = AsusLocalFirmwareUtilityAdapter(
                        descriptor,
                        version_reader=lambda name: self._read_live_firmware_version(name, normalized),
                    )
                except (OSError, ValueError) as exc:
                    result.update({"status": "NO_SUPPORTED_TRANSPORT", "reason": f"LOCAL_TRANSPORT_{type(exc).__name__}"})
                    return result
            else:
                if client is None:
                    result.update({"status": "BLOCKED_BY_AUTH", "reason": "APPROVED_FIRMWARE_CREDENTIAL_UNAVAILABLE"})
                    return result
                adapter = AsusRedfishFirmwareAdapter(
                    client,
                    descriptor,
                    version_reader=lambda name: self._read_live_firmware_version(name, normalized),
                )
            def on_progress(payload: Mapping[str, Any], *, _component=component, _metadata=metadata, _descriptor=transport_payload) -> None:
                persist_progress(payload, component=_component, metadata=_metadata, descriptor_payload=_descriptor)
            execution = AsusFirmwareEngine.execute_component(
                identity={**dict(identity), "current_version": str(component_plan.get("current_version") or ""), "catalog_id": "ASUS_OFFICIAL_CATALOG"},
                metadata=metadata,
                fingerprint=fingerprint,
                repository=repository,
                adapter=adapter,
                mutation_gate=gate,
                run_id=run_id,
                progress_callback=on_progress,
            )
            result["components"].append(execution)
            # A request that was rejected before a Redfish task existed (for
            # example HTTP 400) is an attempted mutation, not a started one.
            # Keep both facts explicit so the console/evidence cannot imply
            # that firmware was accepted when the BMC rejected the payload.
            result["mutation_attempted"] = True
            result["mutation_started"] = bool(result["mutation_started"]) or bool(
                execution.get("mutation_started")
                or (
                    execution.get("task_id")
                    and not str(execution.get("task_id")).startswith("REDFISH-")
                    and not str(execution.get("task_id")).startswith("ASUS-")
                )
            )
            if str(execution.get("status") or "") not in {"SUCCESS", "SUCCESS_WITH_WARNING"}:
                if str(execution.get("status") or "") == "REBOOT_REQUIRED":
                    result["pending_component"] = component
                    result["task_id"] = str(execution.get("task_id") or "")
                else:
                    # A terminal rejection/failure is evidence, not a resume
                    # instruction.  Retain the per-run marker but remove the
                    # global boot-service selector so a later boot cannot
                    # mistake a failed task for an active continuation.
                    try:
                        inflight_global.unlink(missing_ok=True)
                    except OSError:
                        pass
                    clear_firmware_pending(self.config.primary_root, run_dir)
                result.update({"status": str(execution.get("status") or "FAILED"), "reason": execution.get("reason_code")})
                return result
            # A non-reboot task completed and was attested by the executor;
            # retire its task-in-progress checkpoint before the next component
            # is considered.  A REBOOT_REQUIRED result intentionally retains
            # the checkpoint for the host-resume service.
            if str(execution.get("status") or "") in {"SUCCESS", "SUCCESS_WITH_WARNING"}:
                clear_firmware_pending(self.config.primary_root, run_dir)
            if component == "BMC" and deferred_components:
                # Refresh KCS/Redfish evidence after the BMC updater returns.
                # Some ASMB revisions do not advertise BIOS UpdateService
                # resources until the new BMC firmware is running.  Re-plan
                # from the same physical identity, never from a cached
                # previous-server proof, and then prepare only the deferred
                # exact BIOS package.
                fresh_raw = dict(inventory.get("raw") or {}) if isinstance(inventory, Mapping) else {}
                kcs_restore = restore_local_ipmi_kcs(
                    self.executor,
                    timeout_seconds=30,
                    wait_seconds=180,
                    poll_seconds=5.0,
                    # The official ASMB11 updater can leave ipmi_si loaded
                    # without a bound KCS device when it probes before the
                    # restarting BMC is ready.  A bounded reprobe is required
                    # here; this stage is reached only after the updater has
                    # returned a verified SUCCESS result.
                    force_reprobe=True,
                )
                _atomic_json(run_dir / "linux-ipmi-kcs-restore-post-asmb11-yafu.json", kcs_restore)
                fresh_mc = self.executor.run("ipmitool", ("mc", "info"), timeout_seconds=30)
                fresh_raw["ipmi_mc"] = fresh_mc
                fresh_inventory = dict(inventory)
                fresh_inventory["raw"] = fresh_raw
                fresh_normalized = dict(inventory.get("normalized") or {}) if isinstance(inventory.get("normalized"), Mapping) else {}
                fresh_components = [dict(item) if isinstance(item, Mapping) else item for item in fresh_normalized.get("components") or []]
                bmc_revision = parse_ipmi_mc_firmware_version(str(fresh_mc.get("stdout") or ""))
                verified_bmc_revision = bmc_revision or str(execution.get("installed_version") or "").strip()
                for item in fresh_components:
                    if not isinstance(item, dict):
                        continue
                    category = str(item.get("category") or "").upper()
                    slot = str(item.get("slot") or item.get("location") or "").upper()
                    if category in {"BMC", "MANAGEMENT_MODULE"} or (category == "FIRMWARE" and slot == "BMC"):
                        item["firmware"] = verified_bmc_revision or item.get("firmware") or item.get("version")
                        item["version"] = verified_bmc_revision or item.get("version") or item.get("firmware")
                        if verified_bmc_revision:
                            evidence = dict(item.get("field_evidence") or {})
                            evidence["firmware"] = {
                                "value": verified_bmc_revision,
                                "source": "IPMI_MC_LOCAL_KCS" if bmc_revision else "ASUS_FIRMWARE_EXECUTOR_POST_UPDATE_VERIFICATION",
                                "freshness": "BMC_CURRENT_CONFIRMED",
                                "confidence": "HIGH",
                                "conflict": "",
                                "raw_reference": "ipmi-mc-info.txt" if bmc_revision else "firmware-execution.json",
                            }
                            item["field_evidence"] = evidence
                fresh_normalized["components"] = fresh_components
                if verified_bmc_revision:
                    fresh_normalized["bmc_firmware"] = verified_bmc_revision
                    fresh_normalized["bmc_firmware_evidence"] = {
                        "value": verified_bmc_revision,
                        "source": "IPMI_MC_LOCAL_KCS" if bmc_revision else "ASUS_FIRMWARE_EXECUTOR_POST_UPDATE_VERIFICATION",
                        "freshness": "BMC_CURRENT_CONFIRMED",
                        "confidence": "HIGH",
                        "raw_reference": "ipmi-mc-info.txt" if bmc_revision else "firmware-execution.json",
                    }
                fresh_inventory["normalized"] = fresh_normalized
                refreshed_discovery = self._discover_bmc_auth(
                    fresh_normalized,
                    identity,
                    exclude_run_id=run_id,
                    read_only=True,
                    # The successful same-run credential is an approved
                    # candidate; re-probe it after the BMC restart even when
                    # the server has older local run history.
                    allow_default_probe_after_recovery=True,
                )
                # The package-owned ASMB11 KCS BMC transport intentionally
                # ran without BMC credentials.  Only now, after its verified
                # BMC update and a fresh same-server inventory, decide
                # whether a deferred BIOS component needs authenticated
                # transport.  This keeps factory recovery out of the BMC
                # update path while still allowing the complete two-component
                # lifecycle to continue autonomously when BIOS needs Redfish.
                refreshed_plan = self._firmware_plan(fresh_inventory, refreshed_discovery)
                deferred_auth_recovery: dict[str, Any] = {
                    "status": "NOT_REQUIRED",
                    "reason": "DEFERRED_BIOS_TRANSPORT_DOES_NOT_REQUIRE_BMC_AUTH",
                    "mutation_started": False,
                    "sensitive_material_exposed": False,
                }
                if _firmware_requires_authenticated_bmc(refreshed_plan) and not bmc_auth_is_usable(
                    str(refreshed_discovery.get("state") or "")
                ):
                    fresh_inventory, refreshed_discovery, deferred_auth_recovery = self._ensure_authenticated_firmware_access(
                        run_dir=run_dir,
                        identity=identity,
                        platform=platform,
                        probe=probe,
                        inventory=fresh_inventory,
                        firmware=refreshed_plan,
                        run_id=run_id,
                        runner_id=runner_id,
                        discovery=refreshed_discovery,
                    )
                    # Recovery/provisioning can move the BMC LAN endpoint or
                    # change which exact authenticated transport is visible.
                    # Re-plan again from only its fresh, same-server evidence.
                    refreshed_plan = self._firmware_plan(fresh_inventory, refreshed_discovery)
                _atomic_json(run_dir / "bmc-recovery-path-post-asmb11-kcs.json", deferred_auth_recovery)
                _atomic_json(run_dir / "bmc-auth-discovery-post-asmb11-kcs.json", refreshed_discovery)
                _atomic_json(run_dir / "firmware-plan-post-asmb11-kcs.json", refreshed_plan)
                if _firmware_requires_authenticated_bmc(refreshed_plan) and not bmc_auth_is_usable(
                    str(refreshed_discovery.get("state") or "")
                ):
                    result.update({
                        "status": "BLOCKED_BY_AUTH",
                        "reason": str(deferred_auth_recovery.get("reason") or "DEFERRED_BIOS_AUTH_REQUIRED"),
                        "deferred_bios_auth": {
                            "status": str(deferred_auth_recovery.get("status") or "BLOCKED_BY_AUTH"),
                            "reason": str(deferred_auth_recovery.get("reason") or ""),
                            "mutation_started": bool(deferred_auth_recovery.get("mutation_started")),
                            "sensitive_material_exposed": False,
                        },
                    })
                    return result
                refreshed_generic = refreshed_plan.get("generic_asus_firmware_engine") if isinstance(refreshed_plan, Mapping) else {}
                if not isinstance(refreshed_generic, Mapping):
                    result.update({"status": "UNVERIFIED", "reason": "POST_ASMB11_KCS_GENERIC_ENGINE_PLAN_MISSING"})
                    return result
                # Preserve the exact same mutable run objects for the caller:
                # a subsequent BIOS reboot checkpoint and final BMC handoff
                # must see the just-provisioned auth marker, current endpoint,
                # and fresh component plan rather than a pre-KCS snapshot.
                if isinstance(inventory, dict):
                    inventory.clear()
                    inventory.update(fresh_inventory)
                    fresh_inventory = inventory
                if isinstance(bmc_discovery, dict):
                    bmc_discovery.clear()
                    bmc_discovery.update(refreshed_discovery)
                    refreshed_discovery = bmc_discovery
                firmware.clear()
                firmware.update(refreshed_plan)
                normalized = fresh_inventory.get("normalized") if isinstance(fresh_inventory.get("normalized"), Mapping) else {}
                client, policy = self._authenticated_firmware_client(fresh_inventory, refreshed_discovery)
                plan_object = AsusFirmwarePlan(
                    platform=AsusPlatformFingerprint(**dict(refreshed_generic.get("platform") or {})),
                    catalog=dict(refreshed_generic.get("catalog") or {}),
                    transports=dict(refreshed_generic.get("transports") or {}),
                    components=dict(refreshed_generic.get("components") or {}),
                )
                deferred_prepared = AsusFirmwareEngine.prepare_plan_packages(
                    plan_object,
                    repository=repository,
                    downloader=HttpsPackageDownloader(verify_tls=True),
                    components=tuple(deferred_components),
                )
                prepared.update(deferred_prepared)
                result["packages"].update(deferred_prepared)
                result["deferred_bios_auth"] = {
                    "status": str(deferred_auth_recovery.get("status") or "NOT_REQUIRED"),
                    "reason": str(deferred_auth_recovery.get("reason") or ""),
                    "mutation_started": bool(deferred_auth_recovery.get("mutation_started")),
                    "sensitive_material_exposed": False,
                }
                if any(str(item.get("status") or "") != "PACKAGE_READY" for item in deferred_prepared.values()):
                    result.update({"status": "PACKAGE_RESOLUTION_FAILED", "reason": "EXACT_DEFERRED_PACKAGE_NOT_READY"})
                    return result
                deferred_components = []
        try:
            inflight_global.unlink(missing_ok=True)
        except OSError:
            pass
        result.update({"status": "UPDATED_VERIFIED", "reason": "POST_UPDATE_VERSION_VERIFIED"})
        return result

    def _authenticated_firmware_client(self, inventory: Mapping[str, Any], discovery: Mapping[str, Any]):
        normalized = inventory.get("normalized") if isinstance(inventory.get("normalized"), Mapping) else {}
        host = str(normalized.get("bmc_ip") or "")
        if not host:
            return None, None
        policy = BmcAuthPolicy.from_mapping(self.config.bmc_auth_policy)
        successful_kinds = {
            str(item.get("account", {}).get("kind") or "")
            for item in discovery.get("attempts", [])
            if isinstance(item, Mapping) and str(item.get("status") or "").upper() == "PASS"
        }
        candidates = runtime_credential_candidates(
            policy,
            server_id=str(normalized.get("server_id") or ""),
            allow_default_if_discovered="DEFAULT" in successful_kinds,
        )
        selected = next((item for item in candidates if not successful_kinds or item[2] in successful_kinds), None)
        if selected is None:
            return None, policy
        username, password, _kind = selected
        return AuthenticatedRedfishClient(
            host,
            credentials=RedfishCredentials(username=username, password=password, source="runtime-approved-candidate"),
            verify_tls=policy.verify_tls,
        ), policy

    def _approved_firmware_credential(
        self,
        inventory: Mapping[str, Any],
        discovery: Mapping[str, Any],
    ) -> tuple[str, str, str] | None:
        """Return the one credential already proven by bounded auth discovery."""
        policy = BmcAuthPolicy.from_mapping(self.config.bmc_auth_policy)
        normalized = inventory.get("normalized") if isinstance(inventory.get("normalized"), Mapping) else {}
        successful_kinds = {
            str(item.get("account", {}).get("kind") or "")
            for item in discovery.get("attempts", [])
            if isinstance(item, Mapping) and str(item.get("status") or "").upper() == "PASS"
        }
        candidates = runtime_credential_candidates(
            policy,
            server_id=str(normalized.get("server_id") or ""),
            allow_default_if_discovered="DEFAULT" in successful_kinds,
        )
        return next((item for item in candidates if not successful_kinds or item[2] in successful_kinds), None)

    def _authenticated_asus_web_client(self, inventory: Mapping[str, Any], discovery: Mapping[str, Any]):
        """Return an in-memory authenticated ASMB web session.

        Credential selection is exactly the bounded policy used by Redfish;
        no additional password guesses are introduced and the secret never
        enters a result or command line.
        """
        normalized = inventory.get("normalized") if isinstance(inventory.get("normalized"), Mapping) else {}
        host = str(normalized.get("bmc_ip") or "")
        if not host:
            return None, None
        policy = BmcAuthPolicy.from_mapping(self.config.bmc_auth_policy)
        successful_kinds = {
            str(item.get("account", {}).get("kind") or "")
            for item in discovery.get("attempts", [])
            if isinstance(item, Mapping) and str(item.get("status") or "").upper() == "PASS"
        }
        candidates = runtime_credential_candidates(
            policy,
            server_id=str(normalized.get("server_id") or ""),
            allow_default_if_discovered="DEFAULT" in successful_kinds,
        )
        selected = next((item for item in candidates if not successful_kinds or item[2] in successful_kinds), None)
        if selected is None:
            return None, policy
        username, password, _kind = selected
        try:
            session = AsusAsmbWebSession(host, username, password, verify_tls=policy.verify_tls)
            session.login()
            return session, policy
        except Exception:
            return None, policy

    def _read_live_firmware_version(self, component: str, normalized: Mapping[str, Any]) -> str:
        if str(component).upper() == "BIOS":
            try:
                return self.dmi_root.joinpath("bios_version").read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                return ""
        response = self.executor.run("ipmitool", ("mc", "info"), timeout_seconds=30)
        return parse_ipmi_mc_firmware_version(str(response.get("stdout") or ""))

    def _server_specific_enrollment_paths(self) -> tuple[Path, ...]:
        """Files that must never cross a physical-server enrollment boundary.

        Only path metadata is used by enrollment; secret bytes are not read.
        The default BMC factory credential is intentionally excluded because it
        is a shared ASUS factory reference, not a server-specific operational
        credential.  The temporary provisioned account and its binding are
        server-specific and are quarantined on a new/first enrollment.
        """
        policy = BmcAuthPolicy.from_mapping(self.config.bmc_auth_policy)
        return (
            policy.provisioned_password_file,
            policy.provisioned_account_binding_path,
            self.config.bmc_auth_change_marker,
        )

    def run_fleet_intake(self) -> dict[str, Any]:
        """Fast, read-only serial/inventory/SEL collection for fleet intake."""
        self._notify({"event": "WORKFLOW_STARTED", "workflow_mode": "FLEET_INTAKE", "stage": "IDENTITY"})
        probe, platform, identity, fru = detect_current_platform_and_identity(
            dmi_root=self.dmi_root, fru_reader=self.fru_reader
        )
        if not identity.get("resumable") or not identity.get("fingerprint_sha256"):
            raise ProductionWorkflowError("Fleet Intake requires trustworthy current/local identity")
        try:
            runner = load_runner(self.config.runner_config)
        except Exception:
            runner = {"runner_id": "NOT_CONFIGURED", "runtime_version": self.runtime_version}
        enrollment = reconcile_server_enrollment(
            self.config.primary_root,
            identity,
            runner_id=str(runner.get("runner_id") or "NOT_CONFIGURED"),
            server_specific_paths=self._server_specific_enrollment_paths(),
        )
        server = ServerRecord.from_identity(identity)
        run = RunRecord.start(
            server,
            runner_id=str(runner.get("runner_id") or "NOT_CONFIGURED"),
            runtime_version=self.runtime_version,
            boot_id=str(identity.get("boot_id") or read_linux_boot_id()),
            workflow_mode="FLEET_INTAKE",
            test_profile="FLEET_INTAKE",
        )
        run_id = run.run_id
        run_dir = self.config.primary_root / "runs" / run_id
        run_dir.mkdir(parents=True, exist_ok=False)
        _atomic_json(run_dir / "enrollment.json", enrollment)
        _atomic_json(run_dir / "operator-launch.json", {
            "schema_version": 1, "mode": "FLEET_INTAKE", "selected_at_utc": utc_now(),
            "vendor_detected_before_selection": True, "platform_id": platform.get("platform_id"),
            "runtime_version": self.runtime_version, "automatic_action_at_boot": False,
            "firmware_or_power_actions": "DISABLED",
        })
        context = {
            "schema_version": 2, "server": server.to_dict(), "run": run.to_dict(),
            "platform": platform, "enrollment": enrollment, "mode": "FLEET_INTAKE",
            "safety": {"workload_started": False, "firmware_mutation_started": False,
                       "sel_cleanup_started": False, "bmc_reset_started": False,
                       "host_reboot_started": False, "power_action_started": False,
                       "diagnostics_started": False},
        }
        _atomic_json(run_dir / "run.json", context)
        client, central_runtime = self._collector_client()
        event_queue = StoreForwardQueue(self.config.queue_database)
        started_event = run_started_event(
            run, server,
            bmc={"access_state": BmcAuthState.BMC_AUTH_UNAVAILABLE.value, "probe_performed": False},
            runner={"runner_id": runner.get("runner_id", "NOT_CONFIGURED")},
        )
        started_sync = self._enqueue_and_drain(event_queue, started_event, run_dir / "run.json", client)
        _atomic_json(run_dir / "central-run-started.json", started_sync)

        raw_dir = run_dir / "raw"
        inventory = self._collect_inventory(
            raw_dir, identity=identity, platform=platform, probe=probe, run_id=run_id,
            runner_id=str(runner.get("runner_id") or "NOT_CONFIGURED"),
            bmc_auth_state=BmcAuthState.BMC_AUTH_UNAVAILABLE.value, intake_mode=True,
        )
        normalized = dict(inventory.get("normalized") or {})
        normalized["workflow_mode"] = "FLEET_INTAKE"
        normalized["bmc_auth_state"] = BmcAuthState.BMC_AUTH_UNAVAILABLE.value
        _atomic_json(run_dir / "normalized-inventory.json", normalized)
        nic_serial_rows = physical_nic_rows(normalized)

        logs_dir = run_dir / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        sel_source = inventory.get("evidence_by_name", {}).get("ipmi_sel_full")
        sel_target = logs_dir / "SEL_Collected.txt"
        if isinstance(sel_source, Path) and sel_source.is_file():
            shutil.copyfile(sel_source, sel_target)
        sel_info = inventory.get("evidence_by_name", {}).get("ipmi_sel_info")
        if isinstance(sel_info, Path) and sel_info.is_file():
            shutil.copyfile(sel_info, logs_dir / "SEL_Collected_Info.txt")
        kernel_source = inventory.get("evidence_by_name", {}).get("kernel-errors")
        if isinstance(kernel_source, Path) and kernel_source.is_file():
            shutil.copyfile(kernel_source, logs_dir / "Kernel_Errors.txt")

        bmc_version = parse_ipmi_mc_firmware_version(
            str(inventory.get("raw", {}).get("ipmi_mc", {}).get("stdout") or "")
        )
        result = {
            "schema_version": 2, "workflow_mode": "FLEET_INTAKE", "overall": "PASS",
            "collection": "PASS", "identity": "PASS" if normalized.get("system_serial") else "REVIEW",
            "serial_inventory": "PASS" if normalized.get("system_serial") else "REVIEW",
            "hardware_inventory": "PASS", "bios_version": normalized.get("bios_version") or probe.bios_version,
            "bmc_version": bmc_version, "sel_collection": "PASS" if sel_target.exists() else "REVIEW",
            "sel_preserved": True, "sel_cleanup": "NOT_PERFORMED", "cpu": "NOT_PERFORMED",
            "ram": "NOT_PERFORMED", "firmware_update": "NOT_PERFORMED",
            "system_diagnostics": "NOT_PERFORMED", "bmc_reset": "NOT_PERFORMED",
            "host_reboot": "NOT_PERFORMED", "power_cycle": "NOT_PERFORMED",
            "nic_serial_collection": "PASS" if nic_serial_rows else "REVIEW",
            "nic_serials": nic_serial_rows,
            "nic_identity_anchors": normalized.get("nic_identity_anchors", []),
            "identity_fallback": normalized.get("identity_fallback", {}),
            "central_link": "PASS" if central_runtime.get("status") in {"ONLINE", "TEST_OVERRIDE"} else "PENDING_UPLOAD",
            "reason": ["Fast fleet serial, inventory and SEL preservation path; no maintenance actions were requested."],
            "safety": context["safety"],
        }
        firmware = {"policy": "FLEET_INTAKE_NO_FIRMWARE_MUTATION", "mutation_started": False, "components": [
            {"component": "BIOS", "before": result["bios_version"], "target": "", "after": result["bios_version"], "status": "NOT_PERFORMED"},
            {"component": "BMC", "before": bmc_version, "target": "", "after": bmc_version, "status": "NOT_PERFORMED"},
        ]}
        finalization = build_finalization_status(
            sel_cleanup="NOT_PERFORMED", final_sanity="NOT_PERFORMED_FLEET_INTAKE",
            bmc_soft_reset=BmcSoftResetCapability(), evidence_saved=True,
            identity_reverified=True, firmware_reverified=False,
        )
        evidence_manifest = self._evidence_manifest(
            inventory.get("evidence_paths", []) + [run_dir / "normalized-inventory.json", sel_target]
        )
        _atomic_json(run_dir / "evidence-manifest.json", evidence_manifest)
        report_manifest = generate_human_reports(
            run_dir, inventory=normalized, run=run.to_dict(), result=result, firmware=firmware,
            tests={"status": "NOT_PERFORMED_FLEET_INTAKE", "evidence_status": "LOCAL_COMPLETE"},
            finalization=finalization, central={"artifact_status": "LOCAL_COMPLETE", **central_runtime},
            evidence_manifest=evidence_manifest, fleet_intake=True,
        )
        try:
            bundle_path, _ = build_universal_bundle(raw_dir, platform=platform, identity=identity, evidence_paths=inventory.get("evidence_paths", []))
            report_manifest.setdefault("artifacts", []).append({"type": "RAW_EVIDENCE_BUNDLE", "name": bundle_path.name, "path": str(bundle_path), "sha256": _sha256(bundle_path), "size_bytes": bundle_path.stat().st_size, "state": "LOCAL_COMPLETE"})
        except Exception:
            pass
        if sel_target.exists():
            report_manifest.setdefault("artifacts", []).append({"type": "SEL_LOG", "name": sel_target.name, "path": str(sel_target), "sha256": _sha256(sel_target), "size_bytes": sel_target.stat().st_size, "state": "LOCAL_COMPLETE"})
        artifact_sync = self._sync_artifacts(run_id, report_manifest, client)
        archive_sync = self._central_archive_summary(artifact_sync)
        result["artifact_sync"] = artifact_sync
        result["windows_archive"] = archive_sync
        result["artifact_delivery"] = artifact_sync
        result["primary_archive"] = archive_sync.get("primary_paths") or []
        result["secondary_archive"] = archive_sync.get("secondary_paths") or []
        run.completed_at_utc = utc_now()
        run.current_stage = "COMPLETE"
        run.collection_status = OperationStatus.PASS
        run.export_status = OperationStatus.PASS
        run.final_disposition = FinalDisposition.PASS
        run.reason_codes = ("FLEET_INTAKE", "SEL_PRESERVED", "NO_MAINTENANCE_ACTIONS")
        context["run"] = run.to_dict()
        context["result"] = result
        context["report_manifest"] = report_manifest
        _atomic_json(run_dir / "run.json", context)
        _atomic_json(run_dir / "result-summary.json", result)
        completed = self._enqueue_and_drain(
            event_queue, run_completed_event(run, result=result), run_dir / "run.json", client
        )
        _atomic_json(run_dir / "central-run-completed.json", completed)
        return {"run": run.to_dict(), "result": result, "reports": report_manifest, "central": completed, "run_directory": str(run_dir)}

    def run_dry_run(self) -> dict[str, Any]:
        """Create an authoritative, report-producing run without any mutation or workload."""
        self._notify({"event": "WORKFLOW_STARTED", "workflow_mode": "DRY_RUN", "stage": "IDENTITY"})
        probe, platform, identity, fru = detect_current_platform_and_identity(
            dmi_root=self.dmi_root, fru_reader=self.fru_reader
        )
        runner = load_runner(self.config.runner_config)
        enrollment = reconcile_server_enrollment(
            self.config.primary_root,
            identity,
            runner_id=str(runner.get("runner_id") or ""),
            server_specific_paths=self._server_specific_enrollment_paths(),
        )
        if not identity.get("resumable") or not identity.get("fingerprint_sha256"):
            raise ProductionWorkflowError("Dry Run requires trustworthy current/local identity; safe inventory remains available")
        server = ServerRecord.from_identity(identity)
        run = RunRecord.start(
            server,
            runner_id=runner["runner_id"],
            runtime_version=self.runtime_version,
            boot_id=str(identity.get("boot_id") or read_linux_boot_id()),
            workflow_mode="DRY_RUN",
            test_profile="DRY_RUN",
        )
        run_id = run.run_id
        run_dir = self.config.primary_root / "runs" / run_id
        run_dir.mkdir(parents=True, exist_ok=False)
        _atomic_json(run_dir / "enrollment.json", enrollment)
        context: dict[str, Any] = {
            "schema_version": 2,
            "server": server.to_dict(),
            "run": run.to_dict(),
            "platform": platform,
            "enrollment": enrollment,
            "mode": "DRY_RUN",
            "safety": {
                "workload_started": False,
                "firmware_mutation_started": False,
                "sel_cleanup_started": False,
                "bmc_reset_started": False,
                "host_reboot_started": False,
                "power_action_started": False,
                "bmc_auth_change_started": False,
            },
        }
        _atomic_json(run_dir / "run.json", context)
        _atomic_json(
            run_dir / "operator-launch.json",
            {
                "schema_version": 1,
                "mode": "MANUAL_DRY_RUN_SELECTION",
                "selected_at_utc": utc_now(),
                "vendor_detected_before_selection": True,
                "platform_id": platform.get("platform_id"),
                "runtime_version": self.runtime_version,
                "automatic_action_at_boot": False,
            },
        )

        client, central_runtime = self._collector_client()
        event_queue = StoreForwardQueue(self.config.queue_database)
        started = run_started_event(
            run,
            server,
            bmc={"access_state": BmcAuthState.BMC_AUTH_UNAVAILABLE.value},
            runner={
                "runner_id": runner["runner_id"],
                "local_runner_uuid": runner.get("local_runner_uuid", ""),
                "storage_fingerprint_sha256": runner.get("storage_fingerprint_sha256", ""),
            },
        )
        start_sync = self._enqueue_and_drain(event_queue, started, run_dir / "run.json", client)
        _atomic_json(run_dir / "central-run-started.json", start_sync)

        self._notify({"event": "STAGE_STARTED", "workflow_mode": "DRY_RUN", "stage": "INVENTORY"})
        evidence_dir = run_dir / "raw"
        inventory = self._collect_inventory(
            evidence_dir,
            identity=identity,
            platform=platform,
            probe=probe,
            run_id=run_id,
            runner_id=runner["runner_id"],
        )
        normalized = dict(inventory["normalized"])
        # Dry Run is a strict read-only workflow.  It may record whether an
        # approved BMC credential is already usable, but it must never
        # provision a first-login password, recover an account, reset a BMC,
        # or create an auth-change handoff obligation.
        bmc_discovery = self._discover_bmc_auth(
            normalized,
            identity,
            exclude_run_id=run_id,
            read_only=True,
        )
        bmc_auth_state = str(bmc_discovery.get("state") or BmcAuthState.BMC_AUTH_UNAVAILABLE.value)
        context.setdefault("safety", {})["bmc_auth_change_started"] = bool(
            (bmc_discovery.get("provisioning") or {}).get("mutation_performed")
        )
        normalized["bmc_auth_state"] = bmc_auth_state
        _atomic_json(run_dir / "normalized-inventory.json", normalized)
        _atomic_json(run_dir / "bmc-auth-discovery.json", bmc_discovery)
        run.current_stage = "INVENTORY"
        context["run"] = run.to_dict()
        context["normalized_inventory_path"] = str(run_dir / "normalized-inventory.json")
        _atomic_json(run_dir / "run.json", context)
        identity_progress = run_progress_event(
            run,
            stage_result={
                "stage": "SERIAL_INVENTORY_PRESERVED",
                "server_id": normalized.get("server_id"),
                "system_serial": normalized.get("system_serial"),
                "primary_host_mac": normalized.get("primary_host_mac"),
                "component_counts": normalized.get("component_counts", {}),
                "sensitive_data_excluded": True,
            },
        )
        identity_sync = self._enqueue_and_drain(event_queue, identity_progress, run_dir / "run.json", client)
        _atomic_json(run_dir / "central-identity-preserved.json", identity_sync)

        firmware = self._firmware_plan(inventory, bmc_discovery)
        _atomic_json(run_dir / "firmware-plan.json", firmware)
        component_counts = dict(normalized.get("component_counts") or {})
        statuses = {
            "collection": "PASS",
            "serial_inventory": "PASS" if normalized.get("system_serial") else "FAIL",
            "identity": "PASS",
            "cpu": "NOT_TESTED",
            "ram": "NOT_TESTED",
            "storage": inventory["summary"]["storage"]["status"],
            "nic": "PASS" if component_counts.get("NIC/OCP", 0) else "REVIEW",
            "pcie": inventory["summary"]["pcie"]["status"],
            "psu": "PASS" if component_counts.get("PSU", 0) else "NOT_PRESENT",
            "fans": inventory["summary"].get("fans", {}).get("status", "NOT_TESTED"),
            "sensors": inventory["summary"]["sensors"]["status"],
            "sel": "PASS" if inventory["summary"]["command_status"]["ipmi_sel"] == "PASS" else "REVIEW",
            "firmware_update": "NOT_TESTED",
            "system_diagnostics": "NOT_TESTED",
            "bmc_soft_reset": "NOT_PERFORMED",
            "central_link": "PASS"
            if central_runtime.get("status") in {"ONLINE", "TEST_OVERRIDE"}
            else "PENDING_UPLOAD",
        }
        handoff = evaluate_handoff(
            statuses,
            workflow_mode="DRY_RUN",
            policy=HandoffPolicy.from_mapping(self.config.handoff_policy),
        )
        result = {
            **statuses,
            "overall": handoff["overall"],
            "handoff_status": handoff["handoff_status"],
            "handoff_policy": handoff,
            "sel_entries": inventory["summary"]["sel"]["entry_count"],
            "new_critical_sel": 0,
            "kernel_hw_errors": 0,
            "bmc_access_state": bmc_auth_state,
            "global_run_blocked_by_bmc": False,
            "dry_run_safety": context["safety"],
            "bmc_auth_discovery": bmc_discovery,
        }
        result["status_summary"] = human_status_summary(
            statuses=result,
            handoff=handoff,
            workflow_mode="DRY_RUN",
            central_sync="PASS" if central_runtime.get("status") in {"ONLINE", "TEST_OVERRIDE"} else "PENDING_UPLOAD",
            artifact_status="LOCAL_COMPLETE" if self.config.reports_enabled else "NOT_REQUESTED",
            reports_status="PASS" if self.config.reports_enabled else "NOT_REQUESTED",
        )
        finalization = build_finalization_status(
            sel_cleanup="NOT_PERFORMED",
            final_sanity=inventory["summary"]["sensors"]["status"],
            bmc_soft_reset=BmcSoftResetCapability(),
            evidence_saved=True,
            identity_reverified=True,
            firmware_reverified=_firmware_plan_reverified(firmware),
        )
        evidence_manifest = self._evidence_manifest(
            inventory["evidence_paths"] + [run_dir / "bmc-auth-discovery.json"]
        )
        _atomic_json(run_dir / "evidence-manifest.json", evidence_manifest)

        run.completed_at_utc = utc_now()
        run.current_stage = "COMPLETE"
        run.collection_status = OperationStatus.PASS
        run.export_status = OperationStatus.PASS
        run.final_disposition = FinalDisposition(handoff["overall"])
        run.reason_codes = _reason_codes_for_handoff(handoff, workflow_mode="DRY_RUN")
        context["run"] = run.to_dict()
        context["result"] = result
        _atomic_json(run_dir / "run.json", context)

        report_manifest: dict[str, Any] = {"artifacts": []}
        if self.config.reports_enabled:
            report_manifest = generate_human_reports(
                run_dir,
                inventory=normalized,
                run=run.to_dict(),
                result=result,
                firmware=firmware,
                tests={"status": "NOT_TESTED_DRY_RUN", "evidence_status": "LOCAL_COMPLETE"},
                finalization=finalization,
                central={"artifact_status": "LOCAL_COMPLETE", **central_runtime},
                evidence_manifest=evidence_manifest,
            )
        artifact_sync = self._sync_artifacts(run_id, report_manifest, client)
        result["artifact_status"] = artifact_sync["status"]
        result["artifacts"] = artifact_sync
        reports_status = (
            "PASS"
            if self.config.reports_enabled and report_manifest_complete(report_manifest)
            else ("FAIL" if self.config.reports_enabled else "NOT_REQUESTED")
        )
        result["status_summary"] = human_status_summary(
            statuses=result,
            handoff=handoff,
            workflow_mode="DRY_RUN",
            central_sync="SYNCED" if event_queue.status_for_run(run_id) == "SYNCED" else "PENDING_UPLOAD",
            artifact_status=artifact_sync["status"],
            reports_status=reports_status,
        )

        completion = run_completed_event(run, result=result)
        completion_sync = self._enqueue_and_drain(event_queue, completion, run_dir / "run.json", client)
        _atomic_json(run_dir / "central-run-completed.json", completion_sync)
        run.central_sync_status = (
            OperationStatus.SYNCED if event_queue.status_for_run(run_id) == "SYNCED" else OperationStatus.PENDING_UPLOAD
        )
        context["run"] = run.to_dict()
        context["result"] = result
        _atomic_json(run_dir / "run.json", context)
        response = {
            "schema_version": 2,
            "run": run.to_dict(),
            "server": server.to_dict(),
            "normalized_inventory": normalized,
            "firmware": firmware,
            "result": result,
            "finalization": finalization,
            "central": {
                "runtime": central_runtime,
                "event_queue_status": event_queue.status_for_run(run_id),
                "artifact_status": artifact_sync["status"],
            },
            "reports": report_manifest,
            "run_directory": str(run_dir),
        }
        assert_no_sensitive_fields(response)
        _atomic_json(run_dir / "result-summary.json", response)
        self._notify({"event": "WORKFLOW_COMPLETED", "workflow_mode": "DRY_RUN", "stage": "COMPLETE", "status": handoff["overall"], "run_id": run_id})
        return response

    def finalize_server(self, *, operator_authorized: bool = False) -> dict[str, Any]:
        """Perform the explicitly selected, locally verified handoff sequence.

        The only supported mutation is IPMI SEL cleanup, and only after the
        current SEL has been preserved and included in a hashed diagnostic
        bundle.  BMC soft reset, host reboot, power actions, firmware mutation,
        and configuration changes remain closed.
        """
        if not operator_authorized:
            raise ProductionWorkflowError("Finalize Server requires explicit operator authorization")
        probe, platform, identity, _ = detect_current_platform_and_identity(
            dmi_root=self.dmi_root, fru_reader=self.fru_reader
        )
        if platform.get("platform_id") != "ASUS_SERVER" or platform.get("vendor") != "ASUS":
            raise ProductionWorkflowError("Finalize Server is unavailable: current platform is not an ASUS server")
        if not identity.get("resumable") or not identity.get("fingerprint_sha256"):
            raise ProductionWorkflowError("Finalize Server requires trustworthy current/local identity")
        last = last_production_result(self.config.primary_root)
        if last.get("status") != "FOUND":
            raise ProductionWorkflowError("Finalize Server requires an existing completed local run")
        authoritative = Path(str(last["path"]))
        payload = json.loads(authoritative.read_text(encoding="utf-8"))
        run_payload = payload.get("run") if isinstance(payload.get("run"), Mapping) else payload
        server_payload = payload.get("server") if isinstance(payload.get("server"), Mapping) else {}
        if server_payload and str(server_payload.get("fingerprint_sha256") or "") != str(identity["fingerprint_sha256"]):
            raise ProductionWorkflowError("Finalize Server refused: last run belongs to a different physical server")
        if not server_payload and str(run_payload.get("server_fingerprint_sha256") or "") != str(identity["fingerprint_sha256"]):
            raise ProductionWorkflowError("Finalize Server refused: last run identity cannot be matched to this server")
        run_id = str(run_payload.get("run_id") or "")
        if not re.fullmatch(r"RUN-[A-Z0-9-]{8,96}", run_id):
            raise ProductionWorkflowError("Finalize Server found an invalid RUN_ID")

        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        final_root = authoritative.parent / "finalizations" / f"FINALIZE-{stamp}"
        final_root.mkdir(parents=True, exist_ok=False)
        self._notify({"event": "STAGE_STARTED", "stage": "FINALIZATION", "run_id": run_id})
        runner = load_runner(self.config.runner_config)
        inventory = self._collect_inventory(
            final_root / "evidence",
            identity=identity,
            platform=platform,
            probe=probe,
            run_id=run_id,
            runner_id=str(runner["runner_id"]),
        )
        sel_path = inventory["evidence_by_name"].get("ipmi_sel_full")
        if sel_path is None or not sel_path.is_file():
            raise ProductionWorkflowError("Finalize Server cannot preserve the current SEL")
        preclean = preserve_preclean_logs(final_root / "preclean-manifest.json", {"IPMI_SYSTEM_EVENT_LOG": sel_path})
        bundle, bundle_manifest = build_universal_bundle(
            final_root / "diagnostic",
            platform=platform,
            identity=identity,
            evidence_paths=inventory["evidence_paths"],
        )
        included_hashes = {str(item["sha256"]) for item in bundle_manifest["included"]}
        if preclean["artifacts"][0]["sha256"] not in included_hashes:
            raise ProductionWorkflowError("Finalize Server bundle did not attest the preserved SEL")

        entries = int(inventory["summary"]["sel"]["entry_count"])
        if self.config.sel_cleanup_enabled and entries > 0:
            gate = MutationGate(
                authorized=True,
                lab_mode=True,
                approval_id=f"OPERATOR-FINALIZE-{run_id}",
                machine_fingerprint_sha256=str(identity["fingerprint_sha256"]),
                vendor="ASUS",
                model=str(identity["model"]),
                system_serial=str(identity["primary_serial"]),
                run_id=run_id,
                component="SEL",
                allowed_actions=frozenset({"LOG_CLEAR"}),
                expires_at_utc=(datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat(),
            )
            cleanup_result = execute_log_cleanup(
                identity=identity,
                preclean_manifest=preclean,
                diagnostic_artifact_hashes=included_hashes,
                adapter=self.cleanup_adapter_factory(),
                mutation_gate=gate,
                run_id=run_id,
            )
            cleanup: dict[str, Any] = {
                "status": cleanup_result.get("status", "FAILED"),
                "result": cleanup_result,
                "gate": gate.public_record(),
                "preclear_entries": entries,
            }
        else:
            cleanup = {
                "status": "NOT_REQUIRED" if entries == 0 else "DISABLED_BY_CONFIG",
                "preclear_entries": entries,
            }
        _atomic_json(final_root / "sel-cleanup.json", cleanup)
        sanity = self._final_sanity(identity, cleanup)
        prior_result = payload.get("normalized_result") or payload.get("result") or {}
        finalization = build_finalization_status(
            sel_cleanup=(cleanup.get("result") or {}).get("status", cleanup.get("status", "NOT_PERFORMED")),
            final_sanity=sanity.get("sensor_status", "NOT_TESTED"),
            bmc_soft_reset=BmcSoftResetCapability(),
            evidence_saved=True,
            identity_reverified=bool(sanity.get("same_server_fingerprint")),
            firmware_reverified=_firmware_status_reverified(prior_result),
        )
        statuses = dict(prior_result) if isinstance(prior_result, Mapping) else {}
        statuses.update(
            {
                "collection": "PASS",
                "identity": "PASS" if sanity.get("same_server_fingerprint") else "FAIL",
                "sensors": sanity.get("sensor_status", "NOT_TESTED"),
                "sel": "PASS" if finalization["sel_cleanup"] in {"SUCCESS", "NOT_REQUIRED"} else "REVIEW",
                "log_clean": finalization["sel_cleanup"],
                "bmc_soft_reset": "NOT_PERFORMED",
            }
        )
        handoff = evaluate_handoff(
            statuses,
            workflow_mode=str(run_payload.get("workflow_mode") or "PRODUCTION"),
            policy=HandoffPolicy.from_mapping(self.config.handoff_policy),
        )
        finalization["overall"] = handoff["overall"]
        finalization["handoff_status"] = handoff["handoff_status"]
        status_summary = human_status_summary(
            statuses=statuses,
            handoff=handoff,
            workflow_mode=str(run_payload.get("workflow_mode") or "PRODUCTION"),
            central_sync="PENDING_UPLOAD",
            artifact_status="LOCAL_COMPLETE",
            reports_status="NOT_REQUESTED",
        )

        client, central_runtime = self._collector_client()
        event_queue = StoreForwardQueue(self.config.queue_database)
        final_event = run_progress_event(
            RunRecord.from_dict(run_payload),
            stage_result={
                "stage": "FINALIZATION_COMPLETED",
                "overall": handoff["overall"],
                "handoff_status": handoff["handoff_status"],
                "sel_cleanup": finalization["sel_cleanup"],
                "bmc_soft_reset": "NOT_PERFORMED",
            },
        )
        event_sync = self._enqueue_and_drain(event_queue, final_event, authoritative, client)
        artifact_queue = ArtifactStoreForwardQueue(self.config.artifact_queue_database)
        # The SQLite CentralCollector used by local/unit-test runs is an
        # event collector, not an artifact transport.  Keep the authoritative
        # local reports complete when that client is injected; only drain the
        # binary queue through a client that explicitly implements the upload
        # capability.
        artifact_drain = (
            artifact_queue.drain(client)
            if client is not None
            and self.config.artifact_sync_enabled
            and callable(getattr(client, "upload_artifact", None))
            else {"attempted": 0, "synced": 0, "duplicates": 0, "pending": 0, "failed": 0}
        )
        evidence_manifest = self._evidence_manifest(inventory["evidence_paths"] + [bundle])
        response = {
            "schema_version": 1,
            "run_id": run_id,
            "server_id": identity["server_id"],
            "finalized_at_utc": utc_now(),
            "finalization": finalization,
            "handoff": handoff,
            "central": {
                "runtime": central_runtime,
                "event": event_sync,
                "event_queue_status": event_queue.status_for_run(run_id),
                "artifact_queue_status": artifact_queue.status_for_run(run_id),
                "artifact_drain": artifact_drain,
            },
            "safety": {
                "bmc_soft_reset_performed": False,
                "host_reboot_performed": False,
                "power_cycle_performed": False,
                "firmware_mutation_performed": False,
                "configuration_change_performed": False,
            },
            "diagnostic_bundle": str(bundle),
            "evidence_manifest": evidence_manifest,
            "output_directory": str(final_root),
            "status_summary": status_summary,
        }
        assert_no_sensitive_fields(response)
        _atomic_json(final_root / "finalization-result.json", response)
        self._notify({"event": "WORKFLOW_COMPLETED", "stage": "FINALIZATION", "status": handoff["overall"], "run_id": run_id})
        return response

    def run_asus_production(
        self,
        *,
        profile_id: str | None = None,
        custom_hours: float | None = None,
        extended_diagnostics: bool = False,
    ) -> dict[str, Any]:
        """Run or automatically resume the complete ASUS production pipeline.

        A reboot continuation is deliberately not a new production run.  The
        pending record is identity- and runner-bound, and the original run
        context is reopened only after Linux has booted with a new boot ID.
        This lets the firmware service continue Options 1 and 2 before the
        operator console is presented again.
        """
        requested_mode = "PRODUCTION_EXTENDED" if extended_diagnostics else "PRODUCTION"
        self._notify(
            {
                "event": "WORKFLOW_STARTED",
                "workflow_mode": requested_mode,
                "stage": "IDENTITY",
                "resume_check": True,
            }
        )
        probe, platform, identity, fru = detect_current_platform_and_identity(
            dmi_root=self.dmi_root, fru_reader=self.fru_reader
        )
        if platform.get("platform_id") != "ASUS_SERVER" or str(platform.get("vendor")) != "ASUS":
            raise ProductionWorkflowError(
                "ASUS production workflow refused: authoritative vendor detection did not return ASUS_SERVER"
            )
        runner = load_runner(self.config.runner_config)
        if not identity.get("resumable") or str(identity.get("confidence")) not in {"high", "medium"}:
            raise ProductionWorkflowError("ASUS production workflow requires trusted current/local identity")
        orchestrator = ProductionOrchestrator(self.config.primary_root, runtime_version=self.runtime_version)
        pending = self._load_pending_firmware()
        foreign_pending = self._quarantine_foreign_pending(
            pending,
            identity=identity,
            runner_id=str(runner.get("runner_id") or ""),
        )
        if foreign_pending is not None:
            pending = None
        if pending and str(pending.get("state") or "").upper() == "TASK_IN_PROGRESS":
            task_resume = self._resume_inflight_firmware_task(pending)
            if task_resume is not None and not bool(task_resume.pop("_continue", False)):
                return task_resume
            pending = self._load_pending_firmware() or pending
        is_resume = bool(
            pending
            and str(pending.get("workflow_mode") or "").upper() == requested_mode
        )
        if pending:
            same_boot_retry = self._retry_same_boot_firmware_reboot(pending)
            if same_boot_retry is not None:
                return same_boot_retry
        if pending and not is_resume:
            # A pending firmware-only continuation is owned by Option 5, and
            # an extended-production continuation is owned by Option 2.  Do
            # not accidentally consume either from the wrong menu route.
            return {
                "status": "PENDING_FIRMWARE_OTHER_WORKFLOW",
                "pending_workflow_mode": str(pending.get("workflow_mode") or ""),
                "requested_workflow_mode": requested_mode,
                "mutation_started": False,
                "sensitive_material_exposed": False,
            }

        if is_resume:
            assert pending is not None
            try:
                validate_pending_for_resume(
                    pending,
                    identity=identity,
                    runner_id=str(runner.get("runner_id") or ""),
                    require_new_boot=str(pending.get("state") or "").upper()
                    not in {"TASK_IN_PROGRESS", "TASK_RESUMED"},
                )
                context = orchestrator.resume(
                    str(pending.get("run_id") or ""),
                    identity=identity,
                    runner_id=str(runner.get("runner_id") or ""),
                )
            except (FirmwareLifecycleError, WorkflowError) as exc:
                return {
                    "status": "BLOCKED_FIRMWARE_RESUME_IDENTITY",
                    "reason": str(exc),
                    "pending": dict(pending),
                    "mutation_started": False,
                    "sensitive_material_exposed": False,
                }
            workflow_mode = requested_mode
            pending_profile_id = str(pending.get("profile_id") or self.config.default_profile)
            pending_profile_seconds = int(pending.get("profile_total_seconds") or 0)
            profile = resolve_profile(
                pending_profile_id,
                custom_hours=(pending_profile_seconds / 3600) if pending_profile_id.upper() == "CUSTOM" and pending_profile_seconds else None,
            )
            run_id = str(context["run"]["run_id"])
            run_dir = self.config.primary_root / "runs" / run_id
            _atomic_json(
                run_dir / "firmware-resume-launch.json",
                {
                    "schema_version": 1,
                    "mode": "AUTOMATIC_POST_REBOOT_RESUME",
                    "workflow_mode": workflow_mode,
                    "resumed_at_utc": utc_now(),
                    "boot_id": str(identity.get("boot_id") or ""),
                    "pending_created_at_utc": str(pending.get("created_at_utc") or ""),
                    "automatic_workload_at_boot": True,
                    "vendor_detected_before_resume": True,
                },
            )
        else:
            workflow_mode = requested_mode
            profile = resolve_profile(profile_id or self.config.default_profile, custom_hours=custom_hours)
            enrollment = reconcile_server_enrollment(
                self.config.primary_root,
                identity,
                runner_id=str(runner.get("runner_id") or ""),
                server_specific_paths=self._server_specific_enrollment_paths(),
            )
            # Runtime loaded by the current immutable release is authoritative
            # for a new run; the stable runner identifier itself is preserved.
            context = orchestrator.start(
                platform=platform,
                identity=identity,
                runner_id=runner["runner_id"],
                workflow_mode=workflow_mode,
                test_profile=profile.profile_id,
            )
            run_id = str(context["run"]["run_id"])
            run_dir = self.config.primary_root / "runs" / run_id
            _atomic_json(run_dir / "enrollment.json", enrollment)
            _atomic_json(
                run_dir / "operator-launch.json",
                {
                    "schema_version": 1,
                    "mode": "MANUAL_CONSOLE_SELECTION",
                    "workflow_mode": workflow_mode,
                    "selected_at_utc": utc_now(),
                    "automatic_workload_at_boot": False,
                    "vendor_detected_before_selection": True,
                    "platform_id": platform["platform_id"],
                    "runtime_version": self.runtime_version,
                    "test_profile": profile.to_dict(),
                },
            )
        client, central_runtime = self._collector_client()
        queue = StoreForwardQueue(self.config.queue_database)
        if is_resume:
            resumed = run_progress_event(
                RunRecord.from_dict(context["run"]),
                stage_result={
                    "stage": "FIRMWARE_POST_REBOOT_RESUME",
                    "boot_id": str(identity.get("boot_id") or ""),
                    "same_run": True,
                },
            )
            _atomic_json(run_dir / "central-firmware-resumed.json", self._enqueue_and_drain(queue, resumed, run_dir / "run.json", client))
        else:
            server = ServerRecord.from_identity(identity)
            started = run_started_event(
                RunRecord.from_dict(context["run"]),
                server,
                bmc={"access_state": BmcAuthState.BMC_AUTH_UNAVAILABLE.value},
                runner={
                    "runner_id": runner["runner_id"],
                    "local_runner_uuid": runner.get("local_runner_uuid", ""),
                    "storage_fingerprint_sha256": runner.get("storage_fingerprint_sha256", ""),
                },
            )
            start_sync = self._enqueue_and_drain(queue, started, run_dir / "run.json", client)
            _atomic_json(run_dir / "central-run-started.json", start_sync)

        reasons: list[Reason] = []
        inventory: dict[str, Any] = {"summary": {}, "normalized": {}, "evidence_paths": [], "evidence_by_name": {}}
        firmware: dict[str, Any] = {}
        tests: dict[str, Any] = {}
        cleanup: dict[str, Any] = {"status": "NOT_PERFORMED"}
        final_sanity: dict[str, Any] = {"sensor_status": "NOT_TESTED"}
        bmc_auth_discovery: dict[str, Any] = {}
        bmc_auth_state = BmcAuthState.BMC_AUTH_UNAVAILABLE.value
        bmc_handoff: dict[str, Any] = {"status": "NOT_REQUIRED", "required": False}
        capabilities: list[dict[str, Any]] = []
        extended_result: dict[str, Any] = {"status": "NOT_REQUESTED", "workflow_mode": workflow_mode}
        try:
            capabilities = build_asus_capability_path_matrix(
                bmc_auth_state=_coerce_bmc_auth_state(bmc_auth_state),
                verified_local_mechanisms={
                    "identity": "DMI/SMBIOS + local KCS IPMI FRU",
                    "firmware_inventory": "DMI BIOS + local KCS IPMI MC",
                    "hardware_inventory": "Linux current-boot tools",
                    "sensors": "local KCS IPMI SDR",
                    "sel": "local KCS IPMI SEL",
                },
                verified_bmc_mechanisms={
                    "bios_update": "authenticated Redfish/OEM update action",
                    "bmc_update": "authenticated Redfish/OEM update action",
                    "task_completion": "authenticated Redfish TaskService/OEM job",
                    "system_diagnostics": "authenticated ASUS/AMI diagnostic action",
                },
            )
            context = orchestrator.transition(
                context,
                identity=identity,
                next_stage=WorkflowStage.CAPABILITY_DISCOVERY,
                details={
                    "bmc_access_state": bmc_auth_state,
                    "bmc_auth_discovery": bmc_auth_discovery,
                    "global_run_blocked": False,
                    "capability_paths": capabilities,
                    "local_fru_collection": _public_fru_status(fru),
                },
            )

            evidence_dir = run_dir / "evidence"
            self._notify({"event": "STAGE_STARTED", "stage": "INVENTORY", "profile": profile.profile_id})
            inventory = self._collect_inventory(
                evidence_dir,
                identity=identity,
                platform=platform,
                probe=probe,
                run_id=run_id,
                runner_id=runner["runner_id"],
            )
            # Initial BMC discovery is strictly read-only.  Authentication is
            # escalated only after the exact firmware planner proves that an
            # outdated component needs an authenticated transport.
            bmc_auth_discovery = self._discover_bmc_auth(
                inventory.get("normalized") or {}, identity, exclude_run_id=run_id, read_only=True
            )
            bmc_auth_state = str(bmc_auth_discovery.get("state") or BmcAuthState.BMC_AUTH_UNAVAILABLE.value)
            context.setdefault("safety", {})["bmc_auth_change_started"] = bool(
                (bmc_auth_discovery.get("provisioning") or {}).get("mutation_performed")
            )
            if inventory.get("normalized"):
                inventory["normalized"]["bmc_auth_state"] = bmc_auth_state
            _atomic_json(evidence_dir / "inventory-summary.json", inventory["summary"])
            _atomic_json(run_dir / "normalized-inventory.json", inventory["normalized"])
            _atomic_json(run_dir / "bmc-auth-discovery.json", bmc_auth_discovery)
            capabilities = build_asus_capability_path_matrix(
                bmc_auth_state=_coerce_bmc_auth_state(bmc_auth_state),
                verified_local_mechanisms={
                    "identity": "DMI/SMBIOS + local KCS IPMI FRU",
                    "firmware_inventory": "DMI BIOS + local KCS IPMI MC",
                    "hardware_inventory": "Linux current-boot tools",
                    "sensors": "local KCS IPMI SDR",
                    "sel": "local KCS IPMI SEL",
                },
                verified_bmc_mechanisms={
                    "bios_update": "authenticated Redfish/OEM update action",
                    "bmc_update": "authenticated Redfish/OEM update action",
                    "task_completion": "authenticated Redfish TaskService/OEM job",
                    "system_diagnostics": "authenticated ASUS/AMI diagnostic action",
                },
            )
            _atomic_json(run_dir / "capability-paths-final.json", {"schema_version": 1, "paths": capabilities})
            context = orchestrator.transition(
                context,
                identity=identity,
                next_stage=WorkflowStage.INVENTORY,
                details=inventory["summary"],
            )

            # Preserve serial/MAC inventory centrally before any workload or mutation.
            identity_progress = run_progress_event(
                RunRecord.from_dict(context["run"]),
                stage_result={
                    "stage": "SERIAL_INVENTORY_PRESERVED",
                    "server_id": inventory["normalized"].get("server_id"),
                    "system_serial": inventory["normalized"].get("system_serial"),
                    "primary_host_mac": inventory["normalized"].get("primary_host_mac"),
                    "nic_serials": physical_nic_rows(inventory["normalized"]),
                    "component_counts": inventory["normalized"].get("component_counts", {}),
                    "sensitive_data_excluded": True,
                },
            )
            identity_sync = self._enqueue_and_drain(queue, identity_progress, run_dir / "run.json", client)
            _atomic_json(run_dir / "central-identity-preserved.json", identity_sync)
            self._notify({"event": "STAGE_COMPLETED", "stage": "INVENTORY", "status": "PASS"})

            fresh_firmware = self._firmware_plan(inventory, bmc_auth_discovery)
            if is_resume:
                # Do not trust a new catalog result as an instruction to flash
                # again.  First prove every component from the original
                # checkpoint against live DMI/KCS evidence, then continue the
                # *same* approved pipeline.
                post_reboot = self._verify_pending_components_after_reboot(
                    pending or {}, inventory.get("normalized") or {}
                )
                _atomic_json(run_dir / "firmware-post-reboot-verification.json", post_reboot)
                _atomic_json(run_dir / "firmware-plan-current-after-reboot.json", fresh_firmware)
                if str(post_reboot.get("status") or "") != "UPDATED_VERIFIED":
                    context = orchestrator.transition(
                        context,
                        identity=identity,
                        next_stage=WorkflowStage.FIRMWARE_PLAN,
                        details={"resume": True, "post_reboot_verification": post_reboot},
                    )
                    context = orchestrator.transition(
                        context,
                        identity=identity,
                        next_stage=WorkflowStage.BLOCKED,
                        details={"resume": True, "post_reboot_verification": post_reboot},
                    )
                    raise ProductionWorkflowError("Post-reboot firmware versions did not match the approved pending target")
                try:
                    saved_plan = json.loads((run_dir / "firmware-plan.json").read_text(encoding="utf-8"))
                except (OSError, ValueError, json.JSONDecodeError):
                    saved_plan = {}
                firmware = dict(saved_plan) if isinstance(saved_plan, Mapping) else {}
                if not firmware:
                    # The old release may have staged firmware before it wrote
                    # the plan receipt.  Continue safely only with the live
                    # exact plan, and keep that exception explicit.
                    firmware = dict(fresh_firmware)
                    firmware["resume_plan_source"] = "FRESH_EXACT_PLAN_FALLBACK"
                remaining_components = [
                    str(value or "").upper()
                    for value in post_reboot.get("remaining_components") or []
                    if str(value or "").upper() in {"BIOS", "BMC"}
                ]
                # A transport may require an activation boundary before a
                # later component can be applied.  Verify the component that
                # just rebooted, then continue only the still-approved
                # component(s) from this exact run plan.  Never replace the
                # checkpointed plan with a newly fetched catalog during a
                # resume.
                firmware["readiness"] = "UPDATE_REQUIRED" if remaining_components else "UPDATED_VERIFIED"
                firmware["post_reboot_verification"] = post_reboot
                firmware["resume_remaining_components"] = remaining_components
                firmware["fresh_catalog_after_reboot"] = {
                    "readiness": str(fresh_firmware.get("readiness") or "UNVERIFIED"),
                    "generated_at_utc": utc_now(),
                }
                for item in firmware.get("components") or []:
                    if not isinstance(item, dict):
                        continue
                    matching = next(
                        (
                            row for row in post_reboot.get("components") or []
                            if isinstance(row, Mapping)
                            and str(row.get("component") or "").upper() == str(item.get("component") or "").upper()
                        ),
                        None,
                    )
                    if isinstance(matching, Mapping):
                        item["after"] = str(matching.get("after") or "")
                        item["status"] = "UPDATED_VERIFIED"
                if bool((pending or {}).get("bmc_auth_changed")):
                    bmc_auth_discovery["bmc_auth_change_started"] = True
            else:
                firmware = fresh_firmware
            _atomic_json(run_dir / "firmware-plan.json", firmware)
            capabilities = apply_firmware_transport_paths(capabilities, firmware)
            _atomic_json(run_dir / "capability-paths-final.json", {"schema_version": 1, "paths": capabilities})
            context = orchestrator.transition(
                context,
                identity=identity,
                next_stage=WorkflowStage.FIRMWARE_PLAN,
                details=firmware,
            )

            # Options 1 and 2 share the same exact firmware lifecycle as the
            # explicit Option 5 action.  A current, independently verified
            # version proceeds directly; an exact update target must pass the
            # package/cache/transport/auth executor before any hardware test.
            firmware_readiness = str(firmware.get("readiness") or "UNVERIFIED")
            # Authentication can refresh the BMC firmware inventory.  The
            # first plan may therefore say UPDATE_REQUIRED solely because
            # Redfish was unauthenticated, while the authenticated re-plan
            # proves that the component is already current.  Resolve that
            # state before dispatching the update branch so a current BMC is
            # never flashed and the workflow continues to hardware tests.
            if (
                firmware_readiness == "UPDATE_REQUIRED"
                and not is_resume
                and _firmware_requires_authenticated_bmc(firmware)
            ):
                preflight_inventory, preflight_discovery, preflight_recovery = self._ensure_authenticated_firmware_access(
                    run_dir=run_dir,
                    identity=identity,
                    platform=platform,
                    probe=probe,
                    inventory=inventory,
                    firmware=firmware,
                    run_id=run_id,
                    runner_id=runner["runner_id"],
                    discovery=bmc_auth_discovery,
                )
                preflight_state = str(
                    preflight_discovery.get("state") or BmcAuthState.BMC_AUTH_UNAVAILABLE.value
                )
                if bmc_auth_is_usable(preflight_state):
                    inventory = preflight_inventory
                    bmc_auth_discovery = preflight_discovery
                    bmc_recovery = preflight_recovery
                    candidate = self._firmware_plan(inventory, bmc_auth_discovery)
                    candidate_readiness = str(candidate.get("readiness") or "UNVERIFIED")
                    if candidate_readiness in {"CURRENT_VERIFIED", "UPDATED_VERIFIED"}:
                        firmware = candidate
                        firmware_readiness = candidate_readiness
                        inventory_normalized = inventory.get("normalized")
                        if isinstance(inventory_normalized, dict):
                            inventory_normalized["bmc_auth_state"] = preflight_state
                            _atomic_json(run_dir / "normalized-inventory.json", inventory_normalized)
                        _atomic_json(run_dir / "firmware-plan.json", firmware)
                        _atomic_json(run_dir / "bmc-auth-discovery.json", bmc_auth_discovery)
                        _atomic_json(run_dir / "bmc-recovery-path.json", bmc_recovery)
            if firmware_readiness in {"CURRENT_VERIFIED", "UPDATED_VERIFIED"}:
                # Remain in FIRMWARE_PLAN until the workload result is
                # recorded.  The single HARDWARE_TESTS transition below is
                # the completion record; entering that stage here and again
                # after the test is an invalid self-transition.
                if is_resume:
                    context = orchestrator.transition(
                        context,
                        identity=identity,
                        next_stage=WorkflowStage.POST_UPDATE_VERIFY,
                        details={
                            "status": "UPDATED_VERIFIED",
                            "resume": True,
                            "post_reboot_verification": firmware.get("post_reboot_verification") or {},
                        },
                    )
            elif firmware_readiness == "UPDATE_REQUIRED":
                if _firmware_requires_authenticated_bmc(firmware):
                    inventory, bmc_auth_discovery, bmc_recovery = self._ensure_authenticated_firmware_access(
                        run_dir=run_dir,
                        identity=identity,
                        platform=platform,
                        probe=probe,
                        inventory=inventory,
                        firmware=firmware,
                        run_id=run_id,
                        runner_id=runner["runner_id"],
                        discovery=bmc_auth_discovery,
                    )
                else:
                    bmc_recovery = {
                        "status": "NOT_REQUIRED",
                        "reason": "SELECTED_LOCAL_TRANSPORT_DOES_NOT_REQUIRE_BMC_AUTH",
                        "mutation_started": False,
                        "sensitive_material_exposed": False,
                    }
                bmc_auth_state = str(
                    bmc_auth_discovery.get("state") or BmcAuthState.BMC_AUTH_UNAVAILABLE.value
                )
                if inventory.get("normalized"):
                    inventory["normalized"]["bmc_auth_state"] = bmc_auth_state
                    _atomic_json(run_dir / "normalized-inventory.json", inventory["normalized"])
                _atomic_json(run_dir / "bmc-auth-discovery.json", bmc_auth_discovery)
                _atomic_json(run_dir / "bmc-recovery-path.json", bmc_recovery)
                if _firmware_requires_authenticated_bmc(firmware) and not bmc_auth_is_usable(bmc_auth_state):
                    context = orchestrator.transition(
                        context,
                        identity=identity,
                        next_stage=WorkflowStage.BLOCKED,
                        details={
                            "firmware_status": "UPDATE_REQUIRED",
                            "reason": str(bmc_recovery.get("reason") or "AUTHENTICATED_BMC_REQUIRED_FOR_FIRMWARE_APPLY"),
                            "bmc_recovery": bmc_recovery,
                        },
                    )
                    raise ProductionWorkflowError("Authenticated BMC access could not be established for an exact required firmware update")
                # BMC recovery may have moved its address and replaced stale
                # Redfish inventory.  A new run re-plans from that fresh
                # evidence; a post-reboot resume deliberately retains its
                # original exact package plan so a catalog change cannot add
                # an unconfirmed second firmware mutation.
                if is_resume or not _firmware_requires_authenticated_bmc(firmware):
                    _atomic_json(run_dir / "firmware-plan-resume-approved.json", firmware)
                else:
                    firmware = self._firmware_plan(inventory, bmc_auth_discovery)
                    _atomic_json(run_dir / "firmware-plan.json", firmware)
                update_components = [
                    item for item in (firmware.get("components") or [])
                    if isinstance(item, Mapping)
                    and str(item.get("status") or "") == "UPDATE_REQUIRED"
                    and str(item.get("target") or "")
                ]
                if not update_components:
                    raise ProductionWorkflowError("Firmware planner returned UPDATE_REQUIRED without an exact component target")
                first_update = update_components[0]
                generic_plan = firmware.get("generic_asus_firmware_engine") if isinstance(firmware.get("generic_asus_firmware_engine"), Mapping) else {}
                generic_components = generic_plan.get("components") if isinstance(generic_plan.get("components"), Mapping) else {}
                first_component_plan = generic_components.get(str(first_update.get("component") or "").upper()) if isinstance(generic_components, Mapping) else {}
                selected_package = first_component_plan.get("selected_package") if isinstance(first_component_plan, Mapping) else {}
                selected_metadata = selected_package.get("metadata") if isinstance(selected_package, Mapping) else {}
                transition_gate = MutationGate(
                    authorized=True,
                    lab_mode=True,
                    approval_id=f"OPERATOR-PRODUCTION-FIRMWARE-{run_id}",
                    machine_fingerprint_sha256=str(identity.get("fingerprint_sha256") or ""),
                    vendor="ASUS",
                    model=str(identity.get("model") or ""),
                    system_serial=str(identity.get("primary_serial") or ""),
                    run_id=run_id,
                    component=str(first_update.get("component") or "").upper(),
                    target_version=str(first_update.get("target") or ""),
                    package_sha256=str(selected_metadata.get("sha256") or ""),
                    allowed_actions=frozenset({"FIRMWARE_APPLY"}),
                    expires_at_utc=(datetime.now(timezone.utc) + timedelta(minutes=45)).isoformat(),
                )
                context = orchestrator.transition(
                    context,
                    identity=identity,
                    next_stage=WorkflowStage.FIRMWARE_APPLY,
                    mutation_gate=transition_gate,
                    details={
                        "component": transition_gate.component,
                        "target_version": transition_gate.target_version,
                        "package_sha256": transition_gate.package_sha256,
                        "firmware_status": "UPDATE_REQUIRED",
                    },
                )
                firmware_execution = self._execute_firmware_lifecycle(
                    run_dir=run_dir,
                    identity=identity,
                    platform=platform,
                    probe=probe,
                    runner_id=str(runner.get("runner_id") or ""),
                    inventory=inventory,
                    bmc_discovery=bmc_auth_discovery,
                    firmware=firmware,
                    run_id=run_id,
                )
                _atomic_json(run_dir / "firmware-execution.json", firmware_execution)
                if str(firmware_execution.get("status") or "") == "REBOOT_REQUIRED":
                    # Persist the identity-bound continuation before the only
                    # controlled reboot request.  Do not run hardware tests,
                    # SEL cleanup, or a second firmware component until the
                    # post-boot service has verified every approved target.
                    context = orchestrator.transition(
                        context,
                        identity=identity,
                        next_stage=WorkflowStage.REBOOT_PENDING,
                        details=firmware_execution,
                        firmware_task_identity=str(firmware_execution.get("task_id") or ""),
                    )
                    pending_record = self._write_pending_firmware(
                        run_dir=run_dir,
                        identity=identity,
                        plan=firmware,
                        execution=firmware_execution,
                        bmc_auth_changed=bmc_auth_change_required(bmc_auth_discovery),
                        runner_id=str(runner.get("runner_id") or ""),
                        workflow_mode=workflow_mode,
                        profile_id=profile.profile_id,
                        profile_total_seconds=profile.total_seconds,
                        extended_diagnostics=extended_diagnostics,
                    )
                    reboot = request_controlled_reboot(
                        executor=self.executor,
                        primary_root=self.config.primary_root,
                        pending=pending_record,
                    )
                    firmware_execution["reboot"] = reboot
                    _atomic_json(run_dir / "firmware-execution.json", firmware_execution)
                    return {
                        "schema_version": 2,
                        "status": reboot["status"],
                        "run": context["run"],
                        "firmware": firmware,
                        "execution": firmware_execution,
                        "pending": pending_record,
                        "run_directory": str(run_dir),
                        "mutation_started": bool(firmware_execution.get("mutation_started")),
                        "sensitive_material_exposed": False,
                    }
                if str(firmware_execution.get("status") or "") != "UPDATED_VERIFIED":
                    raise ProductionWorkflowError(
                        f"Firmware lifecycle did not complete: {firmware_execution.get('status') or 'UNKNOWN'}"
                    )
                firmware["readiness"] = "UPDATED_VERIFIED"
                firmware["mutation_started"] = bool(firmware_execution.get("mutation_started"))
                firmware["execution"] = firmware_execution
                for item in firmware.get("components") or []:
                    if not isinstance(item, dict):
                        continue
                    if str(item.get("status") or "") == "UPDATE_REQUIRED":
                        item["after"] = next(
                            (
                                str(
                                    component.get("installed_version")
                                    or component.get("after_version")
                                    or component.get("target_version")
                                    or ""
                                )
                                for component in firmware_execution.get("components") or []
                                if str(component.get("component") or "").upper() == str(item.get("component") or "").upper()
                            ),
                        )
                        item["status"] = "UPDATED_VERIFIED"
                context = orchestrator.transition(
                    context,
                    identity=identity,
                    next_stage=WorkflowStage.POST_UPDATE_VERIFY,
                    details=firmware_execution,
                )
                # POST_UPDATE_VERIFY may advance to HARDWARE_TESTS exactly
                # once, after the workload result is recorded below.
            else:
                context = orchestrator.transition(
                    context,
                    identity=identity,
                    next_stage=WorkflowStage.BLOCKED,
                    details={"firmware_status": firmware_readiness, "reason": "EXACT_FIRMWARE_TARGET_NOT_RESOLVED"},
                )
                raise ProductionWorkflowError("Firmware planner did not resolve an exact current or update-required state")

            self._notify({"event": "STAGE_STARTED", "stage": "HARDWARE_TESTS", "profile": profile.profile_id})
            self._write_workload_continuation(
                run_id=run_id,
                run_dir=run_dir,
                identity=identity,
                runner_id=str(runner.get("runner_id") or ""),
                workflow_mode=workflow_mode,
                profile_id=profile.profile_id,
            )
            try:
                tests = self._run_workloads(evidence_dir, profile)
            finally:
                # A normal process-level workload failure is finalized by the
                # surrounding exception handler on this same boot.  Only an
                # abrupt host reset skips this finally block and leaves the
                # durable checkpoint for the boot recovery service.
                self._clear_workload_continuation(run_dir=run_dir, outcome="WORKLOAD_PROCESS_RETURNED")
            _atomic_json(evidence_dir / "hardware-test-summary.json", tests)
            if tests["cpu"]["status"] != "PASS":
                reasons.append(Reason("CPU_TEST_FAILED", ReasonSeverity.FAIL, "CPU stress verification did not pass."))
            if tests["memory"]["status"] != "PASS":
                reasons.append(Reason("DIMM_TEST_FAILED", ReasonSeverity.FAIL, "Memory stress verification did not pass."))
            storage_status = inventory["summary"]["storage"]["status"]
            context = orchestrator.transition(
                context,
                identity=identity,
                next_stage=WorkflowStage.HARDWARE_TESTS,
                details=tests,
            )
            self._notify({"event": "STAGE_COMPLETED", "stage": "HARDWARE_TESTS", "status": tests.get("status", "UNKNOWN")})
            progress = run_progress_event(
                RunRecord.from_dict(context["run"]),
                stage_result={
                    "stage": WorkflowStage.HARDWARE_TESTS.value,
                    "cpu": tests["cpu"]["status"],
                    "ram": tests["memory"]["status"],
                    "storage": storage_status,
                    "runner_storage_smart": inventory["summary"].get("runner_storage", {}).get("smart_status", "UNKNOWN"),
                    "sensors": inventory["summary"]["sensors"]["status"],
                },
            )
            progress_sync = self._enqueue_and_drain(queue, progress, run_dir / "run.json", client)
            _atomic_json(run_dir / "central-run-progress.json", progress_sync)

            context = orchestrator.transition(
                context,
                identity=identity,
                next_stage=WorkflowStage.DIAGNOSTICS,
                details={
                    "local_bundle": "PENDING",
                    "system_diagnostics": "PENDING" if extended_diagnostics else "NOT_REQUESTED",
                    "overall_run_blocked": False,
                },
            )
            sel_path = inventory["evidence_by_name"].get("ipmi_sel_full")
            if sel_path is None or not sel_path.is_file() or sel_path.stat().st_size == 0:
                raise ProductionWorkflowError("Full pre-clean SEL evidence is unavailable")
            if extended_diagnostics:
                self._notify({"event": "STAGE_STARTED", "stage": "ASUS_SYSTEM_DIAGNOSTICS"})
                extended_result = self._run_extended_diagnostics(
                    run_dir,
                    inventory=inventory,
                    bmc_auth_state=bmc_auth_state,
                    bmc_auth_discovery=bmc_auth_discovery,
                    platform=platform,
                    firmware=firmware,
                )
                _atomic_json(run_dir / "diagnostics" / "diagnostic_summary.json", extended_result)
                status = str(extended_result.get("status") or "EXECUTION_FAILED").upper()
                if status == "HARDWARE_FAILURE":
                    reasons.append(
                        Reason(
                            "EXTENDED_DIAGNOSTICS_HARDWARE_FAILURE",
                            ReasonSeverity.FAIL,
                            "ASUS System Diagnostics reported a hardware failure; inspect vendor evidence.",
                        )
                    )
                elif status not in {"PASS", "UNSUPPORTED", "PLATFORM_UNSUPPORTED"}:
                    reasons.append(
                        Reason(
                            "EXTENDED_DIAGNOSTICS_UNAVAILABLE",
                            ReasonSeverity.REVIEW,
                            f"ASUS System Diagnostics status is {status}; capability requires explicit review.",
                        )
                    )
                # Capture SEL again after the diagnostic run and before any
                # cleanup.  This preserves diagnostic-generated events.
                after_diag = self._capture_sel_snapshot(evidence_dir, "ipmi_sel_after_extended_diagnostics")
                if after_diag.get("status") == "PASS":
                    after_path = Path(str(after_diag.get("stdout_path") or ""))
                    if after_path.is_file():
                        inventory["evidence_paths"].extend(
                            path for path in (after_path, Path(str(after_diag.get("receipt_path") or ""))) if path.is_file()
                        )
                        inventory["evidence_by_name"]["ipmi_sel_after_extended_diagnostics"] = after_path
                        inventory.setdefault("summary", {})["sel_after_extended_diagnostics"] = {
                            "entry_count": _sel_entry_count(str(after_diag.get("stdout") or "")),
                            "sha256": _sha256(after_path),
                            "status": "PASS",
                        }
                self._notify({"event": "STAGE_COMPLETED", "stage": "ASUS_SYSTEM_DIAGNOSTICS", "status": status})
            else:
                extended_result = {"status": "NOT_REQUESTED", "workflow_mode": workflow_mode}
            preclean_sources: dict[str, Path] = {"IPMI_SYSTEM_EVENT_LOG": sel_path}
            if extended_diagnostics:
                after_path = inventory["evidence_by_name"].get("ipmi_sel_after_extended_diagnostics")
                if after_path is not None and after_path.is_file():
                    preclean_sources["IPMI_SYSTEM_EVENT_LOG_AFTER_EXTENDED_DIAGNOSTICS"] = after_path
            preclean = preserve_preclean_logs(
                run_dir / "preclean-manifest.json", preclean_sources
            )
            vendor_artifact = None
            artifact_payload = extended_result.get("artifact") if isinstance(extended_result, Mapping) else None
            if isinstance(artifact_payload, Mapping) and artifact_payload.get("path"):
                vendor_artifact = inspect_asmb12_system_diagnostics(
                    Path(str(artifact_payload["path"])),
                    mechanism="ASMB12 WebUI documented System Diagnostics download API",
                )
            bundle, bundle_manifest = build_universal_bundle(
                run_dir / "diagnostic",
                platform=platform,
                identity=identity,
                evidence_paths=inventory["evidence_paths"]
                + [evidence_dir / "hardware-test-summary.json"]
                + sorted(evidence_dir.glob("*-stress*")),
                vendor_artifact=vendor_artifact,
            )
            bundle_hash = _sha256(bundle)
            diagnostic = {
                "schema_version": 1,
                "collection_status": bundle_manifest["collection"]["status"],
                "bundle": str(bundle),
                "bundle_sha256": bundle_hash,
                "included_count": len(bundle_manifest["included"]),
                "system_diagnostics": extended_result.get("status", "NOT_REQUESTED"),
                "extended_diagnostics": extended_result,
                "preclean_sel_attested": any(
                    item["sha256"] == preclean["artifacts"][0]["sha256"]
                    for item in bundle_manifest["included"]
                ),
            }
            _atomic_json(run_dir / "diagnostic-bundle.json", diagnostic)
            if not diagnostic["preclean_sel_attested"]:
                raise ProductionWorkflowError("Diagnostic bundle did not attest the pre-clean SEL")
            context = orchestrator.transition(
                context,
                identity=identity,
                next_stage=WorkflowStage.PRE_CLEAN_LOGS,
                details=diagnostic,
            )

            preclear_entries = int(inventory["summary"]["sel"]["entry_count"])
            if extended_diagnostics:
                preclear_entries = max(
                    preclear_entries,
                    int((inventory.get("summary", {}).get("sel_after_extended_diagnostics") or {}).get("entry_count") or 0),
                )
            cleanup: dict[str, Any]
            if self.config.sel_cleanup_enabled and preclear_entries > 0:
                expiry = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
                gate = MutationGate(
                    authorized=True,
                    lab_mode=True,
                    approval_id=f"OPERATOR-MANUAL-{run_id}",
                    machine_fingerprint_sha256=str(identity["fingerprint_sha256"]),
                    vendor="ASUS",
                    model=str(identity["model"]),
                    system_serial=str(identity["primary_serial"]),
                    run_id=run_id,
                    component="SEL",
                    allowed_actions=frozenset({"LOG_CLEAR"}),
                    expires_at_utc=expiry,
                )
                hashes = {str(item["sha256"]) for item in bundle_manifest["included"]}
                cleanup_result = execute_log_cleanup(
                    identity=identity,
                    preclean_manifest=preclean,
                    diagnostic_artifact_hashes=hashes,
                    adapter=self.cleanup_adapter_factory(),
                    mutation_gate=gate,
                    run_id=run_id,
                )
                cleanup = {
                    "schema_version": 1,
                    "preclear_entries": preclear_entries,
                    "gate": gate.public_record(),
                    "result": cleanup_result,
                    "other_logs_cleared": False,
                }
                context = orchestrator.transition(
                    context,
                    identity=identity,
                    next_stage=WorkflowStage.LOG_CLEAN,
                    mutation_gate=gate,
                    details={"component": "SEL", **cleanup},
                )
                if cleanup_result.get("status") != "SUCCESS":
                    reasons.append(Reason("LOG_CLEAR_FAILED", ReasonSeverity.FAIL, "SEL clean-state verification failed."))
            else:
                cleanup = {
                    "schema_version": 1,
                    "preclear_entries": preclear_entries,
                    "status": "NOT_REQUIRED" if preclear_entries == 0 else "DISABLED_BY_CONFIG",
                    "other_logs_cleared": False,
                }
            _atomic_json(run_dir / "sel-cleanup.json", cleanup)

            final_sanity = self._final_sanity(identity, cleanup)
            _atomic_json(run_dir / "final-sanity.json", final_sanity)
            context = orchestrator.transition(
                context,
                identity=identity,
                next_stage=WorkflowStage.FINAL_SANITY,
                details=final_sanity,
            )
            context = orchestrator.transition(
                context,
                identity=identity,
                next_stage=WorkflowStage.FINALIZE,
                details={"candidate": "REVIEW" if reasons else "PASS"},
            )
            context = orchestrator.finalize(context, reasons, identity=identity)
        except Exception as exc:
            context = self._finalize_unexpected_failure(
                orchestrator, context, identity, reasons, exc
            )

        final_run = RunRecord.from_dict(context["run"])
        diagnostic_candidates = firmware.get("authenticated_diagnostic_action_candidates") or []
        base_diagnostic_status = (
            "AVAILABLE_BMC"
            if bmc_auth_is_usable(bmc_auth_state) and diagnostic_candidates
            else "UNVERIFIED"
            if bmc_auth_is_usable(bmc_auth_state)
            else "BLOCKED_BY_AUTH"
        )
        diagnostic_status = str(extended_result.get("status") or base_diagnostic_status) if extended_diagnostics else base_diagnostic_status
        firmware_readiness_status = {
            "CURRENT_VERIFIED": "CURRENT",
            "UPDATED_VERIFIED": "UPDATED_VERIFIED",
            "UPDATE_REQUIRED": "UPDATE_REQUIRED",
            "UNVERIFIED": "UNVERIFIED",
        }.get(str(firmware.get("readiness") or "UNVERIFIED"), "UNVERIFIED")
        normalized_result = self._normalized_result(
            context,
            central_runtime,
            bmc_auth_state=bmc_auth_state,
            firmware_status=firmware_readiness_status,
            system_diagnostics_status=diagnostic_status,
        )
        normalized_inventory = dict(inventory.get("normalized") or {})
        component_counts = dict(normalized_inventory.get("component_counts") or {})
        normalized_result.update(
            {
                "collection": str(final_run.collection_status.value),
                "serial_inventory": "PASS" if normalized_inventory.get("system_serial") else "FAIL",
                "psu": inventory.get("summary", {}).get("psu", {}).get("status", "NOT_TESTED"),
                "fans": inventory.get("summary", {}).get("fans", {}).get("status", "NOT_TESTED"),
                "sel": "PASS"
                if inventory.get("summary", {}).get("command_status", {}).get("ipmi_sel") == "PASS"
                else "REVIEW",
                "sel_entries": inventory.get("summary", {}).get("sel", {}).get("entry_count", 0),
                "sel_after_extended_diagnostics": inventory.get("summary", {}).get("sel_after_extended_diagnostics", {}),
                "new_critical_sel": tests.get("monitoring", {}).get("new_critical_sel_samples", 0),
                "kernel_hw_errors": tests.get("monitoring", {}).get("kernel_hw_error_samples", 0),
                "bmc_soft_reset": "NOT_PERFORMED",
                "runner_storage_smart": inventory.get("summary", {}).get("runner_storage", {}).get("smart_status", "UNKNOWN"),
                "extended_diagnostics": extended_result,
            }
        )
        finalization = build_finalization_status(
            sel_cleanup=(cleanup.get("result") or {}).get("status", cleanup.get("status", "NOT_PERFORMED")),
            final_sanity=final_sanity.get("sensor_status", "NOT_TESTED"),
            bmc_soft_reset=BmcSoftResetCapability(),
            evidence_saved=True,
            identity_reverified=bool(final_sanity.get("same_server_fingerprint", False)),
            # A partially populated plan must not masquerade as after-version
            # proof when the workflow stopped before a verified terminal state.
            firmware_reverified=_firmware_plan_reverified(firmware),
        )
        handoff_config = dict(self.config.handoff_policy or {})
        # Local/KCS current evidence is sufficient for a firmware-current
        # Option 1 run.  Optional BMC authentication, unused update transport,
        # runner USB SMART, and Option-2-only diagnostics remain visible but
        # cannot downgrade otherwise verified production hardware.
        handoff_config["allow_optional_review_for_ready"] = True
        if extended_diagnostics:
            # Option 2 requests diagnostics, but a platform that truthfully
            # does not expose the capability remains releasable after the
            # complete production pipeline.  Auth/implementation failures on
            # an advertised capability remain mandatory.
            diagnostic_state = normalized_status(diagnostic_status)
            if diagnostic_state not in {"UNSUPPORTED", "PLATFORM_UNSUPPORTED"}:
                required_for_production = list(
                    handoff_config.get("required_for_production", HandoffPolicy().required_for_production)
                )
                if "system_diagnostics" not in required_for_production:
                    required_for_production.append("system_diagnostics")
                handoff_config["required_for_production"] = required_for_production
        if workflow_mode not in {"FLEET_INTAKE", "DRY_RUN", "SERIAL_COLLECTION", "INVENTORY_ONLY"}:
            required_for_production = list(
                handoff_config.get("required_for_production", HandoffPolicy().required_for_production)
            )
            for capability in ("firmware_update", "reports", "artifact_delivery", "primary_archive"):
                if capability not in required_for_production:
                    required_for_production.append(capability)
            handoff_config["required_for_production"] = required_for_production
        handoff = evaluate_handoff(
            normalized_result,
            workflow_mode=workflow_mode,
            policy=HandoffPolicy.from_mapping(handoff_config),
            bmc_auth_changed=bmc_auth_change_required(bmc_auth_discovery),
            bmc_handoff_status=str(bmc_handoff.get("status") or "NOT_REQUIRED"),
        )
        normalized_result["overall"] = handoff["overall"]
        normalized_result["handoff_status"] = handoff["handoff_status"]
        normalized_result["handoff_policy"] = handoff
        normalized_result["readiness"] = _public_readiness_label(
            workflow_mode=workflow_mode,
            overall=handoff["overall"],
        )
        normalized_result["capability_paths"] = capabilities
        normalized_result["status_summary"] = human_status_summary(
            statuses=normalized_result,
            handoff=handoff,
            workflow_mode=workflow_mode,
            central_sync="PASS" if central_runtime.get("status") in {"ONLINE", "TEST_OVERRIDE"} else "PENDING_UPLOAD",
            artifact_status="LOCAL_COMPLETE" if self.config.reports_enabled else "NOT_REQUESTED",
            reports_status="PASS" if self.config.reports_enabled else "NOT_REQUESTED",
        )
        # Preserve the hardware/workflow disposition before adding the
        # mandatory BMC-auth handoff gate.  A provisional REVIEW caused by an
        # uncompleted handoff must be allowed to become PASS after the
        # factory/default proof succeeds; comparing against the already
        # downgraded value would make that downgrade permanent in reports.
        base_disposition = final_run.final_disposition.value if final_run.final_disposition else "PASS"
        stricter = _stricter_disposition(base_disposition, handoff["overall"])
        final_run.final_disposition = FinalDisposition(stricter)
        final_run.reason_codes = _reason_codes_for_handoff(handoff, workflow_mode=workflow_mode)
        final_run.export_status = OperationStatus.PASS if self.config.reports_enabled and normalized_inventory else OperationStatus.PARTIAL
        context["run"] = final_run.to_dict()
        context["final_decision"] = _final_decision_from_handoff(handoff, workflow_mode=workflow_mode)
        context["finalization"] = finalization
        _atomic_json(run_dir / "run.json", context)

        evidence_candidates = list(inventory.get("evidence_paths") or [])
        evidence_candidates.extend(path for path in evidence_dir.glob("*") if path.is_file())
        evidence_candidates.extend(
            path for path in (run_dir / "bmc-auth-discovery.json", run_dir / "capability-paths-final.json") if path.is_file()
        )
        evidence_manifest = self._evidence_manifest(evidence_candidates)
        _atomic_json(run_dir / "evidence-manifest.json", evidence_manifest)
        report_manifest: dict[str, Any] = {"artifacts": []}
        if self.config.reports_enabled and normalized_inventory:
            report_manifest = generate_human_reports(
                run_dir,
                inventory=normalized_inventory,
                run=final_run.to_dict(),
                result=normalized_result,
                firmware=firmware,
                tests=tests,
                finalization=finalization,
                central={"artifact_status": "LOCAL_COMPLETE", **central_runtime},
                evidence_manifest=evidence_manifest,
                extended_diagnostics=extended_result if extended_diagnostics else None,
            )
        artifact_sync = self._sync_artifacts(run_id, report_manifest, client)
        normalized_result["artifact_status"] = artifact_sync["status"]
        normalized_result["central_artifact_delivery"] = artifact_sync
        normalized_result["windows_archive"] = self._central_archive_summary(artifact_sync)
        normalized_result["reports"] = (
            "PASS"
            if report_manifest_complete(report_manifest, extended_diagnostics=bool(extended_diagnostics))
            else "FAIL"
        )
        normalized_result["artifact_delivery"] = (
            "PASS" if str(artifact_sync.get("status") or "") == "SYNCED" else str(artifact_sync.get("status") or "PENDING_UPLOAD")
        )
        normalized_result["primary_archive"] = (
            "PASS"
            if str(normalized_result["windows_archive"].get("primary_status") or "") == "SYNCED"
            else "PENDING_UPLOAD"
        )
        # Delivery is a mandatory part of a sale-ready result, while the
        # secondary UNC mirror remains a retried, non-blocking copy.  Recompute
        # this provisional policy before the final BMC handoff so a Central or
        # primary-archive outage cannot be reported as READY.
        handoff = evaluate_handoff(
            normalized_result,
            workflow_mode=workflow_mode,
            policy=HandoffPolicy.from_mapping(handoff_config),
            bmc_auth_changed=bmc_auth_change_required(bmc_auth_discovery),
            bmc_handoff_status="PENDING" if bmc_auth_change_required(bmc_auth_discovery) else "NOT_REQUIRED",
        )
        normalized_result["overall"] = handoff["overall"]
        normalized_result["handoff_status"] = handoff["handoff_status"]
        normalized_result["handoff_policy"] = handoff
        # Reports/archives are delivered after the initial policy evaluation;
        # keep the technician-facing readiness synchronized with this final
        # delivery-gated evaluation even when BMC authentication was untouched.
        normalized_result["readiness"] = _public_readiness_label(
            workflow_mode=workflow_mode,
            overall=handoff["overall"],
        )

        # Credential handoff is intentionally the last BMC mutation.  At this
        # point the first report set, Central event/artifact queue and hashes
        # already exist.  If this run provisioned an operational account, use
        # the official local ASMB12 factory/default path now, attest firmware
        # preservation and only then publish the final disposition.
        bmc_auth_changed = bmc_auth_change_required(bmc_auth_discovery)
        if bmc_auth_changed:
            expected_bmc = ""
            for component in firmware.get("components") or []:
                if isinstance(component, Mapping) and str(component.get("component") or "").upper() == "BMC":
                    expected_bmc = str(component.get("after") or component.get("current") or component.get("before") or "")
                    break
            delivery_ready = _bmc_handoff_delivery_ready(
                normalized_result,
                artifact_sync=artifact_sync,
                event_queue_status=queue.status_for_run(run_id),
            )
            pending_record = {
                "schema_version": 1,
                "status": "PENDING",
                "run_id": run_id,
                "run_directory": str(run_dir),
                "server_id": str(identity.get("server_id") or ""),
                "fingerprint_sha256": str(identity.get("fingerprint_sha256") or ""),
                "system_serial": str(identity.get("primary_serial") or ""),
                "expected_bmc_version": expected_bmc,
                "created_at_utc": utc_now(),
                "sensitive_material_exposed": False,
            }
            if not delivery_ready:
                # Never reset a BMC while reports or the mandatory Central /
                # primary archive proof is still queued.  The secret-free
                # pending record is consumed by the periodic retry service
                # after the queues become fully synchronized.
                bmc_handoff = {
                    "schema_version": 1,
                    "status": "PENDING",
                    "required": True,
                    "method": "ASUS_ASMB_KCS_FACTORY_DEFAULT_RAW_32_66",
                    "reset_requested": False,
                    "default_state": "NOT_STARTED",
                    "reason": "HANDOFF_DEFERRED_UNTIL_REPORTS_CENTRAL_AND_PRIMARY_ARCHIVE_SYNC",
                    "sensitive_material_exposed": False,
                }
                _atomic_json(run_dir / "bmc-handoff-pending.json", pending_record | {"reason": bmc_handoff["reason"]})
                normalized_result["bmc_auth_handoff"] = bmc_handoff
            else:
                bmc_handoff = self._perform_bmc_handoff(
                    run_dir=run_dir,
                    normalized_inventory=normalized_inventory,
                    expected_bmc_version=expected_bmc,
                    firmware_plan=firmware,
                )
                normalized_result["bmc_auth_handoff"] = bmc_handoff
            normalized_result["bmc_auth_handoff"] = bmc_handoff
            if delivery_ready:
                _atomic_json(run_dir / "bmc-handoff.json", bmc_handoff)
                finalization["bmc_auth_handoff"] = bmc_handoff
                finalization["factory_reset_performed"] = bool(bmc_handoff.get("reset_requested"))
                # The primary report bundle was finalized, hashed, and delivered
                # before the credential mutation.  Do not overwrite those same
                # filenames after handoff: Central rightly treats a different byte
                # stream under the same run/name as a conflict.  Publish the
                # post-handoff attestation as its own immutable raw artifact.
                evidence_manifest = self._evidence_manifest(
                    list(inventory.get("evidence_paths") or [])
                    + [path for path in (run_dir / "bmc-auth-discovery.json", run_dir / "capability-paths-final.json", run_dir / "bmc-handoff.json") if path.is_file()]
                )
                _atomic_json(run_dir / "evidence-manifest.json", evidence_manifest)
                handoff_artifact = run_dir / "bmc-handoff.json"
                handoff_sync = self._sync_artifacts(
                    run_id,
                    {
                        "artifacts": [
                            {
                                "path": str(handoff_artifact),
                                "type": "RAW_BMC_HANDOFF",
                                "sha256": _sha256(handoff_artifact),
                            }
                        ]
                    },
                    client,
                )
                normalized_result["bmc_handoff_artifact"] = handoff_sync
                if str(bmc_handoff.get("status") or "").upper() != "PASS" or str(handoff_sync.get("status") or "") != "SYNCED":
                    _atomic_json(
                        run_dir / "bmc-handoff-pending.json",
                        pending_record
                        | {
                            "reason": "HANDOFF_OR_HANDOFF_ARTIFACT_NOT_COMPLETE",
                            "handoff_status": str(bmc_handoff.get("status") or "FAIL"),
                            "handoff_artifact_status": str(handoff_sync.get("status") or "PENDING_UPLOAD"),
                        },
                    )
                else:
                    (run_dir / "bmc-handoff-pending.json").unlink(missing_ok=True)
                # The handoff artifact itself is part of the final evidence
                # chain.  A successful BMC reset with an unsynchronized
                # attestation must remain REVIEW/NOT_READY until the retry
                # service delivers the exact bytes.
                effective_handoff_status = str(bmc_handoff.get("status") or "FAIL")
                if effective_handoff_status.upper() == "PASS" and str(handoff_sync.get("status") or "").upper() != "SYNCED":
                    effective_handoff_status = "PENDING"
                handoff = evaluate_handoff(
                    normalized_result,
                    workflow_mode=workflow_mode,
                    policy=HandoffPolicy.from_mapping(handoff_config),
                    bmc_auth_changed=True,
                    bmc_handoff_status=effective_handoff_status,
                )
                normalized_result["overall"] = handoff["overall"]
                normalized_result["handoff_status"] = handoff["handoff_status"]
                normalized_result["handoff_policy"] = handoff
                normalized_result["readiness"] = _public_readiness_label(
                    workflow_mode=workflow_mode,
                    overall=handoff["overall"],
                )
                finalization["overall"] = handoff["overall"]
                finalization["handoff_status"] = handoff["handoff_status"]
                # Publish the post-handoff disposition only after the
                # handoff attestation has itself been hash-verified and the
                # effective handoff evaluation has been recomputed.
                stricter_after_handoff = _stricter_disposition(base_disposition, handoff["overall"])
                final_run.final_disposition = FinalDisposition(stricter_after_handoff)
                final_run.reason_codes = _reason_codes_for_handoff(handoff, workflow_mode=workflow_mode)
                context["run"] = final_run.to_dict()
                context["final_decision"] = _final_decision_from_handoff(handoff, workflow_mode=workflow_mode)
                _atomic_json(run_dir / "run.json", context)
            else:
                finalization["bmc_auth_handoff"] = bmc_handoff
                finalization["factory_reset_performed"] = False
                finalization["overall"] = handoff["overall"]
                finalization["handoff_status"] = handoff["handoff_status"]

        # Re-apply the final disposition after the credential handoff.  A
        # failed or unverifiable handoff must override a previously healthy
        # hardware result and remain NOT_READY/REVIEW_REQUIRED.
        stricter = _stricter_disposition(base_disposition, handoff["overall"])
        final_run.final_disposition = FinalDisposition(stricter)
        final_run.reason_codes = _reason_codes_for_handoff(handoff, workflow_mode=workflow_mode)
        final_run.export_status = (
            OperationStatus.PASS
            if normalized_result.get("reports") == "PASS"
            and normalized_result.get("artifact_delivery") == "PASS"
            and normalized_result.get("primary_archive") == "PASS"
            else OperationStatus.PARTIAL
        )
        context["run"] = final_run.to_dict()
        context["final_decision"] = _final_decision_from_handoff(handoff, workflow_mode=workflow_mode)
        context["finalization"] = finalization
        _atomic_json(run_dir / "run.json", context)

        # The first report set is necessarily generated before Central can
        # acknowledge artifact delivery.  Publish a second, uniquely named
        # final bundle after the delivery-gated disposition is known so the
        # human PDF/HTML carries the same readiness and handoff values as the
        # authoritative JSON result.  The original immutable bundle remains
        # intact for audit history; the FINAL bundle is additive and hash
        # verified through the same Central queue.
        final_report_manifest = {}
        final_report_sync = {"status": "NOT_REQUESTED"}
        if self.config.reports_enabled and normalized_inventory:
            final_report_manifest = generate_human_reports(
                run_dir,
                inventory=normalized_inventory,
                run=final_run.to_dict(),
                result=normalized_result,
                firmware=firmware,
                tests=tests,
                finalization=finalization,
                central={"artifact_status": normalized_result.get("artifact_status", "LOCAL_COMPLETE"), **central_runtime},
                evidence_manifest=evidence_manifest,
                extended_diagnostics=extended_result if extended_diagnostics else None,
                report_variant="FINAL",
            )
            final_report_sync = self._sync_artifacts(run_id, final_report_manifest, client)
            report_manifest = dict(report_manifest)
            report_manifest["artifacts"] = list(report_manifest.get("artifacts") or []) + list(
                final_report_manifest.get("artifacts") or []
            )
        normalized_result["final_report_delivery"] = final_report_sync

        normalized_result["status_summary"] = human_status_summary(
            statuses=normalized_result,
            handoff=handoff,
            workflow_mode=workflow_mode,
            central_sync="SYNCED" if queue.status_for_run(run_id) == "SYNCED" else "PENDING_UPLOAD",
            artifact_status=artifact_sync["status"],
            reports_status=(
                "PASS"
                if self.config.reports_enabled
                and report_manifest_complete(report_manifest, extended_diagnostics=bool(extended_diagnostics))
                else "FAIL"
                if self.config.reports_enabled
                else "NOT_REQUESTED"
            ),
        )

        completion = run_completed_event(final_run, result=normalized_result)
        completion_sync = self._enqueue_and_drain(queue, completion, run_dir / "run.json", client)
        _atomic_json(run_dir / "central-run-completed.json", completion_sync)
        pending_completion = (
            self._archive_and_clear_pending_firmware(
                run_dir=run_dir,
                run_id=run_id,
                completion_status=str(final_run.final_disposition.value),
            )
            if is_resume
            else {"status": "NOT_APPLICABLE", "sensitive_material_exposed": False}
        )
        _atomic_json(run_dir / "firmware-pending-completion.json", pending_completion)
        # The queue may have updated central_sync_status in the authoritative file.
        context = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
        result = {
            "schema_version": 2,
            "run": context["run"],
            "server": context["server"],
            "final_decision": context.get("final_decision", {}),
            "normalized_inventory": normalized_inventory,
            "normalized_result": normalized_result,
            "capability_paths": capabilities,
            "bmc_auth_discovery": bmc_auth_discovery,
            "bmc_handoff": bmc_handoff,
            "finalization": finalization,
            "reports": report_manifest,
            "central": {
                "runtime": central_runtime,
                "queue_status": queue.status_for_run(run_id),
                "completion": completion_sync,
                "artifact_status": artifact_sync["status"],
            },
            "firmware_resume_completion": pending_completion,
            "local_authoritative_record": str(run_dir / "run.json"),
            "run_directory": str(run_dir),
        }
        assert_no_sensitive_fields(result)
        _atomic_json(run_dir / "result-summary.json", result)
        self._notify(
            {
                "event": "WORKFLOW_COMPLETED",
                "workflow_mode": workflow_mode,
                "stage": "COMPLETE",
                "status": stricter,
                "handoff_status": handoff["handoff_status"],
                "run_id": run_id,
            }
        )
        return result

    def _run_extended_diagnostics(
        self,
        run_dir: Path,
        *,
        inventory: Mapping[str, Any],
        bmc_auth_state: str,
        bmc_auth_discovery: Mapping[str, Any] | None = None,
        platform: Mapping[str, Any] | None = None,
        firmware: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute the official ASMB12 WebUI diagnostic API when advertised."""
        normalized = inventory.get("normalized") if isinstance(inventory.get("normalized"), Mapping) else {}
        bmc_ip = str(normalized.get("bmc_ip") or "")
        result: dict[str, Any]
        # ASUS System Diagnostics is an ASMB12 WebUI capability, not a
        # generic BMC-auth requirement.  The ASMB11 platform used by RS500A
        # exposes no corresponding documented endpoint, so do not reset or
        # provision its BMC merely to turn an honest platform limitation into
        # an authentication attempt.  Option 2 still completes the full
        # production pipeline and records the capability explicitly.
        platform_capability = classify_asus_system_diagnostics_platform(
            normalized_inventory=normalized,
            platform=platform,
            firmware_plan=firmware,
        )
        if platform_capability.get("status") == "PLATFORM_UNSUPPORTED":
            result = {
                "schema_version": 1,
                "status": "PLATFORM_UNSUPPORTED",
                "transport": "ASMB12_WEBUI_API",
                "reason": str(platform_capability.get("reason") or "ASMB11_SYSTEM_DIAGNOSTICS_ENDPOINT_NOT_ADVERTISED"),
                "authentication_status": str(bmc_auth_state or BmcAuthState.BMC_AUTH_UNAVAILABLE.value),
                "platform_capability": platform_capability,
            }
            _atomic_json(run_dir / "diagnostics" / "capability-discovery.json", result)
            return result
        if not bmc_auth_is_usable(bmc_auth_state):
            result = {
                "schema_version": 1,
                "status": "BLOCKED_BY_AUTH",
                "transport": "ASMB12_WEBUI_API",
                "reason": "BMC_AUTH_UNAVAILABLE",
                "authentication_status": bmc_auth_state,
                "platform_capability": platform_capability,
            }
            _atomic_json(run_dir / "diagnostics" / "capability-discovery.json", result)
            return result
        try:
            policy = BmcAuthPolicy.from_mapping(self.config.bmc_auth_policy)
            successful_kinds = {
                str(item.get("account", {}).get("kind") or "")
                for item in (bmc_auth_discovery or {}).get("attempts", [])
                if isinstance(item, Mapping) and str(item.get("status") or "").upper() == "PASS"
            }
            candidates = runtime_credential_candidates(
                policy,
                server_id=str(normalized.get("server_id") or ""),
                allow_default_if_discovered="DEFAULT" in successful_kinds,
            )
            result = {
                "schema_version": 1,
                "status": "BLOCKED_BY_AUTH",
                "transport": "ASMB12_WEBUI_API",
                "reason": "NO_APPROVED_CREDENTIAL_ACCEPTED",
                "platform_capability": platform_capability,
            }
            # Keep authentication probing outcomes deliberately aggregate.
            # A field named ``credential_*`` is rejected by the evidence
            # boundary even when it contains only status metadata, and a
            # per-candidate record is unnecessary for operator/reporting
            # purposes.  Never persist usernames, candidate kinds, or any
            # credential-bearing structure in the public diagnostic result.
            authentication_statuses: list[str] = []
            # The approved candidate set is deliberately tiny (the
            # provisioned username plus one deterministic administrator alias)
            # and reuses the same secret. Retry only when the individual
            # capability reports AUTH_BLOCKED; never enumerate passwords.
            for username, password, kind in candidates:
                if not username or not password:
                    continue
                candidate_result = execute_asmb12_diagnostics(
                    bmc_ip,
                    credentials=DiagnosticCredentials(username=username, password=password),
                    output_dir=run_dir / "diagnostics",
                    verify_tls=policy.verify_tls,
                )
                authentication_statuses.append(str(candidate_result.get("status") or "UNKNOWN"))
                result = candidate_result
                if str(candidate_result.get("status") or "").upper() != "AUTH_BLOCKED":
                    break
            result["authentication_attempt_count"] = len(authentication_statuses)
            result["authentication_statuses"] = authentication_statuses
            result.setdefault("platform_capability", platform_capability)
            # The adapter uses AUTH_BLOCKED to describe its HTTP/session
            # outcome.  The production record is a capability result, whose
            # canonical vocabulary is BLOCKED_BY_AUTH; retain the raw outcome
            # as secret-free diagnostic evidence rather than conflating it
            # with an unsupported platform or a missing implementation.
            if str(result.get("status") or "").upper() == "AUTH_BLOCKED":
                result["adapter_status"] = "AUTH_BLOCKED"
                result["status"] = "BLOCKED_BY_AUTH"
        except Exception as exc:
            result = {
                "schema_version": 1,
                "status": "EXECUTION_FAILED",
                "transport": "ASMB12_WEBUI_API",
                "reason": type(exc).__name__,
                "platform_capability": platform_capability,
            }
        # The public record is intentionally limited to status, endpoint and
        # artifact metadata; no credential-bearing object is retained.
        _atomic_json(run_dir / "diagnostics" / "capability-discovery.json", result)
        return result

    def _capture_sel_snapshot(self, output: Path, name: str) -> dict[str, Any]:
        """Capture a second SEL snapshot using the same local KCS path."""
        result = self.executor.run("ipmitool", ("sel", "elist", "-v"), timeout_seconds=180)
        stdout_path = output / f"{name}.txt"
        receipt_path = output / f"{name}.json"
        _atomic_text(stdout_path, str(result.get("stdout") or "") or "<no stdout>\n")
        public = {key: value for key, value in result.items() if key not in {"stdout", "stderr"}}
        public["stdout_path"] = str(stdout_path)
        public["stderr"] = str(result.get("stderr") or "")
        _atomic_json(receipt_path, public)
        return {
            **result,
            "stdout_path": str(stdout_path),
            "receipt_path": str(receipt_path),
        }

    def _collect_inventory(
        self,
        output: Path,
        *,
        identity: Mapping[str, Any] | None = None,
        platform: Mapping[str, Any] | None = None,
        probe: PlatformProbe | None = None,
        run_id: str = "",
        runner_id: str = "",
        bmc_auth_state: str = BmcAuthState.BMC_AUTH_UNAVAILABLE.value,
        intake_mode: bool = False,
    ) -> dict[str, Any]:
        output.mkdir(parents=True, exist_ok=True)
        evidence_paths: list[Path] = []
        evidence_by_name: dict[str, Path] = {}

        def capture(name: str, tool: str, *arguments: str, timeout: int = 60) -> dict[str, Any]:
            result = self.executor.run(tool, tuple(arguments), timeout_seconds=timeout)
            stdout_path = output / f"{name}.txt"
            stderr_path = output / f"{name}.stderr.txt"
            _atomic_text(stdout_path, str(result.get("stdout") or "") or "<no stdout>\n")
            if str(result.get("stderr") or ""):
                _atomic_text(stderr_path, str(result["stderr"]))
                evidence_paths.append(stderr_path)
            public = {key: value for key, value in result.items() if key not in {"stdout", "stderr"}}
            public["stdout_path"] = str(stdout_path)
            public["stderr_path"] = str(stderr_path) if stderr_path.exists() else ""
            receipt = output / f"{name}.json"
            _atomic_json(receipt, public)
            evidence_paths.extend([stdout_path, receipt])
            evidence_by_name[name] = stdout_path
            return result

        lscpu = capture("lscpu", "lscpu", "--json")
        dmidecode = capture("dmidecode", "dmidecode", "--type", "0,1,2,3,16,17")
        lsblk = capture("lsblk", "lsblk", "--json", "--bytes", "-O")
        lspci = capture("lspci", "lspci", "-nnvv")
        ip_address = capture("ip-address", "ip", "-json", "address", "show")
        ip_link = capture("ip-link", "ip", "-json", "link", "show")
        ip_route = capture("ip-route", "ip", "-json", "route", "show", "default")
        ipmi_mc = capture("ipmi-mc-info", "ipmitool", "mc", "info")
        # Local KCS can transiently return ``0xff Unspecified error`` while
        # the BMC is servicing another command (especially immediately after
        # boot, a reset, or a fan-control transition).  Do not let that one
        # failed read erase a usable current BMC version from the authoritative
        # inventory/firmware plan.  Retry the same bounded read once; this is
        # still read-only and never probes credentials or mutates the BMC.
        if (
            str(ipmi_mc.get("status") or "") != "PASS"
            or not parse_ipmi_mc_firmware_version(str(ipmi_mc.get("stdout") or ""))
        ):
            kcs_restore = restore_local_ipmi_kcs(
                self.executor,
                timeout_seconds=30,
                # One immediate restore attempt keeps ordinary inventory
                # fast.  The post-YAFU lifecycle below owns the longer,
                # controller-restart-aware retry window.
                wait_seconds=0,
                poll_seconds=2.0,
            )
            kcs_restore_path = output / "linux-ipmi-kcs-restore.json"
            _atomic_json(kcs_restore_path, kcs_restore)
            evidence_paths.append(kcs_restore_path)
            retry = capture("ipmi-mc-info", "ipmitool", "mc", "info", timeout=60)
            retry["retry_after_initial_failure"] = True
            retry["kcs_restore_status"] = str(kcs_restore.get("status") or "UNAVAILABLE")
            ipmi_mc = retry
        ipmi_fru = capture("ipmi-fru", "ipmitool", "fru", "print")
        ipmi_sdr = capture("ipmi-sdr", "ipmitool", "sdr", "elist")
        ipmi_sensors = capture("ipmi-sensors", "ipmitool", "sensor", "list")
        ipmi_sel_info = capture("ipmi-sel-info", "ipmitool", "sel", "info")
        ipmi_sel_full = capture("ipmi_sel_full", "ipmitool", "sel", "elist", timeout=180)
        ipmi_lan: dict[str, Any] = {}
        for channel in (1, 8):
            ipmi_lan[str(channel)] = capture(f"ipmi-lan-{channel}", "ipmitool", "lan", "print", str(channel))
        nvme = capture("nvme-list", "nvme", "list", "-o", "json")
        findmnt = capture("root-source", "findmnt", "-n", "-o", "SOURCE", "/")
        boot_device = _parent_block_device(str(findmnt.get("stdout") or ""))
        smart: dict[str, Any]
        if intake_mode:
            smart = {"tool": "smartctl", "status": "NOT_PERFORMED_FLEET_INTAKE", "stdout": "", "stderr": ""}
        elif boot_device:
            smart = capture("smartctl-boot", "smartctl", "-x", boot_device, timeout=120)
        else:
            smart = capture("smartctl-scan", "smartctl", "--scan-open", timeout=120)

        smart_devices: dict[str, dict[str, Any]] = {}
        if not intake_mode:
            for device in _block_device_paths(str(lsblk.get("stdout") or "")):
                if device == boot_device:
                    continue
                smart_devices[device] = capture(
                    f"smartctl-{_safe_evidence_name(device)}", "smartctl", "-x", device, timeout=120
                )

        interfaces = _safe_interface_names(ip_link.get("stdout"))
        ethtool_results: dict[str, Any] = {}
        if not intake_mode:
            for interface in interfaces:
                ethtool_results[interface] = capture(f"ethtool-{interface}", "ethtool", "-i", interface)
        else:
            capture("kernel-errors", "dmesg", "--level=err,warn", timeout=30)

        network_sysfs = _read_network_sysfs()
        network_sysfs_path = output / "network-sysfs.json"
        _atomic_json(network_sysfs_path, network_sysfs)
        evidence_paths.append(network_sysfs_path)

        sensor_rows = _parse_ipmi_sensors(str(ipmi_sensors.get("stdout") or ""))
        critical = [row for row in sensor_rows if row["status"] not in {"ok", "ns", "na", "unavailable"}]
        fan_rows = [row for row in sensor_rows if re.search(r"fan", row["sensor"], re.IGNORECASE)]
        psu_rows = [row for row in sensor_rows if re.search(r"psu|power supply", row["sensor"], re.IGNORECASE)]
        sel_entries = _sel_entry_count(str(ipmi_sel_info.get("stdout") or ""))
        smart_status = "PASS" if smart.get("status") == "PASS" else "UNKNOWN_USB_BRIDGE"
        nvme_devices = _nvme_device_count(str(nvme.get("stdout") or ""))
        runner_storage = {
            "device": boot_device,
            "smart_status": "PASS" if smart_status == "PASS" else "UNAVAILABLE",
            "raw_status": smart_status,
            "transport": _block_device_transport(str(lsblk.get("stdout") or ""), boot_device),
            "role": "RUNNER_STORAGE",
        }
        customer_storage_statuses = {
            device: _smart_health_status(result)
            for device, result in smart_devices.items()
        }
        customer_storage_status = (
            "FAIL" if "FAIL" in customer_storage_statuses.values()
            else "PASS" if customer_storage_statuses or nvme_devices
            else "REVIEW"
        )
        summary = {
            "schema_version": 1,
            "boot_id": read_linux_boot_id(),
            "sources": {
                "cpu": "LSCPU_CURRENT_BOOT",
                "memory": "DMIDECODE_CURRENT_BOOT",
                "storage": "LSBLK_CURRENT_BOOT",
                "network": "LINUX_IP_CURRENT_BOOT",
                "pcie": "LSPCI_CURRENT_BOOT",
                "firmware": "DMI_BIOS_AND_IPMI_MC_LOCAL_KCS",
                "sensors": "IPMI_SDR_LOCAL_KCS_LIVE",
                "sel": "IPMI_SEL_LOCAL_KCS",
            },
            "command_status": {
                "lscpu": lscpu["status"],
                "dmidecode": dmidecode["status"],
                "lsblk": lsblk["status"],
                "lspci": lspci["status"],
                "ip_address": ip_address["status"],
                "ip_link": ip_link["status"],
                "ipmi_mc": ipmi_mc["status"],
                "ipmi_fru": ipmi_fru["status"],
                "ipmi_sdr": ipmi_sdr["status"],
                "ipmi_sensors": ipmi_sensors["status"],
                "ipmi_sel": ipmi_sel_full["status"],
            },
            "storage": {
                "boot_device": boot_device,
                "boot_media_stressed": False,
                "destructive_test": False,
                "smart_status": smart_status,
                "nvme_devices": nvme_devices,
                "status": customer_storage_status,
                "role": "SERVER_CUSTOMER_STORAGE",
                "customer_devices": customer_storage_statuses,
            },
            "runner_storage": runner_storage,
            "network": {
                "interfaces": interfaces,
                "status": ip_address["status"],
                "serial_discovery_methods": ["PCIe VPD (Linux sysfs)", "Linux PCI enumeration", "ethtool"],
            },
            "pcie": {"status": lspci["status"]},
            "sensors": {
                "status": "FAIL" if critical else "PASS",
                "row_count": len(sensor_rows),
                "critical_count": len(critical),
                "critical_rows": critical,
                "freshness": "LIVE_SENSOR",
            },
            "fans": {
                "status": "FAIL" if any(row in critical for row in fan_rows) else "PASS" if fan_rows else "NOT_EXPOSED",
                "sensor_count": len(fan_rows),
            },
            "psu": {
                "status": "FAIL" if any(row in critical for row in psu_rows) else "PASS" if psu_rows else "NOT_EXPOSED",
                "sensor_count": len(psu_rows),
            },
            "sel": {
                "entry_count": sel_entries,
                "full_log_sha256": _sha256(evidence_by_name["ipmi_sel_full"]),
                "freshness": "LIVE_SENSOR",
            },
        }
        raw = {
            "lscpu": lscpu,
            "dmidecode": dmidecode,
            "lsblk": lsblk,
            "lspci": lspci,
            "ip_address": ip_address,
            "ip_link": ip_link,
            "ip_route": ip_route,
            "ipmi_mc": ipmi_mc,
            "ipmi_fru": ipmi_fru,
            "ipmi_sdr": ipmi_sdr,
            "ipmi_sensors": ipmi_sensors,
            "ipmi_sel_info": ipmi_sel_info,
            "ipmi_sel_full": ipmi_sel_full,
            "ipmi_lan": ipmi_lan,
            "nvme": nvme,
            "smart": smart,
            "smart_devices": smart_devices,
            "ethtool": ethtool_results,
        }
        normalized: dict[str, Any] = {}
        if identity is not None and platform is not None and probe is not None:
            probe_values = probe.to_dict()
            try:
                probe_values["bios_version"] = (self.dmi_root / "bios_version").read_text(
                    encoding="utf-8", errors="replace"
                ).strip()
            except OSError:
                probe_values["bios_version"] = ""
            normalized = build_normalized_inventory(
                identity=identity,
                platform=platform,
                probe=probe_values,
                raw=raw,
                run_id=run_id,
                runner_id=runner_id,
                boot_id=read_linux_boot_id(),
                bmc_auth_state=bmc_auth_state,
                network_sysfs=network_sysfs,
            ).to_dict()
            summary["normalized_component_counts"] = normalized["component_counts"]
            summary["primary_host_mac"] = normalized.get("primary_host_mac", "")
            summary["physical_nic_count"] = normalized["component_counts"].get("NIC/OCP", 0)
            nic_rows = physical_nic_rows(normalized)
            summary["network"]["adapter_serials"] = sorted(
                {row["adapter_serial"] for row in nic_rows if row.get("adapter_serial")}
            )
            summary["network"]["adapter_serials_exposed"] = sum(
                1 for row in nic_rows if row.get("adapter_serial") not in {"", "NOT_EXPOSED"}
            )
            summary["network"]["identity_anchors"] = normalized.get("nic_identity_anchors", [])
            summary["network"]["identity_fallback"] = normalized.get("identity_fallback", {})
            _atomic_json(output / "normalized-inventory.json", normalized)
            evidence_paths.append(output / "normalized-inventory.json")
        return {
            "summary": summary,
            "evidence_paths": list(dict.fromkeys(evidence_paths)),
            "evidence_by_name": evidence_by_name,
            "raw": raw,
            "normalized": normalized,
        }

    def _firmware_plan(
        self,
        inventory: Mapping[str, Any],
        bmc_discovery: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        bios_path = self.dmi_root / "bios_version"
        try:
            bios = bios_path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            bios = ""
        raw_inventory = inventory.get("raw") if isinstance(inventory.get("raw"), Mapping) else {}
        ipmi_mc = raw_inventory.get("ipmi_mc") if isinstance(raw_inventory, Mapping) else {}
        bmc = parse_ipmi_mc_firmware_version(
            str(ipmi_mc.get("stdout") or "") if isinstance(ipmi_mc, Mapping) else ""
        )
        bmc_source = "IPMI_MC_LOCAL_KCS"
        bmc_freshness = "LIVE_SENSOR"
        discovery = dict(bmc_discovery or {})
        auth_state = str(discovery.get("state") or BmcAuthState.BMC_AUTH_UNAVAILABLE.value)
        auth_usable = bmc_auth_is_usable(auth_state)
        authenticated = discovery.get("authenticated_discovery")
        normalized = authenticated.get("normalized") if isinstance(authenticated, Mapping) else {}
        normalized = normalized if isinstance(normalized, Mapping) else {}
        # Credential selection is server-bound. Resolve the current/local
        # normalized inventory before the optional authenticated ASMB WebUI
        # capability probe so this path cannot reference an uninitialized
        # value or omit SERVER_ID.
        normalized_inventory = inventory.get("normalized") if isinstance(inventory.get("normalized"), Mapping) else {}
        # ASMB11 exposes only major/minor through IPMI (for example ``1.02``)
        # while Redfish exposes the active dual-image revision as
        # ``1.02.37``.  Fuse the two only when their shared numeric prefix
        # agrees; a conflicting/stale Redfish value must never replace local
        # evidence or authorize a flash.  With one matching non-zero BMC
        # image this is a stronger current-boot proof than the truncated IPMI
        # field and prevents a current BMC from being re-flashed.
        redfish_bmc_candidates: list[str] = []
        for item in normalized.get("firmware_inventory") or []:
            if not isinstance(item, Mapping):
                continue
            identity = f"{item.get('Id') or ''} {item.get('Name') or ''}".upper()
            value = str(item.get("Version") or item.get("version") or "").strip()
            if "BMC" not in identity or not value or value in {"0", "0.0", "0.0.0"}:
                continue
            if value not in redfish_bmc_candidates:
                redfish_bmc_candidates.append(value)
        ipmi_numbers = tuple(int(token) for token in re.findall(r"\d+", str(bmc or "")))
        matching_redfish = [
            value
            for value in redfish_bmc_candidates
            if ipmi_numbers
            and tuple(int(token) for token in re.findall(r"\d+", value))[: len(ipmi_numbers)] == ipmi_numbers
        ]
        if len(matching_redfish) == 1:
            bmc = matching_redfish[0]
            bmc_source = "REDFISH_FIRMWARE_INVENTORY_PLUS_IPMI_MC_LOCAL_KCS"
            bmc_freshness = "BMC_CURRENT_CONFIRMED"
        # Probe the official ASMB web-HPM capability independently from
        # Redfish UpdateService.  A missing web path never blocks local
        # inventory; it simply leaves the Redfish/local candidates intact.
        web_hpm: dict[str, Any] = {}
        if auth_usable:
            bmc_host = str((inventory.get("normalized") if isinstance(inventory.get("normalized"), Mapping) else {}).get("bmc_ip") or "")
            policy = BmcAuthPolicy.from_mapping(self.config.bmc_auth_policy)
            successful_kinds = {
                str(item.get("account", {}).get("kind") or "")
                for item in discovery.get("attempts", [])
                if isinstance(item, Mapping) and str(item.get("status") or "").upper() == "PASS"
            }
            selected = next(
                (
                    item
                    for item in runtime_credential_candidates(
                        policy,
                        server_id=str(normalized_inventory.get("server_id") or ""),
                        allow_default_if_discovered="DEFAULT" in successful_kinds,
                    )
                    if not successful_kinds or item[2] in successful_kinds
                ),
                None,
            )
            if bmc_host and selected is not None:
                web_hpm = discover_asus_web_hpm_capability(
                    bmc_host,
                    selected[0],
                    selected[1],
                    verify_tls=policy.verify_tls,
                )
        update_mechanisms = [
            item for item in (normalized.get("update_mechanisms") or []) if isinstance(item, Mapping)
        ]
        diagnostic_candidates = [
            item for item in (normalized.get("diagnostic_action_candidates") or []) if isinstance(item, Mapping)
        ]
        endpoint_catalog = authenticated.get("endpoint_catalog") if isinstance(authenticated, Mapping) else []
        endpoint_catalog = endpoint_catalog if isinstance(endpoint_catalog, list) else []
        task_service = next(
            (
                item
                for item in endpoint_catalog
                if isinstance(item, Mapping) and str(item.get("label") or "") == "task_service"
            ),
            {},
        )
        advertised_update = bool(auth_usable and update_mechanisms)
        bmc_update_status = "UNVERIFIED" if advertised_update else "BLOCKED_BY_AUTH"
        task_status = "UNVERIFIED" if auth_usable and int(task_service.get("status") or 0) == 200 else "BLOCKED_BY_AUTH"
        bmc_reason = (
            "Authenticated Redfish UpdateService advertises update transports; exact ASUS package applicability, mutation gate, and post-task verification remain unverified."
            if advertised_update
            else "Authenticated BMC capability is unavailable and the transport is not physically verified."
        )
        components = normalized_inventory.get("components") if isinstance(normalized_inventory, Mapping) else []
        if not bmc:
            # ``firmware-status`` deliberately uses the safe inventory result,
            # which has no raw command blob.  Recover the locally collected
            # BMC version from the normalized component rather than declaring
            # the prior physical proof stale.
            for item in components if isinstance(components, list) else []:
                if not isinstance(item, Mapping):
                    continue
                category = str(item.get("category") or "").upper()
                slot = str(item.get("slot") or item.get("location") or "").upper()
                if category in {"BMC", "MANAGEMENT_MODULE", "FIRMWARE"} and (category == "BMC" or "BMC" in slot):
                    candidate = str(item.get("firmware") or item.get("version") or "").strip()
                    if candidate:
                        bmc = candidate
                        break
        motherboard = next(
            (item for item in components if isinstance(item, Mapping) and str(item.get("category") or "") == "MOTHERBOARD"),
            {},
        )
        management = next(
            (item for item in components if isinstance(item, Mapping) and str(item.get("category") or "") == "MANAGEMENT_MODULE"),
            {},
        )
        generic_fingerprint = AsusPlatformFingerprint.from_sources(
            local={
                "manufacturer": normalized_inventory.get("vendor"),
                "product_name": normalized_inventory.get("model"),
                "system_serial": normalized_inventory.get("system_serial"),
                "board_name": motherboard.get("model"),
                "board_serial": motherboard.get("serial"),
            },
            bmc={"model": management.get("model")},
            redfish=normalized,
        )
        local_discovery = _discover_local_asus_firmware_tools(
            self.config.local_firmware_tools_path,
            fingerprint=generic_fingerprint,
            kcs_evidence={
                # This is collected locally through the host KCS device as
                # part of every inventory.  It is deliberately only a
                # candidate-enablement signal: the ASMB11 adapter repeats a
                # package-owned, read-only Yafuflash ``-kcs -info`` probe
                # immediately before any mutation.
                "available": bool(
                    isinstance(ipmi_mc, Mapping)
                    and str(ipmi_mc.get("stdout") or "").strip()
                    and str(ipmi_mc.get("status") or "").upper() in {"", "PASS"}
                ),
                "status": str(ipmi_mc.get("status") or "") if isinstance(ipmi_mc, Mapping) else "",
                "source": "IPMI_MC_LOCAL_KCS",
                "firmware_revision": bmc,
            },
        )
        catalog_documents = self._load_firmware_catalog_documents(discovery)
        redfish_for_plan = dict(authenticated) if isinstance(authenticated, Mapping) else {}
        redfish_for_plan.setdefault("authentication", {"available": auth_usable})
        redfish_for_plan["web_hpm"] = web_hpm
        catalog_sources = (
            (AsusOfficialCatalogSource(timeout_seconds=self.config.firmware_discovery_timeout_seconds),)
            if self.config.firmware_live_discovery_enabled else ()
        )
        firmware_engine = AsusFirmwareEngine(catalog_sources=catalog_sources)
        generic_engine_plan = firmware_engine.plan(
            fingerprint=generic_fingerprint,
            current_versions={"BIOS": bios, "BMC": bmc},
            redfish_discovery=redfish_for_plan,
            local_tools=local_discovery,
            catalog_documents=catalog_documents,
        ).to_dict()
        # ASUS ASMB11/12 local KCS can expose only a two-part BMC revision
        # after a factory-default handoff (for example ``1.02``).  A factory
        # settings reset does not downgrade firmware, but without authenticated
        # Redfish the live KCS prefix alone must never be guessed to mean a
        # particular full-image build.  Admit a full version only when a
        # same-server, exact-target pre-handoff plan and successful handoff
        # receipt bind the current KCS prefix to that exact target.  Historical
        # evidence from another serial, board, fingerprint or target is always
        # rejected.
        initial_components = generic_engine_plan.get("components") if isinstance(generic_engine_plan, Mapping) else {}
        initial_bmc_plan = initial_components.get("BMC") if isinstance(initial_components, Mapping) else {}
        # The live plan is the authoritative exact-package context for a
        # shortened local KCS revision.  A same-server handoff receipt may
        # bind only to this exact, currently selected ASUS package alias; it
        # can never turn a bare version prefix into a generic update waiver.
        initial_bmc_package_alias = _exact_bmc_package_alias(
            initial_bmc_plan if isinstance(initial_bmc_plan, Mapping) else {}
        )
        continuity = self._load_same_server_bmc_handoff_continuity(
            normalized_inventory=normalized_inventory,
            live_kcs_version=bmc,
            exact_target=str(initial_bmc_plan.get("target_version") or "") if isinstance(initial_bmc_plan, Mapping) else "",
            exact_package_alias=initial_bmc_package_alias,
        )
        if bool(continuity.get("verified")):
            bmc = str(continuity.get("exact_version") or bmc)
            bmc_source = "IPMI_MC_LOCAL_KCS_PLUS_SAME_SERVER_FACTORY_HANDOFF_CONTINUITY"
            bmc_freshness = "CURRENT_BOOT_CONTINUITY_VERIFIED"
            generic_engine_plan = firmware_engine.plan(
                fingerprint=generic_fingerprint,
                current_versions={"BIOS": bios, "BMC": bmc},
                redfish_discovery=redfish_for_plan,
                local_tools=local_discovery,
                catalog_documents=catalog_documents,
            ).to_dict()
        current_proof = self._load_current_firmware_proof(
            normalized_inventory=normalized_inventory,
            bios=bios,
            bmc=bmc,
        )
        component_plans = generic_engine_plan.get("components") if isinstance(generic_engine_plan, Mapping) else {}
        bios_plan = component_plans.get("BIOS") if isinstance(component_plans, Mapping) else {}
        bmc_plan = component_plans.get("BMC") if isinstance(component_plans, Mapping) else {}
        target_available = any(
            isinstance(item, Mapping) and str(item.get("target_version") or "")
            and str(item.get("status") or "") not in {"CURRENT", "NO_EXACT_OFFICIAL_PACKAGE"}
            for item in (bios_plan, bmc_plan)
        )
        # A prior physical proof is valuable continuity evidence, but it is
        # intentionally server-bound.  If that proof belongs to another
        # serial, do not reuse it; independently verify each live component
        # against the exact, officially-proven package metadata selected for
        # this platform.  This allows a newly booted/current server to proceed
        # without a stale proof file while preserving the mismatch as audit
        # evidence.
        exact_current = _exact_current_versions_verified(
            component_plans,
            current_versions={"BIOS": bios, "BMC": bmc},
        )
        # A historical lifecycle proof is continuity evidence only.  It must
        # never suppress a newer exact official target selected for the live
        # platform, even when its serial and previous versions match.  Current
        # readiness is granted solely by current DMI/KCS values matching the
        # exact official metadata resolved in this invocation.
        proof_was_verified = bool(current_proof.get("verified"))
        if exact_current:
            prior_reason = str(current_proof.get("reason") or "PROOF_NOT_FOUND")
            current_proof = {
                **dict(current_proof),
                "verified": True,
                "reason": "CURRENT_VERSIONS_MATCH_EXACT_OFFICIAL_TARGETS",
                "verification_source": "LIVE_DMI_SMBIOS_KCS_PLUS_EXACT_ASUS_PACKAGE_METADATA",
                "prior_proof_check": prior_reason,
                "component_evidence": {
                    "BIOS": {"value": bios, "source": "DMI_SMBIOS", "freshness": "CURRENT_BOOT"},
                    "BMC": {"value": bmc, "source": bmc_source, "freshness": bmc_freshness},
                },
            }
            readiness = "CURRENT_VERIFIED"
        elif target_available:
            readiness = "UPDATE_REQUIRED"
        else:
            readiness = "UNVERIFIED"
        bios_engine_status = str(bios_plan.get("status") or "") if isinstance(bios_plan, Mapping) else ""
        bmc_engine_status = str(bmc_plan.get("status") or "") if isinstance(bmc_plan, Mapping) else ""
        bios_target = str(bios_plan.get("target_version") or "") if isinstance(bios_plan, Mapping) else ""
        bmc_target = str(bmc_plan.get("target_version") or "") if isinstance(bmc_plan, Mapping) else ""
        bios_component_status = (
            "CURRENT" if bios_engine_status == "CURRENT" else
            "UPDATE_REQUIRED" if bios_target and bios_engine_status != "CURRENT" else "UNVERIFIED"
        )
        bmc_component_status = (
            "CURRENT" if bmc_engine_status == "CURRENT" else
            "UPDATE_REQUIRED" if bmc_target and bmc_engine_status != "CURRENT" else bmc_update_status
        )
        current_reason = (
            "Current live version matches the exact official ASUS target metadata; no mutation is required for this run."
            + (" A server-bound historical lifecycle proof also agrees." if proof_was_verified else "")
        )
        return {
            "schema_version": 2,
            "policy": "LATEST_AVAILABLE_BUT_NO_MUTATION_WITHOUT_VERIFIED_CAPABILITY",
            "local_transport_discovery": local_discovery,
            "generic_asus_firmware_engine": generic_engine_plan,
            "readiness": readiness,
            "current_verification": current_proof,
            "bmc_factory_handoff_continuity": continuity,
            "bmc_auth_state": auth_state,
            "authenticated_update_mechanisms": update_mechanisms,
            "authenticated_asus_web_hpm": web_hpm,
            "authenticated_diagnostic_action_candidates": diagnostic_candidates,
            "authenticated_task_service": {
                "status": task_service.get("status"),
                "endpoint": task_service.get("endpoint"),
            },
            "bios": {"value": bios, "source": "DMI_SMBIOS", "freshness": "CURRENT_BOOT", "confidence": "HIGH" if bios else "UNKNOWN"},
            "bmc": {"value": bmc, "source": bmc_source, "freshness": bmc_freshness, "confidence": "HIGH" if bmc else "UNKNOWN"},
            "components": [
                {
                    "component": "BIOS",
                    "before": bios,
                    "target": bios_target,
                    "after": "",
                    "status": bios_component_status,
                    "reason": current_reason
                    if readiness == "CURRENT_VERIFIED"
                    else "Exact official target is known and requires a verified update lifecycle before readiness."
                    if bios_target else "No exact official target was resolved; current firmware proof is absent.",
                },
                {
                    "component": "BMC",
                    "before": bmc,
                    "target": bmc_target,
                    "after": "",
                    "status": bmc_component_status,
                    "reason": current_reason
                    if readiness == "CURRENT_VERIFIED"
                    else "Exact official target is known and requires authenticated/supported update lifecycle verification."
                    if bmc_target else bmc_reason,
                },
            ],
            "workflow": {
                "DISCOVER": "PASS",
                "CURRENT": "PASS" if readiness == "CURRENT_VERIFIED" else "UNVERIFIED",
                "APPLICABILITY": "UNVERIFIED",
                "TARGET_LOCK": "NOT_STARTED",
                "PACKAGE_HASH": "NOT_STARTED",
                "APPLY": "UNVERIFIED",
                "TASK_TRACK": task_status,
                "REBOOT": "NOT_STARTED",
                "SAME_SERVER_RESUME": "NOT_STARTED",
                "AFTER_VERSION_VERIFY": "NOT_STARTED",
            },
            "allowed_component_states": [
                "CURRENT",
                "UPDATE_AVAILABLE",
                "BLOCKED_BY_AUTH",
                "UNVERIFIED",
                "NOT_SUPPORTED",
                "NOT_PRESENT",
                "FAILED",
                "UPDATED_VERIFIED",
            ],
            "bios_update": bios_component_status,
            "bmc_update": bmc_component_status,
            "task_completion": task_status,
            "packages_downloaded": False,
            "target_locked": False,
            "mutation_started": False,
            "update_pass_requires_post_version_verification": True,
            "overall_run_blocked": False,
        }

    def _load_firmware_catalog_documents(
        self, discovery: Mapping[str, Any] | None = None
    ) -> tuple[Mapping[str, Any], ...]:
        """Load only explicit catalog snapshots and discovery documents.

        A package cache or similarly named model is never inferred as an
        applicable target.  The catalog may be a single document, a list of
        documents, or an object containing ``documents``/``entries``.
        """
        documents: list[Mapping[str, Any]] = []
        discovered = (discovery or {}).get("official_catalog_documents") if isinstance(discovery, Mapping) else None
        if isinstance(discovered, list):
            documents.extend(item for item in discovered if isinstance(item, Mapping))
        path = self.config.firmware_catalog_path
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            payload = None
        if isinstance(payload, list):
            documents.extend(item for item in payload if isinstance(item, Mapping))
        elif isinstance(payload, Mapping):
            nested = payload.get("documents")
            if isinstance(nested, list):
                documents.extend(item for item in nested if isinstance(item, Mapping))
            elif isinstance(payload.get("entries"), list):
                documents.append(payload)
            elif payload.get("component"):
                documents.append({"source": "CONFIGURED_CATALOG_SNAPSHOT", "entries": [payload]})
        # A verified content-addressed cache is a valid resolver input only
        # when its metadata itself carries official provenance and explicit
        # compatibility selectors.  The binary alone is never trusted.  This
        # makes the physically proven ASUS packages available to a different
        # boot without hard-coding RS700 or any other model.
        metadata_root = self.config.firmware_cache_root / "metadata"
        try:
            metadata_paths = sorted(metadata_root.glob("*.json"))
        except OSError:
            metadata_paths = []
        for metadata_path in metadata_paths:
            try:
                record = json.loads(metadata_path.read_text(encoding="utf-8"))
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            if not isinstance(record, Mapping) or str(record.get("vendor") or "").upper() != "ASUS":
                continue
            if str(record.get("component") or "").upper() not in {"BIOS", "BMC"}:
                continue
            if not record.get("official_source_verified") or not record.get("applicability_evidence"):
                continue
            if str(record.get("validation_status") or "") not in {
                "CHECKSUM_VERIFIED", "CHECKSUM_VERIFIED_WITHOUT_VENDOR_HASH", "PROVENANCE_VERIFIED", "OFFICIAL_SOURCE_VERIFIED"
            }:
                continue
            documents.append({"source": "VERIFIED_CACHED_ASUS_METADATA", "entries": [dict(record)]})
        return tuple(documents)

    def _load_current_firmware_proof(
        self,
        *,
        normalized_inventory: Mapping[str, Any],
        bios: str,
        bmc: str,
    ) -> dict[str, Any]:
        """Validate a prior physical firmware lifecycle proof for this server."""
        path = self.config.firmware_current_proof
        result: dict[str, Any] = {"verified": False, "path": str(path), "reason": "PROOF_NOT_FOUND"}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            return result
        if not isinstance(payload, Mapping):
            result["reason"] = "PROOF_NOT_OBJECT"
            return result
        proof_serial = str(payload.get("system_serial") or payload.get("server_id") or "")
        proof_model = str(payload.get("model") or (payload.get("platform") or {}).get("model") or "")
        if proof_serial and proof_serial != str(normalized_inventory.get("system_serial") or ""):
            result["reason"] = "SERIAL_MISMATCH"
            return result
        if proof_model and proof_model != str(normalized_inventory.get("model") or ""):
            result["reason"] = "MODEL_MISMATCH"
            return result
        components = payload.get("components")
        observed: dict[str, str] = {}
        if isinstance(components, list):
            for item in components:
                if not isinstance(item, Mapping) or not bool(item.get("verified", True)):
                    continue
                component = str(item.get("component") or "").upper()
                after = item.get("after") if isinstance(item.get("after"), Mapping) else item
                value = str(after.get("value") or after.get("version") or "") if isinstance(after, Mapping) else ""
                if component and value:
                    observed[component] = value
        if not observed:
            current = payload.get("current_versions")
            if isinstance(current, Mapping):
                observed = {str(key).upper(): str(value) for key, value in current.items() if value}
        if not _firmware_versions_equal(observed.get("BIOS", ""), bios) or not _firmware_versions_equal(observed.get("BMC", ""), bmc):
            result["reason"] = "VERSION_MISMATCH"
            result["observed"] = observed
            result["live"] = {"BIOS": bios, "BMC": bmc}
            return result
        result.update({"verified": True, "reason": "PHYSICAL_LIFECYCLE_VERIFIED", "observed": observed, "live": {"BIOS": bios, "BMC": bmc}})
        return result

    def _load_same_server_bmc_handoff_continuity(
        self,
        *,
        normalized_inventory: Mapping[str, Any],
        live_kcs_version: str,
        exact_target: str,
        exact_package_alias: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Bind a shortened live KCS revision to an exact post-handoff image.

        A BMC factory/default reset intentionally discards web credentials and
        may leave local KCS as the only current evidence.  KCS often reports
        only major/minor, which is insufficient on its own to decide that a
        three-part official image is current.  This read-only continuity proof
        is deliberately much narrower than a historical firmware proof: it
        accepts only a prior *same physical server* run that both selected the
        identical exact ASUS target and completed a factory/default handoff
        whose local KCS suffix matches the live local KCS suffix.

        The receipt is never used across model, board, system serial, server
        ID, or target changes.  It contains no credential material.
        """
        result: dict[str, Any] = {
            "schema_version": 1,
            "verified": False,
            "reason": "NO_SAME_SERVER_FACTORY_HANDOFF_CONTINUITY",
            "live_kcs_version": str(live_kcs_version or ""),
            "target_version": str(exact_target or ""),
            "sensitive_material_exposed": False,
        }
        current = {
            "server_id": str(normalized_inventory.get("server_id") or "").strip(),
            "system_serial": str(normalized_inventory.get("system_serial") or "").strip(),
            "model": str(normalized_inventory.get("model") or "").strip(),
            # Normalized inventory intentionally stores physical board
            # identity on the MOTHERBOARD component.  Older callers supplied
            # a top-level board_serial, but current production inventory does
            # not.  Read both representations so a valid same-server receipt
            # cannot be discarded merely because the normalized schema is
            # component-oriented.
            "board_serial": _normalized_inventory_board_serial(normalized_inventory),
        }
        package_alias = _normalize_bmc_package_alias(exact_package_alias)
        if (
            not all(current[key] for key in ("server_id", "system_serial", "model"))
            or not live_kcs_version
            or not exact_target
            or not package_alias
        ):
            result["reason"] = "CURRENT_IDENTITY_OR_TARGET_INCOMPLETE"
            return result
        result["exact_package_alias"] = package_alias
        runs_root = self.config.primary_root / "runs"
        try:
            candidates = sorted(runs_root.glob("RUN-*/bmc-handoff.json"), key=lambda path: path.parent.name, reverse=True)
        except OSError:
            candidates = []
        for handoff_path in candidates:
            handoff = _load_json_mapping(handoff_path)
            if str(handoff.get("status") or "").upper() != "PASS":
                continue
            if not str(handoff.get("default_state") or "").upper().startswith("FACTORY_DEFAULT"):
                continue
            if not _local_bmc_revision_matches(
                str(handoff.get("firmware_after") or ""),
                live_kcs_version,
            ):
                continue
            run_dir = handoff_path.parent
            context = _load_json_mapping(run_dir / "run.json")
            server = context.get("server") if isinstance(context.get("server"), Mapping) else {}
            run = context.get("run") if isinstance(context.get("run"), Mapping) else {}
            recorded_server_id = str(server.get("server_id") or run.get("server_id") or "").strip()
            if recorded_server_id != current["server_id"]:
                continue
            prior_inventory = _load_json_mapping(run_dir / "normalized-inventory.json")
            prior = {
                "system_serial": str(prior_inventory.get("system_serial") or server.get("system_serial") or run.get("system_serial") or "").strip(),
                "model": str(prior_inventory.get("model") or server.get("model") or run.get("model") or "").strip(),
                "board_serial": _normalized_inventory_board_serial(prior_inventory)
                or str(server.get("board_serial") or run.get("board_serial") or "").strip(),
            }
            if any(prior[key] != current[key] for key in ("system_serial", "model")):
                continue
            # Board serial is a mandatory discriminator when it is exposed
            # by both current and prior local evidence.  If either side is
            # genuinely not exposed, only an exact cryptographic SERVER_ID /
            # fingerprint binding may replace it; a serial/model match alone
            # is never enough to accept historical firmware state.
            board_binding = "BOARD_SERIAL_MATCH"
            if current["board_serial"] and prior["board_serial"]:
                if current["board_serial"] != prior["board_serial"]:
                    continue
            else:
                current_fingerprint = _server_id_fingerprint(current["server_id"])
                prior_fingerprint = _context_server_fingerprint(server, run)
                if not current_fingerprint or current_fingerprint != prior_fingerprint:
                    continue
                board_binding = "SERVER_FINGERPRINT_MATCH_BOARD_SERIAL_NOT_EXPOSED"
            prior_plan = _load_json_mapping(run_dir / "firmware-plan.json")
            prior_bmc = _generic_firmware_component_from_plan(prior_plan, "BMC")
            if not prior_bmc:
                # Legacy releases recorded only the public component summary.
                # It is allowed solely as a same-server, exact-target
                # continuity receipt; new packages retain a full package
                # alias below.
                prior_bmc = _firmware_component_from_plan(prior_plan, "BMC")
            prior_target = str(prior_bmc.get("target") or prior_bmc.get("target_version") or "").strip()
            prior_before = str(prior_bmc.get("before") or prior_bmc.get("current_version") or "").strip()
            prior_after = str(prior_bmc.get("after") or "").strip()
            prior_status = str(prior_bmc.get("status") or "").upper()
            target_matches = _firmware_versions_equal(prior_target, exact_target)
            prior_exact = (
                _firmware_versions_equal(prior_before, prior_target)
                or _firmware_versions_equal(prior_after, prior_target)
                or (
                    prior_status in {"CURRENT", "CURRENT_VERIFIED", "UPDATED_VERIFIED"}
                    and bool(prior_target)
                )
            )
            if not target_matches or not prior_exact:
                continue
            prior_alias = _exact_bmc_package_alias(prior_bmc)
            if prior_alias:
                # A package/image identity from a modern receipt must remain
                # the same exact alias as the current plan.  A re-published
                # image with a different pinned SHA256 is intentionally not
                # considered equivalent just because its printed version is
                # the same.
                if not _bmc_package_aliases_equal(prior_alias, package_alias):
                    continue
                package_binding = "EXACT_PACKAGE_ALIAS_MATCH"
            else:
                # Historical receipts predate embedded package aliases.  They
                # can still bind this physical BMC only after every strict
                # identity, exact target and local-KCS condition above has
                # passed.  The current package alias remains mandatory, so
                # this does not authorize a near-model or unproven package.
                package_binding = "LEGACY_EXACT_TARGET_RECEIPT_CURRENT_PACKAGE_ALIAS_VERIFIED"
            result.update(
                {
                    "verified": True,
                    "reason": "CURRENT_KCS_PREFIX_BOUND_TO_SAME_SERVER_FACTORY_HANDOFF_RECEIPT",
                    "exact_version": exact_target,
                    "source_run_id": run_dir.name,
                    "source": "SAME_SERVER_EXACT_ASUS_PLAN_PLUS_FACTORY_HANDOFF_PLUS_CURRENT_KCS",
                    "freshness": "CURRENT_BOOT_CONTINUITY_VERIFIED",
                    "confidence": "HIGH",
                    "board_identity_binding": board_binding,
                    "package_identity_binding": package_binding,
                }
            )
            return result
        return result

    def _run_workloads(self, output: Path, profile: Any) -> dict[str, Any]:
        return self.stress_runner.run(
            profile,
            output,
            executor=self.executor,
            progress=lambda payload: self._notify({"stage": "HARDWARE_TESTS", **dict(payload)}),
        )

    def _final_sanity(self, identity: Mapping[str, Any], cleanup: Mapping[str, Any]) -> dict[str, Any]:
        _, platform, final_identity, _ = detect_current_platform_and_identity(
            dmi_root=self.dmi_root, fru_reader=self.fru_reader
        )
        sensor = self.executor.run("ipmitool", ("sensor", "list"), timeout_seconds=60)
        sensor_rows = _parse_ipmi_sensors(str(sensor.get("stdout") or ""))
        critical = [row for row in sensor_rows if row["status"] not in {"ok", "ns", "na", "unavailable"}]
        sel = self.executor.run("ipmitool", ("sel", "info"), timeout_seconds=60)
        return {
            "schema_version": 1,
            "platform_id": platform.get("platform_id"),
            "same_server_fingerprint": final_identity.get("fingerprint_sha256") == identity.get("fingerprint_sha256"),
            "boot_id": read_linux_boot_id(),
            "same_boot_id": read_linux_boot_id() == identity.get("boot_id"),
            "sensor_status": "PASS" if not critical else "FAIL",
            "critical_sensor_count": len(critical),
            "sel_entries": _sel_entry_count(str(sel.get("stdout") or "")),
            "sel_cleanup": cleanup.get("result", cleanup.get("status", "UNKNOWN")),
            "firmware_or_power_action_started": False,
        }

    def _discover_bmc_auth(
        self,
        normalized_inventory: Mapping[str, Any],
        identity: Mapping[str, Any],
        *,
        exclude_run_id: str = "",
        read_only: bool = False,
        allow_default_probe_after_recovery: bool = False,
        allow_default_probe_after_observed_first_login: bool = False,
        ignore_provisioned_candidates: bool = False,
    ) -> dict[str, Any]:
        """Run the controlled fresh-server/default-account auth probe."""
        try:
            policy = BmcAuthPolicy.from_mapping(self.config.bmc_auth_policy)
        except (TypeError, ValueError) as exc:
            return {
                "schema_version": 1,
                "state": BmcAuthState.BMC_AUTH_UNAVAILABLE.value,
                "usable_for_authenticated_get": False,
                "reason": f"INVALID_POLICY:{type(exc).__name__}",
                "attempts": [],
                "mutation_authorized": False,
            }
        result = discover_bmc_auth(
            str(normalized_inventory.get("bmc_ip") or ""),
            policy=policy,
            primary_root=self.config.primary_root,
            server_id=str(identity.get("server_id") or ""),
            exclude_run_id=exclude_run_id,
            allow_password_provisioning=not read_only,
            allow_default_probe_after_recovery=allow_default_probe_after_recovery,
            allow_default_probe_after_observed_first_login=allow_default_probe_after_observed_first_login,
            ignore_provisioned_candidates=ignore_provisioned_candidates,
        )
        # Persist a credential-change marker immediately after a successful
        # first-login mutation.  The marker contains no secret and lets a
        # post-reboot/resume path force the final ASUS factory handoff even if
        # the original process did not reach its normal completion handler.
        provisioning = result.get("provisioning") if isinstance(result, Mapping) else {}
        if isinstance(provisioning, Mapping) and bool(provisioning.get("mutation_performed")):
            marker_payload = {
                "schema_version": 1,
                "active": True,
                "server_id": str(identity.get("server_id") or ""),
                # A server ID is derived from the physical identity, but keep
                # the independently calculated live fingerprint as a second
                # binding.  A marker from a different server must never
                # authorize BMC work merely because a stale filesystem state
                # happened to retain a similarly shaped server record.
                "fingerprint_sha256": str(identity.get("fingerprint_sha256") or ""),
                "bmc_ip": str(normalized_inventory.get("bmc_ip") or ""),
                "bmc_endpoint_verified": True,
                "bmc_endpoint_source": "AUTHENTICATED_REDFISH_CURRENT_ENDPOINT",
                "bmc_mac": str(normalized_inventory.get("bmc_mac") or ""),
                "method": "ASUS_FIRST_LOGIN_ACCOUNT_PASSWORD_PATCH",
                "account_path": str(provisioning.get("account_path") or ""),
                "changed_at_utc": utc_now(),
                "sensitive_material_exposed": False,
            }
            try:
                _atomic_json(self.config.bmc_auth_change_marker, marker_payload)
                os.chmod(self.config.bmc_auth_change_marker, 0o600)
                result["bmc_auth_change_marker_persisted"] = True
            except OSError as exc:
                # Keep the mutation visible and credential-free; callers will
                # still perform the same-run handoff, while a reboot-pending
                # path retains its own explicit bmc_auth_changed flag.
                result["bmc_auth_change_marker_persisted"] = False
                result["bmc_auth_change_marker_error"] = type(exc).__name__
        # A prior boot may have performed first-login provisioning before the
        # run could reach its final handoff (for example, a staged BIOS reboot
        # checkpoint).  Carry only non-sensitive marker metadata forward so
        # the next run cannot accidentally release the server with our
        # credential still present.
        try:
            marker = json.loads(self.config.bmc_auth_change_marker.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            marker = {}
        if (
            isinstance(marker, Mapping)
            and bool(marker.get("active"))
            and str(marker.get("server_id") or "") == str(identity.get("server_id") or "")
            and (
                not str(marker.get("fingerprint_sha256") or "")
                or str(marker.get("fingerprint_sha256") or "")
                == str(identity.get("fingerprint_sha256") or "")
            )
        ):
            result["bmc_auth_change_started"] = True
            result["auth_change_provenance"] = "CNServerOps_PERSISTED_MARKER"
            result["bmc_auth_change_marker"] = {
                "method": str(marker.get("method") or "UNKNOWN"),
                "changed_at_utc": str(marker.get("changed_at_utc") or ""),
                "active": True,
                "sensitive_material_exposed": False,
            }
        return result

    def _perform_bmc_handoff(
        self,
        *,
        run_dir: Path,
        normalized_inventory: Mapping[str, Any],
        expected_bmc_version: str,
        firmware_plan: Mapping[str, Any] | None = None,
        reset_already_requested: bool = False,
    ) -> dict[str, Any]:
        """Execute and attest the official ASUS factory/default BMC handoff."""
        try:
            policy = BmcAuthPolicy.from_mapping(self.config.bmc_auth_policy)
            # Some ASMB11 boards expose only ``Unknown (0x####)`` as the
            # management-module model in local inventory.  The exact ASUS
            # firmware planner has already resolved the management generation
            # from platform/catalog evidence; carry that non-sensitive fact
            # into the handoff adapter instead of treating a known ASMB11 as
            # an unknown controller.
            handoff_inventory = dict(normalized_inventory)
            if not any(str(handoff_inventory.get(key) or "").strip() for key in ("bmc_generation", "management_model", "bmc_model")):
                generic = (firmware_plan or {}).get("generic_asus_firmware_engine") if isinstance(firmware_plan, Mapping) else {}
                platform_plan = generic.get("platform") if isinstance(generic, Mapping) else {}
                generation = str(platform_plan.get("bmc_generation") or "").strip() if isinstance(platform_plan, Mapping) else ""
                if generation:
                    handoff_inventory["bmc_generation"] = generation
            result = perform_asus_factory_handoff(
                executor=self.executor,
                normalized_inventory=handoff_inventory,
                expected_bmc_version=expected_bmc_version,
                policy=policy,
                reset_already_requested=reset_already_requested,
            )
            payload = result.to_dict()
            if str(payload.get("status") or "") == "PASS":
                # The factory/default handoff has proven the internal account
                # is gone.  Remove the root-only operational secret reference
                # from this runner as well; no password material is copied to
                # evidence or Central.
                try:
                    policy.provisioned_password_file.unlink(missing_ok=True)
                except OSError:
                    pass
                clear_provisioned_account_binding(policy)
                self._clear_bmc_auth_change_marker()
            return payload
        except Exception as exc:
            # Keep the production record deterministic and credential-free. A
            # handoff exception is a mandatory readiness blocker.
            return {
                "schema_version": 1,
                "status": "FAIL",
                "required": True,
                "method": "ASUS_ASMB_KCS_FACTORY_DEFAULT_RAW_32_66",
                "reset_requested": False,
                "default_state": "UNVERIFIED",
                "reason": f"HANDOFF_EXCEPTION:{type(exc).__name__}",
                "sensitive_material_exposed": False,
            }

    def _persist_bmc_auth_change_marker(
        self,
        *,
        identity: Mapping[str, Any],
        bmc_ip: str,
        method: str,
        account_path: str,
        bmc_endpoint_verified: bool = False,
        bmc_endpoint_source: str = "",
        bmc_mac: str = "",
    ) -> bool:
        """Persist only the fact of an auth-state mutation, never a secret."""
        marker_payload = {
            "schema_version": 1,
            "active": True,
            "server_id": str(identity.get("server_id") or ""),
            "fingerprint_sha256": str(identity.get("fingerprint_sha256") or ""),
            "bmc_ip": str(bmc_ip or ""),
            "bmc_endpoint_verified": bool(bmc_endpoint_verified),
            "bmc_endpoint_source": str(bmc_endpoint_source or ""),
            "bmc_mac": str(bmc_mac or ""),
            "method": str(method or "BMC_AUTH_STATE_MUTATION"),
            "account_path": str(account_path or ""),
            "changed_at_utc": utc_now(),
            "sensitive_material_exposed": False,
        }
        try:
            _atomic_json(self.config.bmc_auth_change_marker, marker_payload)
            os.chmod(self.config.bmc_auth_change_marker, 0o600)
            return True
        except OSError:
            return False

    def _active_bmc_auth_change_marker(self, identity: Mapping[str, Any]) -> dict[str, Any]:
        """Return the active same-server auth marker without exposing secrets."""
        try:
            marker = json.loads(self.config.bmc_auth_change_marker.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            return {}
        if not isinstance(marker, Mapping) or not bool(marker.get("active")):
            return {}
        if str(marker.get("server_id") or "") != str(identity.get("server_id") or ""):
            return {}
        # Permit a historical marker that predates this field only after the
        # existing server-ID proof.  Every newly written marker is bound to
        # both values, and a populated mismatched fingerprint fails closed.
        if (
            str(marker.get("fingerprint_sha256") or "")
            and str(marker.get("fingerprint_sha256") or "")
            != str(identity.get("fingerprint_sha256") or "")
        ):
            return {}
        return {
            "active": True,
            "server_id": str(marker.get("server_id") or ""),
            "fingerprint_sha256": str(marker.get("fingerprint_sha256") or ""),
            "bmc_ip": str(marker.get("bmc_ip") or ""),
            "bmc_endpoint_verified": bool(marker.get("bmc_endpoint_verified")),
            "bmc_endpoint_source": str(marker.get("bmc_endpoint_source") or ""),
            "bmc_mac": str(marker.get("bmc_mac") or ""),
            "method": str(marker.get("method") or "UNKNOWN"),
            "changed_at_utc": str(marker.get("changed_at_utc") or ""),
            "sensitive_material_exposed": False,
        }

    def _clear_bmc_auth_change_marker(self) -> None:
        """Remove only the credential-change marker after a proven handoff."""
        try:
            self.config.bmc_auth_change_marker.unlink(missing_ok=True)
        except OSError:
            pass

    def _collector_client(self) -> tuple[Any | None, dict[str, Any]]:
        if self._collector_client_override is not None:
            return self._collector_client_override, {"status": "TEST_OVERRIDE"}
        status = central_runtime_status(self.config.central_config)
        if status["status"] not in {"ONLINE", "OFFLINE"}:
            return None, status
        try:
            payload = json.loads(self.config.central_config.read_text(encoding="utf-8"))
            access_file = Path(str(payload.get("access_file") or ""))
            credential = central_credential_from_file(access_file)
            client = HttpsCollectorClient(
                str(payload["endpoint"]),
                credential=credential,
                verify_tls=True,
                ca_file=str(payload.get("ca_file") or "") or None,
                timeout_seconds=15,
            )
            return client, status
        except (OSError, ValueError, KeyError, json.JSONDecodeError, CentralApiError) as exc:
            return None, {"status": "OFFLINE", "reason": type(exc).__name__}

    def _notify(self, payload: Mapping[str, Any]) -> None:
        if self.progress_callback is not None:
            self.progress_callback(dict(payload))

    def _evidence_manifest(self, paths: list[Path]) -> dict[str, Any]:
        artifacts = []
        for path in sorted(set(paths), key=lambda item: str(item)):
            if path.is_file() and not path.is_symlink():
                artifacts.append(
                    {
                        "name": path.name,
                        "path": str(path),
                        "sha256": _sha256(path),
                        "size_bytes": path.stat().st_size,
                    }
                )
        return {"schema_version": 1, "created_at_utc": utc_now(), "artifacts": artifacts}

    def _sync_artifacts(
        self,
        run_id: str,
        report_manifest: Mapping[str, Any],
        client: Any | None,
    ) -> dict[str, Any]:
        queue = ArtifactStoreForwardQueue(self.config.artifact_queue_database)
        enqueued: list[dict[str, Any]] = []
        if self.config.artifact_sync_enabled:
            for artifact in report_manifest.get("artifacts", []):
                if not isinstance(artifact, Mapping) or not artifact.get("path"):
                    continue
                enqueued.append(
                    queue.enqueue(
                        run_id,
                        Path(str(artifact["path"])),
                        artifact_type=str(artifact.get("type") or "REPORT"),
                    )
                )
        drain = {"attempted": 0, "synced": 0, "duplicates": 0, "pending": len(enqueued), "failed": 0}
        if (
            client is not None
            and self.config.artifact_sync_enabled
            and callable(getattr(client, "upload_artifact", None))
        ):
            # Handoff-final bundles are generated after the ordinary report
            # queue.  Drain the full bounded batch here so a busy SSD does not
            # record a permanently stale PENDING_UPLOAD result merely because
            # twenty older artifacts occupied the default retry window.
            drain = queue.drain(client, limit=100)
        return {
            "status": queue.status_for_run(run_id),
            "enqueued": len(enqueued),
            "drain": drain,
            "records": queue.records_for_run(run_id),
            "central_failure_invalidates_local_collection": False,
        }

    @staticmethod
    def _central_archive_summary(artifact_sync: Mapping[str, Any]) -> dict[str, Any]:
        records = list(artifact_sync.get("records") or []) if isinstance(artifact_sync, Mapping) else []
        responses = [item.get("central_response") or {} for item in records if isinstance(item, Mapping)]
        primary = [item.get("primary_archive") or {} for item in responses if isinstance(item, Mapping)]
        secondary = [item.get("secondary_archive") or {} for item in responses if isinstance(item, Mapping)]
        return {
            "status": "CENTRAL_HANDLED" if records else "PENDING_UPLOAD",
            "transport": "HTTPS_ARTIFACT_UPLOAD",
            "primary_status": "SYNCED" if primary and all(item.get("status") == "SYNCED" for item in primary) else "PENDING_UPLOAD",
            "secondary_status": "SYNCED" if secondary and all(item.get("status") == "SYNCED" for item in secondary) else "PENDING_RETRY",
            "primary_paths": [str(item.get("path") or "") for item in primary if item.get("path")],
            "secondary_paths": [str(item.get("path") or "") for item in secondary if item.get("path")],
        }

    def _copy_fleet_archive(
        self,
        inventory: Mapping[str, Any],
        run_id: str,
        report_manifest: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Legacy API retained as an explicit Central-only no-op.

        The SSD never writes a Windows host mount.  It uploads immutable
        report bytes over HTTPS; Central creates the serial/run archive and
        handles the optional UNC mirror with a separate retry queue.
        """
        return {
            "status": "CENTRAL_ONLY",
            "run_id": run_id,
            "transport": "HTTPS_ARTIFACT_UPLOAD",
            "linux_windows_mount_used": False,
            "files": [],
        }

    @staticmethod
    def _enqueue_and_drain(
        queue: StoreForwardQueue,
        event: Mapping[str, Any],
        authoritative_record: Path,
        client: Any | None,
    ) -> dict[str, Any]:
        enqueue = queue.enqueue(event, authoritative_record=authoritative_record)
        drain = {"attempted": 0, "synced": 0, "pending": 1}
        if client is not None:
            drain = queue.drain(client)
        return {
            "event_id": event["event_id"],
            "event_type": event["event_type"],
            "enqueue": enqueue,
            "drain": drain,
            "queue_status": queue.status_for_run(str(event["run"]["run_id"])),
        }

    def _finalize_unexpected_failure(
        self,
        orchestrator: ProductionOrchestrator,
        context: dict[str, Any],
        identity: Mapping[str, Any],
        reasons: list[Reason],
        error: Exception,
    ) -> dict[str, Any]:
        reasons.append(
            Reason(
                "PRODUCTION_WORKFLOW_EXCEPTION",
                ReasonSeverity.FAIL,
                f"{type(error).__name__}: {str(error)[:300]}",
            )
        )
        try:
            stage = WorkflowStage(context["run"]["current_stage"])
            if WorkflowStage.BLOCKED in _allowed_transitions(stage):
                context = orchestrator.transition(
                    context,
                    identity=identity,
                    next_stage=WorkflowStage.BLOCKED,
                    details={"reason_code": "PRODUCTION_WORKFLOW_EXCEPTION", "error_type": type(error).__name__},
                )
            return orchestrator.finalize(context, reasons, identity=identity)
        except Exception as finalize_error:
            raise ProductionWorkflowError(
                f"Workflow failed and authoritative finalization also failed: {type(finalize_error).__name__}"
            ) from error

    @staticmethod
    def _normalized_result(
        context: Mapping[str, Any],
        central_runtime: Mapping[str, Any],
        *,
        bmc_auth_state: str = BmcAuthState.BMC_AUTH_UNAVAILABLE.value,
        firmware_status: str = "UNVERIFIED",
        system_diagnostics_status: str = "BLOCKED_BY_AUTH",
    ) -> dict[str, Any]:
        history = list(context.get("stage_history") or [])
        by_stage = {str(item.get("stage")): item.get("details", {}) for item in history}
        hardware = dict(by_stage.get(WorkflowStage.HARDWARE_TESTS.value) or {})
        inventory = dict(by_stage.get(WorkflowStage.INVENTORY.value) or {})
        cleanup = dict(by_stage.get(WorkflowStage.LOG_CLEAN.value) or {})
        return {
            "identity": "PASS",
            "cpu": dict(hardware.get("cpu") or {}).get("status", "NOT_RUN"),
            "ram": dict(hardware.get("memory") or {}).get("status", "NOT_RUN"),
            "storage": dict(inventory.get("storage") or {}).get("status", "UNKNOWN"),
            "runner_storage_smart": dict(inventory.get("runner_storage") or {}).get("smart_status", "UNKNOWN"),
            "nic": dict(inventory.get("network") or {}).get("status", "UNKNOWN"),
            "pcie": dict(inventory.get("pcie") or {}).get("status", "UNKNOWN"),
            "sensors": dict(inventory.get("sensors") or {}).get("status", "UNKNOWN"),
            "firmware_update": normalized_status(firmware_status),
            "system_diagnostics": system_diagnostics_status,
            "log_clean": dict(cleanup.get("result") or {}).get("status", cleanup.get("status", "NOT_REQUIRED")),
            "central_link": "PASS"
            if central_runtime.get("status") in {"ONLINE", "TEST_OVERRIDE"}
            else "PENDING_UPLOAD",
            "bmc_access_state": str(bmc_auth_state or BmcAuthState.BMC_AUTH_UNAVAILABLE.value),
            "global_run_blocked_by_bmc": False,
        }


def central_runtime_status(config_path: Path) -> dict[str, Any]:
    if not config_path.is_file():
        return {"status": "NOT_CONFIGURED", "endpoint": ""}
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
        endpoint = str(payload.get("endpoint") or "").rstrip("/")
        if not endpoint.startswith("https://"):
            return {"status": "INVALID_CONFIG", "endpoint": endpoint}
        ca_file = str(payload.get("ca_file") or "") or None
        context = ssl.create_default_context(cafile=ca_file)
        with urlopen(endpoint + "/healthz", timeout=3, context=context) as response:
            body = json.loads(response.read().decode("utf-8"))
        return {
            "status": "ONLINE" if response.status == 200 and body.get("status") == "OK" else "OFFLINE",
            "endpoint": endpoint,
        }
    except (OSError, ValueError, json.JSONDecodeError, HTTPError, URLError, ssl.SSLError) as exc:
        return {"status": "OFFLINE", "endpoint": "", "reason": type(exc).__name__}


def _result_server_fingerprint(payload: Mapping[str, Any], run: Mapping[str, Any]) -> str:
    """Extract only an explicit physical-server binding from a saved result.

    A serial/model alone is not enough to make prior evidence current. This
    helper intentionally refuses to infer a binding from filenames or a
    hostname, so callers that know the currently detected fingerprint can
    safely omit historical records that cannot be tied to this machine.
    """
    server = payload.get("server")
    if isinstance(server, Mapping) and server.get("fingerprint_sha256"):
        return str(server["fingerprint_sha256"])
    if run.get("server_fingerprint_sha256"):
        return str(run["server_fingerprint_sha256"])
    if payload.get("server_fingerprint_sha256"):
        return str(payload["server_fingerprint_sha256"])
    return ""


def last_production_result(
    primary_root: Path,
    *,
    expected_fingerprint: str = "",
) -> dict[str, Any]:
    """Return the latest result, optionally bound to the current server.

    CLI history may intentionally be global, but the technician console and
    any operation acting on a detected server must not display a previous
    machine's disposition/BMC state as if it were current. A supplied
    fingerprint therefore permits only an exact saved binding.
    """
    runs_root = primary_root / "runs"
    summaries = sorted(
        (path for path in runs_root.glob("RUN-*/result-summary.json") if path.is_file()),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if expected_fingerprint:
        # Include old run.json-only records during a filtered lookup, while
        # preserving result-summary precedence for normal global history.
        candidates = sorted(
            {*summaries, *(path for path in runs_root.glob("RUN-*/run.json") if path.is_file())},
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
    else:
        candidates = summaries
    if not candidates:
        # Historical versions may have only run.json.
        candidates = sorted(
            (path for path in runs_root.glob("RUN-*/run.json") if path.is_file()),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
    selected_path: Path | None = None
    payload: Mapping[str, Any] | None = None
    run: Mapping[str, Any] | None = None
    for candidate in candidates:
        try:
            candidate_payload = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            # A malformed historical result is never authoritative.
            continue
        if not isinstance(candidate_payload, Mapping):
            continue
        candidate_run = candidate_payload.get("run") if isinstance(candidate_payload.get("run"), Mapping) else candidate_payload
        if not isinstance(candidate_run, Mapping):
            continue
        if expected_fingerprint and _result_server_fingerprint(candidate_payload, candidate_run) != expected_fingerprint:
            continue
        selected_path, payload, run = candidate, candidate_payload, candidate_run
        break
    if selected_path is None or payload is None or run is None:
        response: dict[str, Any] = {"status": "NO_RESULT"}
        if expected_fingerprint:
            response["reason"] = "NO_RESULT_FOR_CURRENT_SERVER"
        return response
    result = payload.get("normalized_result") or payload.get("result") or {}
    result = dict(result) if isinstance(result, Mapping) else {}
    bmc_auth_state = str(result.get("bmc_access_state") or BmcAuthState.BMC_AUTH_UNAVAILABLE.value)
    auth_evidence = selected_path.parent / "bmc-auth-discovery.json"
    try:
        auth_payload = json.loads(auth_evidence.read_text(encoding="utf-8"))
        if isinstance(auth_payload, Mapping) and auth_payload.get("state"):
            bmc_auth_state = str(auth_payload["state"])
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    summary = dict(result.get("status_summary") or {})
    component_statuses = dict(summary.get("component_statuses") or {})
    if bmc_auth_is_usable(bmc_auth_state):
        component_statuses["bmc_access_state"] = bmc_auth_state
        if component_statuses.get("system_diagnostics") == "BLOCKED_BY_AUTH":
            component_statuses["system_diagnostics"] = "UNVERIFIED"
        summary["component_statuses"] = component_statuses
        summary["reason"] = [
            item
            for item in (summary.get("reason") or [])
            if "bmc access state requires" not in str(item).lower()
            and "system diagnostics requires authenticated bmc access" not in str(item).lower()
        ]
        summary["reason_text"] = " ".join(summary["reason"]) or "No outstanding review reason."
    return {
        "status": "FOUND",
        "path": str(selected_path),
        "run_id": run.get("run_id", ""),
        "disposition": run.get("final_disposition", ""),
        "collection_status": run.get("collection_status", ""),
        "completed_at_utc": run.get("completed_at_utc", ""),
        "reason_codes": run.get("reason_codes", []),
        "workflow_mode": run.get("workflow_mode", ""),
        "test_profile": run.get("test_profile", ""),
        "handoff_status": result.get("handoff_status", "") if isinstance(result, Mapping) else "",
        "readiness": result.get("readiness", "") if isinstance(result, Mapping) else "",
        "artifact_status": result.get("artifact_status", "") if isinstance(result, Mapping) else "",
        "status_summary": summary,
        "bmc_auth_state": bmc_auth_state,
    }


def human_status_summary(
    *,
    statuses: Mapping[str, Any],
    handoff: Mapping[str, Any],
    workflow_mode: str,
    central_sync: str = "",
    artifact_status: str = "",
    reports_status: str = "",
) -> dict[str, Any]:
    """Produce a compact operator explanation without replacing raw evidence."""
    mode = str(workflow_mode or "PRODUCTION").upper()
    component_statuses = dict(handoff.get("component_statuses") or {})
    reasons: list[str] = []

    for item in handoff.get("failures") or []:
        capability = str(item.get("capability") or "capability").replace("_", " ")
        state = str(item.get("status") or "FAIL")
        reasons.append(f"{capability} reported a genuine {state} state; inspect the raw evidence before handoff.")
    for item in handoff.get("reviews") or []:
        capability_key = str(item.get("capability") or "capability")
        capability = capability_key.replace("_", " ")
        state = str(item.get("status") or "REVIEW")
        if mode in {"DRY_RUN", "SERIAL_COLLECTION", "INVENTORY_ONLY"} and state in {"NOT_TESTED", "NOT_PERFORMED"}:
            reasons.append(f"{capability} was intentionally not exercised in {mode}; no workload or mutation was requested.")
        elif capability_key == "storage" and state == "REVIEW":
            reasons.append("Storage inventory was collected, but SMART health is unavailable through the SSD USB bridge.")
        elif state == "BLOCKED_BY_AUTH":
            reasons.append(f"{capability} requires authenticated BMC access; local capabilities continued.")
        elif state in {"UNVERIFIED", "NOT_SUPPORTED", "PARTIAL"}:
            reasons.append(f"{capability} remains {state}; this does not by itself indicate a hardware failure.")
        else:
            reasons.append(f"{capability} requires operator review ({state}).")

    central_value = str(central_sync or statuses.get("central_link") or "UNKNOWN").upper()
    artifact_value = str(artifact_status or statuses.get("artifact_status") or "").upper()
    if artifact_value == "SYNCED" and central_value in {"PASS", "ONLINE", "SYNCED", "TEST_OVERRIDE"}:
        central_display = "PASS"
    elif artifact_value in {"PENDING_UPLOAD", "UPLOAD_FAILED"} or central_value in {"PENDING_UPLOAD", "OFFLINE"}:
        central_display = "REVIEW"
    else:
        central_display = "PASS" if central_value in {"PASS", "ONLINE", "SYNCED", "TEST_OVERRIDE"} else central_value
    report_display = str(reports_status or "").upper()
    if not report_display:
        report_display = "PASS" if artifact_value in {"SYNCED", "LOCAL_COMPLETE"} else "REVIEW"
    if report_display not in {"PASS", "REVIEW", "FAIL", "NOT_RUN", "NOT_REQUESTED"}:
        report_display = "REVIEW"
    collection_display = str(statuses.get("collection") or "UNKNOWN").upper()
    if collection_display == "IN_PROGRESS":
        collection_display = "REVIEW"
    readiness = str(statuses.get("readiness") or "").upper()
    if not readiness:
        readiness = _public_readiness_label(workflow_mode=mode, overall=str(handoff.get("overall") or "UNKNOWN"))
    return {
        "schema_version": 1,
        "overall": str(handoff.get("overall") or statuses.get("overall") or "UNKNOWN").upper(),
        "collection": collection_display,
        "readiness": readiness,
        "central_sync": central_display,
        "reports": report_display,
        "reason": reasons,
        "reason_text": " ".join(reasons) if reasons else "No outstanding review reason.",
        "workflow_mode": mode,
        "raw_handoff_status": str(handoff.get("handoff_status") or "UNKNOWN"),
        "component_statuses": component_statuses,
    }


def _reason_codes_for_handoff(handoff: Mapping[str, Any], *, workflow_mode: str) -> list[str]:
    mode = str(workflow_mode or "PRODUCTION").upper()
    codes: list[str] = []
    for item in handoff.get("failures") or []:
        capability = re.sub(r"[^A-Z0-9]+", "_", str(item.get("capability") or "CAPABILITY").upper()).strip("_")
        codes.append(f"{capability}_FAILED")
    for item in handoff.get("reviews") or []:
        capability = re.sub(r"[^A-Z0-9]+", "_", str(item.get("capability") or "CAPABILITY").upper()).strip("_")
        status = str(item.get("status") or "REVIEW").upper()
        if mode in {"DRY_RUN", "SERIAL_COLLECTION", "INVENTORY_ONLY"} and status in {"NOT_TESTED", "NOT_PERFORMED"}:
            codes.append(f"{capability}_NOT_TESTED_{mode}")
        elif capability == "STORAGE" and status == "REVIEW":
            codes.append("STORAGE_SMART_UNKNOWN_USB_BRIDGE")
        else:
            codes.append(f"{capability}_{status}")
    return list(dict.fromkeys(codes))


def _final_decision_from_handoff(handoff: Mapping[str, Any], *, workflow_mode: str) -> dict[str, Any]:
    """Derive the persisted operator decision from the final handoff result.

    The initial orchestrator decision is made before Central delivery and (for
    a deferred BMC handoff) before the final factory-state proof.  Reusing that
    early decision can leave a completed, healthy Option 2 run displaying a
    stale FAIL/REVIEW even though the final handoff policy is PASS.  Optional
    capability reviews are deliberately omitted when the policy has promoted
    the run to PASS; their raw statuses remain in ``handoff_policy`` and the
    human status summary.
    """
    overall = str(handoff.get("overall") or "REVIEW").upper()
    reasons: list[Reason] = []
    if overall != "PASS":
        for item in handoff.get("failures") or []:
            capability = re.sub(
                r"[^A-Z0-9]+", "_", str(item.get("capability") or "CAPABILITY").upper()
            ).strip("_")
            status = str(item.get("status") or "FAIL").upper()
            reasons.append(
                Reason(
                    f"{capability}_FAILED",
                    ReasonSeverity.FAIL,
                    f"{str(item.get('capability') or 'Capability').replace('_', ' ')} reported a genuine {status} state; inspect the raw evidence before handoff.",
                )
            )
        for item in handoff.get("reviews") or []:
            capability = re.sub(
                r"[^A-Z0-9]+", "_", str(item.get("capability") or "CAPABILITY").upper()
            ).strip("_")
            status = str(item.get("status") or "REVIEW").upper()
            reasons.append(
                Reason(
                    f"{capability}_{status}",
                    ReasonSeverity.REVIEW,
                    f"{str(item.get('capability') or 'Capability').replace('_', ' ')} requires operator review ({status}).",
                )
            )
    decision = decide_final_disposition(reasons)
    if overall in {"PASS", "PASS_WITH_WARNINGS", "REVIEW", "FAIL", "BLOCKED"}:
        decision["disposition"] = overall
    decision["central_sync_is_non_blocking"] = True
    decision["workflow_mode"] = str(workflow_mode or "PRODUCTION").upper()
    return decision


def _allowed_transitions(stage: WorkflowStage) -> set[WorkflowStage]:
    # Keep the recovery boundary local rather than exposing orchestrator internals.
    if stage in {WorkflowStage.COMPLETE, WorkflowStage.BLOCKED}:
        return set()
    return {WorkflowStage.BLOCKED}


def _stricter_disposition(first: str, second: str) -> str:
    order = {"PASS": 0, "PASS_WITH_WARNINGS": 1, "REVIEW": 2, "FAIL": 3, "BLOCKED": 4}
    left = str(first or "PASS").upper()
    right = str(second or "PASS").upper()
    return left if order.get(left, 2) >= order.get(right, 2) else right


def _public_readiness_label(*, workflow_mode: str, overall: str) -> str:
    """Expose the technician-facing sale/readiness contract without changing
    the historical enum stored in Central.

    ``PASS``/``READY_FOR_HANDOFF`` remain the machine compatibility values;
    production reports and console consumers can use the explicit labels
    below to distinguish a sale-ready result from a review or failure.
    """
    mode = str(workflow_mode or "").upper()
    state = str(overall or "").upper()
    if mode in {"PRODUCTION", "PRODUCTION_EXTENDED"}:
        if state == "PASS":
            return "READY_FOR_SALE"
        if state in {"REVIEW", "PASS_WITH_WARNINGS"}:
            return "REVIEW_REQUIRED"
        return "NOT_READY_FOR_SALE"
    if mode == "FIRMWARE_ONLY":
        return "READY_FOR_HANDOFF" if state == "PASS" else "REVIEW_REQUIRED" if state in {"REVIEW", "PASS_WITH_WARNINGS"} else "NOT_READY_FOR_HANDOFF"
    return "NOT_APPLICABLE"


def _merge_post_recovery_inventory(
    normalized: Mapping[str, Any] | None,
    *,
    recovery: Mapping[str, Any] | None,
    firmware: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Carry KCS recovery endpoint/platform proof into refreshed inventory.

    A factory/default action can briefly make the BMC disappear from host-side
    discovery (especially while DHCP/static LAN services restart).  The KCS
    recovery result is a fresh, same-run proof of the returned LAN address and
    the exact firmware plan is the authoritative platform-generation evidence.
    A verified post-reset KCS endpoint supersedes a pre-reset or cached
    collector address.  If endpoint verification is absent, this helper never
    replaces the collector value: an old address could belong to another host
    after a DHCP/static reset.
    """
    result = dict(normalized or {})
    recovery = recovery if isinstance(recovery, Mapping) else {}
    firmware = firmware if isinstance(firmware, Mapping) else {}
    recovery_ip = str(recovery.get("bmc_ip_after") or "").strip()
    endpoint_verified = str(recovery.get("bmc_endpoint_status") or "").upper() == "DISCOVERED"
    if recovery_ip and endpoint_verified:
        previous_ip = str(result.get("bmc_ip") or "").strip()
        if previous_ip and previous_ip != recovery_ip:
            result["bmc_ip_before_reset"] = previous_ip
        result["bmc_ip"] = recovery_ip
        result["bmc_ip_evidence"] = {
            "value": recovery_ip,
            "source": str(recovery.get("bmc_endpoint_source") or "ASUS_KCS_RECOVERY_IPMI_LAN"),
            "freshness": "CURRENT_BOOT",
            "confidence": "HIGH",
            "raw_reference": "bmc-recovery.json",
        }
        recovery_mac = str(recovery.get("bmc_mac") or "").strip()
        if recovery_mac:
            result["bmc_mac"] = recovery_mac
    recovery_firmware = str(recovery.get("firmware_after") or "").strip()
    kcs_verified = str(recovery.get("kcs_after") or "").upper() == "PASS"
    if recovery_firmware and kcs_verified:
        # A post-reset recollection can race the returning KCS device and
        # temporarily contain a blank/old BMC value. The recovery result is a
        # same-run stable-KCS proof, so keep it in normalized current evidence.
        result["bmc_firmware"] = recovery_firmware
        result["bmc_firmware_evidence"] = {
            "value": recovery_firmware,
            "source": "ASUS_KCS_RECOVERY_POST_RESET_MC_INFO",
            "freshness": "BMC_CURRENT_CONFIRMED",
            "confidence": "HIGH",
            "raw_reference": "bmc-recovery.json",
        }
        updated_components: list[Any] = []
        for raw_component in result.get("components") or []:
            if not isinstance(raw_component, Mapping):
                updated_components.append(raw_component)
                continue
            component = dict(raw_component)
            category = str(component.get("category") or "").upper()
            slot = str(component.get("slot") or component.get("location") or "").upper()
            if category in {"BMC", "MANAGEMENT_MODULE"} or (category == "FIRMWARE" and slot == "BMC"):
                component["firmware"] = recovery_firmware
                component["version"] = recovery_firmware
                field_evidence = dict(component.get("field_evidence") or {})
                field_evidence["firmware"] = dict(result["bmc_firmware_evidence"])
                component["field_evidence"] = field_evidence
            updated_components.append(component)
        if "components" in result:
            result["components"] = updated_components
    engine = firmware.get("generic_asus_firmware_engine")
    engine = engine if isinstance(engine, Mapping) else {}
    descriptor = engine.get("platform")
    descriptor = descriptor if isinstance(descriptor, Mapping) else {}
    generation = str(descriptor.get("bmc_generation") or "").strip().upper()
    if generation and not str(result.get("bmc_generation") or "").strip():
        result["bmc_generation"] = generation
        result["bmc_generation_evidence"] = {
            "value": generation,
            "source": "ASUS_EXACT_FIRMWARE_PLATFORM_DESCRIPTOR",
            "freshness": "CURRENT_BOOT",
            "confidence": "HIGH",
            "raw_reference": "firmware-plan.json",
        }
    return result


def _bmc_handoff_delivery_ready(
    normalized_result: Mapping[str, Any],
    *,
    artifact_sync: Mapping[str, Any],
    event_queue_status: str,
) -> bool:
    """Gate the final BMC reset on immutable delivery proof.

    A credential handoff is the last destructive BMC action.  Reports and the
    primary Windows archive must already be hash-verified by Central, and the
    run's pre-handoff events must be durable there.  The optional secondary UNC
    mirror is intentionally not part of this gate; Central owns its retry.
    """
    if str(normalized_result.get("reports") or "").upper() != "PASS":
        return False
    if str(normalized_result.get("artifact_delivery") or "").upper() != "PASS":
        return False
    if str(normalized_result.get("primary_archive") or "").upper() != "PASS":
        return False
    if str((artifact_sync or {}).get("status") or "").upper() != "SYNCED":
        return False
    return str(event_queue_status or "").upper() in {"SYNCED", "SYNCED_WITH_QUARANTINED"}


def _public_fru_status(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "status": payload.get("status", "UNKNOWN"),
        "mechanism": payload.get("mechanism", ""),
        "error": payload.get("error", ""),
    }


def _coerce_bmc_auth_state(value: str | BmcAuthState) -> BmcAuthState:
    try:
        return value if isinstance(value, BmcAuthState) else BmcAuthState(str(value))
    except ValueError:
        return BmcAuthState.BMC_AUTH_UNAVAILABLE


def _write_workload_evidence(output: Path, name: str, result: Mapping[str, Any]) -> None:
    stdout = output / f"{name}.txt"
    stderr = output / f"{name}.stderr.txt"
    _atomic_text(stdout, str(result.get("stdout") or "") or "<no stdout>\n")
    if result.get("stderr"):
        _atomic_text(stderr, str(result["stderr"]))
    _atomic_json(
        output / f"{name}.json",
        {key: value for key, value in result.items() if key not in {"stdout", "stderr"}},
    )


def _parse_ipmi_field(text: str, field: str) -> str:
    match = re.search(rf"^{re.escape(field)}\s*:\s*(.+?)\s*$", text, re.MULTILINE | re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _firmware_plan_reverified(plan: Mapping[str, Any] | None) -> bool:
    """Return true only for a live exact current/after-version terminal state."""
    value = str((plan or {}).get("readiness") or "").upper()
    return value in {"CURRENT_VERIFIED", "UPDATED_VERIFIED"}


def _firmware_status_reverified(result: Mapping[str, Any] | None) -> bool:
    """Interpret normalized result status without treating PASS as proof."""
    value = str((result or {}).get("firmware_status") or "").upper()
    if value in {"CURRENT", "CURRENT_VERIFIED", "UPDATED_VERIFIED"}:
        return True
    # Older receipts used firmware_update for the terminal state.  Accept
    # only explicit current/updated values; a generic PASS is insufficient.
    return value in {"CURRENT_VERIFIED", "UPDATED_VERIFIED"}


def _firmware_requires_authenticated_bmc(plan: Mapping[str, Any] | None) -> bool:
    """Return whether an outdated component has a selected BMC-auth path.

    A missing transport is reported as a capability failure by the executor;
    it is not a reason to reset/provision BMC credentials speculatively.
    """
    payload = plan or {}
    generic = payload.get("generic_asus_firmware_engine") if isinstance(payload, Mapping) else {}
    components = generic.get("components") if isinstance(generic, Mapping) else {}
    platform = generic.get("platform") if isinstance(generic, Mapping) else {}
    generation = str(platform.get("bmc_generation") or "").replace(" ", "").upper() if isinstance(platform, Mapping) else ""
    bmc_plan = components.get("BMC") if isinstance(components, Mapping) else {}
    bmc_transport = bmc_plan.get("selected_transport") if isinstance(bmc_plan, Mapping) else {}
    bmc_update_required = any(
        isinstance(item, Mapping)
        and str(item.get("component") or "").upper() == "BMC"
        and str(item.get("status") or "").upper() == "UPDATE_REQUIRED"
        for item in (payload.get("components") or [])
    )
    asmb11_kcs_selected = bool(
        isinstance(bmc_transport, Mapping)
        and str(bmc_transport.get("name") or "") == "ASUS_ASMB11_KCS_YAFUFLASH"
        and bool(bmc_transport.get("selectable"))
        and not bool(bmc_transport.get("requires_authenticated_bmc", True))
        and bmc_update_required
    )
    items = payload.get("components") if isinstance(payload, Mapping) else []
    for item in items or []:
        if not isinstance(item, Mapping) or str(item.get("status") or "").upper() != "UPDATE_REQUIRED":
            continue
        name = str(item.get("component") or "").upper()
        component_plan = components.get(name) if isinstance(components, Mapping) else {}
        transport = component_plan.get("selected_transport") if isinstance(component_plan, Mapping) else {}
        if isinstance(transport, Mapping):
            if bool(transport.get("requires_authenticated_bmc", True)):
                return True
            # A selected local transport is an affirmative proof that this
            # component does not need a BMC credential.  In particular, the
            # ASMB11 package-owned KCS updater must not be pre-empted by a
            # speculative credential-recovery flow merely because BIOS will
            # later need its own authenticated transport.
            continue
        # Once an ASMB11 BMC KCS update is selected, defer a BIOS auth path
        # until after the BMC restart and fresh capability re-plan.  Doing a
        # factory/auth recovery before the credential-free BMC path would be
        # unnecessary and would incorrectly mark the BMC as modified.
        if asmb11_kcs_selected and name == "BIOS":
            continue
        # No selected transport is not normally a reason to reset/provision
        # credentials.  For ASMB11/12 it is the one bounded exception: an
        # exact package-owned local/Redfish path may become selectable only
        # after the supported recovery/first-login flow proves a credential.
        if generation in {"ASMB11", "ASMB12"} and name in {"BIOS", "BMC"}:
            return True
    return False


def _discover_local_asus_firmware_tools(
    config_path: Path | None = None,
    *,
    fingerprint: AsusPlatformFingerprint | None = None,
    kcs_evidence: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Read-only discovery of possible official ASUS/local packages.

    Candidate names are evidence only.  No candidate is executed or treated as
    a supported transport until the exact ASUS package, model applicability,
    authorization gate, and post-update verification are physically proven.
    """
    roots = (
        Path("/usr/local/bin"),
        Path("/usr/local/sbin"),
        Path("/usr/sbin"),
        Path("/opt/asus"),
        Path("/opt/ASUS"),
        Path("/usr/local/lib/asus"),
        Path("/usr/lib/asus"),
        Path("/var/lib/cnserverops/firmware"),
    )
    name_pattern = re.compile(r"(?i)(asus|asmb|ast|bmc).*(flash|firm|update)|(^|[-_])(asus|asmb)[-_]?(fw|bmc)")
    package_pattern = re.compile(r"(?i)\.(bin|cap|run|deb|rpm|zip|tar\.gz)$")
    found: list[dict[str, Any]] = []
    inspected_roots: list[str] = []
    for root in roots:
        inspected_roots.append(str(root))
        try:
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if not path.is_file() or path.is_symlink() or len(found) >= 128:
                    continue
                name = path.name
                if not (name_pattern.search(name) or package_pattern.search(name)):
                    continue
                try:
                    found.append(
                        {
                            "path": str(path),
                            "name": name,
                            "executable": bool(os.access(path, os.X_OK)),
                            "size_bytes": path.stat().st_size,
                            "sha256": _sha256(path),
                            "status": "CANDIDATE_ONLY",
                        }
                    )
                except OSError:
                    continue
        except OSError:
            continue
    configured: list[dict[str, Any]] = []
    if config_path is not None:
        try:
            payload = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            payload = None
        entries = payload.get("tools") if isinstance(payload, Mapping) else payload
        if isinstance(entries, list):
            for raw in entries[:32]:
                if not isinstance(raw, Mapping):
                    continue
                path = Path(str(raw.get("path") or ""))
                command = tuple(str(item) for item in (raw.get("command") or ()) if str(item).strip())
                digest = str(raw.get("sha256") or "").strip().lower()
                models = {str(item).strip().casefold() for item in (raw.get("compatible_models") or ()) if str(item).strip()}
                boards = {str(item).strip().casefold() for item in (raw.get("compatible_boards") or ()) if str(item).strip()}
                generations = {str(item).strip().casefold() for item in (raw.get("compatible_bmc_generations") or ()) if str(item).strip()}
                try:
                    actual_digest = _sha256(path) if path.is_file() and not path.is_symlink() else ""
                except OSError:
                    actual_digest = ""
                platform_match = bool(
                    fingerprint
                    and (not models or fingerprint.model.casefold() in models)
                    and (not boards or fingerprint.board.casefold() in boards)
                    and (not generations or fingerprint.bmc_generation.casefold() in generations)
                    and bool(models or boards or generations)
                )
                valid = (
                    path.is_absolute()
                    and path.is_file()
                    and not path.is_symlink()
                    and os.access(path, os.X_OK)
                    and bool(re.fullmatch(r"[0-9a-f]{64}", digest))
                    and actual_digest.casefold() == digest
                    and bool(raw.get("official_source_verified"))
                    and platform_match
                    and bool(command)
                    and "{package}" in command
                    and not bool(raw.get("task_tracking"))
                )
                configured.append(
                    {
                        **{str(key): value for key, value in raw.items() if str(key) not in {"password", "secret", "token"}},
                        "path": str(path),
                        "name": path.name,
                        "sha256": digest,
                        "command": list(command),
                        "status": "APPROVED" if valid else "CONFIG_INVALID",
                        "exact_platform_verified": platform_match,
                        "official_source_verified": bool(raw.get("official_source_verified")),
                        "compatible_models": sorted(models),
                        "compatible_boards": sorted(boards),
                        "compatible_bmc_generations": sorted(generations),
                        "sensitive_material_exposed": False,
                    }
                )
    all_candidates = found + configured
    kcs = kcs_evidence if isinstance(kcs_evidence, Mapping) else {}
    kcs_status = str(kcs.get("status") or "").upper()
    kcs_available = bool(kcs.get("available")) and kcs_status in {"", "PASS", "AVAILABLE", "VERIFIED"}
    return {
        "schema_version": 1,
        "status": "APPROVED_CONFIGURED_TOOL" if any(item.get("status") == "APPROVED" for item in configured) else ("CANDIDATES_FOUND" if found else "NOT_FOUND"),
        "inspected_roots": inspected_roots,
        "candidates": all_candidates,
        "configured_candidates": configured,
        # Do not infer KCS availability from a device-node filename alone.
        # The caller supplies current, read-only local IPMI evidence; a
        # selected ASMB11 transport must still pass its own Yafuflash -kcs
        # non-mutating preflight before an update command is considered.
        "kcs": {
            "available": kcs_available,
            "status": "PASS" if kcs_available else (kcs_status or "NOT_OBSERVED"),
            "source": str(kcs.get("source") or "IPMI_MC_LOCAL_KCS"),
            "firmware_revision": str(kcs.get("firmware_revision") or ""),
            "preflight_required": "YAFU_KCS_INFO",
        },
        "selected_transport": "",
        "mutation_authorized": False,
        "verification_required": [
            "official_ASUS_source_or_package_identity",
            "exact_model_applicability",
            "checksum",
            "supported_transport",
            "terminal_task_state",
            "post_version_verification",
        ],
    }


def _parse_ipmi_sensors(text: str) -> list[dict[str, str]]:
    """Parse ``ipmitool sensor list`` without mistaking units for health.

    ``sensor list`` uses ``Name | Reading | Units | Status | ...`` while
    ``sdr elist`` uses ``Name | ID | Status | ...``.  The previous parser
    always selected column 3, so a healthy ``degrees C``/``RPM`` row became a
    false critical sensor.  We accept both layouts and normalize only the
    actual health token.
    """
    rows: list[dict[str, str]] = []
    health_tokens = {
        "ok",
        "ns",
        "na",
        "nr",
        "nc",
        "cr",
        "unavailable",
        "disabled",
        "unknown",
    }
    for line in text.splitlines():
        parts = [part.strip() for part in line.split("|")]
        if len(parts) < 3 or not parts[0]:
            continue
        candidates = []
        if len(parts) >= 4:
            candidates.append(parts[3].lower())
        candidates.append(parts[2].lower())
        if parts[2].lower() == "discrete" and len(parts) >= 4 and re.fullmatch(r"0x[0-9a-f]+", parts[3].lower()):
            # ipmitool encodes discrete presence/event state as a hex value in
            # the Status column; it is not a health word and must not become a
            # false critical sensor.  The SDR command remains the authority
            # for any discrete-event interpretation.
            status = "ns"
        else:
            status = next((item for item in candidates if item in health_tokens), candidates[0] or "unavailable")
        rows.append({"sensor": parts[0], "reading": parts[1], "status": status})
    return rows


def _sel_entry_count(text: str) -> int:
    match = re.search(r"^Entries\s*:\s*(\d+)\s*$", text, re.MULTILINE | re.IGNORECASE)
    return int(match.group(1)) if match else 0


def _nvme_device_count(text: str) -> int:
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return 0
    devices = payload.get("Devices") if isinstance(payload, dict) else None
    return len(devices) if isinstance(devices, list) else 0


def _safe_interface_names(value: Any) -> list[str]:
    try:
        payload = json.loads(str(value or ""))
    except json.JSONDecodeError:
        return []
    names: list[str] = []
    for row in payload if isinstance(payload, list) else []:
        name = str(row.get("ifname") or "") if isinstance(row, dict) else ""
        if name != "lo" and re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", name):
            names.append(name)
    return sorted(set(names))


def _block_device_paths(value: str) -> list[str]:
    try:
        payload = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return []
    found: list[str] = []

    def visit(rows: Any) -> None:
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, Mapping):
                continue
            if str(row.get("type") or "").lower() in {"disk", "mpath", "raid"}:
                path = str(row.get("path") or "")
                if not path and re.fullmatch(r"[A-Za-z0-9._-]+", str(row.get("name") or "")):
                    path = f"/dev/{row['name']}"
                if re.fullmatch(r"/dev/[A-Za-z0-9._/-]+", path):
                    found.append(path)
            visit(row.get("children"))

    visit(payload.get("blockdevices") if isinstance(payload, Mapping) else [])
    return sorted(set(found))


def _block_device_transport(value: str, device: str) -> str:
    """Return the transport for a block device from lsblk JSON."""
    try:
        payload = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return ""

    def visit(rows: Any) -> str:
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, Mapping):
                continue
            path = str(row.get("path") or "")
            if path == device or (not path and str(row.get("name") or "") == device.removeprefix("/dev/")):
                return str(row.get("tran") or "").lower()
            found = visit(row.get("children"))
            if found:
                return found
        return ""

    return visit(payload.get("blockdevices") if isinstance(payload, Mapping) else [])


def _smart_health_status(result: Mapping[str, Any]) -> str:
    """Classify SMART output by health evidence, not only exit code.

    smartctl returns non-zero for unsupported optional log pages even when an
    NVMe device reports a clean overall health result.  Explicit health failure
    is still a production failure; unsupported runner-bridge SMART is handled
    separately as RUNNER_STORAGE.
    """
    text = str(result.get("stdout") or "")
    upper = text.upper()
    if re.search(r"SMART\s+OVERALL-HEALTH[^\n]*\bPASSED\b", upper) or re.search(
        r"SMART\s+HEALTH\s+STATUS[^\n]*\bOK\b", upper
    ):
        warning = re.search(r"CRITICAL WARNING:\s*0X([0-9A-F]+)", upper)
        if warning and int(warning.group(1), 16) != 0:
            return "FAIL"
        return "PASS"
    if re.search(r"SMART\s+OVERALL-HEALTH[^\n]*\bFAILED\b", upper) or re.search(
        r"SMART\s+HEALTH\s+STATUS[^\n]*\bFAILED\b", upper
    ):
        return "FAIL"
    return "UNAVAILABLE"


def _firmware_versions_equal(left: str, right: str) -> bool:
    def key(value: str) -> tuple[Any, ...]:
        tokens = re.findall(r"\d+|[A-Za-z]+", str(value or "").upper())
        normalized = [int(token) if token.isdigit() else token for token in tokens]
        while normalized and normalized[-1] == 0:
            normalized.pop()
        return tuple(normalized)

    return bool(left and right and key(left) == key(right))


def _local_bmc_revision_matches(recorded: str, live: str) -> bool:
    """Compare local KCS revisions without turning a prefix into full proof."""
    def key(value: str) -> tuple[int, ...]:
        return tuple(int(token) for token in re.findall(r"\d+", str(value or "")))

    recorded_key = key(recorded)
    live_key = key(live)
    return bool(recorded_key and live_key and recorded_key == live_key)


def _firmware_component_from_plan(plan: Mapping[str, Any], component: str) -> dict[str, Any]:
    """Return one component across the public plan schemas used by releases."""
    desired = str(component or "").upper()
    items = plan.get("components") if isinstance(plan, Mapping) else None
    if isinstance(items, list):
        for item in items:
            if isinstance(item, Mapping) and str(item.get("component") or "").upper() == desired:
                return dict(item)
    if isinstance(items, Mapping):
        candidate = items.get(desired)
        if isinstance(candidate, Mapping):
            return dict(candidate)
    engine = plan.get("generic_asus_firmware_engine") if isinstance(plan, Mapping) else None
    engine_components = engine.get("components") if isinstance(engine, Mapping) else None
    if isinstance(engine_components, Mapping):
        candidate = engine_components.get(desired)
        if isinstance(candidate, Mapping):
            return dict(candidate)
    return {}


def _generic_firmware_component_from_plan(plan: Mapping[str, Any], component: str) -> dict[str, Any]:
    """Return the package-bearing generic component from a saved plan.

    The public ``components`` list is intentionally concise for reports and
    often has only before/target/status.  The nested generic engine component
    is the one that records exact ASUS package metadata and applicability.
    Continuity must prefer that richer record whenever it is available.
    """
    desired = str(component or "").upper()
    engine = plan.get("generic_asus_firmware_engine") if isinstance(plan, Mapping) else None
    components = engine.get("components") if isinstance(engine, Mapping) else None
    candidate = components.get(desired) if isinstance(components, Mapping) else None
    return dict(candidate) if isinstance(candidate, Mapping) else {}


def _normalized_inventory_board_serial(inventory: Mapping[str, Any]) -> str:
    """Read the authoritative board serial from either supported schema.

    ``NormalizedInventory`` deliberately keeps board identity on the physical
    MOTHERBOARD component.  Older JSON evidence also carried a top-level
    ``board_serial``.  This helper makes the continuity reader schema-aware
    without trusting a guessed model or a BMC-derived serial.
    """
    direct = str(inventory.get("board_serial") or "").strip()
    if direct:
        return direct
    components = inventory.get("components") if isinstance(inventory, Mapping) else None
    for item in components if isinstance(components, list) else []:
        if not isinstance(item, Mapping) or str(item.get("category") or "").upper() != "MOTHERBOARD":
            continue
        serial = str(item.get("serial") or "").strip()
        if serial:
            return serial
        evidence = item.get("field_evidence") if isinstance(item.get("field_evidence"), Mapping) else {}
        field = evidence.get("serial") if isinstance(evidence, Mapping) else {}
        value = str(field.get("value") or "").strip() if isinstance(field, Mapping) else ""
        if value:
            return value
    return ""


def _server_id_fingerprint(server_id: str) -> str:
    """Return the canonical SHA-256 suffix of a current SERVER_ID, if any."""
    match = re.fullmatch(r"SERVER-([0-9A-Fa-f]{64})", str(server_id or "").strip())
    return match.group(1).lower() if match else ""


def _context_server_fingerprint(server: Mapping[str, Any], run: Mapping[str, Any]) -> str:
    """Read a historical run's identity fingerprint without broad fallback."""
    values = (
        server.get("fingerprint_sha256") if isinstance(server, Mapping) else "",
        run.get("server_fingerprint_sha256") if isinstance(run, Mapping) else "",
        _server_id_fingerprint(str(server.get("server_id") or "")) if isinstance(server, Mapping) else "",
        _server_id_fingerprint(str(run.get("server_id") or "")) if isinstance(run, Mapping) else "",
    )
    for value in values:
        text = str(value or "").strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", text):
            return text
    return ""


def _exact_bmc_package_alias(component_plan: Mapping[str, Any]) -> dict[str, Any]:
    """Build a minimal exact ASUS BMC package identity for continuity.

    This is not a resolver and it never converts a version prefix into an
    image claim.  It only accepts the generic planner's own exact-platform,
    official package selection.  The alias preserves the target version and,
    where available, the pinned package SHA256 so a different/re-published
    image cannot silently inherit an earlier factory-handoff receipt.
    """
    target = str(component_plan.get("target_version") or component_plan.get("target") or "").strip()
    selected = component_plan.get("selected_package") if isinstance(component_plan, Mapping) else None
    match = selected.get("match") if isinstance(selected, Mapping) else None
    metadata = selected.get("metadata") if isinstance(selected, Mapping) else None
    if not target or not isinstance(match, Mapping) or not isinstance(metadata, Mapping):
        return {}
    if not bool(match.get("exact_match")):
        return {}
    if str(metadata.get("vendor") or "").upper() != "ASUS":
        return {}
    if str(metadata.get("component") or "").upper() != "BMC":
        return {}
    if not _firmware_versions_equal(str(metadata.get("version") or ""), target):
        return {}
    if not bool(metadata.get("official_source_verified")) or not metadata.get("applicability_evidence"):
        return {}
    if str(metadata.get("validation_status") or "") not in ASUS_VALIDATED_PACKAGE_STATUSES:
        return {}
    source_url = str(metadata.get("source_url") or metadata.get("official_release_url") or "").strip()
    if not source_url.startswith("https://") or "asus.com" not in source_url.casefold():
        return {}
    sha256 = str(metadata.get("sha256") or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", sha256) or sha256 == "0" * 64:
        sha256 = ""
    return {
        "component": "BMC",
        "target_version": target,
        "package_sha256": sha256,
        "package_filename": str(metadata.get("package_filename") or "").strip(),
        "source_url": source_url,
        "compatible_models": tuple(sorted(str(item).strip().upper() for item in metadata.get("compatible_models") or () if str(item).strip())),
        "compatible_boards": tuple(sorted(str(item).strip().upper() for item in metadata.get("compatible_boards") or () if str(item).strip())),
        "compatible_bmc_generations": tuple(sorted(str(item).strip().upper() for item in metadata.get("compatible_bmc_generations") or () if str(item).strip())),
        "alias_strength": "PINNED_PACKAGE_SHA256" if sha256 else "OFFICIAL_EXACT_PLATFORM_PROVENANCE",
    }


def _normalize_bmc_package_alias(alias: Mapping[str, Any] | None) -> dict[str, Any]:
    """Validate a stored/current alias before it affects a current plan."""
    payload = dict(alias or {}) if isinstance(alias, Mapping) else {}
    target = str(payload.get("target_version") or "").strip()
    if str(payload.get("component") or "").upper() != "BMC" or not target:
        return {}
    source_url = str(payload.get("source_url") or "").strip()
    if not source_url.startswith("https://") or "asus.com" not in source_url.casefold():
        return {}
    package_sha256 = str(payload.get("package_sha256") or "").strip().lower()
    if package_sha256 and not re.fullmatch(r"[0-9a-f]{64}", package_sha256):
        return {}
    return {
        "component": "BMC",
        "target_version": target,
        "package_sha256": package_sha256,
        "package_filename": str(payload.get("package_filename") or "").strip(),
        "source_url": source_url,
        "compatible_models": tuple(str(item).strip().upper() for item in payload.get("compatible_models") or () if str(item).strip()),
        "compatible_boards": tuple(str(item).strip().upper() for item in payload.get("compatible_boards") or () if str(item).strip()),
        "compatible_bmc_generations": tuple(str(item).strip().upper() for item in payload.get("compatible_bmc_generations") or () if str(item).strip()),
        "alias_strength": str(payload.get("alias_strength") or "OFFICIAL_EXACT_PLATFORM_PROVENANCE"),
    }


def _bmc_package_aliases_equal(prior: Mapping[str, Any], current: Mapping[str, Any]) -> bool:
    """Require target and, when available, pinned image identity equality."""
    left = _normalize_bmc_package_alias(prior)
    right = _normalize_bmc_package_alias(current)
    if not left or not right:
        return False
    if not _firmware_versions_equal(str(left["target_version"]), str(right["target_version"])):
        return False
    left_hash = str(left.get("package_sha256") or "")
    right_hash = str(right.get("package_sha256") or "")
    if left_hash or right_hash:
        return bool(left_hash and right_hash and left_hash == right_hash)
    # A provenance-only entry has no downloaded-byte hash.  Retain an exact
    # package alias instead of accepting a bare version: the official URL,
    # filename and all explicitly supplied platform selectors must agree.
    return all(
        left.get(key) == right.get(key)
        for key in (
            "package_filename",
            "source_url",
            "compatible_models",
            "compatible_boards",
            "compatible_bmc_generations",
        )
    )


def _exact_current_versions_verified(
    component_plans: Mapping[str, Any] | Any,
    *,
    current_versions: Mapping[str, str],
) -> bool:
    """Verify current firmware from exact official target metadata.

    A lifecycle proof file is deliberately server-bound and may be missing or
    belong to an earlier chassis.  When the live DMI/KCS versions already
    equal the exact package selected by the generic ASUS engine, that package
    metadata is sufficient to prove that no mutation is required.  Every
    component must still have an exact applicability match, official source
    evidence, and our pinned SHA256; similarly named/family-only packages are
    never accepted here.
    """
    if not isinstance(component_plans, Mapping):
        return False
    for component in ("BIOS", "BMC"):
        plan = component_plans.get(component)
        if not isinstance(plan, Mapping) or str(plan.get("status") or "").upper() != "CURRENT":
            return False
        current = str(current_versions.get(component) or "").strip()
        target = str(plan.get("target_version") or "").strip()
        if not _firmware_versions_equal(current, target):
            return False
        selected = plan.get("selected_package")
        if not isinstance(selected, Mapping):
            return False
        match = selected.get("match")
        metadata = selected.get("metadata")
        if not isinstance(match, Mapping) or not bool(match.get("exact_match")):
            return False
        if not isinstance(metadata, Mapping):
            return False
        if str(metadata.get("component") or "").upper() not in {component, "UNKNOWN"}:
            return False
        if not bool(metadata.get("official_source_verified")):
            return False
        if not metadata.get("applicability_evidence"):
            return False
        if str(metadata.get("validation_status") or "") not in ASUS_VALIDATED_PACKAGE_STATUSES:
            return False
        sha256 = str(metadata.get("sha256") or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", sha256):
            return False
        if sha256 == "0" * 64:
            # A current, installed version does not need a package transfer
            # or mutation.  For a live official catalog entry, exact model
            # applicability and provenance are enough to establish that no
            # update is required; own SHA256 pinning is mandatory if bytes
            # are ever downloaded for mutation.
            if str(metadata.get("validation_status") or "") != "PROVENANCE_VERIFIED":
                return False
        source_url = str(metadata.get("source_url") or metadata.get("official_release_url") or "").strip()
        if not source_url.startswith("https://") or "asus.com" not in source_url.casefold():
            return False
    return True


def _safe_evidence_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-._")[:80] or "device"


def _read_network_sysfs(root: Path = Path("/sys/class/net")) -> dict[str, Any]:
    result: dict[str, Any] = {}
    try:
        interfaces = list(root.iterdir())
    except OSError:
        return result
    for interface in interfaces:
        name = interface.name
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", name):
            continue
        values: dict[str, str] = {}
        device = interface / "device"
        try:
            resolved = device.resolve(strict=True)
            values["device_path"] = str(resolved)
            if re.fullmatch(r"[0-9A-Fa-f]{4}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\.[0-7]", resolved.name):
                values["pci_address"] = resolved.name.lower()
        except OSError:
            pass
        for key, filename in (("phys_port_name", "phys_port_name"), ("address", "address"), ("operstate", "operstate"), ("vendor_id", "vendor"), ("device_id", "device")):
            try:
                values[key] = (interface / filename).read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                pass
        try:
            vpd = (device / "vpd").read_bytes()
            if vpd:
                values["vpd_hex"] = vpd.hex()
        except OSError:
            pass
        if values:
            result[name] = values
    return result


def _parent_block_device(value: str) -> str:
    source = value.strip().splitlines()[0] if value.strip() else ""
    if not re.fullmatch(r"/dev/[A-Za-z0-9._/-]+", source):
        return ""
    if re.search(r"/nvme\d+n\d+p\d+$", source):
        return re.sub(r"p\d+$", "", source)
    return re.sub(r"\d+$", "", source)


def _total_memory_bytes(path: Path = Path("/proc/meminfo")) -> int:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return 2 * 1024**3
    match = re.search(r"^MemTotal:\s*(\d+)\s*kB", text, re.MULTILINE)
    return int(match.group(1)) * 1024 if match else 2 * 1024**3


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(value)
            if value and not value.endswith("\n"):
                stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        Path(temporary_name).replace(path)
    finally:
        temporary = Path(temporary_name)
        if temporary.exists():
            temporary.unlink()


def _atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
    _atomic_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _load_json_mapping(path: Path) -> dict[str, Any]:
    """Load a non-sensitive JSON checkpoint as a mapping, or return empty."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return {}
    return dict(payload) if isinstance(payload, Mapping) else {}
