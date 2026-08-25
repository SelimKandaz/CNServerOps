"""ASUS BMC credential handoff after CNServerOps-owned authentication changes.

The handoff is deliberately separate from firmware transport.  It is invoked
only after the selected workflow has completed its evidence/report/archive
steps, and only when the current run records that CNServerOps provisioned or
recovered an account.  The ASMB11/ASMB12 factory/default action is a bounded local
KCS command; no password is passed on a command line or returned in evidence.
"""

from __future__ import annotations

import os
import re
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .bmc_auth import BmcAuthPolicy
from .bmc_recovery import LocalBmcEndpoint, discover_local_bmc_endpoint, restore_local_ipmi_kcs
from .bmc_version import parse_ipmi_mc_firmware_version, versions_equivalent
from .asus.profiles import infer_inventory_platform_bmc_generation
from .evidence import BmcAuthState


class BmcHandoffError(RuntimeError):
    """Sanitized handoff failure; never contains a credential or response body."""


class HandoffCommandExecutor(Protocol):
    def run(self, tool: str, arguments: tuple[str, ...], *, timeout_seconds: int) -> dict[str, Any]: ...


@dataclass(frozen=True)
class BmcHandoffResult:
    status: str
    required: bool
    method: str
    reset_requested: bool
    bmc_ip: str = ""
    kcs_status: str = "NOT_TESTED"
    firmware_before: str = ""
    firmware_after: str = ""
    default_state: str = "NOT_TESTED"
    password_change_required: bool | None = None
    bmc_endpoint_status: str = "NOT_TESTED"
    bmc_endpoint_source: str = ""
    bmc_mac: str = ""
    post_reset_sensor_status: str = "NOT_TESTED"
    post_reset_fan_status: str = "NOT_TESTED"
    post_reset_sensor_samples: int = 0
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "status": self.status,
            "required": self.required,
            "method": self.method,
            "reset_requested": self.reset_requested,
            "bmc_ip": self.bmc_ip,
            "kcs_status": self.kcs_status,
            "firmware_before": self.firmware_before,
            "firmware_after": self.firmware_after,
            "default_state": self.default_state,
            "first_login_change_required": self.password_change_required,
            "bmc_endpoint_status": self.bmc_endpoint_status,
            "bmc_endpoint_source": self.bmc_endpoint_source,
            "bmc_mac": self.bmc_mac,
            "post_reset_sensor_status": self.post_reset_sensor_status,
            "post_reset_fan_status": self.post_reset_fan_status,
            "post_reset_sensor_samples": self.post_reset_sensor_samples,
            "reason": self.reason,
            "sensitive_material_exposed": False,
        }


def bmc_auth_change_required(discovery: Mapping[str, Any] | None) -> bool:
    """Return true only for a mutation actually performed by CNServerOps."""
    payload = discovery or {}
    provisioning = payload.get("provisioning") if isinstance(payload, Mapping) else {}
    if isinstance(provisioning, Mapping) and bool(provisioning.get("mutation_performed")):
        return True
    if isinstance(payload, Mapping) and bool(payload.get("bmc_auth_change_started")):
        return True
    marker = payload.get("bmc_auth_change_marker") if isinstance(payload, Mapping) else None
    return bool(marker.get("active")) if isinstance(marker, Mapping) else False


def perform_asus_factory_handoff(
    *,
    executor: HandoffCommandExecutor,
    normalized_inventory: Mapping[str, Any],
    expected_bmc_version: str = "",
    policy: BmcAuthPolicy | None = None,
    timeout_seconds: int = 30,
    wait_seconds: int = 180,
    poll_seconds: float = 2.0,
    sensor_stabilization_seconds: int | None = None,
    reset_already_requested: bool = False,
    sleep_fn: Callable[[float], None] = time.sleep,
    redfish_factory: Callable[[str, str, str, bool], Any] | None = None,
) -> BmcHandoffResult:
    """Reset an exact supported ASUS ASMB account to factory/default state.

    ``ipmitool raw 0x32 0x66`` is the bounded ASUS ASMB11/ASMB12 local KCS
    factory recovery operation documented by ASUS.  It resets BMC configuration,
    not firmware.  The caller supplies the expected pre-reset BMC version so
    a reset that unexpectedly changes firmware cannot pass handoff.
    """
    generation = _bmc_generation(normalized_inventory)
    method = f"ASUS_{generation}_KCS_FACTORY_DEFAULT_RAW_32_66" if generation else "ASUS_ASMB_KCS_FACTORY_DEFAULT_RAW_32_66"
    if generation not in {"ASMB11", "ASMB12"}:
        # This raw OEM command is intentionally not a generic IPMI reset.
        # Refuse rather than guessing on an unknown future ASMB or a
        # similarly named management device.
        return BmcHandoffResult(
            "UNSUPPORTED",
            True,
            method,
            False,
            reason="NO_VALIDATED_ASUS_ASMB_FACTORY_HANDOFF_FOR_CURRENT_PLATFORM",
        )
    # KCS can be briefly unavailable while a preceding ASUS recovery action is
    # still restarting the controller.  Wait within the same bounded handoff
    # window instead of immediately converting that transient state into a
    # mandatory handoff failure.
    restore_local_ipmi_kcs(executor, timeout_seconds=timeout_seconds)
    before: dict[str, Any] = {}
    firmware_before = ""
    kcs_deadline = time.monotonic() + max(1, min(int(wait_seconds), 60))
    while time.monotonic() < kcs_deadline:
        before = _mc_info(executor, timeout_seconds)
        firmware_before = _firmware_revision(before)
        if _command_passed(before) and firmware_before:
            break
        sleep_fn(max(0.5, min(float(poll_seconds or 1.0), 2.0)))
    if not firmware_before:
        return BmcHandoffResult(
            "FAIL", True, method, False, kcs_status="FAIL", reason="BMC_KCS_UNAVAILABLE_BEFORE_HANDOFF"
        )
    if expected_bmc_version and not _versions_equal(firmware_before, expected_bmc_version):
        return BmcHandoffResult(
            "FAIL", True, method, False, kcs_status="PASS", firmware_before=firmware_before,
            reason="BMC_VERSION_CHANGED_BEFORE_HANDOFF",
        )
    # Establish a local KCS baseline before the reset.  Fan RPM is deliberately
    # not treated as a failure signal: ASMB controllers may run fans at maximum
    # while restarting.  We only require the same *sensor presence/health*
    # after the controller returns.
    pre_reset_sensors = _sensor_snapshot(executor, timeout_seconds)
    if reset_already_requested:
        # A prior attempt may have completed the raw factory action but timed
        # out during LAN/default-account/sensor verification.  Never issue
        # the bounded reset a second time: verify the post-reset state that is
        # now present instead.
        after = before
        endpoint = discover_local_bmc_endpoint(
            executor,
            normalized_inventory=normalized_inventory,
            timeout_seconds=timeout_seconds,
        )
    else:
        reset = executor.run("ipmitool", ("raw", "0x32", "0x66"), timeout_seconds=timeout_seconds)
        if not _command_passed(reset):
            return BmcHandoffResult(
                "FAIL", True, method, True, kcs_status="PASS", firmware_before=firmware_before,
                reason="ASUS_FACTORY_DEFAULT_ACTION_FAILED",
            )

        deadline = time.monotonic() + max(1, int(wait_seconds))
        after = {}
        endpoint = LocalBmcEndpoint("NOT_TESTED")
        while time.monotonic() < deadline:
            after = _mc_info(executor, timeout_seconds)
            if _command_passed(after):
                endpoint = discover_local_bmc_endpoint(
                    executor,
                    normalized_inventory=normalized_inventory,
                    timeout_seconds=timeout_seconds,
                )
                if endpoint.status == "DISCOVERED":
                    break
            sleep_fn(max(0.1, float(poll_seconds)))
    firmware_after = _firmware_revision(after)
    bmc_ip = endpoint.ip
    if not firmware_after:
        return BmcHandoffResult(
            "FAIL", True, method, True, bmc_ip=bmc_ip, kcs_status="FAIL",
            firmware_before=firmware_before, bmc_endpoint_status=endpoint.status,
            bmc_endpoint_source=endpoint.source, bmc_mac=endpoint.mac,
            reason="BMC_DID_NOT_RETURN_AFTER_FACTORY_DEFAULT",
        )
    if expected_bmc_version and not _versions_equal(firmware_after, expected_bmc_version):
        return BmcHandoffResult(
            "FAIL", True, method, True, bmc_ip=bmc_ip, kcs_status="PASS",
            firmware_before=firmware_before, firmware_after=firmware_after,
            bmc_endpoint_status=endpoint.status, bmc_endpoint_source=endpoint.source,
            bmc_mac=endpoint.mac,
            reason="BMC_FIRMWARE_NOT_PRESERVED_BY_HANDOFF",
        )
    if endpoint.status != "DISCOVERED" or not bmc_ip:
        # A factory reset may move the BMC from a static address to DHCP.
        # Never authenticate to the previous inventory address.  The only
        # admissible fallback is the helper's exact BMC-MAC neighbour proof.
        return BmcHandoffResult(
            "FAIL", True, method, True, bmc_ip="", kcs_status="PASS",
            firmware_before=firmware_before, firmware_after=firmware_after,
            bmc_endpoint_status=endpoint.status, bmc_endpoint_source=endpoint.source,
            bmc_mac=endpoint.mac,
            reason=f"BMC_ENDPOINT_REDISCOVERY_FAILED:{endpoint.reason or endpoint.status}",
        )

    policy = policy or BmcAuthPolicy()
    default_password = _read_secret(policy.default_password_env, policy.default_password_file)
    if not bmc_ip or not default_password:
        return BmcHandoffResult(
            "FAIL", True, method, True, bmc_ip=bmc_ip, kcs_status="PASS",
            firmware_before=firmware_before, firmware_after=firmware_after,
            bmc_endpoint_status=endpoint.status, bmc_endpoint_source=endpoint.source,
            bmc_mac=endpoint.mac,
            default_state="UNVERIFIED", reason="DEFAULT_LOGIN_PROOF_UNAVAILABLE",
        )
    factory = redfish_factory or _default_redfish_factory
    # A factory reset restarts the BMC web stack after KCS becomes available.
    # Do not turn that short, expected readiness window into a failed handoff:
    # retry the authenticated, read-only account proof until the same bounded
    # deadline used for BMC return.  Only an explicit password-change-required
    # response or an account resource for the factory user is positive proof.
    default_state = "UNVERIFIED"
    password_change_required = False
    # ASMB11/ASMB12 can bring KCS back before the HTTPS/Redfish stack.  Use
    # the full bounded handoff window for the default-state proof instead of
    # failing after an arbitrary 60-second slice.
    verification_deadline = time.monotonic() + max(1, min(int(wait_seconds), 180))
    last_error: Exception | None = None
    while time.monotonic() < verification_deadline:
        try:
            client = factory(bmc_ip, policy.default_username, default_password, policy.verify_tls)
            account_payload: Mapping[str, Any] = {}
            account_paths = tuple(dict.fromkeys((
                str(policy.provision_account_path or ""),
                "/redfish/v1/AccountService/Accounts/1",
                "/redfish/v1/AccountService/Accounts/2",
                "/redfish/v1/AccountService/Accounts/4",
            )))
            for account_path in account_paths:
                if not account_path:
                    continue
                try:
                    account = client.get_json(account_path)
                    candidate = account.payload if hasattr(account, "payload") else {}
                    if isinstance(candidate, Mapping):
                        candidate_username = str(candidate.get("UserName") or "").casefold()
                        if candidate_username in {"", policy.default_username.casefold()}:
                            account_payload = candidate
                            break
                except Exception as exc:
                    last_error = exc
                    kind = str(getattr(getattr(exc, "kind", None), "value", getattr(exc, "kind", ""))).upper()
                    if kind == "PASSWORD_CHANGE_REQUIRED":
                        default_state = "FACTORY_DEFAULT_FIRST_LOGIN"
                        password_change_required = True
                        break
            if default_state == "FACTORY_DEFAULT_FIRST_LOGIN":
                break
            if account_payload:
                username = str(account_payload.get("UserName") or "").casefold()
                password_change_required = bool(account_payload.get("PasswordChangeRequired"))
                if username and username != policy.default_username.casefold():
                    raise BmcHandoffError("DEFAULT_ACCOUNT_USERNAME_MISMATCH")
                default_state = (
                    "FACTORY_DEFAULT_FIRST_LOGIN" if password_change_required else "FACTORY_DEFAULT_AUTHENTICATED"
                )
                break
            if last_error is not None:
                raise last_error
            raise BmcHandoffError("DEFAULT_ACCOUNT_NOT_FOUND")
        except Exception as exc:
            last_error = exc
            kind = str(getattr(getattr(exc, "kind", None), "value", getattr(exc, "kind", ""))).upper()
            if kind == "PASSWORD_CHANGE_REQUIRED":
                default_state = "FACTORY_DEFAULT_FIRST_LOGIN"
                password_change_required = True
                break
        if default_state != "UNVERIFIED":
            break
        sleep_fn(max(0.5, min(float(poll_seconds or 1.0), 2.0)))
    if default_state == "UNVERIFIED":
        return BmcHandoffResult(
            "FAIL", True, method, True, bmc_ip=bmc_ip, kcs_status="PASS",
            firmware_before=firmware_before, firmware_after=firmware_after,
            bmc_endpoint_status=endpoint.status, bmc_endpoint_source=endpoint.source,
            bmc_mac=endpoint.mac,
            default_state="UNVERIFIED",
            reason=f"DEFAULT_LOGIN_VERIFY_FAILED:{type(last_error).__name__ if last_error else 'UNKNOWN'}",
        )
    stabilization_seconds = (
        min(max(1, int(wait_seconds)), 120)
        if sensor_stabilization_seconds is None
        else max(1, int(sensor_stabilization_seconds))
    )
    sensor_stability = _wait_for_post_reset_sensor_stability(
        executor,
        pre_reset=pre_reset_sensors,
        timeout_seconds=timeout_seconds,
        wait_seconds=stabilization_seconds,
        poll_seconds=poll_seconds,
        sleep_fn=sleep_fn,
    )
    if sensor_stability.status != "PASS":
        return BmcHandoffResult(
            "FAIL", True, method, True, bmc_ip=bmc_ip, kcs_status="PASS",
            firmware_before=firmware_before, firmware_after=firmware_after,
            default_state=default_state, password_change_required=password_change_required,
            bmc_endpoint_status=endpoint.status, bmc_endpoint_source=endpoint.source,
            bmc_mac=endpoint.mac,
            post_reset_sensor_status=sensor_stability.status,
            post_reset_fan_status=sensor_stability.fan_status,
            post_reset_sensor_samples=sensor_stability.samples,
            reason=sensor_stability.reason,
        )
    return BmcHandoffResult(
        "PASS", True, method, True, bmc_ip=bmc_ip, kcs_status="PASS",
        firmware_before=firmware_before, firmware_after=firmware_after,
        default_state=default_state, password_change_required=password_change_required,
        bmc_endpoint_status=endpoint.status, bmc_endpoint_source=endpoint.source,
        bmc_mac=endpoint.mac,
        post_reset_sensor_status=sensor_stability.status,
        post_reset_fan_status=sensor_stability.fan_status,
        post_reset_sensor_samples=sensor_stability.samples,
        reason="BMC_HANDOFF_VERIFIED_AFTER_PREVIOUS_RESET" if reset_already_requested else "BMC_HANDOFF_COMPLETE",
    )


def _mc_info(executor: HandoffCommandExecutor, timeout_seconds: int) -> dict[str, Any]:
    try:
        return executor.run("ipmitool", ("mc", "info"), timeout_seconds=timeout_seconds)
    except Exception:
        return {"status": "ERROR", "stdout": "", "stderr": "executor failure"}


@dataclass(frozen=True)
class _SensorStability:
    status: str
    fan_status: str
    samples: int
    reason: str


def _sensor_snapshot(executor: HandoffCommandExecutor, timeout_seconds: int) -> dict[str, Any]:
    """Read local KCS sensors and normalize only their actual health column."""
    try:
        result = executor.run("ipmitool", ("sensor", "list"), timeout_seconds=timeout_seconds)
    except Exception:
        return {"status": "UNAVAILABLE", "rows": [], "fan_count": 0, "faults": []}
    if not _command_passed(result):
        return {"status": "UNAVAILABLE", "rows": [], "fan_count": 0, "faults": []}
    rows = _parse_sensor_rows(str(result.get("stdout") or ""))
    faults = [row for row in rows if row["status"] in {"cr", "nr", "nc"}]
    return {
        "status": "PASS" if rows else "EMPTY",
        "rows": rows,
        "fan_count": sum(1 for row in rows if _is_fan_sensor(row["sensor"])),
        "faults": faults,
    }


def _wait_for_post_reset_sensor_stability(
    executor: HandoffCommandExecutor,
    *,
    pre_reset: Mapping[str, Any],
    timeout_seconds: int,
    wait_seconds: int,
    poll_seconds: float,
    sleep_fn: Callable[[float], None],
) -> _SensorStability:
    """Require two local healthy sensor samples after an ASMB reset.

    This guards against a controller that has returned enough for KCS/HTTPS
    but is still in fan fail-safe or has lost its sensor table.  It does not
    judge fan speed; high RPM during recovery is expected and is not evidence
    of a failed fan controller.
    """
    expected_fans = int(pre_reset.get("fan_count") or 0)
    deadline = time.monotonic() + max(1, int(wait_seconds))
    healthy_samples = 0
    samples = 0
    last_status = "UNAVAILABLE"
    last_fan_status = "NOT_TESTED"
    while time.monotonic() < deadline:
        snapshot = _sensor_snapshot(executor, timeout_seconds)
        samples += 1
        status = str(snapshot.get("status") or "UNAVAILABLE")
        fan_count = int(snapshot.get("fan_count") or 0)
        faults = snapshot.get("faults") if isinstance(snapshot.get("faults"), list) else []
        last_status = status
        if faults:
            return _SensorStability("FAIL", "FAULT", samples, "BMC_POST_RESET_SENSOR_FAULT")
        if status != "PASS":
            healthy_samples = 0
            last_fan_status = "UNAVAILABLE" if status == "UNAVAILABLE" else "NOT_EXPOSED"
        elif expected_fans and not fan_count:
            healthy_samples = 0
            last_fan_status = "MISSING"
        else:
            healthy_samples += 1
            last_fan_status = "STABLE" if fan_count else "NOT_EXPOSED"
            if healthy_samples >= 2:
                return _SensorStability("PASS", last_fan_status, samples, "BMC_POST_RESET_SENSORS_STABLE")
        sleep_fn(max(0.1, min(float(poll_seconds), 5.0)))
    if expected_fans and last_fan_status == "MISSING":
        return _SensorStability("FAIL", last_fan_status, samples, "BMC_POST_RESET_FAN_SENSOR_MISSING")
    if last_status == "EMPTY":
        return _SensorStability("FAIL", last_fan_status, samples, "BMC_POST_RESET_SENSOR_EMPTY")
    if last_status == "UNAVAILABLE":
        return _SensorStability("FAIL", last_fan_status, samples, "BMC_POST_RESET_SENSOR_QUERY_UNAVAILABLE")
    return _SensorStability("FAIL", last_fan_status, samples, "BMC_POST_RESET_SENSOR_STABILIZATION_TIMEOUT")


def _parse_sensor_rows(text: str) -> list[dict[str, str]]:
    """Parse ``sensor list`` without treating units such as RPM as health."""
    health_tokens = {"ok", "ns", "na", "nr", "nc", "cr", "unavailable", "disabled", "unknown"}
    rows: list[dict[str, str]] = []
    for line in str(text or "").splitlines():
        parts = [item.strip() for item in line.split("|")]
        if len(parts) < 3 or not parts[0]:
            continue
        candidates = [parts[3].lower()] if len(parts) >= 4 else []
        candidates.append(parts[2].lower())
        if parts[2].lower() == "discrete" and len(parts) >= 4 and re.fullmatch(r"0x[0-9a-f]+", parts[3].lower()):
            status = "ns"
        else:
            status = next((item for item in candidates if item in health_tokens), candidates[0] or "unavailable")
        rows.append({"sensor": parts[0], "reading": parts[1], "status": status})
    return rows


def _is_fan_sensor(name: str) -> bool:
    return bool(re.search(r"(?:^|[^a-z])fan(?:\d|\s|_|$)", str(name or ""), re.IGNORECASE))


def _command_passed(result: Mapping[str, Any]) -> bool:
    status = str(result.get("status") or "").upper()
    exit_code = result.get("exit_code")
    return status in {"PASS", "OK", "COMPLETED"} or exit_code == 0


def _firmware_revision(result: Mapping[str, Any]) -> str:
    return parse_ipmi_mc_firmware_version(str(result.get("stdout") or ""))


def _lan_ip(result: Mapping[str, Any]) -> str:
    text = str(result.get("stdout") or "")
    match = re.search(r"(?im)^IP Address\s*:\s*([0-9a-f:.]+)", text)
    return match.group(1).strip() if match else ""


def _versions_equal(left: str, right: str) -> bool:
    return versions_equivalent(left, right)


def _bmc_generation(normalized_inventory: Mapping[str, Any]) -> str:
    """Return an explicit ASMB generation from current inventory evidence."""
    direct = " ".join(
        str(normalized_inventory.get(key) or "")
        for key in ("bmc_generation", "management_model", "bmc_model")
    )
    match = re.search(r"(?i)(ASMB\s*\d+)", direct)
    if match:
        return re.sub(r"\s+", "", match.group(1)).upper()
    for component in normalized_inventory.get("components") or []:
        if not isinstance(component, Mapping):
            continue
        if str(component.get("category") or "").upper() != "MANAGEMENT_MODULE":
            continue
        text = " ".join(
            str(component.get(key) or "") for key in ("model", "manufacturer", "slot", "location")
        )
        match = re.search(r"(?i)(ASMB\s*\d+)", text)
        if match:
            return re.sub(r"\s+", "", match.group(1)).upper()
    generation, _evidence = infer_inventory_platform_bmc_generation(normalized_inventory)
    return generation


def _is_exact_asmb12(normalized_inventory: Mapping[str, Any]) -> bool:
    """Backward-compatible ASMB12 predicate."""
    return _bmc_generation(normalized_inventory) == "ASMB12"


def _read_secret(env_name: str, path: Path) -> str:
    value = os.environ.get(str(env_name or ""), "") if env_name else ""
    if value:
        return value
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            return ""
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _default_redfish_factory(host: str, username: str, password: str, verify_tls: bool) -> Any:
    from cndellops_asus.redfish import ReadOnlyRedfishClient, RedfishCredentials

    return ReadOnlyRedfishClient(
        host,
        credentials=RedfishCredentials(username=username, password=password, source="factory-default-proof"),
        verify_tls=verify_tls,
        timeout_seconds=30,
    )
